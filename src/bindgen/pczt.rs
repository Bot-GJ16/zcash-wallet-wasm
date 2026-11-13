// Portions derived from ChainSafe WebZjs.
// Copyright 2024 ChainSafe Systems
// Modified by NoirWallet; see THIRD_PARTY_NOTICES.md for licensing.

use orchard::ValuePool;
use pczt::roles::{
    combiner::Combiner,
    redactor::Redactor,
    signer::{Signer, SpendAuthSignature},
    updater::Updater,
};
use serde::Deserialize;

use crate::*;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LedgerSignatures {
    orchard: Vec<LedgerActionSignature>,
    transparent_input_sigs: Vec<Vec<u8>>,
    ironwood: Vec<LedgerActionSignature>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LedgerActionSignature {
    spend_auth_sig: Vec<u8>,
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct Pczt(pczt::Pczt);

impl From<pczt::Pczt> for Pczt {
    fn from(pczt: pczt::Pczt) -> Self {
        Self(pczt)
    }
}

impl From<Pczt> for pczt::Pczt {
    fn from(pczt: Pczt) -> Self {
        pczt.0
    }
}

#[wasm_bindgen]
impl Pczt {
    /// Returns a JSON object with the details of the Pczt.
    pub fn to_json(&self) -> Result<JsValue, Error> {
        serde_wasm_bindgen::to_value(&self.serialize()?).map_err(Error::from)
    }

    /// Returns a Pczt from a JSON object
    pub fn from_json(s: JsValue) -> Result<Pczt, Error> {
        let bytes: Vec<u8> = serde_wasm_bindgen::from_value(s).map_err(Error::from)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the postcard serialization of the Pczt.
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        self.0
            .clone()
            .serialize()
            .map_err(|e| Error::Generic(format!("Failed to serialize PCZT: {e:?}")))
    }

    /// Deserialize to a Pczt from postcard bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Pczt, Error> {
        pczt::Pczt::parse(bytes)
            .map(Self)
            .map_err(|e| Error::Generic(format!("Failed to parse PCZT bytes: {e:?}")))
    }

    /// Strips prover-only data so the PCZT is small enough to transport to an
    /// external signer (e.g. Keystone) as an animated QR.
    ///
    /// Mirrors the "redact for signer" role used by Zashi: removes spend
    /// witnesses (the per-note Merkle authentication paths that dominate the
    /// serialized size) and the `zcash_client_backend` proprietary metadata.
    /// The signer only needs the spend randomizers, values and derivation
    /// paths, so the redacted PCZT still produces valid signatures. The
    /// original (full) PCZT must be retained and merged back with [`combine`]
    /// after signing to restore the witnesses required for proving.
    ///
    /// [`combine`]: Pczt::combine
    pub fn redact_for_signer(&self) -> Pczt {
        let redacted = Redactor::new(self.0.clone())
            .redact_global_with(|mut r| r.redact_proprietary("zcash_client_backend:proposal_info"))
            .redact_orchard_with(|mut r| {
                r.redact_actions(|mut ar| {
                    ar.clear_spend_witness();
                    ar.redact_output_proprietary("zcash_client_backend:output_info");
                });
            })
            .redact_sapling_with(|mut r| {
                r.redact_spends(|mut sr| sr.clear_witness());
                r.redact_outputs(|mut or| or.redact_proprietary("zcash_client_backend:output_info"));
            })
            .redact_transparent_with(|mut r| {
                r.redact_outputs(|mut or| or.redact_proprietary("zcash_client_backend:output_info"));
            })
            .finish();
        Pczt(redacted)
    }

    /// Produces the structured transaction consumed by Ledger's Zcash signer.
    /// The returned action-index arrays are retained by the wallet and bind the
    /// device's compact signature result back to the original PCZT actions.
    pub fn to_ledger_signing_payload(&self, account_index: u32) -> Result<JsValue, Error> {
        let payload = crate::ledger_pczt::signing_payload(&self.0, Some(account_index)).map_err(|message| Error::PcztSign(message))?;
        serde_wasm_bindgen::to_value(&payload).map_err(Error::from)
    }

    /// Verifies and applies signatures returned by Ledger's PCZT signer.
    pub fn apply_ledger_signatures(&self, value: JsValue, account_index: u32) -> Result<Pczt, Error> {
        let signatures: LedgerSignatures = serde_wasm_bindgen::from_value(value).map_err(Error::from)?;
        apply_ledger_signatures_inner(&self.0, signatures, account_index).map(Pczt)
    }

    /// Combines this PCZT with another representing the same transaction.
    ///
    /// Used after external signing: `self` is the full PCZT kept by the wallet
    /// (with witnesses) and `other` is the redacted PCZT returned by the signer
    /// (with signatures). The result carries both, ready for proving and
    /// extraction.
    pub fn combine(&self, other: &Pczt) -> Result<Pczt, Error> {
        Combiner::new(vec![self.0.clone(), other.0.clone()])
            .combine()
            .map(Pczt)
            .map_err(|e| Error::Generic(format!("Failed to combine PCZTs: {e:?}")))
    }
}

fn apply_ledger_signatures_inner(pczt: &pczt::Pczt, signatures: LedgerSignatures, account_index: u32) -> Result<pczt::Pczt, Error> {
    let payload = crate::ledger_pczt::signing_payload(pczt, Some(account_index)).map_err(Error::PcztSign)?;

    if signatures.transparent_input_sigs.len() != payload.transaction.transparent_inputs.len() {
        return Err(Error::PcztSign(format!(
            "Ledger returned {} transparent signatures, expected {}",
            signatures.transparent_input_sigs.len(),
            payload.transaction.transparent_inputs.len()
        )));
    }
    if signatures.orchard.len() != payload.orchard_signature_indices.len() {
        return Err(Error::PcztSign(format!(
            "Ledger returned {} Orchard signatures, expected {}",
            signatures.orchard.len(),
            payload.orchard_signature_indices.len()
        )));
    }
    if signatures.ironwood.len() != payload.ironwood_signature_indices.len() {
        return Err(Error::PcztSign(format!(
            "Ledger returned {} Ironwood signatures, expected {}",
            signatures.ironwood.len(),
            payload.ironwood_signature_indices.len()
        )));
    }

    // The PCZT builder populates bip32_derivation (keyed by compressed pubkey)
    // but does not fill hash160_preimages. The Signer's append_signature needs
    // hash160_preimages to resolve pubkeyhash → pubkey for P2PKH verification.
    // Populate it from the bip32_derivation keys before signing.
    let patched = populate_transparent_hash160_preimages(pczt.clone());

    let mut signer = Signer::new(patched).map_err(|error| Error::PcztSign(format!("Invalid PCZT: {error:?}")))?;

    for (index, raw) in signatures.transparent_input_sigs.iter().enumerate() {
        let Some((&sighash_type, der)) = raw.split_last() else {
            return Err(Error::PcztSign(format!("Ledger returned an empty transparent signature for input {index}")));
        };
        if sighash_type != 1 {
            return Err(Error::PcztSign(format!(
                "Ledger returned unsupported sighash type {sighash_type} for input {index}"
            )));
        }
        let signature = secp256k1::ecdsa::Signature::from_der(der)
            .map_err(|error| Error::PcztSign(format!("Ledger returned invalid DER for transparent input {index}: {error}")))?;
        signer
            .append_transparent_signature(index, signature)
            .map_err(|error| Error::PcztSign(format!("Invalid Ledger signature for transparent input {index}: {error:?}")))?;
    }

    for (result, action_index) in signatures.orchard.iter().zip(payload.orchard_signature_indices) {
        apply_action_signature(&mut signer, ValuePool::Orchard, action_index, result)?;
    }
    for (result, action_index) in signatures.ironwood.iter().zip(payload.ironwood_signature_indices) {
        apply_action_signature(&mut signer, ValuePool::Ironwood, action_index, result)?;
    }

    Ok(signer.finish())
}

fn apply_action_signature(signer: &mut Signer, pool: ValuePool, action_index: usize, result: &LedgerActionSignature) -> Result<(), Error> {
    let signature: [u8; 64] = result.spend_auth_sig.as_slice().try_into().map_err(|_| {
        Error::PcztSign(format!(
            "Ledger returned a {}-byte {pool:?} signature for action {action_index}",
            result.spend_auth_sig.len()
        ))
    })?;
    signer
        .apply_orchard_spend_auth_signature(&SpendAuthSignature::from_parts(pool, action_index, signature))
        .map_err(|error| Error::PcztSign(format!("Invalid Ledger {pool:?} signature for action {action_index}: {error:?}")))
}

/// Ensures every transparent input carries its bip32_derivation pubkeys as
/// hash160 preimages so the Signer role can verify externally-provided
/// signatures for P2PKH inputs.
fn populate_transparent_hash160_preimages(pczt: pczt::Pczt) -> pczt::Pczt {
    Updater::new(pczt)
        .update_transparent_with(|mut updater| {
            let pubkeys_per_input: Vec<Vec<[u8; 33]>> = updater
                .bundle()
                .inputs()
                .iter()
                .map(|input| input.bip32_derivation().keys().copied().collect())
                .collect();
            for (index, pubkeys) in pubkeys_per_input.iter().enumerate() {
                for pubkey in pubkeys {
                    updater.update_input_with(index, |mut input_updater| {
                        input_updater.set_hash160_preimage(pubkey.to_vec());
                        Ok(())
                    })?;
                }
            }
            Ok(())
        })
        .expect("populate_transparent_hash160_preimages: updater failed")
        .finish()
}

#[cfg(test)]
mod tests {
    use super::{LedgerActionSignature, LedgerSignatures, apply_ledger_signatures_inner};
    use crate::{
        bindgen::sign::{
            pczt_sign_inner,
            tests::{OrchardPool, orchard_pczt},
        },
        error::Error,
        ledger_pczt::signing_payload,
    };

    #[test]
    fn converts_real_pczt_to_ledger_payload() {
        let (_, pczt, _, _, spend_index) = orchard_pczt(OrchardPool::Orchard, true);
        let payload = signing_payload(&pczt, Some(0)).unwrap();
        let orchard = payload.transaction.orchard_bundle.unwrap();

        assert_eq!(payload.transaction.global.coin_type, 1);
        assert_eq!(payload.orchard_signature_indices, vec![spend_index]);
        assert!(payload.ironwood_signature_indices.is_empty());
        assert_eq!(orchard.actions[spend_index].spend_value, 1_000_000);
        assert_eq!(orchard.actions[spend_index].signing_path, "32'/1'/0'");
        assert!(payload.transaction.ironwood_bundle.is_some());
    }

    #[tokio::test]
    async fn applies_external_orchard_signature_to_pczt() {
        let (network, pczt, usk, seed_fingerprint, spend_index) = orchard_pczt(OrchardPool::Orchard, true);
        let signed = pczt_sign_inner(network, pczt.clone(), usk, seed_fingerprint).await.unwrap();
        let signature = signed.orchard().actions()[spend_index].spend().spend_auth_sig().unwrap();

        let applied = apply_ledger_signatures_inner(
            &pczt,
            LedgerSignatures {
                orchard: vec![LedgerActionSignature {
                    spend_auth_sig: signature.to_vec(),
                }],
                transparent_input_sigs: vec![],
                ironwood: vec![],
            },
            0,
        )
        .unwrap();

        assert_eq!(applied.orchard().actions()[spend_index].spend().spend_auth_sig(), &Some(signature));
    }

    #[test]
    fn rejects_missing_orchard_signature() {
        let (_, pczt, _, _, _) = orchard_pczt(OrchardPool::Orchard, true);
        let error = apply_ledger_signatures_inner(
            &pczt,
            LedgerSignatures {
                orchard: vec![],
                transparent_input_sigs: vec![],
                ironwood: vec![],
            },
            0,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            Error::PcztSign(message)
                if message == "Ledger returned 0 Orchard signatures, expected 1"
        ));
    }
}
