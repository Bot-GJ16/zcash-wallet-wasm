use std::collections::BTreeMap;

use ff::PrimeField;
use orchard::{ValuePool, bundle::BundleVersion, note::NoteVersion};
use pczt::{
    Pczt,
    roles::verifier::{OrchardError, SaplingError, TransparentError, Verifier},
};
use serde::Serialize;
use transparent::pczt::Bip32Derivation;
use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;
use zcash_protocol::consensus::BranchId;
use zcash_script::script::Evaluable;

const V6_TX_VERSION: u32 = 6;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SigningPayload {
    pub transaction: Transaction,
    pub orchard_signature_indices: Vec<usize>,
    pub ironwood_signature_indices: Vec<usize>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Transaction {
    pub global: Global,
    pub transparent_inputs: Vec<TransparentInput>,
    pub transparent_outputs: Vec<TransparentOutput>,
    pub orchard_bundle: Option<OrchardBundle>,
    pub ironwood_bundle: Option<IronwoodBundle>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Global {
    pub tx_version: u32,
    pub version_group_id: u32,
    pub consensus_branch_id: u32,
    pub fallback_lock_time: Option<u32>,
    pub expiry_height: u32,
    pub coin_type: u32,
    pub tx_modifiable: u8,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Derivation {
    pub signing_path: String,
    pub pubkey: Vec<u8>,
    pub seed_fingerprint: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransparentInput {
    pub prevout_txid: Vec<u8>,
    pub prevout_index: u32,
    pub sequence: Option<u32>,
    pub value: u64,
    pub script_pub_key: Vec<u8>,
    pub sighash_type: u8,
    pub derivation: Derivation,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransparentOutput {
    pub value: u64,
    pub script_pub_key: Vec<u8>,
    pub derivation: Option<Derivation>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OrchardAction {
    pub cv_net: Vec<u8>,
    pub nullifier: Vec<u8>,
    pub rk: Vec<u8>,
    pub spend_recipient: Vec<u8>,
    pub spend_value: u64,
    pub spend_rho: Vec<u8>,
    pub spend_rseed: Vec<u8>,
    pub alpha: Vec<u8>,
    pub signing_path: String,
    pub seed_fingerprint: Vec<u8>,
    pub cmx: Vec<u8>,
    pub ephemeral_key: Vec<u8>,
    pub enc_ciphertext: Vec<u8>,
    pub out_ciphertext: Vec<u8>,
    pub recipient: Vec<u8>,
    pub value: u64,
    pub rseed: Vec<u8>,
    pub rcv: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IronwoodAction {
    #[serde(flatten)]
    pub action: OrchardAction,
    pub note_plaintext_version: u8,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OrchardBundle {
    pub actions: Vec<OrchardAction>,
    pub flags: u8,
    pub value_balance: i64,
    pub anchor: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IronwoodBundle {
    pub actions: Vec<IronwoodAction>,
    pub flags: u8,
    pub value_balance: i64,
    pub anchor: Vec<u8>,
}

pub(crate) fn signing_payload(
    pczt: &Pczt,
    fallback_account_index: Option<u32>,
) -> Result<SigningPayload, String> {
    let global = parse_global(pczt)?;
    let mut transparent_inputs = Vec::new();
    let mut transparent_outputs = Vec::new();
    let mut orchard_bundle = None;
    let mut ironwood_bundle = None;
    let mut has_sapling = false;

    let branch = BranchId::try_from(global.consensus_branch_id).map_err(|_| {
        format!(
            "Unrecognized consensus branch ID {:#010x}",
            global.consensus_branch_id
        )
    })?;

    let verifier = Verifier::new(pczt.clone())
        .with_transparent::<String, _>(|bundle| {
            for input in bundle.inputs() {
                transparent_inputs
                    .push(convert_transparent_input(input).map_err(TransparentError::Custom)?);
            }
            for output in bundle.outputs() {
                transparent_outputs
                    .push(convert_transparent_output(output).map_err(TransparentError::Custom)?);
            }
            Ok(())
        })
        .map_err(map_transparent_error)?;

    let verifier = verifier
        .with_sapling::<String, _>(|bundle| {
            has_sapling = !bundle.spends().is_empty() || !bundle.outputs().is_empty();
            Ok(())
        })
        .map_err(map_sapling_error)?;
    if has_sapling {
        return Err("SAPLING_UNSUPPORTED: Ledger does not inspect Sapling PCZT data".into());
    }

    let verifier = verifier
        .with_orchard::<String, _>(|bundle| {
            orchard_bundle = convert_orchard_bundle(
                bundle,
                branch,
                ValuePool::Orchard,
                global.coin_type,
                fallback_account_index,
            )
            .map_err(OrchardError::Custom)?;
            Ok(())
        })
        .map_err(|error| map_orchard_error("Orchard", error))?;

    if global.tx_version >= V6_TX_VERSION {
        verifier
            .with_ironwood::<String, _>(|bundle| {
                ironwood_bundle = convert_ironwood_bundle(
                    bundle,
                    branch,
                    global.coin_type,
                    fallback_account_index,
                )
                .map_err(OrchardError::Custom)?;
                Ok(())
            })
            .map_err(|error| map_orchard_error("Ironwood", error))?;
    }

    let orchard_signature_indices = orchard_bundle
        .as_ref()
        .map(|bundle| real_spend_indices(&bundle.actions))
        .unwrap_or_default();
    let ironwood_signature_indices = ironwood_bundle
        .as_ref()
        .map(|bundle| {
            bundle
                .actions
                .iter()
                .enumerate()
                .filter_map(|(index, action)| (action.action.spend_value != 0).then_some(index))
                .collect()
        })
        .unwrap_or_default();

    Ok(SigningPayload {
        transaction: Transaction {
            global,
            transparent_inputs,
            transparent_outputs,
            orchard_bundle,
            ironwood_bundle,
        },
        orchard_signature_indices,
        ironwood_signature_indices,
    })
}

fn parse_global(pczt: &Pczt) -> Result<Global, String> {
    let value = serde_json::to_value(pczt.global())
        .map_err(|error| format!("Failed to inspect PCZT global fields: {error}"))?;
    let number = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("Missing PCZT global field {name}"))
    };
    let fallback_lock_time = match value.get("fallback_lock_time") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            value
                .as_u64()
                .ok_or_else(|| "Invalid PCZT fallback_lock_time".to_string())?
                .try_into()
                .map_err(|_| "PCZT fallback_lock_time exceeds u32".to_string())?,
        ),
    };

    Ok(Global {
        tx_version: *pczt.global().tx_version(),
        version_group_id: *pczt.global().version_group_id(),
        consensus_branch_id: *pczt.global().consensus_branch_id(),
        fallback_lock_time,
        expiry_height: *pczt.global().expiry_height(),
        coin_type: number("coin_type")?
            .try_into()
            .map_err(|_| "PCZT coin_type exceeds u32".to_string())?,
        tx_modifiable: number("tx_modifiable")?
            .try_into()
            .map_err(|_| "PCZT tx_modifiable exceeds u8".to_string())?,
    })
}

fn convert_transparent_input(input: &transparent::pczt::Input) -> Result<TransparentInput, String> {
    let derivation = single_derivation(input.bip32_derivation())?
        .ok_or_else(|| "Transparent input requires one derivation".to_string())?;
    let sighash_type = input.sighash_type().encode();
    if sighash_type != 1 {
        return Err(format!(
            "Ledger requires SIGHASH_ALL, received {sighash_type}"
        ));
    }
    Ok(TransparentInput {
        prevout_txid: input.prevout_txid().as_ref().to_vec(),
        prevout_index: *input.prevout_index(),
        sequence: *input.sequence(),
        value: input.value().into_u64(),
        script_pub_key: input.script_pubkey().to_bytes(),
        sighash_type,
        derivation,
    })
}

fn convert_transparent_output(
    output: &transparent::pczt::Output,
) -> Result<TransparentOutput, String> {
    Ok(TransparentOutput {
        value: output.value().into_u64(),
        script_pub_key: output.script_pubkey().to_bytes(),
        derivation: single_derivation(output.bip32_derivation())?,
    })
}

fn single_derivation(
    map: &BTreeMap<[u8; 33], Bip32Derivation>,
) -> Result<Option<Derivation>, String> {
    match map.len() {
        0 => Ok(None),
        1 => {
            let (pubkey, derivation) = map.iter().next().unwrap();
            Ok(Some(Derivation {
                signing_path: format_path(
                    derivation.derivation_path().iter().copied().map(u32::from),
                ),
                pubkey: pubkey.to_vec(),
                seed_fingerprint: derivation.seed_fingerprint().to_vec(),
            }))
        }
        count => Err(format!(
            "Ledger supports at most one transparent derivation, found {count}"
        )),
    }
}

fn convert_orchard_bundle(
    bundle: &orchard::pczt::Bundle,
    branch: BranchId,
    pool: ValuePool,
    coin_type: u32,
    fallback_account_index: Option<u32>,
) -> Result<Option<OrchardBundle>, String> {
    if bundle.actions().is_empty() {
        return Ok(None);
    }
    let version = bundle_version_for_branch(branch, pool)
        .ok_or_else(|| format!("No {pool:?} bundle version for {branch:?}"))?;
    let actions = bundle
        .actions()
        .iter()
        .map(|action| convert_orchard_action(action, coin_type, fallback_account_index))
        .collect::<Result<_, _>>()?;
    let (magnitude, sign) = bundle.value_sum().magnitude_sign();
    let magnitude = i64::try_from(magnitude)
        .map_err(|_| "Orchard value balance exceeds Ledger's signed 64-bit range".to_string())?;
    Ok(Some(OrchardBundle {
        actions,
        flags: bundle
            .flags()
            .to_byte(version)
            .ok_or_else(|| "Orchard flags are not representable".to_string())?,
        value_balance: if matches!(sign, orchard::value::Sign::Negative) {
            -magnitude
        } else {
            magnitude
        },
        anchor: bundle.anchor().to_bytes().to_vec(),
    }))
}

fn convert_ironwood_bundle(
    bundle: &orchard::pczt::Bundle,
    branch: BranchId,
    coin_type: u32,
    fallback_account_index: Option<u32>,
) -> Result<Option<IronwoodBundle>, String> {
    // Ledger's V6 PCZT protocol requires the Ironwood section to be present even
    // when the transaction has no Ironwood actions. The signer SDK uses `null`
    // to mean an invalid V6 payload, while a zero-action bundle is serialized as
    // the canonical empty section.
    if bundle.actions().is_empty() {
        return Ok(Some(IronwoodBundle {
            actions: vec![],
            flags: 0,
            value_balance: 0,
            anchor: vec![0; 32],
        }));
    }

    let Some(converted) = convert_orchard_bundle(
        bundle,
        branch,
        ValuePool::Ironwood,
        coin_type,
        fallback_account_index,
    )?
    else {
        return Ok(None);
    };
    let version = bundle_version_for_branch(branch, ValuePool::Ironwood)
        .ok_or_else(|| format!("No Ironwood bundle version for {branch:?}"))?;
    let note_plaintext_version = note_plaintext_version(version);
    Ok(Some(IronwoodBundle {
        actions: converted
            .actions
            .into_iter()
            .map(|action| IronwoodAction {
                action,
                note_plaintext_version,
            })
            .collect(),
        flags: converted.flags,
        value_balance: converted.value_balance,
        anchor: converted.anchor,
    }))
}

fn convert_orchard_action(
    action: &orchard::pczt::Action,
    coin_type: u32,
    fallback_account_index: Option<u32>,
) -> Result<OrchardAction, String> {
    let spend = action.spend();
    let output = action.output();
    let spend_value = spend
        .value()
        .map(|value| value.inner())
        .ok_or_else(|| "Orchard spend is missing its value".to_string())?;
    let derivation = spend.zip32_derivation().as_ref();
    let (signing_path, seed_fingerprint) = match derivation {
        Some(derivation) => (
            format_path(
                derivation
                    .derivation_path()
                    .iter()
                    .map(|component| component.index()),
            ),
            derivation.seed_fingerprint().to_vec(),
        ),
        None if spend_value == 0 => {
            let account_index = fallback_account_index.ok_or_else(|| {
                "Dummy Orchard spend requires the hardware account index".to_string()
            })?;
            dummy_signing_derivation(coin_type, account_index)?
        }
        None => return Err("Orchard spend is missing its derivation".to_string()),
    };
    let note = output.encrypted_note();

    Ok(OrchardAction {
        cv_net: action.cv_net().to_bytes().to_vec(),
        nullifier: spend.nullifier().to_bytes().to_vec(),
        rk: <[u8; 32]>::from(spend.rk()).to_vec(),
        spend_recipient: spend
            .recipient()
            .map(|value| value.to_raw_address_bytes().to_vec())
            .ok_or_else(|| "Orchard spend is missing its recipient".to_string())?,
        spend_value,
        spend_rho: spend
            .rho()
            .map(|value| value.to_bytes().to_vec())
            .ok_or_else(|| "Orchard spend is missing rho".to_string())?,
        spend_rseed: spend
            .rseed()
            .map(|value| value.as_bytes().to_vec())
            .ok_or_else(|| "Orchard spend is missing rseed".to_string())?,
        alpha: spend
            .alpha()
            .map(|value| value.to_repr().to_vec())
            .ok_or_else(|| "Orchard spend is missing alpha".to_string())?,
        signing_path,
        seed_fingerprint,
        cmx: output.cmx().to_bytes().to_vec(),
        ephemeral_key: note.epk_bytes.to_vec(),
        enc_ciphertext: note.enc_ciphertext.as_ref().to_vec(),
        out_ciphertext: note.out_ciphertext.as_ref().to_vec(),
        recipient: output
            .recipient()
            .map(|value| value.to_raw_address_bytes().to_vec())
            .ok_or_else(|| "Orchard output is missing its recipient".to_string())?,
        value: output
            .value()
            .map(|value| value.inner())
            .ok_or_else(|| "Orchard output is missing its value".to_string())?,
        rseed: output
            .rseed()
            .map(|value| value.as_bytes().to_vec())
            .ok_or_else(|| "Orchard output is missing rseed".to_string())?,
        rcv: action
            .rcv()
            .as_ref()
            .map(|value| value.to_bytes().to_vec())
            .ok_or_else(|| "Orchard action is missing rcv".to_string())?,
    })
}

fn real_spend_indices(actions: &[OrchardAction]) -> Vec<usize> {
    actions
        .iter()
        .enumerate()
        .filter_map(|(index, action)| (action.spend_value != 0).then_some(index))
        .collect()
}

fn dummy_signing_derivation(
    coin_type: u32,
    account_index: u32,
) -> Result<(String, Vec<u8>), String> {
    if account_index >= 1 << 31 {
        return Err("Hardware account index must be below 2^31".to_string());
    }
    Ok((
        format_path(
            [
                32 | (1 << 31),
                coin_type | (1 << 31),
                account_index | (1 << 31),
            ]
            .into_iter(),
        ),
        vec![0; 32],
    ))
}

fn note_plaintext_version(version: BundleVersion) -> u8 {
    match version.note_version() {
        NoteVersion::V2 => 2,
        NoteVersion::V3 => 3,
    }
}

fn format_path(indices: impl Iterator<Item = u32>) -> String {
    indices
        .map(|index| {
            if index & 0x8000_0000 != 0 {
                format!("{}'", index & 0x7fff_ffff)
            } else {
                index.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn map_transparent_error(error: TransparentError<String>) -> String {
    match error {
        TransparentError::Custom(message) => message,
        other => format!("Invalid transparent PCZT bundle: {other:?}"),
    }
}

fn map_sapling_error(error: SaplingError<String>) -> String {
    match error {
        SaplingError::Custom(message) => message,
        other => format!("Invalid Sapling PCZT bundle: {other:?}"),
    }
}

fn map_orchard_error(pool: &str, error: OrchardError<String>) -> String {
    match error {
        OrchardError::Custom(message) => message,
        other => format!("Invalid {pool} PCZT bundle: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{dummy_signing_derivation, format_path, signing_payload};
    use pczt::roles::creator::Creator;
    use zcash_protocol::consensus::BranchId;

    #[test]
    fn formats_hardened_paths_for_ledger() {
        assert_eq!(
            format_path([0x8000_002c, 0x8000_0085, 0x8000_0000, 0, 7].into_iter()),
            "44'/133'/0'/0/7"
        );
    }

    #[test]
    fn supplies_the_account_path_only_for_dummy_spend_metadata() {
        let (path, fingerprint) = dummy_signing_derivation(133, 7).unwrap();
        assert_eq!(path, "32'/133'/7'");
        assert_eq!(fingerprint, vec![0; 32]);
        assert!(dummy_signing_derivation(133, 1 << 31).is_err());
    }

    #[test]
    fn includes_an_empty_ironwood_bundle_for_v6_transactions() {
        let pczt = Creator::new(BranchId::Nu6_3.into(), 1, 133, None, None)
            .unwrap()
            .build()
            .unwrap();

        let payload = signing_payload(&pczt, Some(0)).unwrap();
        let ironwood = payload.transaction.ironwood_bundle.unwrap();

        assert!(ironwood.actions.is_empty());
        assert!(payload.ironwood_signature_indices.is_empty());
    }
}
