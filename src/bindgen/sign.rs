// Portions derived from ChainSafe WebZjs.
// Copyright 2024 ChainSafe Systems
// Modified by NoirWallet; see THIRD_PARTY_NOTICES.md for licensing.

use crate::Network;
use crate::bindgen::UnifiedSpendingKey;
use crate::error::Error;
use pczt::roles::signer::Signer;
use pczt::roles::verifier::Verifier;
use std::convert::Infallible;
use std::str::FromStr;
use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
use wasm_bindgen::prelude::wasm_bindgen;
use zcash_protocol::consensus::{NetworkConstants, Parameters};

pub(crate) async fn pczt_sign_inner(
    network: Network,
    pczt: pczt::Pczt,
    usk: zcash_keys::keys::UnifiedSpendingKey,
    seed_fp: zip32::fingerprint::SeedFingerprint,
) -> Result<pczt::Pczt, Error> {
    pczt_sign_owned(network, pczt, usk, seed_fp)
}

fn pczt_sign_owned(
    network: Network,
    pczt: pczt::Pczt,
    usk: zcash_keys::keys::UnifiedSpendingKey,
    seed_fp: zip32::fingerprint::SeedFingerprint,
) -> Result<pczt::Pczt, Error> {
    // Find the spends this one-click signer should authorize.
    #[derive(Debug)]
    enum KeyRef {
        Orchard {
            index: usize,
        },
        Ironwood {
            index: usize,
        },
        Sapling {
            index: usize,
        },
        Transparent {
            index: usize,
            scope: TransparentKeyScope,
            address_index: NonHardenedChildIndex,
        },
    }
    let mut spends_to_sign = Vec::<KeyRef>::new();
    let verifier = Verifier::new(pczt)
        .with_orchard::<Infallible, _>(|bundle| {
            // One-click PCZTs are built for a single wallet account. Legacy or imported
            // accounts may lack ZIP-32 metadata, so let the signer validate the USK against rk.
            for (index, action) in bundle.actions().iter().enumerate() {
                if action.spend().spend_auth_sig().is_none() {
                    spends_to_sign.push(KeyRef::Orchard { index });
                }
            }
            Ok(())
        })
        .map_err(|e| Error::PcztSign(format!("Invalid PCZT: {e:?}")))?;
    let verifier = verifier
        .with_ironwood::<Infallible, _>(|bundle| {
            for (index, action) in bundle.actions().iter().enumerate() {
                if action.spend().spend_auth_sig().is_none() {
                    spends_to_sign.push(KeyRef::Ironwood { index });
                }
            }
            Ok(())
        })
        .map_err(|e| Error::PcztSign(format!("Invalid PCZT: {e:?}")))?;
    let pczt = verifier
        .with_sapling::<Infallible, _>(|bundle| {
            for (index, spend) in bundle.spends().iter().enumerate() {
                if spend
                    .zip32_derivation()
                    .as_ref()
                    .and_then(|derivation| {
                        derivation.extract_account_index(
                            &seed_fp,
                            zip32::ChildIndex::hardened(network.network_type().coin_type()),
                        )
                    })
                    .is_some()
                {
                    spends_to_sign.push(KeyRef::Sapling { index });
                }
            }
            Ok(())
        })
        .map_err(|e| Error::PcztSign(format!("Invalid PCZT: {e:?}")))?
        .with_transparent::<Infallible, _>(|bundle| {
            for (index, input) in bundle.inputs().iter().enumerate() {
                for derivation in input.bip32_derivation().values() {
                    // The HARDENED_FLAG constant (2^31)
                    const HARDENED_FLAG: u32 = 1 << 31;

                    // Create ChildNumber directly from u32 using the internal representation
                    // This matches the coin_type with hardened flag set
                    let coin_type_value = network.network_type().coin_type() | HARDENED_FLAG;

                    if let Some((_, scope, address_index)) =
                        derivation.extract_bip_44_fields(&seed_fp, coin_type_value.into())
                    {
                        spends_to_sign.push(KeyRef::Transparent {
                            index,
                            scope,
                            address_index,
                        });
                    }
                }
            }
            Ok(())
        })
        .map_err(|e| Error::PcztSign(format!("Invalid PCZT: {e:?}")))?
        .finish();

    // Add proof generation key for Sapling spends before signing.
    // This is required for sapling-crypto 0.5+ / pczt 0.5+.
    //
    // Sapling notes can be received via two scopes:
    // - External: regular incoming payments (uses the external IVK)
    // - Internal: change outputs from previous transactions (uses a derived internal IVK)
    //
    // The internal FVK has a different nullifier-deriving key (nk) than the external FVK,
    // which means the proof_generation_key (ak, nsk) is also different. We must set the
    // correct proof_generation_key for each spend based on whether the note was received
    // by the external or internal key. We determine this by checking which ViewingKey
    // can produce the spend's recipient PaymentAddress from its diversifier.
    let pczt = {
        use pczt::roles::updater::Updater;

        let external_proof_gen_key = usk.sapling().expsk().proof_generation_key();
        let internal_proof_gen_key = usk
            .sapling()
            .derive_internal()
            .ok_or_else(|| Error::PcztSign("Failed to derive internal Sapling key".into()))?
            .expsk()
            .proof_generation_key();

        let external_vk = external_proof_gen_key.to_viewing_key();
        let internal_vk = internal_proof_gen_key.to_viewing_key();

        Updater::new(pczt)
            .update_sapling_with(|mut updater| {
                // Collect spends that need a proof generation key, along with the
                // correct key determined by matching the recipient address.
                let spends_needing_key: Vec<(usize, sapling::ProofGenerationKey)> = updater
                    .bundle()
                    .spends()
                    .iter()
                    .enumerate()
                    .filter_map(|(index, spend)| {
                        // Only process spends that don't already have a proof generation key
                        if spend.proof_generation_key().is_some() {
                            return None;
                        }

                        // Determine the correct key by checking which VK matches
                        // the spend's recipient address
                        let key = if let Some(recipient) = spend.recipient() {
                            let diversifier = recipient.diversifier();
                            if external_vk.to_payment_address(*diversifier) == Some(*recipient) {
                                external_proof_gen_key.clone()
                            } else if internal_vk.to_payment_address(*diversifier)
                                == Some(*recipient)
                            {
                                internal_proof_gen_key.clone()
                            } else {
                                // Neither key matches; use external as fallback.
                                // The signer will report WrongFvkForNote if this is wrong.
                                external_proof_gen_key.clone()
                            }
                        } else {
                            // No recipient set; use external as default
                            external_proof_gen_key.clone()
                        };

                        Some((index, key))
                    })
                    .collect();

                // Add the correct proof generation key to each spend
                for (index, key) in spends_needing_key {
                    updater.update_spend_with(index, |mut spend_updater| {
                        spend_updater.set_proof_generation_key(key)
                    })?;
                }

                Ok(())
            })
            .map_err(|e| Error::PcztSign(format!("Failed to add proof generation key: {e:?}")))?
            .finish()
    };

    let mut signer = Signer::new(pczt)
        .map_err(|e| Error::PcztSign(format!("Failed to initialize signer: {e:?}")))?;
    for keyref in spends_to_sign {
        match keyref {
            KeyRef::Orchard { index } => {
                signer
                    .sign_orchard(
                        rand::rand_core::UnwrapErr(rand::rngs::SysRng),
                        index,
                        &orchard::keys::SpendAuthorizingKey::from(usk.orchard()),
                    )
                    .map_err(|e| {
                        Error::PcztSign(format!("Failed to sign Orchard spend {index}: {e:?}"))
                    })?;
            }
            KeyRef::Ironwood { index } => {
                signer
                    .sign_ironwood(
                        rand::rand_core::UnwrapErr(rand::rngs::SysRng),
                        index,
                        &orchard::keys::SpendAuthorizingKey::from(usk.orchard()),
                    )
                    .map_err(|e| {
                        Error::PcztSign(format!("Failed to sign Ironwood spend {index}: {e:?}"))
                    })?;
            }
            KeyRef::Sapling { index } => {
                signer
                    .sign_sapling(
                        rand::rand_core::UnwrapErr(rand::rngs::SysRng),
                        index,
                        usk.sapling().expsk().ask(),
                    )
                    .map_err(|e| {
                        Error::PcztSign(format!("Failed to sign Sapling spend {index}: {e:?}"))
                    })?;
            }
            KeyRef::Transparent {
                index,
                scope,
                address_index,
            } => {
                signer
                    .sign_transparent(
                        index,
                        &usk.transparent()
                            .derive_secret_key(scope, address_index)
                            .map_err(|e| {
                                Error::PcztSign(format!(
                                    "Failed to derive transparent key at .../{scope:?}/{address_index:?}: {e:?}",
                                ))
                            })?,
                    )
                    .map_err(|e| {
                        Error::PcztSign(format!(
                            "Failed to sign transparent input {index}: {e:?}"
                        ))
                    })?;
            }
        }
    }

    Ok(signer.finish())
}

/// TX1 is only a signing artifact; this helper has no transaction extraction or submission path.
#[cfg(feature = "voting")]
pub(crate) fn sign_delegation_owned(
    pczt: pczt::Pczt,
    usk: zcash_keys::keys::UnifiedSpendingKey,
    expected: zcash_voting::delegate::DelegationAccountKeys,
    fingerprint: zip32::fingerprint::SeedFingerprint,
    action_index: usize,
) -> Result<Vec<u8>, crate::voting::types::VotingApiError> {
    use crate::voting::types::{VotingApiError, VotingErrorCode};
    let invalid = || VotingApiError::new(VotingErrorCode::RecoveryConflict);
    if expected.seed_fingerprint != fingerprint.to_bytes()
        || expected.orchard_fvk_bytes
            != orchard::keys::FullViewingKey::from(usk.orchard()).to_bytes()
        || !pczt.orchard().actions().is_empty()
        || !pczt.sapling().spends().is_empty()
        || !pczt.sapling().outputs().is_empty()
        || !pczt.transparent().inputs().is_empty()
        || !pczt.transparent().outputs().is_empty()
        || pczt.ironwood().actions().len() != 1
        || action_index != 0
    {
        return Err(invalid());
    }
    let pczt = Verifier::new(pczt)
        .with_ironwood::<(), _>(|bundle| {
            let spend = bundle.actions()[action_index].spend();
            let index = spend.zip32_derivation().as_ref().and_then(|path| {
                path.extract_account_index(&fingerprint, zip32::ChildIndex::hardened(1))
            });
            if index.map(u32::from) != Some(expected.account_index)
                || spend.spend_auth_sig().is_some()
            {
                return Err(pczt::roles::verifier::OrchardError::Custom(()));
            }
            Ok(())
        })
        .map_err(|_| invalid())?
        .finish();
    pczt_sign_owned(Network::TestNetwork, pczt, usk, fingerprint)
        .and_then(|signed| {
            signed
                .serialize()
                .map_err(|_| Error::PcztSign("invalid signed artifact".into()))
        })
        .map_err(|_| invalid())
}

fn encode_compact_size(size: usize) -> Vec<u8> {
    let mut result = Vec::new();
    match size {
        0x00..=0xfc => {
            result.push(size as u8);
        }
        0x00fd..=0xffff => {
            result.push(0xfd);
            result.extend_from_slice(&(size as u16).to_le_bytes());
        }
        0x0001_0000..=0xffff_ffff => {
            result.push(0xfe);
            result.extend_from_slice(&(size as u32).to_le_bytes());
        }
        _ => {
            result.push(0xff);
            result.extend_from_slice(&(size as u64).to_le_bytes());
        }
    }
    result
}

/// Sign a message with the transparent address private key
///
/// This implements the Bitcoin/Zcash message signing convention compatible with
/// the `signmessage` RPC call.
///
/// # Arguments
///
/// * `network` - Network type ("main" or "test")
/// * `usk` - The Unified Spending Key
/// * `message` - The message to sign
/// * `address_index` - Optional external transparent address index to sign with. If omitted, the default full unified address index is used.
///
/// # Returns
///
/// Returns a JSON object with:
/// - signature: Hex-encoded signature (65 bytes: recovery_id + r + s)
/// - pubkey: Hex-encoded uncompressed public key (65 bytes: 04 + x + y)
/// - address: The transparent address used for signing
///
/// # Example
///
/// ```javascript
/// const result = await sign_message_with_transparent("main", usk, "Hello Zcash!", undefined);
/// // Return the signature to the requesting flow; avoid logging account identifiers.
/// ```
#[wasm_bindgen]
pub fn sign_message_with_transparent(
    network: &str,
    usk: UnifiedSpendingKey,
    message: &str,
    address_index: Option<u32>,
) -> Result<wasm_bindgen::JsValue, Error> {
    use bitcoin_hashes::{Hash, sha256d};
    use secp256k1::{Message as Secp256k1Message, Secp256k1};
    use serde::{Deserialize, Serialize};
    use transparent::keys::{IncomingViewingKey, NonHardenedChildIndex};
    use zcash_client_backend::encoding::AddressCodec;
    use zcash_keys::keys::UnifiedAddressRequest;

    #[derive(Serialize, Deserialize)]
    struct SignatureResult {
        signature: String,
        pubkey: String,
        address: String,
    }

    let net = Network::from_str(network)?;
    let usk_inner: zcash_keys::keys::UnifiedSpendingKey = usk.into();
    let transparent_key = usk_inner.transparent();

    let address_index = match address_index {
        Some(index) => NonHardenedChildIndex::from_index(index)
            .ok_or_else(|| Error::Generic("Invalid transparent child index".into()))?,
        None => {
            let ufvk = usk_inner.to_unified_full_viewing_key();
            let uivk = ufvk.to_unified_incoming_viewing_key();
            let (ua, diversifier_idx) = uivk
                .default_address(UnifiedAddressRequest::AllAvailableKeys)
                .map_err(|e| Error::Generic(format!("Failed to derive default address: {e:?}")))?;
            let transparent_j =
                crate::bindgen::mnemonic::transparent_address_index(&ua, diversifier_idx)
                    .ok_or_else(|| Error::Generic("Invalid transparent child index".into()))?;
            NonHardenedChildIndex::from_index(transparent_j)
                .expect("transparent_address_index returns a valid non-hardened child index")
        }
    };

    let address_obj = transparent_key
        .to_account_pubkey()
        .derive_external_ivk()
        .map_err(|e| Error::Generic(format!("Failed to derive IVK: {e:?}")))?
        .derive_address(address_index)
        .map_err(|e| Error::Generic(format!("Failed to derive address: {e:?}")))?;
    let address_str = address_obj.encode(&net);

    let privkey = transparent_key
        .derive_external_secret_key(address_index)
        .map_err(|e| Error::Generic(format!("Failed to derive private key: {e:?}")))?;

    let secp = Secp256k1::new();

    // Get the uncompressed public key (65 bytes: 04 + x + y)
    let public_key = privkey.public_key();
    let pubkey_uncompressed = public_key.serialize_uncompressed();
    let pubkey_hex = hex::encode(pubkey_uncompressed);

    // Create message hash following Zcash message signing convention
    // "Zcash Signed Message:\n" + message
    let mut msg_bytes = Vec::new();
    let prefix = "Zcash Signed Message:\n";
    msg_bytes.extend_from_slice(&encode_compact_size(prefix.len()));
    msg_bytes.extend_from_slice(prefix.as_bytes());
    msg_bytes.extend_from_slice(&encode_compact_size(message.len()));
    msg_bytes.extend_from_slice(message.as_bytes());

    // Double SHA256
    let hash = sha256d::Hash::hash(&msg_bytes);
    let message_hash = Secp256k1Message::from_digest(hash.to_byte_array());

    // Sign with recovery ID
    let signature = secp.sign_ecdsa_recoverable(message_hash, &privkey);
    let (recovery_id, sig_bytes) = signature.serialize_compact();

    // For Zcash message signing:
    // - Uncompressed pubkey: recovery_id + 27 (range 27-30)
    // - Compressed pubkey: recovery_id + 31 (range 31-34)
    let recovery_byte = 27 + recovery_id.to_u8();

    // Combine recovery_id + signature bytes (65 bytes total)
    let mut full_sig = Vec::with_capacity(65);
    full_sig.push(recovery_byte);
    full_sig.extend_from_slice(&sig_bytes);
    let signature_hex = hex::encode(&full_sig);

    let result = SignatureResult {
        signature: signature_hex,
        pubkey: pubkey_hex,
        address: address_str,
    };

    Ok(serde_wasm_bindgen::to_value(&result)?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::pczt_sign_inner;
    use crate::{Network, error::Error};
    use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer, updater::Updater};
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_primitives::transaction::{
        builder::{BuildConfig, Builder, PcztResult},
        fees::zip317,
    };
    use zcash_protocol::{
        consensus::{NetworkConstants, NetworkUpgrade, Parameters},
        memo::MemoBytes,
        value::Zatoshis,
    };

    #[derive(Clone, Copy)]
    pub(crate) enum OrchardPool {
        Orchard,
        Ironwood,
    }

    #[cfg(feature = "voting")]
    #[test]
    fn delegation_tx1_signing_enforces_account_fingerprint_and_single_ironwood_action() {
        let network = Network::TestNetwork;
        let usk =
            UnifiedSpendingKey::from_seed(&network, &[7; 32], zip32::AccountId::ZERO).unwrap();
        let fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&[7; 32]).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();
        let fvk = ufvk.orchard().unwrap();
        let rho = orchard::note::Rho::from_bytes(&[1; 32]).unwrap();
        let seed = (0..=255)
            .find_map(|b| orchard::note::RandomSeed::from_bytes([b; 32], &rho).into_option())
            .unwrap();
        let note = orchard::Note::from_parts(
            fvk.address_at(0u32, zip32::Scope::External),
            orchard::value::NoteValue::from_raw(100_000_000),
            rho,
            seed,
            orchard::NoteVersion::V3,
        )
        .unwrap();
        let note = zcash_voting::NoteInfo::from_orchard_note(
            &note,
            0,
            zip32::Scope::External,
            &ufvk,
            &network,
        )
        .unwrap();
        let db = zcash_voting::storage::VotingDb::open_browser(
            "fixture",
            zcash_voting::Network::Testnet,
            None,
        )
        .unwrap();
        let id = "01".repeat(32);
        let height = u64::from(u32::from(
            network.activation_height(NetworkUpgrade::Nu6_3).unwrap(),
        ));
        db.init_round(
            zcash_voting::Network::Testnet,
            &zcash_voting::VotingRoundParams {
                vote_round_id: id.clone(),
                snapshot_height: height,
                ea_pk: vec![7; 32],
                nc_root: vec![0; 32],
                nullifier_imt_root: vec![0; 32],
            },
            None,
        )
        .unwrap();
        let hotkey = db.ensure_voting_hotkey(&id).unwrap();
        let keys = zcash_voting::delegate::DelegationKeys::with_voting_hotkey(
            fvk.to_bytes().to_vec(),
            &hotkey,
            fingerprint.to_bytes(),
            0,
            "fixture".into(),
        )
        .unwrap();
        db.ensure_bundles(&id, std::slice::from_ref(&note)).unwrap();
        let setup = db
            .build_governance_pczt(
                &id,
                0,
                &[note],
                &keys,
                zcash_voting::delegate::branch_id_for_height(
                    zcash_voting::Network::Testnet,
                    height,
                )
                .unwrap(),
            )
            .unwrap();
        let metadata = |account_index| zcash_voting::delegate::DelegationAccountKeys {
            account_index,
            orchard_fvk_bytes: fvk.to_bytes(),
            seed_fingerprint: fingerprint.to_bytes(),
        };
        let pczt = pczt::Pczt::parse(&setup.pczt_bytes).unwrap();
        assert!(
            super::sign_delegation_owned(pczt.clone(), usk.clone(), metadata(1), fingerprint, 0)
                .is_err()
        );
        let wrong = zip32::fingerprint::SeedFingerprint::from_seed(&[8; 32]).unwrap();
        assert!(
            super::sign_delegation_owned(pczt.clone(), usk.clone(), metadata(0), wrong, 0).is_err()
        );
        assert!(
            super::sign_delegation_owned(pczt.clone(), usk.clone(), metadata(0), fingerprint, 1)
                .is_err()
        );
        let bytes = super::sign_delegation_owned(pczt, usk, metadata(0), fingerprint, 0).unwrap();
        assert_eq!(
            zcash_voting::delegate::pczt_sighash(&bytes)
                .unwrap()
                .to_vec(),
            setup.pczt_sighash
        );
        assert!(zcash_voting::delegate::spend_auth_signature(&bytes, 0).is_ok());
        let signed = pczt::Pczt::parse(&bytes).unwrap();
        assert!(signed.orchard().actions().is_empty());
        assert_eq!(signed.ironwood().actions().len(), 1);
    }

    pub(crate) fn orchard_pczt(
        pool: OrchardPool,
        include_derivation: bool,
    ) -> (
        Network,
        pczt::Pczt,
        UnifiedSpendingKey,
        zip32::fingerprint::SeedFingerprint,
        usize,
    ) {
        let network = Network::TestNetwork;
        let seed = [7; 32];
        let account_id = zip32::AccountId::ZERO;
        let usk = UnifiedSpendingKey::from_seed(&network, &seed, account_id).unwrap();
        let seed_fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&seed).unwrap();
        let orchard_fvk = orchard::keys::FullViewingKey::from(usk.orchard());
        let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

        let rho = orchard::note::Rho::from_bytes(&[1; 32]).unwrap();
        let rseed = (0u8..=255)
            .find_map(|byte| orchard::note::RandomSeed::from_bytes([byte; 32], &rho).into_option())
            .expect("at least one test rseed is valid");
        let note_version = match pool {
            OrchardPool::Orchard => orchard::note::NoteVersion::V2,
            OrchardPool::Ironwood => orchard::note::NoteVersion::V3,
        };
        let note = orchard::Note::from_parts(
            recipient,
            orchard::value::NoteValue::from_raw(1_000_000),
            rho,
            rseed,
            note_version,
        )
        .unwrap();
        let zero = orchard::tree::MerkleHashOrchard::from_bytes(&[0; 32]).unwrap();
        let merkle_path = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
        let anchor = merkle_path.root(note.commitment().into());
        let target_height = network.activation_height(NetworkUpgrade::Nu6_3).unwrap() + 1;

        let mut builder = Builder::new(
            network,
            target_height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: matches!(pool, OrchardPool::Orchard).then_some(anchor),
                ironwood_anchor: Some(anchor),
                orchard_padding: zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
                ironwood_padding: zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
            },
        );
        match pool {
            OrchardPool::Orchard => {
                builder
                    .add_orchard_spend::<zip317::FeeRule>(orchard_fvk.clone(), note, merkle_path)
                    .unwrap();
            }
            OrchardPool::Ironwood => {
                builder
                    .add_ironwood_spend::<zip317::FeeRule>(orchard_fvk.clone(), note, merkle_path)
                    .unwrap();
            }
        }
        builder
            .add_ironwood_output::<zip317::FeeRule>(
                Some(orchard_fvk.to_ovk(orchard::keys::Scope::External)),
                recipient,
                Zatoshis::const_from_u64(match pool {
                    OrchardPool::Orchard => 980_000,
                    OrchardPool::Ironwood => 990_000,
                }),
                MemoBytes::empty(),
            )
            .unwrap();
        let PcztResult {
            pczt_parts,
            orchard_meta,
            ironwood_meta,
            ..
        } = builder
            .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
            .unwrap();
        let spend_index = match pool {
            OrchardPool::Orchard => orchard_meta.spend_action_index(0).unwrap(),
            OrchardPool::Ironwood => ironwood_meta.spend_action_index(0).unwrap(),
        };
        let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
            .finalize_io(UnwrapErr(SysRng))
            .unwrap();
        let pczt = if include_derivation {
            let derivation = orchard::pczt::Zip32Derivation::parse(
                seed_fingerprint.to_bytes(),
                vec![
                    zip32::ChildIndex::hardened(32).index(),
                    zip32::ChildIndex::hardened(network.network_type().coin_type()).index(),
                    zip32::ChildIndex::hardened(u32::from(account_id)).index(),
                ],
            )
            .unwrap();
            match pool {
                OrchardPool::Orchard => Updater::new(pczt)
                    .update_orchard_with(|mut updater| {
                        updater.update_action_with(spend_index, |mut action| {
                            action.set_spend_zip32_derivation(derivation);
                            Ok(())
                        })?;
                        Ok(())
                    })
                    .unwrap()
                    .finish(),
                OrchardPool::Ironwood => Updater::new(pczt)
                    .update_ironwood_with(|mut updater| {
                        updater.update_action_with(spend_index, |mut action| {
                            action.set_spend_zip32_derivation(derivation);
                            Ok(())
                        })?;
                        Ok(())
                    })
                    .unwrap()
                    .finish(),
            }
        } else {
            pczt
        };

        (network, pczt, usk, seed_fingerprint, spend_index)
    }

    #[tokio::test]
    async fn signs_ironwood_spends() {
        let (network, pczt, usk, seed_fingerprint, spend_index) =
            orchard_pczt(OrchardPool::Ironwood, true);

        assert!(
            pczt.ironwood().actions()[spend_index]
                .spend()
                .spend_auth_sig()
                .is_none()
        );

        let signed = pczt_sign_inner(network, pczt, usk, seed_fingerprint)
            .await
            .unwrap();

        assert!(
            signed.ironwood().actions()[spend_index]
                .spend()
                .spend_auth_sig()
                .is_some()
        );
    }

    #[tokio::test]
    async fn signs_orchard_spend_without_derivation() {
        let (network, pczt, usk, seed_fingerprint, spend_index) =
            orchard_pczt(OrchardPool::Orchard, false);

        let signed = pczt_sign_inner(network, pczt, usk, seed_fingerprint)
            .await
            .unwrap();

        assert!(
            signed.orchard().actions()[spend_index]
                .spend()
                .spend_auth_sig()
                .is_some()
        );
    }

    #[tokio::test]
    async fn signs_ironwood_spend_with_mismatched_seed_fingerprint() {
        let (network, pczt, usk, _, spend_index) = orchard_pczt(OrchardPool::Ironwood, true);
        let mismatched_seed_fingerprint =
            zip32::fingerprint::SeedFingerprint::from_seed(&[8; 32]).unwrap();

        let signed = pczt_sign_inner(network, pczt, usk, mismatched_seed_fingerprint)
            .await
            .unwrap();

        assert!(
            signed.ironwood().actions()[spend_index]
                .spend()
                .spend_auth_sig()
                .is_some()
        );
    }

    #[tokio::test]
    async fn rejects_orchard_spend_with_wrong_spending_key() {
        let (network, pczt, _, seed_fingerprint, spend_index) =
            orchard_pczt(OrchardPool::Orchard, false);
        let wrong_usk =
            UnifiedSpendingKey::from_seed(&network, &[8; 32], zip32::AccountId::ZERO).unwrap();

        let err = pczt_sign_inner(network, pczt, wrong_usk, seed_fingerprint)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            Error::PcztSign(message)
                if message.contains(&format!("Failed to sign Orchard spend {spend_index}"))
                    && message.contains("WrongSpendAuthorizingKey")
        ));
    }
}
