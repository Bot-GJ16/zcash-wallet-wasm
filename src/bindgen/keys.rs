// Portions derived from ChainSafe WebZjs.
// Copyright 2024 ChainSafe Systems
// Modified by NoirWallet; see THIRD_PARTY_NOTICES.md for licensing.

use std::str::FromStr;
use wasm_bindgen::prelude::*;

use crate::Network;
use crate::error::Error;
use secrecy::Zeroize;
use zip32::AccountId;

#[wasm_bindgen]
pub struct SeedFingerprint {
    inner: zip32::fingerprint::SeedFingerprint,
}
#[wasm_bindgen]
impl SeedFingerprint {
    #[wasm_bindgen(constructor)]
    pub fn new(mut seed: Box<[u8]>) -> Result<SeedFingerprint, Error> {
        let result = zip32::fingerprint::SeedFingerprint::from_seed(&seed)
            .ok_or(Error::SeedFingerprint)
            .map(|inner| Self { inner });
        seed.zeroize();
        result
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SeedFingerprint, Error> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::SeedFingerprint)?;
        Ok(Self {
            inner: zip32::fingerprint::SeedFingerprint::from_bytes(bytes),
        })
    }
}

impl From<SeedFingerprint> for zip32::fingerprint::SeedFingerprint {
    fn from(value: SeedFingerprint) -> Self {
        value.inner
    }
}

impl From<zip32::fingerprint::SeedFingerprint> for SeedFingerprint {
    fn from(value: zip32::fingerprint::SeedFingerprint) -> Self {
        Self { inner: value }
    }
}

#[wasm_bindgen]
pub struct ProofGenerationKey {
    inner: sapling::ProofGenerationKey,
}

impl From<ProofGenerationKey> for sapling::ProofGenerationKey {
    fn from(value: ProofGenerationKey) -> sapling::ProofGenerationKey {
        value.inner
    }
}

impl From<sapling::ProofGenerationKey> for ProofGenerationKey {
    fn from(value: sapling::ProofGenerationKey) -> Self {
        Self { inner: value }
    }
}

#[wasm_bindgen]
pub struct UnifiedSpendingKey {
    inner: zcash_keys::keys::UnifiedSpendingKey,
    #[cfg(feature = "voting")]
    voting_derivation: (
        Network,
        AccountId,
        Option<zip32::fingerprint::SeedFingerprint>,
    ),
}

#[wasm_bindgen]
impl UnifiedSpendingKey {
    /// Construct a new UnifiedSpendingKey
    ///
    /// # Arguments
    ///
    /// * `network` - Must be either "main" or "test"
    /// * `seed` - At least 32 bytes of entry. Care should be taken as to how this is derived
    /// * `hd_index` - [ZIP32](https://zips.z.cash/zip-0032) hierarchical deterministic index of the account
    ///
    #[wasm_bindgen(constructor)]
    pub fn new(
        network: &str,
        mut seed: Box<[u8]>,
        hd_index: u32,
    ) -> Result<UnifiedSpendingKey, Error> {
        let network = Network::from_str(network)?;
        let account_id = AccountId::try_from(hd_index)?;
        #[cfg(feature = "voting")]
        let voting_derivation = (
            network,
            account_id,
            zip32::fingerprint::SeedFingerprint::from_seed(&seed),
        );
        let result = zcash_keys::keys::UnifiedSpendingKey::from_seed(&network, &seed, account_id)
            .map(|inner| Self {
                inner,
                #[cfg(feature = "voting")]
                voting_derivation,
            })
            .map_err(Error::from);
        seed.zeroize();
        result
    }

    /// Obtain the UFVK corresponding to this spending key
    pub fn to_unified_full_viewing_key(&self) -> UnifiedFullViewingKey {
        UnifiedFullViewingKey {
            inner: self.inner.to_unified_full_viewing_key(),
        }
    }

    pub fn to_sapling_proof_generation_key(&self) -> ProofGenerationKey {
        ProofGenerationKey {
            inner: self.inner.sapling().expsk().proof_generation_key(),
        }
    }

    // /// Encode the Sapling Extended Spending Key to Bech32 format
    // ///
    // /// # Arguments
    // /// * `network` - Must be either "main" or "test"
    // ///
    // /// # Returns
    // /// String in format "secret-extended-key-main..." or "secret-extended-key-test..."
    // pub fn encode_sapling_extended_spending_key(&self, network: &str) -> Result<String, Error> {
    //     let network = Network::from_str(network)?;
    //     let hrp = match network {
    //         Network::MainNetwork => "secret-extended-key-main",
    //         Network::TestNetwork => "secret-extended-key-test",
    //     };
    //     Ok(zcash_keys::encoding::encode_extended_spending_key(
    //         hrp,
    //         self.inner.sapling(),
    //     ))
    // }

    // /// Encode the Sapling Extended Full Viewing Key to Bech32 format
    // ///
    // /// # Arguments
    // /// * `network` - Must be either "main" or "test"
    // ///
    // /// # Returns
    // /// String in format "zxviews..." or "zxviewtestsapling..."
    // #[allow(deprecated)]
    // pub fn encode_sapling_extended_full_viewing_key(&self, network: &str) -> Result<String, Error> {
    //     let network = Network::from_str(network)?;

    //     // Get ExtendedFullViewingKey from ExtendedSpendingKey
    //     let extfvk = self.inner.sapling().to_extended_full_viewing_key();

    //     let hrp = match network {
    //         Network::MainNetwork => "zxviews",
    //         Network::TestNetwork => "zxviewtestsapling",
    //     };

    //     Ok(zcash_keys::encoding::encode_extended_full_viewing_key(hrp, &extfvk))
    // }

    // /// Encode the transparent secret key to WIF (Wallet Import Format)
    // ///
    // /// # Arguments
    // /// * `network` - Must be either "main" or "test"
    // ///
    // /// # Returns
    // /// String in WIF format
    // pub fn encode_transparent_secret_key(&self, network: &str) -> Result<String, Error> {
    //     use transparent::keys::NonHardenedChildIndex;

    //     let network = Network::from_str(network)?;
    //     let account_priv_key = self.inner.transparent();

    //     // Get the extended private key at the external address path (m/44'/coin_type'/account'/0/0)
    //     let address_index = NonHardenedChildIndex::from_index(0)
    //         .ok_or(Error::KeyDerivation)?;
    //     let external_priv_key = account_priv_key.derive_external_secret_key(address_index)
    //         .map_err(|_| Error::KeyDerivation)?;

    //     // Encode to WIF format
    //     let secret_key_bytes = external_priv_key.secret_bytes();
    //     let prefix = match network {
    //         Network::MainNetwork => [0x80u8],
    //         Network::TestNetwork => [0xEF],
    //     };

    //     let mut data = Vec::new();
    //     data.extend_from_slice(&prefix);
    //     data.extend_from_slice(&secret_key_bytes);
    //     data.push(0x01); // Compressed public key flag

    //     // Double SHA256 for checksum
    //     use sha2::{Sha256, Digest};
    //     let hash1 = Sha256::digest(&data);
    //     let hash2 = Sha256::digest(&hash1);
    //     data.extend_from_slice(&hash2[..4]);

    //     Ok(bs58::encode(data).into_string())
    // }
}

impl From<UnifiedSpendingKey> for zcash_keys::keys::UnifiedSpendingKey {
    fn from(value: UnifiedSpendingKey) -> Self {
        value.inner
    }
}

#[cfg(feature = "voting")]
impl UnifiedSpendingKey {
    pub(crate) fn into_voting_parts(
        self,
    ) -> (
        zcash_keys::keys::UnifiedSpendingKey,
        Network,
        AccountId,
        Option<zip32::fingerprint::SeedFingerprint>,
    ) {
        let (network, index, fingerprint) = self.voting_derivation;
        (self.inner, network, index, fingerprint)
    }
}

#[cfg(all(test, feature = "voting"))]
mod voting_tests {
    #[test]
    fn delegation_key_wrapper_retains_constructor_derivation_without_seed() {
        let key =
            super::UnifiedSpendingKey::new("test", vec![17; 32].into_boxed_slice(), 1).unwrap();
        let (_, network, index, fingerprint) = key.into_voting_parts();
        assert!(matches!(network, crate::Network::TestNetwork));
        assert_eq!(u32::from(index), 1);
        assert_eq!(
            fingerprint,
            zip32::fingerprint::SeedFingerprint::from_seed(&[17; 32])
        );
    }
}

/// A Zcash viewing key
///
/// This is a wrapper around the `zcash_keys::keys::ViewingKey` type.
/// UFVKs should be generated from a spending key by calling `to_unified_full_viewing_key`
/// They can also be encoded and decoded to a canonical string representation
#[wasm_bindgen]
pub struct UnifiedFullViewingKey {
    inner: zcash_keys::keys::UnifiedFullViewingKey,
}

#[wasm_bindgen]
impl UnifiedFullViewingKey {
    pub fn encode(&self, network: &str) -> Result<String, Error> {
        let network = Network::from_str(network)?;
        self.inner
            .encode(&network)
            .map_err(|error| Error::KeyDecoding(error.to_string()))
    }

    #[wasm_bindgen(constructor)]
    pub fn new(network: &str, encoding: &str) -> Result<UnifiedFullViewingKey, Error> {
        let network = Network::from_str(network)?;
        Ok(Self {
            inner: zcash_keys::keys::UnifiedFullViewingKey::decode(&network, encoding)
                .map_err(|error| Error::KeyDecoding(error.to_string()))?,
        })
    }
}

impl UnifiedFullViewingKey {
    /// Get a reference to the inner UnifiedFullViewingKey
    pub(crate) fn as_inner(&self) -> &zcash_keys::keys::UnifiedFullViewingKey {
        &self.inner
    }
}
