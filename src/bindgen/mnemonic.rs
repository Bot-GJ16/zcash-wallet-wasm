use crate::Error;
use crate::bindgen::{SeedFingerprint, UnifiedSpendingKey};
use bip0039::{Count, English, Mnemonic};
use secrecy::Zeroize;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Addresses for all Zcash pools.
#[derive(Serialize, Deserialize)]
pub struct UnifiedAddresses {
    /// The shielded-only unified address (contains Orchard/Sapling receivers only)
    pub unified: String,
    /// The full unified address (contains all available receivers)
    pub full_unified: String,
    /// The Orchard receiver address (if available)
    pub orchard: Option<String>,
    /// The Sapling receiver unified address (u1 format, if available)
    pub sapling: Option<String>,
    /// The Sapling receiver traditional address (zs format, if available)
    pub sapling_zs: Option<String>,
    /// The Transparent receiver address (if available)
    pub transparent: Option<String>,
    /// Transparent child address index corresponding to the full unified address.
    pub address_index: Option<u32>,
}

pub(crate) fn unified_addresses_from_full<P>(
    address: &zcash_keys::address::UnifiedAddress,
    params: &P,
    address_index: Option<u32>,
) -> UnifiedAddresses
where
    P: zcash_protocol::consensus::Parameters,
{
    use zcash_client_backend::encoding::AddressCodec;
    use zcash_keys::address::UnifiedAddress as ZcashUnifiedAddress;

    let orchard_receiver = address.orchard().cloned();
    let sapling_receiver = address.sapling().cloned();
    let shielded_unified =
        ZcashUnifiedAddress::from_receivers(orchard_receiver, sapling_receiver, None, None, None)
            .expect("all-available unified address should include a shielded receiver");

    let orchard = orchard_receiver.as_ref().and_then(|receiver| {
        ZcashUnifiedAddress::from_receivers(Some(*receiver), None, None, None, None)
            .map(|ua| ua.encode(params))
    });

    let sapling = sapling_receiver.as_ref().and_then(|receiver| {
        ZcashUnifiedAddress::from_receivers(None, Some(*receiver), None, None, None)
            .map(|ua| ua.encode(params))
    });

    UnifiedAddresses {
        unified: shielded_unified.encode(params),
        full_unified: address.encode(params),
        orchard,
        sapling,
        sapling_zs: address.sapling().map(|addr| addr.encode(params)),
        transparent: address.transparent().map(|addr| addr.encode(params)),
        address_index,
    }
}

pub(crate) fn transparent_address_index(
    address: &zcash_keys::address::UnifiedAddress,
    diversifier_index: zip32::DiversifierIndex,
) -> Option<u32> {
    address.transparent()?;

    let (low_4_bytes, rest) = diversifier_index.as_bytes().split_at(4);
    if rest.iter().any(|byte| *byte != 0) {
        return None;
    }

    let index = u32::from_le_bytes(low_4_bytes.try_into().ok()?);
    transparent::keys::NonHardenedChildIndex::from_index(index).map(|_| index)
}

/// Generate a new 24-word BIP-39 mnemonic phrase.
///
/// # Arguments
///
/// * `word_count` - Number of words in the mnemonic. Must be 24 for new wallet generation.
///
/// # Returns
///
/// A string containing the mnemonic phrase
///
/// # Example
///
/// ```javascript
/// const mnemonic = generate_mnemonic(24);
/// // Show the phrase only in the wallet's protected backup flow; never log it.
/// ```
#[wasm_bindgen]
pub fn generate_mnemonic(word_count: u32) -> Result<String, Error> {
    let count = match word_count {
        24 => Count::Words24,
        _ => return Err(Error::InvalidSeedPhrase),
    };

    let mnemonic: Mnemonic<English> = Mnemonic::generate(count);
    Ok(mnemonic.phrase().to_string())
}

/// Validate a BIP-39 mnemonic phrase.
///
/// # Arguments
///
/// * `phrase` - The mnemonic phrase to validate
///
/// # Returns
///
/// Returns Ok(()) if valid, or an error if invalid
///
/// # Example
///
/// ```javascript
/// try {
///     validate_mnemonic("abandon abandon abandon ... art");
///     console.log("Valid mnemonic");
/// } catch (e) {
///     console.error("Invalid mnemonic:", e);
/// }
/// ```
#[wasm_bindgen]
pub fn validate_mnemonic(phrase: &str) -> Result<(), Error> {
    Mnemonic::<English>::validate(phrase).map_err(|_| Error::InvalidSeedPhrase)
}

/// Convert a mnemonic phrase to a seed with an optional passphrase.
///
/// # Arguments
///
/// * `phrase` - The mnemonic phrase
/// * `passphrase` - Optional passphrase (use empty string for no passphrase)
///
/// # Returns
///
/// A 64-byte seed that can be used for key derivation
///
/// # Example
///
/// ```javascript
/// const seed = mnemonic_to_seed("abandon abandon abandon ... art", "");
/// // Use the seed for local key derivation; never log or persist it as plaintext.
/// ```
#[wasm_bindgen]
pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> Result<Vec<u8>, Error> {
    let mnemonic: Mnemonic<English> =
        Mnemonic::from_phrase(phrase).map_err(|_| Error::InvalidSeedPhrase)?;

    let mut seed = mnemonic.to_seed(passphrase);
    let result = seed.to_vec();
    seed.zeroize();
    Ok(result)
}

/// Generate a UnifiedSpendingKey from a mnemonic phrase.
///
/// # Arguments
///
/// * `network` - Network name ("main" or "test")
/// * `phrase` - The mnemonic phrase
/// * `passphrase` - Optional passphrase (use empty string "" if none)
/// * `account_index` - The account index for HD derivation (usually 0)
///
/// # Returns
///
/// A UnifiedSpendingKey that can be used for signing transactions
///
/// # Example
///
/// ```javascript
/// const mnemonic = generate_mnemonic(24);
/// const usk = mnemonic_to_spending_key(
///     "main",
///     mnemonic,
///     "",  // no passphrase
///     0    // first account
/// );
/// ```
#[wasm_bindgen]
pub fn mnemonic_to_spending_key(
    network: &str,
    phrase: &str,
    passphrase: &str,
    account_index: u32,
) -> Result<UnifiedSpendingKey, Error> {
    // Convert mnemonic to seed
    let mnemonic: Mnemonic<English> =
        Mnemonic::from_phrase(phrase).map_err(|_| Error::InvalidSeedPhrase)?;

    let mut seed = mnemonic.to_seed(passphrase);

    // Create UnifiedSpendingKey from seed
    let result = UnifiedSpendingKey::new(network, seed.to_vec().into_boxed_slice(), account_index);
    seed.zeroize();
    result
}

/// Generate a SeedFingerprint from a mnemonic phrase.
///
/// # Arguments
///
/// * `phrase` - The mnemonic phrase
/// * `passphrase` - Optional passphrase (use empty string "" if none)
///
/// # Returns
///
/// A SeedFingerprint that can be used for key derivation path identification
///
/// # Example
///
/// ```javascript
/// const mnemonic = generate_mnemonic(24);
/// const seed_fp = mnemonic_to_seed_fingerprint(
///     mnemonic,
///     ""  // no passphrase
/// );
/// ```
#[wasm_bindgen]
pub fn mnemonic_to_seed_fingerprint(
    phrase: &str,
    passphrase: &str,
) -> Result<SeedFingerprint, Error> {
    // Convert mnemonic to seed
    let mnemonic: Mnemonic<English> =
        Mnemonic::from_phrase(phrase).map_err(|_| Error::InvalidSeedPhrase)?;

    let mut seed = mnemonic.to_seed(passphrase);

    // Create SeedFingerprint from seed
    let result = SeedFingerprint::new(seed.to_vec().into_boxed_slice());
    seed.zeroize();
    result
}

/// Transparent address data for a specific external address index.
#[derive(Serialize, Deserialize)]
pub struct TransparentAddressInfo {
    /// The transparent P2PKH address for the given index.
    pub address: String,
    /// Hex-encoded uncompressed public key (65 bytes: 04 + x + y).
    pub pubkey: String,
}

/// Get a transparent address and public key from a mnemonic at a specific external address index.
///
/// # Arguments
///
/// * `network` - Network name ("main" or "test")
/// * `phrase` - The mnemonic phrase
/// * `passphrase` - Optional passphrase (use empty string "" if none)
/// * `account_index` - The account index for HD derivation (usually 0)
/// * `address_index` - The external transparent child address index
#[wasm_bindgen]
pub fn mnemonic_to_transparent_address(
    network: &str,
    phrase: &str,
    passphrase: &str,
    account_index: u32,
    address_index: u32,
) -> Result<JsValue, Error> {
    use std::str::FromStr;
    use transparent::keys::{IncomingViewingKey, NonHardenedChildIndex, TransparentKeyScope};
    use zcash_client_backend::encoding::AddressCodec;

    let mnemonic: Mnemonic<English> =
        Mnemonic::from_phrase(phrase).map_err(|_| Error::InvalidSeedPhrase)?;
    let mut seed = mnemonic.to_seed(passphrase);
    let usk = UnifiedSpendingKey::new(network, seed.to_vec().into_boxed_slice(), account_index);
    seed.zeroize();
    let usk = usk?;

    let net = crate::Network::from_str(network)?;
    let address_index = NonHardenedChildIndex::from_index(address_index)
        .ok_or_else(|| Error::Generic("Invalid transparent child index".into()))?;
    let usk_inner: zcash_keys::keys::UnifiedSpendingKey = usk.into();
    let transparent_key = usk_inner.transparent();

    let address = transparent_key
        .to_account_pubkey()
        .derive_external_ivk()
        .map_err(|e| Error::Generic(format!("Failed to derive IVK: {e:?}")))?
        .derive_address(address_index)
        .map_err(|e| Error::Generic(format!("Failed to derive address: {e:?}")))?
        .encode(&net);

    let public_key = transparent_key
        .to_account_pubkey()
        .derive_address_pubkey(TransparentKeyScope::EXTERNAL, address_index)
        .map_err(|e| Error::Generic(format!("Failed to derive public key: {e:?}")))?;
    let pubkey = hex::encode(public_key.serialize_uncompressed());

    Ok(serde_wasm_bindgen::to_value(&TransparentAddressInfo {
        address,
        pubkey,
    })?)
}

/// Get all addresses (shielded unified, orchard, sapling, transparent) from a mnemonic phrase.
///
/// # Arguments
///
/// * `network` - Network name ("main" or "test")
/// * `phrase` - The mnemonic phrase
/// * `passphrase` - Optional passphrase (use empty string "" if none)
/// * `account_index` - The account index for HD derivation (usually 0)
///
/// # Returns
///
/// A JSON object containing all address types
///
/// # Example
///
/// ```javascript
/// const mnemonic = generate_mnemonic(24);
/// const addresses = mnemonic_to_addresses(
///     "main",
///     mnemonic,
///     "",  // no passphrase
///     0    // first account
/// );
/// // Display the selected receiver in the wallet UI; avoid logging account addresses.
/// ```
#[wasm_bindgen]
pub fn mnemonic_to_addresses(
    network: &str,
    phrase: &str,
    passphrase: &str,
    account_index: u32,
) -> Result<JsValue, Error> {
    use std::str::FromStr;
    use zcash_keys::keys::UnifiedAddressRequest;

    // Convert mnemonic to seed
    let mnemonic: Mnemonic<English> =
        Mnemonic::from_phrase(phrase).map_err(|_| Error::InvalidSeedPhrase)?;

    let mut seed = mnemonic.to_seed(passphrase);

    // Create UnifiedSpendingKey from seed
    let usk = UnifiedSpendingKey::new(network, seed.to_vec().into_boxed_slice(), account_index);
    seed.zeroize();
    let usk = usk?;

    // Get UnifiedFullViewingKey
    let ufvk = usk.to_unified_full_viewing_key();

    // Get the network
    let net = crate::Network::from_str(network)?;

    // Get UIVK (unified incoming viewing key) from UFVK
    let uivk = ufvk.as_inner().to_unified_incoming_viewing_key();

    // Generate the first address that includes every receiver supported by the UIVK.
    let (address, diversifier_index) =
        uivk.default_address(UnifiedAddressRequest::AllAvailableKeys)?;
    let address_index = transparent_address_index(&address, diversifier_index);

    let result = unified_addresses_from_full(&address, &net, address_index);

    // Convert to JsValue using serde_wasm_bindgen
    Ok(serde_wasm_bindgen::to_value(&result)?)
}

/// Parse a unified address string and extract individual receiver addresses.
///
/// # Arguments
///
/// * `network` - Network name ("main" or "test")
/// * `unified_address` - The unified address string to parse
///
/// # Returns
///
/// A JSON object containing individual address types extracted from the unified address
///
/// # Example
///
/// ```javascript
/// const addresses = parse_unified_address(
///     "main",
///     "u1..." // unified address string
/// );
/// // Select the receiver needed by the payment flow; avoid logging addresses.
/// ```
#[wasm_bindgen]
pub fn parse_unified_address(network: &str, unified_address: &str) -> Result<JsValue, Error> {
    use std::str::FromStr;
    use transparent::address::TransparentAddress;
    use zcash_address::unified::{self, Container, Encoding};
    use zcash_client_backend::encoding::AddressCodec;
    use zcash_protocol::consensus::Parameters;

    // Get the network
    let net = crate::Network::from_str(network)?;

    let (parsed_net, revision, ua) =
        unified::Address::decode(unified_address).map_err(|_| Error::InvalidAddress)?;

    // Verify network matches
    if parsed_net != net.network_type() {
        return Err(Error::InvalidAddress);
    }

    // Extract individual receivers and create single-receiver addresses
    let mut orchard_addr: Option<String> = None;
    let mut sapling_addr: Option<String> = None;
    let mut sapling_zs_addr: Option<String> = None;
    let mut transparent_addr: Option<String> = None;
    let mut shielded_receivers = Vec::new();

    // Iterate through receivers to extract each type
    for receiver in ua.items() {
        match receiver {
            unified::Receiver::Orchard(data) => {
                shielded_receivers.push(unified::Receiver::Orchard(data));
                // Create a unified address with only Orchard receiver
                let single_ua = unified::Address::try_from_items(
                    revision,
                    vec![unified::Uitem::Data(unified::Receiver::Orchard(data))],
                )
                .map_err(|_| Error::InvalidAddress)?;
                // Encode the single-receiver UA
                orchard_addr = Some(single_ua.encode(&parsed_net));
            }
            unified::Receiver::Sapling(data) => {
                shielded_receivers.push(unified::Receiver::Sapling(data));
                // Create a unified address with only Sapling receiver
                let single_ua = unified::Address::try_from_items(
                    revision,
                    vec![unified::Uitem::Data(unified::Receiver::Sapling(data))],
                )
                .map_err(|_| Error::InvalidAddress)?;
                // Encode the single-receiver UA
                sapling_addr = Some(single_ua.encode(&parsed_net));

                // Also generate traditional zs format address
                use sapling::PaymentAddress;
                if let Some(payment_addr) = PaymentAddress::from_bytes(&data) {
                    sapling_zs_addr = Some(payment_addr.encode(&net));
                }
            }
            unified::Receiver::P2pkh(data) => {
                // Create a standalone transparent P2PKH address
                let t_addr = TransparentAddress::PublicKeyHash(data);
                transparent_addr = Some(t_addr.encode(&net));
            }
            unified::Receiver::P2sh(_) | unified::Receiver::Unknown { .. } => {
                return Err(Error::InvalidAddress);
            }
        }
    }

    let shielded_ua = unified::Address::try_from_items(
        revision,
        shielded_receivers
            .into_iter()
            .map(unified::Uitem::Data)
            .collect(),
    )
    .map_err(|_| Error::InvalidAddress)?;

    // Create the result structure
    let result = UnifiedAddresses {
        unified: shielded_ua.encode(&parsed_net),
        full_unified: unified_address.to_string(),
        orchard: orchard_addr,
        sapling: sapling_addr,
        sapling_zs: sapling_zs_addr,
        transparent: transparent_addr,
        address_index: None,
    };

    // Convert to JsValue using serde_wasm_bindgen
    Ok(serde_wasm_bindgen::to_value(&result)?)
}

#[cfg(test)]
mod tests {
    use super::generate_mnemonic;
    use crate::Error;

    #[test]
    fn generate_mnemonic_only_allows_24_words() {
        for word_count in [12, 15, 18, 21] {
            assert!(matches!(
                generate_mnemonic(word_count),
                Err(Error::InvalidSeedPhrase)
            ));
        }

        let mnemonic = generate_mnemonic(24).expect("24-word mnemonic generation should succeed");
        assert_eq!(mnemonic.split_whitespace().count(), 24);
    }
}
