// Portions derived from ChainSafe WebZjs.
// Copyright 2024 ChainSafe Systems
// Modified by NoirWallet; see THIRD_PARTY_NOTICES.md for licensing.

use std::fmt::Display;

use wasm_bindgen::JsValue;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid account id")]
    AccountIdConversion(#[from] zip32::TryFromIntError),
    #[error("Failed to derive key from seed")]
    // doesn't implement std::error. Should probably fix this upstream
    Derivation(#[from] zcash_keys::keys::DerivationError),
    #[error("Failed to derive key")]
    KeyDerivation,
    #[error("Javascript error")]
    Js(JsValue),
    #[error("DomException {name} ({code}): {message}")]
    DomException { name: String, message: String, code: u16 },
    #[error("Address generation error")]
    AddressGeneration(#[from] zcash_keys::keys::AddressGenerationError),
    #[error("Error attempting to decode address: {0}")]
    AddressDecoding(#[from] zcash_address::ParseError),
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Error attempting to decode key: {0}")]
    KeyDecoding(String),
    #[error("Invalid network string given: {0}")]
    InvalidNetwork(String),
    #[error("Invalid transfer funding source: {0}. Expected 'shielded' or 'transparent'")]
    InvalidTransferFundingSource(String),
    #[error("Error returned from GRPC server: {0}")]
    Grpc(#[from] tonic::Status),
    #[error("Error handling wallet birthday")]
    Birthday,
    #[error("Memory client error: {0}")]
    MemoryClient(#[from] zcash_client_memory::Error),
    #[error("Error scanning: {0}")]
    Scan(zcash_client_backend::scanning::ScanError),
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Error parsing zatoshi amount: {0}")]
    InvalidAmount(#[from] zcash_protocol::value::BalanceError),
    #[error("Failed to send transaction")]
    SendFailed { code: i32, reason: String },
    #[error("Transaction {txid} may have been submitted: {reason}")]
    TransactionSubmissionUnknown { txid: String, reason: String },
    #[error("Failed to parse key: {0}")]
    KeyParse(String),

    #[error("Syncing Error: {0}")]
    Sync(String),

    /// An outstanding network reply belongs to an earlier wallet chain revision.
    #[error("Wallet chain state changed during history query; retry synchronization")]
    HistoryQueryStale,

    #[error("Attempted to create a transaction with a memo to an unsupported recipient. Only shielded addresses are supported.")]
    UnsupportedMemoRecipient,
    #[error("Error decoding memo: {0}")]
    MemoDecoding(#[from] zcash_protocol::memo::Error),

    #[error("Invalid seed phrase")]
    InvalidSeedPhrase,
    #[error("Failed when creating transaction")]
    FailedToCreateTransaction,
    #[error("Account with given id not found: {0}")]
    AccountNotFound(u32),
    #[error("Account with given name not found")]
    AccountNameNotFound,
    #[error("Account with name '{0}' already exists")]
    AccountExists(String),
    #[error("Transaction with given txid not found: {0}")]
    TransactionNotFound(zcash_primitives::transaction::TxId),
    #[error("Error constructing ZIP321 transaction request: {0}")]
    Zip321(#[from] zcash_client_backend::zip321::Zip321Error),
    #[error("serde wasm-bindgen error")]
    SerdeWasmBindgen(#[from] serde_wasm_bindgen::Error),
    #[error("Fail to parse TxIds")]
    TxIdParse,
    #[error("Failed to create Pczt")]
    PcztCreate,
    #[error(
        "WALLET_SPENDABILITY_INCONSISTENT: account {account_id} has {note_count} confirmed note(s) with incomplete spendability metadata totaling {value_zats} zatoshis"
    )]
    SpendabilityMetadataIncomplete { account_id: u32, note_count: usize, value_zats: u64 },
    #[error("{0}")]
    InsufficientTransferFunds(String),
    #[error("Failed to prove Pczt: {0}")]
    PcztProve(String),
    #[error("Failed to send Pczt: {0}")]
    PcztSend(String),
    #[error("Failed to combine Pczt: {0}")]
    PcztCombine(String),
    #[error("An generic error occurred: {0}")]
    Generic(String),

    #[error("Failed to sign Pczt: {0}")]
    PcztSign(String),
    #[error("Error attempting to get seed fingerprint.")]
    SeedFingerprint,
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
}

impl From<Error> for JsValue {
    fn from(e: Error) -> Self {
        let error = js_sys::Error::new(&e.to_string());
        if let Error::TransactionSubmissionUnknown { txid, .. } = &e {
            error.set_name("TransactionSubmissionUnknown");
            let _ = js_sys::Reflect::set(error.as_ref(), &JsValue::from_str("txId"), &JsValue::from_str(txid));
        }
        error.into()
    }
}

impl<A, B, C> From<zcash_client_backend::sync::Error<A, B, C>> for Error
where
    A: Display,
    B: Display,
    C: Display,
{
    fn from(e: zcash_client_backend::sync::Error<A, B, C>) -> Self {
        Self::Sync(e.to_string())
    }
}
#[cfg(all(feature = "voting", target_arch = "wasm32"))]
impl From<crate::voting::types::VotingApiError> for wasm_bindgen::JsValue {
    fn from(value: crate::voting::types::VotingApiError) -> Self {
        let error = js_sys::Error::new(&value.message);
        error.set_name(value.code.as_str());
        error.into()
    }
}
