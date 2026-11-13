// Portions derived from ChainSafe WebZjs.
// Copyright 2024 ChainSafe Systems
// Modified by NoirWallet; see THIRD_PARTY_NOTICES.md for licensing.

use crate::error::Error;
use wasm_bindgen::prelude::*;
use zcash_address::ZcashAddress;
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

#[wasm_bindgen]
pub struct TransactionRequest(zip321::TransactionRequest);

#[wasm_bindgen]
impl TransactionRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(payments: Vec<PaymentRequest>) -> Result<TransactionRequest, Error> {
        let payments = payments.into_iter().map(|p| p.0).collect();
        Ok(TransactionRequest(zip321::TransactionRequest::new(payments)?))
    }

    pub fn empty() -> TransactionRequest {
        TransactionRequest(zip321::TransactionRequest::empty())
    }

    pub fn payment_requests(&self) -> Vec<PaymentRequest> {
        self.0.payments().values().map(|p| PaymentRequest(p.clone())).collect()
    }

    pub fn total(&self) -> Result<u64, Error> {
        Ok(self.0.total()?.map(u64::from).unwrap_or(0))
    }

    pub fn from_uri(uri: &str) -> Result<TransactionRequest, Error> {
        Ok(zip321::TransactionRequest::from_uri(uri).map(TransactionRequest)?)
    }

    pub fn to_uri(&self) -> String {
        self.0.to_uri()
    }
}

#[wasm_bindgen]
pub struct PaymentRequest(zip321::Payment);

#[wasm_bindgen]
impl PaymentRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        recipient_address: &str,
        amount: u64,
        memo: Option<Vec<u8>>,
        label: Option<String>,
        message: Option<String>,
        other_params: JsValue,
    ) -> Result<PaymentRequest, Error> {
        let address = ZcashAddress::try_from_encoded(recipient_address)?;
        let amount = Some(Zatoshis::from_u64(amount)?);
        let memo = if let Some(memo_bytes) = memo {
            Some(MemoBytes::from_bytes(&memo_bytes)?)
        } else {
            None
        };
        let other_params = serde_wasm_bindgen::from_value(other_params)?;

        let payment = zip321::Payment::new(address, amount, memo, label, message, other_params).map_err(|e| Error::Zip321(e.with_index(0)))?;
        Ok(PaymentRequest(payment))
    }

    pub fn simple_payment(recipient_address: &str, amount: u64) -> Result<PaymentRequest, Error> {
        let address = ZcashAddress::try_from_encoded(recipient_address)?;
        let amount = Zatoshis::from_u64(amount)?;
        Ok(PaymentRequest(zip321::Payment::without_memo(address, amount)))
    }

    pub fn recipient_address(&self) -> String {
        self.0.recipient_address().encode()
    }

    pub fn amount(&self) -> u64 {
        self.0.amount().map(u64::from).unwrap_or(0)
    }

    pub fn memo(&self) -> Option<Vec<u8>> {
        self.0.memo().map(|m| m.as_array().to_vec())
    }

    pub fn label(&self) -> Option<String> {
        self.0.label().cloned()
    }

    pub fn message(&self) -> Option<String> {
        self.0.message().cloned()
    }

    pub fn other_params(&self) -> Result<JsValue, Error> {
        serde_wasm_bindgen::to_value(&self.0.other_params()).map_err(Error::from)
    }
}
