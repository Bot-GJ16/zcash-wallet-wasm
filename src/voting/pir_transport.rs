//! PIR adapts the generic Fetch boundary without changing its ownership rules.
use super::transport::BrowserFetchTransport;
use zcash_voting::platform::{HttpTransport, OwnedHttpRequest};

impl zcash_voting::pir::Transport for BrowserFetchTransport {
    fn get<'a>(&'a self, url: &'a str) -> zcash_voting::pir::TransportFuture<'a> {
        pir_request("GET", url, Vec::new())
    }
    fn post<'a>(&'a self, url: &'a str, body: Vec<u8>) -> zcash_voting::pir::TransportFuture<'a> {
        pir_request("POST", url, body)
    }
}

fn pir_request(method: &str, url: &str, body: Vec<u8>) -> zcash_voting::pir::TransportFuture<'static> {
    let response = BrowserFetchTransport.execute(OwnedHttpRequest {
        method: method.into(),
        url: url.into(),
        headers: if method == "POST" {
            vec![("Content-Type".into(), "application/octet-stream".into())]
        } else {
            vec![]
        },
        body,
        timeout_ms: super::constants::REQUEST_TIMEOUT_MS,
        max_response_bytes: super::constants::PIR_LIMIT,
        kind: zcash_voting::platform::RequestKind::Idempotent,
    });
    Box::pin(async move {
        let response = match response.await {
            Ok(response) => response,
            Err(error) if error.is_safe_to_retry() => {
                return Err(zcash_voting::pir::RetryableTransportError.into());
            }
            Err(error) => return Err(error.into()),
        };
        Ok(zcash_voting::pir::TransportResponse {
            status: response.status,
            headers: vec![],
            body: response.body,
        })
    })
}

/// Deterministic browser fixture: returns only success/rejection, never protocol artifacts.
#[cfg(debug_assertions)]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = votingTestPir)]
pub async fn voting_test_pir(url: String, query: bool) -> Result<bool, wasm_bindgen::JsValue> {
    let layout = zcash_voting::wire::PirLayout {
        pir_depth: 19,
        tier0_layers: 11,
        tier1_layers: 8,
        poly_len: 2048,
    };
    let client = zcash_voting::pir::connect_pir_for_snapshot(
        layout,
        &url,
        std::sync::Arc::new(BrowserFetchTransport),
        zcash_voting::Network::Testnet,
        &[0; 32],
        100,
    )
    .await
    .map_err(|_| super::types::VotingApiError::new(super::types::VotingErrorCode::PirSnapshotMismatch))?;
    if query {
        Ok(client.fetch_proof(zcash_voting::backend::pasta_curves::pallas::Base::from(1)).await.is_err())
    } else {
        Ok(true)
    }
}

#[cfg(debug_assertions)]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = votingTestPirFallback)]
pub async fn voting_test_pir_fallback(urls: Vec<String>, handshake_only: bool) -> Result<bool, wasm_bindgen::JsValue> {
    let mismatch = |_| super::types::VotingApiError::new(super::types::VotingErrorCode::PirSnapshotMismatch);
    let mut client = zcash_voting::pir::OrderedSnapshotPir::connect(
        zcash_voting::wire::PirLayout {
            pir_depth: 19,
            tier0_layers: 11,
            tier1_layers: 8,
            poly_len: 2048,
        },
        urls,
        std::sync::Arc::new(BrowserFetchTransport),
        zcash_voting::Network::Testnet,
        &[0; 32],
        100,
    )
    .await
    .map_err(mismatch)?;
    if !handshake_only {
        client.fetch_proofs(&[1.into(), 2.into()]).await.map_err(mismatch)?;
    }
    Ok(true)
}

#[cfg(debug_assertions)]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = votingTestProofExecutor)]
pub async fn voting_test_proof_executor() -> Result<bool, wasm_bindgen::JsValue> {
    use zcash_voting::proof_executor::{ProofExecutor, SequentialProofExecutor};
    let sequential = SequentialProofExecutor
        .prove(vec![1u64, 2, 3], |values| Ok(values.into_iter().sum::<u64>()))
        .await;
    #[cfg(feature = "wasm-parallel")]
    let parallel = super::proof_executor::RayonProofExecutor
        .prove(vec![1u64, 2, 3], |values| {
            if rayon::current_thread_index().is_none() {
                return Err(zcash_voting::VotingError::ProofFailed {
                    message: "not running in initialized pool".into(),
                });
            }
            Ok(values.into_iter().sum::<u64>())
        })
        .await;
    #[cfg(not(feature = "wasm-parallel"))]
    let parallel = Ok::<_, zcash_voting::VotingError>(6u64);
    Ok(matches!(sequential, Ok(6)) && matches!(parallel, Ok(6)))
}
