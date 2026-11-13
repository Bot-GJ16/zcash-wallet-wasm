//! Vote-tree HTTP adapts the owned Fetch boundary without retaining JS values.

use super::transport::BrowserFetchTransport;
use zcash_voting::platform::{HttpTransport, OwnedHttpRequest, RequestKind};

impl zcash_voting::tree_sync::AsyncTransport for BrowserFetchTransport {
    fn get(
        &self,
        url: String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<zcash_voting::tree_sync::AsyncTransportResponse, zcash_voting::tree_sync::AsyncTransportError>> + Send>,
    > {
        let response = self.execute(OwnedHttpRequest {
            method: "GET".into(),
            url,
            headers: Vec::new(),
            body: Vec::new(),
            timeout_ms: super::constants::REQUEST_TIMEOUT_MS,
            max_response_bytes: super::constants::API_LIMIT,
            kind: RequestKind::Idempotent,
        });
        Box::pin(async move {
            response
                .await
                .map(|response| zcash_voting::tree_sync::AsyncTransportResponse {
                    status: response.status,
                    body: response.body,
                })
                .map_err(|_| zcash_voting::tree_sync::AsyncTransportError::Request("browser tree request failed".into()))
        })
    }
}

#[cfg(debug_assertions)]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = votingTestTreeFixture)]
pub fn voting_test_tree_fixture() -> Vec<String> {
    let (leaf, root) = zcash_voting::tree_sync::browser_runtime_fixture();
    vec![leaf, root]
}

#[cfg(debug_assertions)]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = votingTestTreeSync)]
pub async fn voting_test_tree_sync(base_url: String) -> Result<bool, wasm_bindgen::JsValue> {
    let failed = || super::types::VotingApiError::new(super::types::VotingErrorCode::ProofFailed);
    let round_id = "0303030303030303030303030303030303030303030303030303030303030303";
    let db = zcash_voting::storage::VotingDb::open_browser("browser-tree-runtime", zcash_voting::Network::Testnet, None).map_err(|_| failed())?;
    db.create_round(
        zcash_voting::Network::Testnet,
        &zcash_voting::round::RoundParams {
            vote_round_id: round_id.into(),
            snapshot_height: 1,
            ea_pk: vec![1; 32],
            nc_root: vec![2; 32],
            nullifier_imt_root: vec![3; 32],
        },
        None,
    )
    .map_err(|_| failed())?;
    let api = zcash_voting::tree_sync::AsyncHttpTreeSyncApi::new(base_url, round_id, std::sync::Arc::new(BrowserFetchTransport)).map_err(|_| failed())?;
    let height = zcash_voting::tree_sync::VoteTreeSync::new()
        .sync_with_async_api(&db, round_id, &api)
        .await
        .map_err(|_| failed())?;
    Ok(height == 1)
}
