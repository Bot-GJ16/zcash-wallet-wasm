use super::*;
use prost::Message;
use std::sync::atomic::{AtomicUsize, Ordering};
use tonic::{
    body::Body,
    codec::{EncodeBody, EncodeBuf, Encoder},
    codegen::{BoxFuture, http},
};

struct FeeEncoder;

impl Encoder for FeeEncoder {
    type Item = service::StandardFee;
    type Error = tonic::Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        item.encode(dst)
            .map_err(|error| tonic::Status::internal(error.to_string()))
    }
}

#[derive(Clone)]
struct FeeRpc {
    calls: Arc<AtomicUsize>,
    fee: Option<u64>,
}

impl tonic::client::GrpcService<Body> for FeeRpc {
    type ResponseBody = Body;
    type Error = std::io::Error;
    type Future = BoxFuture<http::Response<Body>, Self::Error>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        assert_eq!(
            request.uri().path(),
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetStandardFee"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        let response = self.fee.map_or_else(
            || Err(tonic::Status::unimplemented("old lightwalletd")),
            |fee_zat| {
                Ok(service::StandardFee {
                    fee_zat,
                    estimator_version: 0,
                })
            },
        );
        let body = Body::new(EncodeBody::new_server(
            FeeEncoder,
            futures_util::stream::once(async move { response }),
            None,
            Default::default(),
            None,
        ));
        Box::pin(async move {
            Ok(http::Response::builder()
                .header("content-type", "application/grpc")
                .body(body)
                .unwrap())
        })
    }
}

fn rpc(fee: Option<u64>) -> (FeeRpc, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let rpc = FeeRpc {
        calls: calls.clone(),
        fee,
    };
    (rpc, calls)
}

fn wallet(fee: Option<u64>) -> (Wallet<MemoryWalletDb<Network>, FeeRpc>, Arc<AtomicUsize>) {
    let (rpc, calls) = rpc(fee);
    let db = MemoryWalletDb::new(Network::TestNetwork, 100);
    (Wallet::new(db, rpc, Network::TestNetwork).unwrap(), calls)
}

#[tokio::test]
async fn explicit_fee_bypasses_rpc_and_rejects_zero() {
    let (wallet, calls) = wallet(Some(1_000));
    assert_eq!(
        wallet.resolve_transfer_fee(Some(5_000)).await.unwrap(),
        Some(5_000)
    );
    assert!(wallet.resolve_transfer_fee(Some(0)).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn uses_valid_backend_fee() {
    for fee in [1_000, 50_001] {
        let (wallet, calls) = wallet(Some(fee));
        assert_eq!(wallet.resolve_transfer_fee(None).await.unwrap(), Some(fee));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn unsupported_or_invalid_backend_fee_uses_standard_rule() {
    for fee in [None, Some(0), Some(u64::MAX)] {
        let (wallet, calls) = wallet(fee);
        assert_eq!(wallet.resolve_transfer_fee(None).await.unwrap(), None);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn estimate_reports_selected_rate_and_total_fee() {
    for (recommended, expected_rate, expected_fee) in
        [(Some(1_000), "1000", "2000"), (None, "5000", "10000")]
    {
        let (db, account_id) = super::confirmations_tests::funded_db_at_confirmations(10);
        let (rpc, calls) = rpc(recommended);
        let wallet = Wallet::new(db, rpc, Network::TestNetwork).unwrap();
        let recipient = zcash_client_backend::address::Address::Transparent(
            transparent::address::TransparentAddress::PublicKeyHash([42; 20]),
        )
        .to_zcash_address(&Network::TestNetwork);
        let estimate = wallet
            .estimate_transfer(
                account_id,
                recipient,
                100_000,
                TransferFundingSource::Transparent,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(estimate.marginal_fee_zats, expected_rate);
        assert_eq!(estimate.fee_zats, expected_fee);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
