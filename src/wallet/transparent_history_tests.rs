//! Synthetic, offline regression tests for history RPC / database interleavings.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use futures_util::{FutureExt, poll};
use prost::Message;
use tonic::{
    body::Body,
    codec::{EncodeBody, EncodeBuf, Encoder},
    codegen::{BoxFuture, http},
};
use transparent::{
    address::Script,
    bundle::{Authorized, Bundle, OutPoint, TxIn, TxOut},
    keys::{IncomingViewingKey, NonHardenedChildIndex},
};
use zcash_client_backend::{
    data_api::{AccountBirthday, AccountPurpose, TransactionDataRequest, WalletCommitmentTrees, WalletRead, WalletWrite, chain::ChainState},
    proto::service,
};
use zcash_client_memory::MemoryWalletDb;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::{
    block::BlockHash,
    transaction::{Transaction, TransactionData, TxVersion},
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::Zatoshis,
};

use super::Wallet;
use crate::Network;

const BIRTHDAY: BlockHeight = BlockHeight::from_u32(3_000_000);
const TIP: BlockHeight = BlockHeight::from_u32(3_000_010);

struct RawEncoder;

impl Encoder for RawEncoder {
    type Item = service::RawTransaction;
    type Error = tonic::Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        item.encode(dst).map_err(|e| tonic::Status::internal(e.to_string()))
    }
}

type Replies = Arc<Mutex<VecDeque<(&'static str, Body)>>>;

#[derive(Clone, Default)]
struct HistoryRpc(Replies);

fn response_body(stream: impl futures_util::Stream<Item = Result<service::RawTransaction, tonic::Status>> + Send + 'static) -> Body {
    Body::new(EncodeBody::new_server(RawEncoder, stream, None, Default::default(), None))
}

impl HistoryRpc {
    fn pending(&self, path: &'static str) -> tokio::sync::mpsc::Sender<Result<service::RawTransaction, tonic::Status>> {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        self.0
            .lock()
            .unwrap()
            .push_back((path, response_body(tonic::codegen::tokio_stream::wrappers::ReceiverStream::new(receiver))));
        sender
    }
}

impl tonic::client::GrpcService<Body> for HistoryRpc {
    type ResponseBody = Body;
    type Error = std::io::Error;
    type Future = BoxFuture<http::Response<Body>, Self::Error>;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let (path, body) = self
            .0
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| ("/GetTaddressTxids", response_body(futures_util::stream::empty())));
        assert!(request.uri().path().ends_with(path), "unexpected RPC: {}", request.uri());
        Box::pin(async move { Ok(http::Response::builder().header("content-type", "application/grpc").body(body).unwrap()) })
    }
}

fn fixture() -> (Wallet<MemoryWalletDb<Network>, HistoryRpc>, Transaction, service::RawTransaction) {
    let network = Network::MainNetwork;
    // Public deterministic fixture, unrelated to any user's seed or keys.
    let ufvk = UnifiedSpendingKey::from_seed(&network, &[42; 32], zip32::AccountId::ZERO)
        .unwrap()
        .to_unified_full_viewing_key();
    let internal = ufvk
        .transparent()
        .unwrap()
        .derive_internal_ivk()
        .unwrap()
        .derive_address(NonHardenedChildIndex::from_index(0).unwrap())
        .unwrap();
    let mut db = MemoryWalletDb::new(network, 100);
    db.import_account_ufvk(
        "synthetic history test",
        &ufvk,
        &AccountBirthday::from_parts(ChainState::empty(BIRTHDAY - 1, BlockHash([0; 32])), None),
        AccountPurpose::ViewOnly,
        None,
    )
    .unwrap();
    for height in [BIRTHDAY - 1, TIP] {
        db.with_sapling_tree_mut(|tree| tree.checkpoint(height)).unwrap();
        db.with_orchard_tree_mut(|tree| tree.checkpoint(height)).unwrap();
        db.with_ironwood_tree_mut(|tree| tree.checkpoint(height)).unwrap();
    }
    db.update_chain_tip(TIP).unwrap();
    let tx = TransactionData::from_parts(
        TxVersion::V5,
        BranchId::Nu6,
        0,
        TIP + 20,
        Some(Bundle {
            vin: vec![TxIn::from_parts(OutPoint::new([7; 32], 0), Script::default(), u32::MAX)],
            vout: vec![TxOut::new(Zatoshis::const_from_u64(70_000), internal.script().into())],
            authorization: Authorized,
        }),
        None,
        None,
        None,
    )
    .freeze()
    .unwrap();
    let mut data = Vec::new();
    tx.write(&mut data).unwrap();
    let raw = service::RawTransaction { data, height: u64::from(TIP) };
    let wallet = Wallet {
        db: Arc::new(tokio::sync::RwLock::new(db)),
        client: super::CompactTxStreamerClient::new(HistoryRpc::default()),
        zero_indexer_clients: vec![],
        zero_indexer_send_timeout: super::DEFAULT_ZERO_INDEXER_SEND_TIMEOUT,
        network,
        confirmations_policy: zcash_client_backend::data_api::wallet::ConfirmationsPolicy::default(),
        compact_block_cdn: None,
        target_note_count: 4,
        min_split_output_value: 10_000_000,
    };
    (wallet, tx, raw)
}

fn first_history_start(db: &MemoryWalletDb<Network>) -> Option<BlockHeight> {
    db.transaction_data_requests()
        .unwrap()
        .iter()
        .filter_map(|request| match request {
            TransactionDataRequest::TransactionsInvolvingAddress(request) => Some(request.block_range_start()),
            _ => None,
        })
        .min()
}

fn bytes(db: &MemoryWalletDb<Network>) -> Vec<u8> {
    let mut bytes = Vec::new();
    db.encode(&mut bytes).unwrap();
    bytes
}

fn rewind_and_restore_tip(db: &mut MemoryWalletDb<Network>) {
    assert_eq!(db.truncate_to_height(BIRTHDAY - 1).unwrap(), BIRTHDAY - 1);
    // Detect ABA: height alone looks unchanged by the time the old reply arrives.
    db.update_chain_tip(TIP).unwrap();
    assert_eq!(db.chain_height().unwrap(), Some(TIP));
}

#[tokio::test]
async fn history_stream_allows_wallet_access_and_cancelled_work_can_retry() {
    let (mut wallet, tx, raw) = fixture();
    let rpc = HistoryRpc::default();
    let sender = rpc.pending("/GetTaddressTxids");
    wallet.client = super::CompactTxStreamerClient::new(rpc.clone());
    let mut processing = Box::pin(wallet.process_pending_transaction_requests());
    assert!(poll!(&mut processing).is_pending());
    assert!(wallet.db.try_read().is_ok(), "stream waiting must not block wallet reads");
    assert!(wallet.db.try_write().is_ok(), "stream waiting must not block wallet writes");
    assert!(wallet.db_to_bytes().now_or_never().unwrap().is_ok());

    sender.send(Ok(raw.clone())).await.unwrap();
    assert!(poll!(&mut processing).is_pending());
    {
        let db = wallet.db.try_read().unwrap();
        assert!(db.get_transaction(tx.txid()).unwrap().is_some());
        assert_eq!(first_history_start(&db), Some(BIRTHDAY), "partial stream must not advance history progress");
    }
    drop(processing);
    drop(sender);
    // Receiving a wallet output also queues a transaction status lookup.
    let status = rpc.pending("/GetTransaction");
    status.send(Ok(raw)).await.unwrap();
    drop(status);
    wallet.process_pending_transaction_requests().await.unwrap();
    let db = wallet.db.read().await;
    assert!(db.get_transaction(tx.txid()).unwrap().is_some());
    assert_eq!(first_history_start(&db), None, "retry completes the interrupted ranges");
}

#[tokio::test]
async fn history_item_from_before_rewind_cannot_restore_orphaned_transaction() {
    let (mut wallet, tx, raw) = fixture();
    let rpc = HistoryRpc::default();
    let sender = rpc.pending("/GetTaddressTxids");
    wallet.client = super::CompactTxStreamerClient::new(rpc);
    let mut processing = Box::pin(wallet.process_pending_transaction_requests());
    assert!(poll!(&mut processing).is_pending());
    let after_rewind = {
        let mut db = wallet.db.try_write().expect("history RPC must release the database lock");
        rewind_and_restore_tip(&mut db);
        bytes(&db)
    };
    sender.send(Ok(raw)).await.unwrap();
    drop(sender);
    assert!(
        matches!(processing.await, Err(crate::Error::HistoryQueryStale)),
        "an old-chain reply must require a fresh sync"
    );
    let db = wallet.db.read().await;
    assert!(db.get_transaction(tx.txid()).unwrap().is_none());
    assert_eq!(bytes(&db), after_rewind, "stale reply must not mutate any wallet data");
}

#[tokio::test]
async fn history_eof_from_before_rewind_cannot_advance_recovery_progress() {
    let (mut wallet, _, raw) = fixture();
    let rpc = HistoryRpc::default();
    let sender = rpc.pending("/GetTaddressTxids");
    wallet.client = super::CompactTxStreamerClient::new(rpc);
    sender.send(Ok(raw)).await.unwrap();
    let mut processing = Box::pin(wallet.process_pending_transaction_requests());
    assert!(poll!(&mut processing).is_pending());
    let after_rewind = {
        let mut db = wallet.db.try_write().expect("history stream must release the database lock");
        rewind_and_restore_tip(&mut db);
        bytes(&db)
    };
    drop(sender);
    assert!(
        matches!(processing.await, Err(crate::Error::HistoryQueryStale)),
        "EOF cannot complete a range from a previous chain revision"
    );
    let db = wallet.db.read().await;
    assert_eq!(first_history_start(&db), Some(BIRTHDAY));
    assert_eq!(bytes(&db), after_rewind);
}

#[tokio::test]
async fn history_reply_from_before_snapshot_reload_cannot_write_to_replacement_database() {
    let (mut wallet, _, _) = fixture();
    let rpc = HistoryRpc::default();
    let sender = rpc.pending("/GetTaddressTxids");
    wallet.client = super::CompactTxStreamerClient::new(rpc);
    let mut processing = Box::pin(wallet.process_pending_transaction_requests());
    assert!(poll!(&mut processing).is_pending());
    let snapshot = {
        let mut db = wallet.db.try_write().expect("history RPC must release the database lock");
        let snapshot = bytes(&db);
        *db = MemoryWalletDb::decode_new(snapshot.as_slice(), Network::MainNetwork, 100).unwrap();
        snapshot
    };
    drop(sender);
    assert!(
        matches!(processing.await, Err(crate::Error::HistoryQueryStale)),
        "replacing the DB invalidates all outstanding queries"
    );
    assert_eq!(wallet.db_to_bytes().await.unwrap(), snapshot);
}

enum TransactionQuery {
    Status,
    Enhancement,
}

#[tokio::test]
async fn history_query_remains_valid_during_forward_sync_and_address_allocation() {
    let (mut wallet, _, _) = fixture();
    let rpc = HistoryRpc::default();
    let sender = rpc.pending("/GetTaddressTxids");
    wallet.client = super::CompactTxStreamerClient::new(rpc);
    let mut processing = Box::pin(wallet.process_pending_transaction_requests());
    assert!(poll!(&mut processing).is_pending());
    {
        let mut db = wallet.db.try_write().unwrap();
        db.update_chain_tip(TIP + 1).unwrap();
        let account_id = db.get_account_ids().unwrap()[0];
        db.get_next_available_address(account_id, zcash_keys::keys::UnifiedAddressRequest::ALLOW_ALL)
            .unwrap()
            .unwrap();
    }
    drop(sender);
    processing.await.unwrap();
    let db = wallet.db.read().await;
    assert_eq!(db.chain_height().unwrap(), Some(TIP + 1));
    assert_eq!(first_history_start(&db), None);
}

async fn stale_transaction_reply_is_rejected(query: TransactionQuery, not_found: bool) {
    let (mut wallet, tx, raw) = fixture();
    {
        let mut db = wallet.db.write().await;
        match query {
            TransactionQuery::Status => {
                zcash_client_backend::data_api::wallet::decrypt_and_store_transaction(&wallet.network, &mut *db, &tx, None).unwrap();
                assert!(
                    db.transaction_data_requests()
                        .unwrap()
                        .iter()
                        .any(|r| matches!(r, TransactionDataRequest::GetStatus(id) if *id == tx.txid()))
                );
            }
            TransactionQuery::Enhancement => {
                let account_id = db.get_account_ids().unwrap()[0];
                let output = zcash_client_backend::wallet::WalletTransparentOutput::from_parts(
                    OutPoint::new(tx.txid().into(), 0),
                    tx.transparent_bundle().unwrap().vout[0].clone(),
                    Some(TIP),
                    Some(account_id),
                    Some(transparent::keys::TransparentKeyScope::INTERNAL),
                    None,
                )
                .unwrap();
                db.put_received_transparent_utxo(&output).unwrap();
                assert!(
                    db.transaction_data_requests()
                        .unwrap()
                        .iter()
                        .any(|r| matches!(r, TransactionDataRequest::Enhancement(id) if *id == tx.txid()))
                );
            }
        }
    }
    let rpc = HistoryRpc::default();
    let sender = rpc.pending("/GetTransaction");
    wallet.client = super::CompactTxStreamerClient::new(rpc);
    let mut processing = Box::pin(wallet.process_pending_transaction_requests());
    assert!(poll!(&mut processing).is_pending());
    assert!(wallet.db.try_read().is_ok(), "GetTransaction must not block balance reads");
    let after_rewind = {
        let mut db = wallet.db.try_write().expect("GetTransaction must not block wallet writes");
        rewind_and_restore_tip(&mut db);
        bytes(&db)
    };
    sender
        .send(if not_found {
            Err(tonic::Status::not_found("synthetic missing transaction"))
        } else {
            Ok(raw)
        })
        .await
        .unwrap();
    drop(sender);
    assert!(matches!(processing.await, Err(crate::Error::HistoryQueryStale)));
    assert_eq!(
        wallet.db_to_bytes().await.unwrap(),
        after_rewind,
        "neither status nor full transaction data may overwrite a rewind"
    );
}

#[tokio::test]
async fn get_transaction_mined_status_from_before_rewind_is_rejected() {
    stale_transaction_reply_is_rejected(TransactionQuery::Status, false).await;
}

#[tokio::test]
async fn get_transaction_not_found_from_before_rewind_is_rejected() {
    stale_transaction_reply_is_rejected(TransactionQuery::Status, true).await;
}

#[tokio::test]
async fn get_transaction_enhancement_from_before_rewind_is_rejected() {
    stale_transaction_reply_is_rejected(TransactionQuery::Enhancement, false).await;
}

#[tokio::test]
async fn history_stream_error_does_not_mark_partial_history_complete() {
    let (mut wallet, tx, raw) = fixture();
    let rpc = HistoryRpc::default();
    let sender = rpc.pending("/GetTaddressTxids");
    wallet.client = super::CompactTxStreamerClient::new(rpc.clone());
    let mut processing = Box::pin(wallet.process_pending_transaction_requests());
    sender.send(Ok(raw.clone())).await.unwrap();
    assert!(poll!(&mut processing).is_pending());
    assert!(wallet.db.try_read().unwrap().get_transaction(tx.txid()).unwrap().is_some());
    sender.send(Err(tonic::Status::unavailable("synthetic interrupted stream"))).await.unwrap();
    drop(sender);
    assert!(matches!(processing.await, Err(crate::Error::Grpc(_))));
    assert_eq!(first_history_start(&*wallet.db.read().await), Some(BIRTHDAY));
    let status = rpc.pending("/GetTransaction");
    status.send(Ok(raw)).await.unwrap();
    drop(status);
    wallet.process_pending_transaction_requests().await.unwrap();
    assert_eq!(first_history_start(&*wallet.db.read().await), None);
}
