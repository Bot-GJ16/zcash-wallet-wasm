use bytes::{Buf, BufMut};
use consensus::Parameters;
use prost::Message;
use prost::encoding::{self, message, uint32, uint64};

use super::*;
use crate::error::Result;
use crate::proto::memwallet as proto;
use crate::read_optional;
use crate::wallet_commitment_trees::serialization::{tree_from_protobuf, tree_to_protobuf};
use shardtree::{
    ShardTree,
    store::{ShardStore, memory::MemoryShardStore},
};
use zcash_client_backend::{
    data_api::TransactionDataRequest, serialization::shardtree::write_shard,
};
use zcash_protocol::consensus::BlockHeight;

impl<P: Parameters> MemoryWalletDb<P> {
    /// Returns the encoded protobuf size of this memory wallet db.
    ///
    /// This is intentionally computed without materializing the top-level
    /// `proto::MemoryWallet`, so callers can pre-reserve the output buffer
    /// without doubling peak memory usage.
    pub fn encoded_len(&self) -> Result<usize> {
        let mut len = uint32::encoded_len(1, &1);
        len += message::encoded_len(2, &self.proto_accounts());

        for block in self.blocks.values() {
            len += message::encoded_len(3, &proto::WalletBlock::from(block.clone()));
        }

        for (txid, tx) in &self.tx_table.0 {
            len += message::encoded_len(
                4,
                &proto::TransactionTableRecord {
                    tx_id: Some((*txid).into()),
                    tx_entry: Some(tx.clone().into()),
                },
            );
        }

        for note in self.received_notes.iter() {
            len += message::encoded_len(5, &proto::ReceivedNote::from(note.clone()));
        }

        for (note_id, tx_id) in &self.received_note_spends.0 {
            len += message::encoded_len(
                6,
                &proto::ReceivedNoteSpendRecord {
                    note_id: Some((*note_id).into()),
                    tx_id: Some((*tx_id).into()),
                },
            );
        }

        for (nullifier, (height, tx_index)) in &self.nullifiers.0 {
            len += message::encoded_len(
                7,
                &proto::NullifierRecord {
                    block_height: (*height).into(),
                    tx_index: *tx_index,
                    nullifier: Some((*nullifier).into()),
                },
            );
        }

        for (id, note) in &self.sent_notes.0 {
            len += message::encoded_len(
                8,
                &proto::SentNoteRecord {
                    sent_note_id: Some(id.clone().into()),
                    sent_note: Some(proto::SentNote::from(note.clone())),
                },
            );
        }

        for ((height, tx_index), txid) in &self.tx_locator.0 {
            len += message::encoded_len(
                9,
                &proto::TxLocatorRecord {
                    block_height: (*height).into(),
                    tx_index: *tx_index,
                    tx_id: Some((*txid).into()),
                },
            );
        }

        for r in self.scan_queue.iter() {
            len += message::encoded_len(10, &proto::ScanQueueRecord::from(*r));
        }

        len += self.encoded_shard_tree_len(11, &self.sapling_tree)?;

        for (address, height) in &self.sapling_tree_shard_end_heights {
            len += message::encoded_len(
                12,
                &proto::TreeEndHeightsRecord {
                    level: address.level().into(),
                    index: address.index(),
                    block_height: (*height).into(),
                },
            );
        }

        #[cfg(feature = "orchard")]
        {
            len += self.encoded_shard_tree_len(13, &self.orchard_tree)?;

            for (address, height) in &self.orchard_tree_shard_end_heights {
                len += message::encoded_len(
                    14,
                    &proto::TreeEndHeightsRecord {
                        level: address.level().into(),
                        index: address.index(),
                        block_height: (*height).into(),
                    },
                );
            }
        }

        for (outpoint, output) in &self.transparent_received_outputs.0 {
            len += message::encoded_len(
                15,
                &proto::TransparentReceivedOutputRecord {
                    outpoint: Some(proto::OutPoint::from(outpoint.clone())),
                    output: Some(proto::ReceivedTransparentOutput::from(output.clone())),
                },
            );
        }

        for (outpoint, txid) in &self.transparent_received_output_spends.0 {
            len += message::encoded_len(
                16,
                &proto::TransparentReceivedOutputSpendRecord {
                    outpoint: Some(proto::OutPoint::from(outpoint.clone())),
                    tx_id: Some((*txid).into()),
                },
            );
        }

        for (txid, outpoint) in &self.transparent_spend_map.0 {
            len += message::encoded_len(
                17,
                &proto::TransparentSpendCacheRecord {
                    tx_id: Some((*txid).into()),
                    outpoint: Some(proto::OutPoint::from(outpoint.clone())),
                },
            );
        }

        for request in &self.transaction_data_request_queue.0 {
            len += message::encoded_len(18, &proto::TransactionDataRequest::from(request.clone()));
        }

        #[cfg(feature = "orchard")]
        {
            len += self.encoded_shard_tree_len(19, &self.ironwood_tree)?;
            for (address, height) in &self.ironwood_tree_shard_end_heights {
                len += message::encoded_len(
                    20,
                    &proto::TreeEndHeightsRecord {
                        level: address.level().into(),
                        index: address.index(),
                        block_height: (*height).into(),
                    },
                );
            }
        }

        for record in self.proto_output_locks() {
            len += message::encoded_len(21, &record);
        }
        Ok(len)
    }

    /// Encode a memory wallet db as a protobuf byte buffer
    /// Always uses the latest version of the wire protocol
    pub fn encode<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        uint32::encode(1, &1, buf);
        message::encode(2, &self.proto_accounts(), buf);

        for block in self.blocks.values() {
            message::encode(3, &proto::WalletBlock::from(block.clone()), buf);
        }

        for (txid, tx) in &self.tx_table.0 {
            message::encode(
                4,
                &proto::TransactionTableRecord {
                    tx_id: Some((*txid).into()),
                    tx_entry: Some(tx.clone().into()),
                },
                buf,
            );
        }

        for note in self.received_notes.iter() {
            message::encode(5, &proto::ReceivedNote::from(note.clone()), buf);
        }

        for (note_id, tx_id) in &self.received_note_spends.0 {
            message::encode(
                6,
                &proto::ReceivedNoteSpendRecord {
                    note_id: Some((*note_id).into()),
                    tx_id: Some((*tx_id).into()),
                },
                buf,
            );
        }

        for (nullifier, (height, tx_index)) in &self.nullifiers.0 {
            message::encode(
                7,
                &proto::NullifierRecord {
                    block_height: (*height).into(),
                    tx_index: *tx_index,
                    nullifier: Some((*nullifier).into()),
                },
                buf,
            );
        }

        for (id, note) in &self.sent_notes.0 {
            message::encode(
                8,
                &proto::SentNoteRecord {
                    sent_note_id: Some(id.clone().into()),
                    sent_note: Some(proto::SentNote::from(note.clone())),
                },
                buf,
            );
        }

        for ((height, tx_index), txid) in &self.tx_locator.0 {
            message::encode(
                9,
                &proto::TxLocatorRecord {
                    block_height: (*height).into(),
                    tx_index: *tx_index,
                    tx_id: Some((*txid).into()),
                },
                buf,
            );
        }

        for r in self.scan_queue.iter() {
            message::encode(10, &proto::ScanQueueRecord::from(*r), buf);
        }

        self.encode_shard_tree(11, &self.sapling_tree, buf)?;

        for (address, height) in &self.sapling_tree_shard_end_heights {
            message::encode(
                12,
                &proto::TreeEndHeightsRecord {
                    level: address.level().into(),
                    index: address.index(),
                    block_height: (*height).into(),
                },
                buf,
            );
        }

        #[cfg(feature = "orchard")]
        {
            self.encode_shard_tree(13, &self.orchard_tree, buf)?;

            for (address, height) in &self.orchard_tree_shard_end_heights {
                message::encode(
                    14,
                    &proto::TreeEndHeightsRecord {
                        level: address.level().into(),
                        index: address.index(),
                        block_height: (*height).into(),
                    },
                    buf,
                );
            }
        }

        for (outpoint, output) in &self.transparent_received_outputs.0 {
            message::encode(
                15,
                &proto::TransparentReceivedOutputRecord {
                    outpoint: Some(proto::OutPoint::from(outpoint.clone())),
                    output: Some(proto::ReceivedTransparentOutput::from(output.clone())),
                },
                buf,
            );
        }

        for (outpoint, txid) in &self.transparent_received_output_spends.0 {
            message::encode(
                16,
                &proto::TransparentReceivedOutputSpendRecord {
                    outpoint: Some(proto::OutPoint::from(outpoint.clone())),
                    tx_id: Some((*txid).into()),
                },
                buf,
            );
        }

        for (txid, outpoint) in &self.transparent_spend_map.0 {
            message::encode(
                17,
                &proto::TransparentSpendCacheRecord {
                    tx_id: Some((*txid).into()),
                    outpoint: Some(proto::OutPoint::from(outpoint.clone())),
                },
                buf,
            );
        }

        for request in &self.transaction_data_request_queue.0 {
            message::encode(
                18,
                &proto::TransactionDataRequest::from(request.clone()),
                buf,
            );
        }

        #[cfg(feature = "orchard")]
        {
            self.encode_shard_tree(19, &self.ironwood_tree, buf)?;
            for (address, height) in &self.ironwood_tree_shard_end_heights {
                message::encode(
                    20,
                    &proto::TreeEndHeightsRecord {
                        level: address.level().into(),
                        index: address.index(),
                        block_height: (*height).into(),
                    },
                    buf,
                );
            }
        }

        for record in self.proto_output_locks() {
            message::encode(21, &record, buf);
        }
        Ok(())
    }

    fn proto_output_locks(&self) -> impl Iterator<Item = proto::OutputLockRecord> + '_ {
        self.output_locks
            .iter()
            .map(|(output, lock)| proto::OutputLockRecord {
                tx_id: output.txid().as_ref().to_vec(),
                pool: match output.pool() {
                    zcash_protocol::PoolType::Transparent => 0,
                    zcash_protocol::PoolType::Shielded(ShieldedPool::Sapling) => 2,
                    zcash_protocol::PoolType::Shielded(ShieldedPool::Orchard) => 3,
                    zcash_protocol::PoolType::Shielded(ShieldedPool::Ironwood) => 4,
                },
                output_index: output.output_index(),
                owner: lock.owner.as_bytes().to_vec(),
                expiry_height: lock.expiry_height.into(),
            })
    }

    pub fn encode_chunked<F: FnMut(&[u8])>(&self, flush_fn: F) -> Result<()> {
        let mut writer = ChunkedWriter::new(flush_fn);
        self.encode(&mut writer)?;
        writer.flush();
        Ok(())
    }

    fn proto_accounts(&self) -> proto::Accounts {
        proto::Accounts {
            accounts: self
                .accounts
                .accounts
                .values()
                .cloned()
                .map(proto::Account::from)
                .collect(),
            account_nonce: self.accounts.nonce,
        }
    }

    fn encoded_shard_tree_len<
        H: Clone
            + incrementalmerkletree::Hashable
            + PartialEq
            + zcash_primitives::merkle_tree::HashSer
            + Send
            + Sync,
        const DEPTH: u8,
        const SHARD_HEIGHT: u8,
    >(
        &self,
        tag: u32,
        tree: &ShardTree<MemoryShardStore<H, BlockHeight>, DEPTH, SHARD_HEIGHT>,
    ) -> Result<usize> {
        let shard_tree = StreamingShardTree { tree };
        let encoded_len = shard_tree.encoded_len()?;
        Ok(length_delimited_field_len(tag, encoded_len))
    }

    fn encode_shard_tree<
        H: Clone
            + incrementalmerkletree::Hashable
            + PartialEq
            + zcash_primitives::merkle_tree::HashSer
            + Send
            + Sync,
        const DEPTH: u8,
        const SHARD_HEIGHT: u8,
        B: BufMut,
    >(
        &self,
        tag: u32,
        tree: &ShardTree<MemoryShardStore<H, BlockHeight>, DEPTH, SHARD_HEIGHT>,
        buf: &mut B,
    ) -> Result<()> {
        let shard_tree = StreamingShardTree { tree };
        let encoded_len = shard_tree.encoded_len()?;
        encode_length_delimited_field_header(tag, encoded_len, buf);
        shard_tree.encode(buf)?;
        Ok(())
    }

    /// Create a mew memory wallet db from a protobuf encoded byte buffer with version awareness
    pub fn decode_new<B: Buf>(buf: B, params: P, max_checkpoints: usize) -> Result<Self> {
        let proto_wallet = proto::MemoryWallet::decode(buf)?;
        Self::new_from_proto(proto_wallet, params, max_checkpoints)
    }

    /// Build a memory wallet db from protobuf type with version awareness
    pub fn new_from_proto(
        proto_wallet: proto::MemoryWallet,
        params: P,
        max_checkpoints: usize,
    ) -> Result<Self> {
        match proto_wallet.version {
            1 => Self::new_from_proto_v1(proto_wallet, params, max_checkpoints),
            _ => Err(Error::UnsupportedProtoVersion(1, proto_wallet.version)),
        }
    }

    fn new_from_proto_v1(
        proto_wallet: proto::MemoryWallet,
        params: P,
        max_checkpoints: usize,
    ) -> Result<Self> {
        if proto_wallet.version != 1 {
            return Err(Error::UnsupportedProtoVersion(1, proto_wallet.version));
        }

        let mut wallet = MemoryWalletDb::new(params, max_checkpoints);

        wallet.accounts = {
            let proto_accounts = read_optional!(proto_wallet, accounts)?;
            let accounts = proto_accounts
                .accounts
                .into_iter()
                .map(|proto_account| {
                    let id = proto_account.account_id;
                    let account = Account::try_from(proto_account)?;
                    Ok((AccountId::from(id), account))
                })
                .collect::<Result<_>>()?;
            Ok::<Accounts, Error>(Accounts {
                accounts,
                nonce: proto_accounts.account_nonce,
            })
        }?;

        wallet.blocks = proto_wallet
            .blocks
            .into_iter()
            .map(|proto_block| {
                Ok((
                    proto_block.height.into(),
                    MemoryWalletBlock::try_from(proto_block)?,
                ))
            })
            .collect::<Result<_>>()?;

        wallet.tx_table = TransactionTable(
            proto_wallet
                .tx_table
                .into_iter()
                .map(|proto_tx| {
                    let txid = read_optional!(proto_tx, tx_id)?;
                    let tx = read_optional!(proto_tx, tx_entry)?;
                    Ok((txid.try_into()?, tx.try_into()?))
                })
                .collect::<Result<_>>()?,
        );

        wallet.received_notes = ReceivedNoteTable(
            proto_wallet
                .received_note_table
                .into_iter()
                .map(ReceivedNote::try_from)
                .collect::<Result<_>>()?,
        );

        wallet.received_note_spends = ReceievedNoteSpends(
            proto_wallet
                .received_note_spends
                .into_iter()
                .map(|proto_spend| {
                    let note_id = read_optional!(proto_spend, note_id)?;
                    let tx_id = read_optional!(proto_spend, tx_id)?;
                    Ok((note_id.try_into()?, tx_id.try_into()?))
                })
                .collect::<Result<_>>()?,
        );

        wallet.nullifiers = NullifierMap(
            proto_wallet
                .nullifiers
                .into_iter()
                .map(|proto_nullifier| {
                    let block_height = proto_nullifier.block_height.into();
                    let tx_index = proto_nullifier.tx_index;
                    let nullifier = read_optional!(proto_nullifier, nullifier)?.try_into()?;
                    Ok((nullifier, (block_height, tx_index)))
                })
                .collect::<Result<_>>()?,
        );

        wallet.sent_notes = SentNoteTable(
            proto_wallet
                .sent_notes
                .into_iter()
                .map(|proto_sent_note| {
                    let sent_note_id = read_optional!(proto_sent_note, sent_note_id)?;
                    let sent_note = read_optional!(proto_sent_note, sent_note)?;
                    Ok((sent_note_id.try_into()?, SentNote::try_from(sent_note)?))
                })
                .collect::<Result<_>>()?,
        );

        wallet.tx_locator = TxLocatorMap(
            proto_wallet
                .tx_locator
                .into_iter()
                .map(|proto_locator| {
                    let block_height = proto_locator.block_height.into();
                    let tx_index = proto_locator.tx_index;
                    let tx_id = read_optional!(proto_locator, tx_id)?.try_into()?;
                    Ok(((block_height, tx_index), tx_id))
                })
                .collect::<Result<_>>()?,
        );

        wallet.scan_queue = ScanQueue(
            proto_wallet
                .scan_queue
                .into_iter()
                .map(|item| item.into())
                .collect(),
        );

        wallet.sapling_tree =
            tree_from_protobuf(read_optional!(proto_wallet, sapling_tree)?, 100, 16.into())?;

        wallet.sapling_tree_shard_end_heights = proto_wallet
            .sapling_tree_shard_end_heights
            .into_iter()
            .map(|proto_end_height| {
                let address = Address::from_parts(
                    Level::from(u8::try_from(proto_end_height.level)?),
                    proto_end_height.index,
                );
                let height = proto_end_height.block_height.into();
                Ok((address, height))
            })
            .collect::<Result<_>>()?;

        #[cfg(feature = "orchard")]
        {
            wallet.orchard_tree =
                tree_from_protobuf(read_optional!(proto_wallet, orchard_tree)?, 100, 16.into())?;
        };

        #[cfg(feature = "orchard")]
        {
            wallet.orchard_tree_shard_end_heights = proto_wallet
                .orchard_tree_shard_end_heights
                .into_iter()
                .map(|proto_end_height| {
                    let address = Address::from_parts(
                        Level::from(u8::try_from(proto_end_height.level)?),
                        proto_end_height.index,
                    );
                    let height = proto_end_height.block_height.into();
                    Ok((address, height))
                })
                .collect::<Result<_>>()?;
        };

        #[cfg(feature = "orchard")]
        {
            if let Some(tree) = proto_wallet.ironwood_tree {
                wallet.ironwood_tree = tree_from_protobuf(tree, 100, 16.into())?;
            }
            wallet.ironwood_tree_shard_end_heights = proto_wallet
                .ironwood_tree_shard_end_heights
                .into_iter()
                .map(|proto_end_height| {
                    let address = Address::from_parts(
                        Level::from(u8::try_from(proto_end_height.level)?),
                        proto_end_height.index,
                    );
                    let height = proto_end_height.block_height.into();
                    Ok((address, height))
                })
                .collect::<Result<_>>()?;
        }

        wallet.transparent_received_outputs = TransparentReceivedOutputs(
            proto_wallet
                .transparent_received_outputs
                .into_iter()
                .map(|proto_output| {
                    let outpoint = read_optional!(proto_output, outpoint)?;
                    let output = read_optional!(proto_output, output)?.try_into()?;
                    Ok((OutPoint::try_from(outpoint)?, output))
                })
                .collect::<Result<_>>()?,
        );

        wallet.transparent_received_output_spends = TransparentReceivedOutputSpends(
            proto_wallet
                .transparent_received_output_spends
                .into_iter()
                .map(|proto_spend| {
                    let outpoint = read_optional!(proto_spend, outpoint)?;
                    let txid = read_optional!(proto_spend, tx_id)?.try_into()?;
                    Ok((OutPoint::try_from(outpoint)?, txid))
                })
                .collect::<Result<_>>()?,
        );

        wallet.transparent_spend_map = TransparentSpendCache(
            proto_wallet
                .transparent_spend_map
                .into_iter()
                .map(|proto_spend| {
                    let txid = read_optional!(proto_spend, tx_id)?.try_into()?;
                    let outpoint = read_optional!(proto_spend, outpoint)?;
                    Ok((txid, OutPoint::try_from(outpoint)?))
                })
                .collect::<Result<_>>()?,
        );

        wallet.transaction_data_request_queue = TransactionDataRequestQueue(
            proto_wallet
                .transaction_data_requests
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
        );

        // Wallets saved before Orchard status queries were queued still have the
        // locally created transaction bytes needed to recover those requests.
        let chain_tip = wallet.chain_height()?;
        let pending_orchard_txids = wallet
            .tx_table
            .iter()
            .filter(|(_, entry)| {
                entry.created_locally()
                    && entry.raw().is_some()
                    && !matches!(entry.status(), TransactionStatus::Mined(_))
                    && entry
                        .expiry_height()
                        .is_none_or(|expiry| chain_tip.is_none_or(|tip| tip <= expiry))
            })
            .map(|(txid, _)| *txid)
            .collect::<Vec<_>>();
        for txid in pending_orchard_txids {
            if matches!(wallet.get_transaction(txid), Ok(Some(tx)) if tx.orchard_bundle().is_some())
                && !wallet.transaction_data_request_queue.iter().any(
                    |request| matches!(request, TransactionDataRequest::GetStatus(id) if *id == txid),
                )
            {
                wallet
                    .transaction_data_request_queue
                    .queue_status_retrieval(&txid);
            }
        }

        for record in proto_wallet.output_locks {
            let pool = match record.pool {
                0 => zcash_protocol::PoolType::Transparent,
                2 => zcash_protocol::PoolType::SAPLING,
                3 => zcash_protocol::PoolType::ORCHARD,
                4 => zcash_protocol::PoolType::IRONWOOD,
                _ => return Err(Error::CorruptedData("invalid output lock pool".into())),
            };
            let output = OutputRef::new(
                TxId::from_bytes(record.tx_id.try_into()?),
                pool,
                record.output_index,
            );
            if wallet.output_account(&output).is_none() || wallet.output_locks.contains_key(&output)
            {
                return Err(Error::CorruptedData(
                    "unknown or duplicated locked output".into(),
                ));
            }
            wallet.output_locks.insert(
                output,
                crate::output_locks::OutputLock {
                    owner: zcash_client_backend::wallet::LockOwner::new(record.owner.try_into()?),
                    expiry_height: record.expiry_height.into(),
                },
            );
        }

        #[cfg(feature = "transparent-inputs")]
        wallet.ensure_internal_address_gaps()?;
        Ok(wallet)
    }
}

impl From<&TxId> for proto::TxId {
    fn from(txid: &TxId) -> Self {
        proto::TxId {
            hash: txid.as_ref().to_vec(),
        }
    }
}

impl From<TxId> for proto::TxId {
    fn from(txid: TxId) -> Self {
        proto::TxId {
            hash: txid.as_ref().to_vec(),
        }
    }
}

impl TryFrom<proto::TxId> for TxId {
    type Error = Error;

    fn try_from(txid: proto::TxId) -> Result<Self> {
        Ok(TxId::from_bytes(txid.hash.try_into()?))
    }
}

struct StreamingShardTree<'a, H, const DEPTH: u8, const SHARD_HEIGHT: u8>
where
    H: Clone + incrementalmerkletree::Hashable + PartialEq + zcash_primitives::merkle_tree::HashSer,
{
    tree: &'a ShardTree<MemoryShardStore<H, BlockHeight>, DEPTH, SHARD_HEIGHT>,
}

impl<H, const DEPTH: u8, const SHARD_HEIGHT: u8> std::fmt::Debug
    for StreamingShardTree<'_, H, DEPTH, SHARD_HEIGHT>
where
    H: Clone + incrementalmerkletree::Hashable + PartialEq + zcash_primitives::merkle_tree::HashSer,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingShardTree").finish_non_exhaustive()
    }
}

impl<H, const DEPTH: u8, const SHARD_HEIGHT: u8> StreamingShardTree<'_, H, DEPTH, SHARD_HEIGHT>
where
    H: Clone + incrementalmerkletree::Hashable + PartialEq + zcash_primitives::merkle_tree::HashSer,
{
    fn cap_bytes(&self) -> Result<Vec<u8>> {
        let mut cap_bytes = FallibleVecWriter::new();
        let cap = self.tree.store().get_cap()?;
        write_shard(&mut cap_bytes, &cap)?;
        Ok(cap_bytes.into_inner())
    }

    fn shard_bytes(&self, shard_root: incrementalmerkletree::Address) -> Result<Vec<u8>> {
        let shard = self.tree.store().get_shard(shard_root)?.ok_or_else(|| {
            Error::CorruptedData("shard root returned by store is missing".into())
        })?;

        let mut shard_data = FallibleVecWriter::new();
        write_shard(&mut shard_data, shard.root())?;
        Ok(shard_data.into_inner())
    }

    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        let cap_bytes = self.cap_bytes()?;
        if !cap_bytes.is_empty() {
            encoding::bytes::encode(1, &cap_bytes, buf);
        }

        for shard_root in self.tree.store().get_shard_roots()? {
            let shard_data = self.shard_bytes(shard_root)?;
            encode_tree_shard(2, shard_root.index(), &shard_data, buf);
        }

        self.tree
            .store()
            .for_each_checkpoint(usize::MAX, |id, checkpoint| {
                message::encode(
                    3,
                    &proto::TreeCheckpoint {
                        checkpoint_id: (*id).into(),
                        position: match checkpoint.tree_state() {
                            shardtree::store::TreeState::Empty => 0,
                            shardtree::store::TreeState::AtPosition(position) => position.into(),
                        },
                    },
                    buf,
                );
                Ok(())
            })?;

        Ok(())
    }

    fn encoded_len(&self) -> Result<usize> {
        let cap_bytes = self.cap_bytes()?;
        let mut len = if cap_bytes.is_empty() {
            0
        } else {
            encoding::bytes::encoded_len(1, &cap_bytes)
        };

        for shard_root in self.tree.store().get_shard_roots()? {
            let shard_data = self.shard_bytes(shard_root)?;
            len += length_delimited_field_len(
                2,
                tree_shard_encoded_len(shard_root.index(), &shard_data),
            );
        }

        self.tree
            .store()
            .for_each_checkpoint(usize::MAX, |id, checkpoint| {
                len += message::encoded_len(
                    3,
                    &proto::TreeCheckpoint {
                        checkpoint_id: (*id).into(),
                        position: match checkpoint.tree_state() {
                            shardtree::store::TreeState::Empty => 0,
                            shardtree::store::TreeState::AtPosition(position) => position.into(),
                        },
                    },
                );
                Ok(())
            })?;

        Ok(len)
    }
}

const CHUNK_FLUSH_SIZE: usize = 4 * 1024 * 1024; // 4 MB

pub struct ChunkedWriter<F> {
    buf: Vec<u8>,
    flush_fn: F,
    flush_threshold: usize,
}

impl<F: FnMut(&[u8])> ChunkedWriter<F> {
    pub fn new(flush_fn: F) -> Self {
        Self {
            buf: Vec::with_capacity(CHUNK_FLUSH_SIZE),
            flush_fn,
            flush_threshold: CHUNK_FLUSH_SIZE,
        }
    }

    pub fn flush(&mut self) {
        if !self.buf.is_empty() {
            (self.flush_fn)(&self.buf);
            self.buf.clear();
        }
    }
}

unsafe impl<F: FnMut(&[u8])> BufMut for ChunkedWriter<F> {
    fn remaining_mut(&self) -> usize {
        usize::MAX
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        let new_len = self.buf.len() + cnt;
        unsafe {
            self.buf.set_len(new_len);
        }
        if self.buf.len() >= self.flush_threshold {
            self.flush();
        }
    }

    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        if self.buf.len() >= self.flush_threshold {
            self.flush();
        }
        let spare = self.buf.spare_capacity_mut();
        if spare.is_empty() {
            self.buf.reserve(self.flush_threshold);
            let spare = self.buf.spare_capacity_mut();
            unsafe {
                bytes::buf::UninitSlice::from_raw_parts_mut(spare.as_mut_ptr().cast(), spare.len())
            }
        } else {
            unsafe {
                bytes::buf::UninitSlice::from_raw_parts_mut(spare.as_mut_ptr().cast(), spare.len())
            }
        }
    }

    fn put_slice(&mut self, src: &[u8]) {
        self.buf.extend_from_slice(src);
        if self.buf.len() >= self.flush_threshold {
            self.flush();
        }
    }
}

struct FallibleVecWriter {
    bytes: Vec<u8>,
}

impl FallibleVecWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl std::io::Write for FallibleVecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes.try_reserve_exact(buf.len()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to allocate shard serialization buffer: {e}"),
            )
        })?;
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn length_delimited_field_len(tag: u32, value_len: usize) -> usize {
    encoding::key_len(tag) + encoding::encoded_len_varint(value_len as u64) + value_len
}

fn encode_length_delimited_field_header<B: BufMut>(tag: u32, value_len: usize, buf: &mut B) {
    encoding::encode_key(tag, encoding::WireType::LengthDelimited, buf);
    encoding::encode_varint(value_len as u64, buf);
}

fn tree_shard_encoded_len(shard_index: u64, shard_data: &[u8]) -> usize {
    let shard_index_len = if shard_index == 0 {
        0
    } else {
        uint64::encoded_len(1, &shard_index)
    };

    let shard_data_len = if shard_data.is_empty() {
        0
    } else {
        encoding::key_len(3)
            + encoding::encoded_len_varint(shard_data.len() as u64)
            + shard_data.len()
    };

    shard_index_len + shard_data_len
}

fn encode_tree_shard<B: BufMut>(tag: u32, shard_index: u64, shard_data: &[u8], buf: &mut B) {
    encode_length_delimited_field_header(tag, tree_shard_encoded_len(shard_index, shard_data), buf);

    if shard_index != 0 {
        uint64::encode(1, &shard_index, buf);
    }

    if !shard_data.is_empty() {
        encoding::encode_key(3, encoding::WireType::LengthDelimited, buf);
        encoding::encode_varint(shard_data.len() as u64, buf);
        buf.put_slice(shard_data);
    }
}

impl<P: Parameters> From<&MemoryWalletDb<P>> for proto::MemoryWallet {
    fn from(wallet: &MemoryWalletDb<P>) -> Self {
        Self {
            version: 1,
            output_locks: wallet.proto_output_locks().collect(),
            accounts: Some(proto::Accounts {
                accounts: wallet
                    .accounts
                    .accounts
                    .clone()
                    .into_values()
                    .map(proto::Account::from)
                    .collect(),
                account_nonce: wallet.accounts.nonce,
            }),

            blocks: wallet
                .blocks
                .clone()
                .into_values()
                .map(proto::WalletBlock::from)
                .collect(),

            tx_table: wallet
                .tx_table
                .0
                .clone()
                .into_iter()
                .map(|(txid, tx)| proto::TransactionTableRecord {
                    tx_id: Some(txid.into()),
                    tx_entry: Some(tx.into()),
                })
                .collect(),

            received_note_table: wallet
                .received_notes
                .iter()
                .map(|note| proto::ReceivedNote::from(note.clone()))
                .collect(),

            received_note_spends: wallet
                .received_note_spends
                .0
                .clone()
                .into_iter()
                .map(|(note_id, tx_id)| proto::ReceivedNoteSpendRecord {
                    note_id: Some(note_id.into()),
                    tx_id: Some(tx_id.into()),
                })
                .collect(),

            nullifiers: wallet
                .nullifiers
                .0
                .clone()
                .into_iter()
                .map(|(nullifier, (height, tx_index))| proto::NullifierRecord {
                    block_height: height.into(),
                    tx_index,
                    nullifier: Some(nullifier.into()),
                })
                .collect(),

            sent_notes: wallet
                .sent_notes
                .0
                .clone()
                .into_iter()
                .map(|(id, note)| proto::SentNoteRecord {
                    sent_note_id: Some(id.into()),
                    sent_note: Some(proto::SentNote::from(note)),
                })
                .collect(),

            tx_locator: wallet
                .tx_locator
                .0
                .clone()
                .into_iter()
                .map(|((height, tx_index), txid)| proto::TxLocatorRecord {
                    block_height: height.into(),
                    tx_index,
                    tx_id: Some(txid.into()),
                })
                .collect(),

            scan_queue: wallet
                .scan_queue
                .iter()
                .map(|r| proto::ScanQueueRecord::from(*r))
                .collect(),

            sapling_tree: tree_to_protobuf(&wallet.sapling_tree).unwrap(),
            sapling_tree_shard_end_heights: wallet
                .sapling_tree_shard_end_heights
                .clone()
                .into_iter()
                .map(|(address, height)| proto::TreeEndHeightsRecord {
                    level: address.level().into(),
                    index: address.index(),
                    block_height: height.into(),
                })
                .collect(),

            #[cfg(feature = "orchard")]
            orchard_tree: tree_to_protobuf(&wallet.orchard_tree).unwrap(),
            #[cfg(not(feature = "orchard"))]
            orchard_tree: None,

            #[cfg(feature = "orchard")]
            orchard_tree_shard_end_heights: wallet
                .orchard_tree_shard_end_heights
                .clone()
                .into_iter()
                .map(|(address, height)| proto::TreeEndHeightsRecord {
                    level: address.level().into(),
                    index: address.index(),
                    block_height: height.into(),
                })
                .collect(),
            #[cfg(not(feature = "orchard"))]
            orchard_tree_shard_end_heights: Vec::new(),

            #[cfg(feature = "orchard")]
            ironwood_tree: tree_to_protobuf(&wallet.ironwood_tree).unwrap(),
            #[cfg(not(feature = "orchard"))]
            ironwood_tree: None,

            #[cfg(feature = "orchard")]
            ironwood_tree_shard_end_heights: wallet
                .ironwood_tree_shard_end_heights
                .clone()
                .into_iter()
                .map(|(address, height)| proto::TreeEndHeightsRecord {
                    level: address.level().into(),
                    index: address.index(),
                    block_height: height.into(),
                })
                .collect(),
            #[cfg(not(feature = "orchard"))]
            ironwood_tree_shard_end_heights: Vec::new(),

            transparent_received_outputs: wallet
                .transparent_received_outputs
                .0
                .clone()
                .into_iter()
                .map(
                    |(outpoint, output)| proto::TransparentReceivedOutputRecord {
                        outpoint: Some(proto::OutPoint::from(outpoint)),
                        output: Some(proto::ReceivedTransparentOutput::from(output)),
                    },
                )
                .collect(),

            transparent_received_output_spends: wallet
                .transparent_received_output_spends
                .0
                .clone()
                .into_iter()
                .map(
                    |(outpoint, txid)| proto::TransparentReceivedOutputSpendRecord {
                        outpoint: Some(proto::OutPoint::from(outpoint)),
                        tx_id: Some(txid.into()),
                    },
                )
                .collect(),

            transparent_spend_map: wallet
                .transparent_spend_map
                .0
                .clone()
                .into_iter()
                .map(|(txid, outpoint)| proto::TransparentSpendCacheRecord {
                    tx_id: Some(txid.into()),
                    outpoint: Some(proto::OutPoint::from(outpoint)),
                })
                .collect(),

            transaction_data_requests: wallet
                .transaction_data_request_queue
                .0
                .clone()
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}
