use std::{collections::BTreeMap, convert::Infallible, io};

use incrementalmerkletree::{Address, Hashable, Level, Position, Retention};
use shardtree::{
    LocatedPrunableTree, LocatedTree, ShardTree,
    error::{InsertionError, ShardTreeError},
    store::{ShardStore, memory::MemoryShardStore},
};
#[cfg(feature = "orchard")]
use zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT;
use zcash_client_backend::data_api::{
    SAPLING_SHARD_HEIGHT, WalletCommitmentTrees, chain::CommitmentTreeRoot,
};
use zcash_client_backend::serialization::shardtree::{read_shard, write_shard};
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::consensus::{self, BlockHeight};

use crate::MemoryWalletDb;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ShiftedRoot<H, const SHARD_HEIGHT: u8>(H);

impl<H: Hashable, const SHARD_HEIGHT: u8> Hashable for ShiftedRoot<H, SHARD_HEIGHT> {
    fn empty_leaf() -> Self {
        Self(H::empty_root(SHARD_HEIGHT.into()))
    }

    fn combine(level: Level, left: &Self, right: &Self) -> Self {
        Self(H::combine(level + SHARD_HEIGHT, &left.0, &right.0))
    }

    fn empty_root(level: Level) -> Self {
        Self(H::empty_root(level + SHARD_HEIGHT))
    }
}

impl<H: HashSer, const SHARD_HEIGHT: u8> HashSer for ShiftedRoot<H, SHARD_HEIGHT> {
    fn read<R: io::Read>(reader: R) -> io::Result<Self> {
        H::read(reader).map(Self)
    }

    fn write<W: io::Write>(&self, writer: W) -> io::Result<()> {
        self.0.write(writer)
    }
}

fn validate_cap_roots<H, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &ShardTree<MemoryShardStore<H, BlockHeight>, DEPTH, SHARD_HEIGHT>,
    start_index: u64,
    roots: &[CommitmentTreeRoot<H>],
) -> Result<(), ShardTreeError<Infallible>>
where
    H: Hashable + HashSer + Clone + Eq,
{
    if roots.is_empty() {
        return Ok(());
    }

    // Include completed local shards outside the supplied range so that a
    // partial update can still verify cached ancestors spanning both ranges.
    let mut known_roots = BTreeMap::new();
    for address in tree
        .store()
        .get_shard_roots()
        .map_err(ShardTreeError::Storage)?
    {
        if let Some(hash) = tree
            .store()
            .get_shard(address)
            .map_err(ShardTreeError::Storage)?
            .and_then(|shard| shard.root_hash(address.position_range_end()).ok())
        {
            known_roots.insert(address.index(), hash);
        }
    }
    for (root, index) in roots.iter().zip(start_index..) {
        known_roots.insert(index, root.root_hash().clone());
    }

    // Validate the complete known shard set against cached cap annotations in
    // bulk instead of repeating ancestor hashing for every existing shard.
    let cap_address = Address::from_parts((DEPTH - SHARD_HEIGHT).into(), 0);
    let malformed = || ShardTreeError::Insert(InsertionError::InputMalformed(cap_address));
    let mut cap_bytes = Vec::new();
    write_shard(
        &mut cap_bytes,
        &tree.store().get_cap().map_err(ShardTreeError::Storage)?,
    )
    .map_err(|_| malformed())?;
    let mut cap = LocatedTree::from_parts(
        cap_address,
        read_shard::<ShiftedRoot<H, SHARD_HEIGHT>, _>(cap_bytes.as_slice())
            .map_err(|_| malformed())?,
    )
    .map_err(|_| malformed())?;
    let mut run_start = None;
    let mut previous = None;
    let mut run_roots = Vec::new();
    for (index, hash) in known_roots {
        if previous.is_some_and(|last: u64| last.checked_add(1) != Some(index)) {
            cap = merge_cap_roots(cap, run_start.unwrap(), std::mem::take(&mut run_roots))?;
            run_start = None;
        }
        run_start.get_or_insert(index);
        run_roots.push(ShiftedRoot(hash));
        previous = Some(index);
    }
    if let Some(start) = run_start {
        merge_cap_roots(cap, start, run_roots)?;
    }
    Ok(())
}

fn merge_cap_roots<H, const SHARD_HEIGHT: u8>(
    cap: LocatedPrunableTree<ShiftedRoot<H, SHARD_HEIGHT>>,
    start_index: u64,
    roots: Vec<ShiftedRoot<H, SHARD_HEIGHT>>,
) -> Result<LocatedPrunableTree<ShiftedRoot<H, SHARD_HEIGHT>>, ShardTreeError<Infallible>>
where
    H: Hashable + Clone + Eq,
{
    Ok(cap
        .batch_insert::<(), _>(
            Position::from(start_index),
            roots.into_iter().map(|root| (root, Retention::Reference)),
        )
        .map_err(ShardTreeError::Insert)?
        .expect("each cap run contains a root")
        .subtree)
}

fn put_subtree_roots<H, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &mut ShardTree<MemoryShardStore<H, BlockHeight>, DEPTH, SHARD_HEIGHT>,
    end_heights: &mut BTreeMap<Address, BlockHeight>,
    start_index: u64,
    roots: &[CommitmentTreeRoot<H>],
) -> Result<(), ShardTreeError<Infallible>>
where
    H: Hashable + HashSer + Clone + Eq,
{
    validate_cap_roots(tree, start_index, roots)?;

    let mut missing = Vec::new();
    for (root, index) in roots.iter().zip(start_index..) {
        let address = Address::from_parts(SHARD_HEIGHT.into(), index);
        let stored = tree
            .store()
            .get_shard(address)
            .map_err(ShardTreeError::Storage)?
            .and_then(|shard| shard.root_hash(address.position_range_end()).ok());
        match stored {
            Some(hash) if hash == *root.root_hash() => {}
            Some(_) => return Err(InsertionError::Conflict(address).into()),
            None => missing.push((address, root.root_hash().clone())),
        }
    }
    for (address, hash) in missing {
        tree.insert(address, hash)?;
    }

    for (root, index) in roots.iter().zip(start_index..) {
        end_heights.insert(
            Address::from_parts(SHARD_HEIGHT.into(), index),
            root.subtree_end_height(),
        );
    }
    Ok(())
}

impl<P: consensus::Parameters> WalletCommitmentTrees for MemoryWalletDb<P> {
    type Error = Infallible;
    type SaplingShardStore<'a> = MemoryShardStore<sapling::Node, BlockHeight>;

    fn get_sapling_subtree_root(
        &mut self,
        index: u64,
    ) -> Result<Option<sapling::Node>, ShardTreeError<Self::Error>> {
        let address = Address::from_parts(SAPLING_SHARD_HEIGHT.into(), index);
        Ok(self
            .sapling_tree
            .store()
            .get_shard(address)
            .map_err(ShardTreeError::Storage)?
            .and_then(|shard| shard.root_hash(address.position_range_end()).ok()))
    }

    #[cfg(feature = "orchard")]
    fn get_orchard_subtree_root(
        &mut self,
        index: u64,
    ) -> Result<Option<orchard::tree::MerkleHashOrchard>, ShardTreeError<Self::Error>> {
        let address = Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), index);
        Ok(self
            .orchard_tree
            .store()
            .get_shard(address)
            .map_err(ShardTreeError::Storage)?
            .and_then(|shard| shard.root_hash(address.position_range_end()).ok()))
    }

    #[cfg(feature = "orchard")]
    fn get_ironwood_subtree_root(
        &mut self,
        index: u64,
    ) -> Result<Option<orchard::tree::MerkleHashOrchard>, ShardTreeError<Self::Error>> {
        let address = Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), index);
        Ok(self
            .ironwood_tree
            .store()
            .get_shard(address)
            .map_err(ShardTreeError::Storage)?
            .and_then(|shard| shard.root_hash(address.position_range_end()).ok()))
    }

    fn with_sapling_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::SaplingShardStore<'a>,
                { sapling::NOTE_COMMITMENT_TREE_DEPTH },
                SAPLING_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Infallible>>,
    {
        tracing::debug!("with_sapling_tree_mut");
        callback(&mut self.sapling_tree)
    }

    fn put_sapling_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<sapling::Node>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        tracing::debug!("put_sapling_subtree_roots");
        put_subtree_roots(
            &mut self.sapling_tree,
            &mut self.sapling_tree_shard_end_heights,
            start_index,
            roots,
        )
    }

    #[cfg(feature = "orchard")]
    type OrchardShardStore<'a> = MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>;

    #[cfg(feature = "orchard")]
    fn with_orchard_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                { ORCHARD_SHARD_HEIGHT * 2 },
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        tracing::debug!("with_orchard_tree_mut");
        callback(&mut self.orchard_tree)
    }

    /// Adds a sequence of note commitment tree subtree roots to the data store.
    #[cfg(feature = "orchard")]
    fn put_orchard_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        tracing::debug!("put_orchard_subtree_roots");
        put_subtree_roots(
            &mut self.orchard_tree,
            &mut self.orchard_tree_shard_end_heights,
            start_index,
            roots,
        )
    }

    #[cfg(feature = "orchard")]
    fn with_ironwood_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<Option<A>, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                { ORCHARD_SHARD_HEIGHT * 2 },
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        tracing::debug!("with_ironwood_tree_mut");
        callback(&mut self.ironwood_tree).map(Some)
    }

    #[cfg(feature = "orchard")]
    fn put_ironwood_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        tracing::debug!("put_ironwood_subtree_roots");
        put_subtree_roots(
            &mut self.ironwood_tree,
            &mut self.ironwood_tree_shard_end_heights,
            start_index,
            roots,
        )
    }
}

pub(crate) mod serialization {
    use std::io::Cursor;

    use incrementalmerkletree::{Address, Level};
    use shardtree::{
        LocatedPrunableTree, ShardTree,
        store::{Checkpoint, ShardStore, memory::MemoryShardStore},
    };
    use zcash_client_backend::serialization::shardtree::{read_shard, write_shard};
    use zcash_protocol::consensus::BlockHeight;

    use crate::{Error, proto::memwallet as proto};

    pub(crate) fn tree_to_protobuf<
        H: Clone
            + incrementalmerkletree::Hashable
            + PartialEq
            + zcash_primitives::merkle_tree::HashSer,
        const DEPTH: u8,
        const SHARD_HEIGHT: u8,
    >(
        tree: &ShardTree<MemoryShardStore<H, BlockHeight>, DEPTH, SHARD_HEIGHT>,
    ) -> Result<Option<crate::proto::memwallet::ShardTree>, Error> {
        use crate::proto::memwallet::{ShardTree, TreeCheckpoint, TreeShard};

        let mut cap_bytes = Vec::new();
        write_shard(&mut cap_bytes, &tree.store().get_cap()?)?;

        let shards = tree
            .store()
            .get_shard_roots()?
            .iter()
            .map(|shard_root| {
                let shard = tree.store().get_shard(*shard_root)?.unwrap();

                let mut shard_data = Vec::new();
                write_shard(&mut shard_data, shard.root())?;

                Ok(TreeShard {
                    shard_index: shard_root.index(),
                    shard_data,
                })
            })
            .collect::<Result<Vec<TreeShard>, Error>>()?;

        let mut checkpoints = Vec::new();
        tree.store()
            .for_each_checkpoint(usize::MAX, |id, checkpoint| {
                checkpoints.push(TreeCheckpoint {
                    checkpoint_id: (*id).into(),
                    position: match checkpoint.tree_state() {
                        shardtree::store::TreeState::Empty => 0,
                        shardtree::store::TreeState::AtPosition(position) => position.into(),
                    },
                });
                Ok(())
            })
            .ok();

        Ok(Some(ShardTree {
            cap: cap_bytes,
            shards,
            checkpoints,
        }))
    }

    pub(crate) fn tree_from_protobuf<
        H: Clone
            + incrementalmerkletree::Hashable
            + PartialEq
            + zcash_primitives::merkle_tree::HashSer,
        const DEPTH: u8,
        const SHARD_HEIGHT: u8,
    >(
        proto_tree: proto::ShardTree,
        max_checkpoints: usize,
        shard_root_level: Level,
    ) -> Result<ShardTree<MemoryShardStore<H, BlockHeight>, DEPTH, SHARD_HEIGHT>, Error> {
        let mut tree = ShardTree::new(MemoryShardStore::empty(), max_checkpoints);

        let cap = read_shard(Cursor::new(&proto_tree.cap))?;
        tree.store_mut().put_cap(cap)?;

        for proto_shard in proto_tree.shards {
            let shard_root = Address::from_parts(shard_root_level, proto_shard.shard_index);
            let shard_tree = read_shard(&mut Cursor::new(proto_shard.shard_data))?;
            let shard = LocatedPrunableTree::from_parts(shard_root, shard_tree)
                .map_err(|_| Error::Other("shard persistence invalid".to_string()))?;
            tree.store_mut().put_shard(shard)?;
        }

        for proto_checkpoint in proto_tree.checkpoints {
            tree.store_mut().add_checkpoint(
                BlockHeight::from(proto_checkpoint.checkpoint_id),
                Checkpoint::at_position(proto_checkpoint.position.into()),
            )?;
        }

        Ok(tree)
    }
}
