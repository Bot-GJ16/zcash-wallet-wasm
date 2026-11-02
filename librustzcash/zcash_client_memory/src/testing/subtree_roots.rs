use incrementalmerkletree::{Address, Hashable, Level};
use shardtree::{
    ShardTree,
    error::{InsertionError, ShardTreeError},
    store::{ShardStore, memory::MemoryShardStore},
};
use zcash_client_backend::data_api::{
    ORCHARD_SHARD_HEIGHT, SAPLING_SHARD_HEIGHT, WalletCommitmentTrees, chain::CommitmentTreeRoot,
};
use zcash_protocol::consensus::{BlockHeight, Network};

use crate::MemoryWalletDb;

fn root<H>(height: u32, hash: H) -> CommitmentTreeRoot<H> {
    CommitmentTreeRoot::from_parts(BlockHeight::from_u32(height), hash)
}

#[test]
fn repeated_roots_survive_restore_and_allow_new_roots() {
    let sapling = sapling::Node::empty_root(Level::from(SAPLING_SHARD_HEIGHT));
    let orchard = orchard::tree::MerkleHashOrchard::empty_root(Level::from(ORCHARD_SHARD_HEIGHT));
    let sapling_roots = [root(100, sapling), root(101, sapling)];
    let orchard_roots = [root(100, orchard), root(101, orchard)];
    let ironwood_roots = [root(100, orchard), root(101, orchard)];
    let mut wallet = MemoryWalletDb::new(Network::TestNetwork, 100);

    wallet.put_sapling_subtree_roots(0, &sapling_roots).unwrap();
    wallet.put_orchard_subtree_roots(0, &orchard_roots).unwrap();
    wallet
        .put_ironwood_subtree_roots(0, &ironwood_roots)
        .unwrap();

    let mut before = vec![];
    wallet.encode(&mut before).unwrap();
    wallet.put_sapling_subtree_roots(0, &sapling_roots).unwrap();
    wallet.put_orchard_subtree_roots(0, &orchard_roots).unwrap();
    wallet
        .put_ironwood_subtree_roots(0, &ironwood_roots)
        .unwrap();
    let mut after = vec![];
    wallet.encode(&mut after).unwrap();
    assert_eq!(before, after);

    let mut restored =
        MemoryWalletDb::decode_new(after.as_slice(), Network::TestNetwork, 100).unwrap();
    restored
        .put_sapling_subtree_roots(0, &sapling_roots)
        .unwrap();
    restored
        .put_orchard_subtree_roots(0, &orchard_roots)
        .unwrap();
    restored
        .put_ironwood_subtree_roots(0, &ironwood_roots)
        .unwrap();

    restored
        .put_sapling_subtree_roots(1, &[root(103, sapling)])
        .unwrap();
    let second = Address::from_parts(SAPLING_SHARD_HEIGHT.into(), 1);
    assert_eq!(
        restored.sapling_tree_shard_end_heights[&second],
        BlockHeight::from_u32(103)
    );

    restored
        .put_sapling_subtree_roots(2, &[root(104, sapling)])
        .unwrap();
    restored
        .put_orchard_subtree_roots(2, &[root(104, orchard)])
        .unwrap();
    restored
        .put_ironwood_subtree_roots(2, &[root(104, orchard)])
        .unwrap();
    assert_eq!(restored.get_sapling_subtree_root(2).unwrap(), Some(sapling));
    assert_eq!(restored.get_orchard_subtree_root(2).unwrap(), Some(orchard));
    assert_eq!(
        restored.get_ironwood_subtree_root(2).unwrap(),
        Some(orchard)
    );
}

#[test]
fn changed_roots_keep_the_original_shards_and_heights() {
    let sapling = sapling::Node::empty_root(Level::from(SAPLING_SHARD_HEIGHT));
    let sapling_changed = sapling::Node::empty_root(Level::from(SAPLING_SHARD_HEIGHT - 1));
    let orchard = orchard::tree::MerkleHashOrchard::empty_root(Level::from(ORCHARD_SHARD_HEIGHT));
    let orchard_changed =
        orchard::tree::MerkleHashOrchard::empty_root(Level::from(ORCHARD_SHARD_HEIGHT - 1));
    assert_ne!(sapling, sapling_changed);
    assert_ne!(orchard, orchard_changed);

    let mut wallet = MemoryWalletDb::new(Network::TestNetwork, 100);
    wallet
        .put_sapling_subtree_roots(0, &[root(100, sapling)])
        .unwrap();
    wallet
        .put_orchard_subtree_roots(0, &[root(100, orchard)])
        .unwrap();
    wallet
        .put_ironwood_subtree_roots(0, &[root(100, orchard)])
        .unwrap();

    assert!(matches!(
        wallet.put_sapling_subtree_roots(0, &[root(101, sapling_changed)]),
        Err(ShardTreeError::Insert(InsertionError::Conflict(_)))
    ));
    assert!(matches!(
        wallet.put_orchard_subtree_roots(0, &[root(101, orchard_changed)]),
        Err(ShardTreeError::Insert(InsertionError::Conflict(_)))
    ));
    assert!(matches!(
        wallet.put_ironwood_subtree_roots(0, &[root(101, orchard_changed)]),
        Err(ShardTreeError::Insert(InsertionError::Conflict(_)))
    ));

    let first = Address::from_parts(SAPLING_SHARD_HEIGHT.into(), 0);
    assert_eq!(wallet.get_sapling_subtree_root(0).unwrap(), Some(sapling));
    assert_eq!(wallet.get_orchard_subtree_root(0).unwrap(), Some(orchard));
    assert_eq!(wallet.get_ironwood_subtree_root(0).unwrap(), Some(orchard));
    assert_eq!(
        wallet.sapling_tree_shard_end_heights[&first],
        BlockHeight::from_u32(100)
    );

    wallet
        .put_sapling_subtree_roots(2, &[root(102, sapling)])
        .unwrap();
    assert!(matches!(
        wallet.put_sapling_subtree_roots(1, &[root(101, sapling), root(102, sapling_changed)]),
        Err(ShardTreeError::Insert(InsertionError::Conflict(_)))
    ));
    assert_eq!(wallet.get_sapling_subtree_root(1).unwrap(), None);
    assert_eq!(wallet.get_sapling_subtree_root(2).unwrap(), Some(sapling));
}

#[test]
fn restored_cap_conflict_is_not_hidden_by_matching_shards() {
    let sapling = sapling::Node::empty_root(Level::from(SAPLING_SHARD_HEIGHT));
    let stale = sapling::Node::empty_root(Level::from(SAPLING_SHARD_HEIGHT));
    let roots = [root(100, sapling), root(101, sapling)];
    let mut wallet = MemoryWalletDb::new(Network::TestNetwork, 100);
    wallet.put_sapling_subtree_roots(0, &roots).unwrap();

    let mut inconsistent = ShardTree::<
        MemoryShardStore<sapling::Node, BlockHeight>,
        { SAPLING_SHARD_HEIGHT * 2 },
        SAPLING_SHARD_HEIGHT,
    >::new(MemoryShardStore::empty(), 100);
    inconsistent
        .insert(
            Address::from_parts((SAPLING_SHARD_HEIGHT + 1).into(), 0),
            stale,
        )
        .unwrap();
    wallet
        .sapling_tree
        .store_mut()
        .put_cap(inconsistent.store().get_cap().unwrap())
        .unwrap();

    let mut bytes = vec![];
    wallet.encode(&mut bytes).unwrap();
    let mut restored =
        MemoryWalletDb::decode_new(bytes.as_slice(), Network::TestNetwork, 100).unwrap();
    assert_eq!(restored.get_sapling_subtree_root(0).unwrap(), Some(sapling));
    assert_eq!(restored.get_sapling_subtree_root(1).unwrap(), Some(sapling));
    assert!(matches!(
        restored.put_sapling_subtree_roots(0, &roots),
        Err(ShardTreeError::Insert(InsertionError::Conflict(_)))
    ));
    assert!(matches!(
        restored.put_sapling_subtree_roots(0, &roots[..1]),
        Err(ShardTreeError::Insert(InsertionError::Conflict(_)))
    ));
}

#[test]
fn a_rewound_shard_accepts_the_replacement_root() {
    let original = sapling::Node::empty_root(Level::from(SAPLING_SHARD_HEIGHT));
    let replacement = sapling::Node::empty_root(Level::from(SAPLING_SHARD_HEIGHT - 1));
    let mut wallet = MemoryWalletDb::new(Network::TestNetwork, 100);
    wallet
        .put_sapling_subtree_roots(0, &[root(100, original)])
        .unwrap();
    let checkpoint = BlockHeight::from_u32(100);
    wallet.sapling_tree.checkpoint(checkpoint).unwrap();
    wallet
        .put_sapling_subtree_roots(1, &[root(101, original)])
        .unwrap();
    wallet
        .sapling_tree
        .truncate_to_checkpoint(&checkpoint)
        .unwrap();
    wallet
        .put_sapling_subtree_roots(1, &[root(102, replacement)])
        .unwrap();
    assert_eq!(
        wallet.get_sapling_subtree_root(1).unwrap(),
        Some(replacement)
    );
}
