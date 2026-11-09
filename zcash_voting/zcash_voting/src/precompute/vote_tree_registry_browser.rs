//! Browser-local vote-tree cache keyed to one open sidecar and wallet.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use crate::{round::VotingDb, tree_sync::VoteTreeSync, types::VotingError};

type WalletKey = (u64, u64, String);
static VOTE_TREES: OnceLock<Mutex<HashMap<WalletKey, Arc<VoteTreeSync>>>> = OnceLock::new();

fn key(db: &VotingDb) -> WalletKey {
    (db.sidecar_id(), db.sidecar_epoch(), db.wallet_id())
}

fn registry(
) -> Result<std::sync::MutexGuard<'static, HashMap<WalletKey, Arc<VoteTreeSync>>>, VotingError> {
    VOTE_TREES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|error| VotingError::Internal {
            message: format!("vote-tree cache lock poisoned: {error}"),
        })
}

pub(super) fn vote_tree_for_round(
    db: &VotingDb,
    _round_id: &str,
) -> Result<Arc<VoteTreeSync>, VotingError> {
    let mut trees = registry()?;
    Ok(Arc::clone(
        trees
            .entry(key(db))
            .or_insert_with(|| Arc::new(VoteTreeSync::new())),
    ))
}

pub(super) fn reset_round(db: &VotingDb, round_id: &str) -> Result<(), VotingError> {
    let tree = registry()?.get(&key(db)).cloned();
    if let Some(tree) = tree {
        tree.reset(round_id)?;
    }
    Ok(())
}

pub(super) fn forget_wallet(db: &VotingDb) -> Result<(), VotingError> {
    let tree = registry()?.remove(&key(db));
    if let Some(tree) = tree {
        tree.reset("")?;
    }
    Ok(())
}

pub(super) fn cached_rounds(db: &VotingDb) -> Vec<String> {
    registry()
        .ok()
        .and_then(|trees| trees.get(&key(db)).map(|tree| tree.cached_rounds()))
        .unwrap_or_default()
}
