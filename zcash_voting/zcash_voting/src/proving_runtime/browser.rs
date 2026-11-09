//! Single-threaded browser proving with the same interruption context as native.

#[path = "operation.rs"]
mod operation;

use crate::{ObservationScope, VotingError};
use std::num::NonZeroUsize;
use std::sync::OnceLock;

pub(crate) use operation::{check_interruption, Operation};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvingPolicy {
    pub cpu_worker_count: NonZeroUsize,
    pub max_active_heavy_jobs: NonZeroUsize,
}

impl Default for ProvingPolicy {
    fn default() -> Self {
        Self {
            cpu_worker_count: NonZeroUsize::MIN,
            max_active_heavy_jobs: NonZeroUsize::MIN,
        }
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProvingConfigurationError {
    #[error("proving runtime is already configured with a different policy")]
    AlreadyConfigured,
    #[error("browser proving requires one worker and one active job")]
    UnsupportedBrowserPolicy,
}

static POLICY: OnceLock<ProvingPolicy> = OnceLock::new();

pub fn configure_proving_runtime(policy: ProvingPolicy) -> Result<(), ProvingConfigurationError> {
    if policy != ProvingPolicy::default() {
        return Err(ProvingConfigurationError::UnsupportedBrowserPolicy);
    }
    if *POLICY.get_or_init(|| policy) != policy {
        return Err(ProvingConfigurationError::AlreadyConfigured);
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) enum CacheKind {
    Delegation,
    Vote,
}

pub(crate) fn ensure_cache(
    kind: CacheKind,
    observations: &ObservationScope,
) -> Result<(), VotingError> {
    observations.measure_result("proving::cache_ready", || {
        match kind {
            CacheKind::Delegation => voting_circuits::delegation::warm_delegation_keys(),
            CacheKind::Vote => voting_circuits::vote_proof::warm_vote_proof_keys(),
        }
        .map_err(|error| VotingError::ProofFailed {
            message: error.to_string(),
        })
    })
}

pub(crate) fn execute<R>(
    observations: &ObservationScope,
    compute: impl FnOnce() -> Result<R, VotingError>,
) -> Result<R, VotingError> {
    check_interruption()?;
    let result = observations.measure_result("proving::heavy_job", compute)?;
    check_interruption()?;
    Ok(result)
}

pub(crate) fn execute_many<R>(
    count: usize,
    _maximum: usize,
    observations: &ObservationScope,
    compute: impl Fn(usize) -> Result<R, VotingError>,
) -> Result<Vec<R>, VotingError> {
    (0..count)
        .map(|index| execute(observations, || compute(index)))
        .collect()
}

pub(crate) fn spawn_orchestration(work: impl FnOnce()) -> Result<(), VotingError> {
    work();
    Ok(())
}

fn internal(message: impl ToString) -> VotingError {
    VotingError::Internal {
        message: message.to_string(),
    }
}
