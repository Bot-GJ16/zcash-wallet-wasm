//! JS-thread checkpoints and journal-before-dispatch orchestration.
#![allow(dead_code)]
use super::types::{VotingApiError, VotingErrorCode};
use std::{cell::Cell, future::Future};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;
use zcash_voting::transport::TransportError;

#[derive(Default)]
pub(crate) struct Revision(Cell<u64>);
impl Revision {
    pub(crate) async fn checkpoint<F, Fut>(&self, serialize: impl FnOnce() -> Result<Vec<u8>, VotingApiError>, persist: F) -> Result<(), VotingApiError>
    where
        F: FnOnce(Vec<u8>, u64) -> Fut,
        Fut: Future<Output = Result<(), VotingApiError>>,
    {
        let bytes = serialize()?;
        let revision = self
            .0
            .get()
            .checked_add(1)
            .ok_or_else(|| VotingApiError::new(VotingErrorCode::PersistenceFailed))?;
        self.0.set(revision);
        persist(bytes, revision).await
    }
}

pub(crate) async fn checkpointed_dispatch<T, F, C, D>(
    intent: impl FnOnce() -> Result<(), VotingApiError>,
    checkpoint: C,
    dispatch: impl FnOnce() -> D,
    record: impl FnOnce(&Result<T, TransportError>) -> Result<(), VotingApiError>,
) -> Result<T, VotingApiError>
where
    C: Fn() -> F,
    F: Future<Output = Result<(), VotingApiError>>,
    D: Future<Output = Result<T, TransportError>>,
{
    intent()?;
    checkpoint().await?;
    let result = dispatch().await;
    record(&result).map_err(|_| VotingApiError::new(VotingErrorCode::SubmissionUnknown))?;
    checkpoint().await.map_err(|_| VotingApiError::new(VotingErrorCode::SubmissionUnknown))?;
    result.map_err(|error| {
        VotingApiError::new(if matches!(error, TransportError::Ambiguous) {
            VotingErrorCode::SubmissionUnknown
        } else {
            VotingErrorCode::SubmissionRejected
        })
    })
}

pub(crate) struct Persistence {
    pub(crate) revision: Revision,
    pending: Cell<bool>,
    #[cfg(target_arch = "wasm32")]
    callback: js_sys::Function,
}

impl Persistence {
    pub(crate) fn has_pending_checkpoint(&self) -> bool {
        self.pending.get()
    }

    // Session mutations and helper checkpoints serialize access to this boundary.
    // Failure or dropping the future must not acknowledge the in-memory snapshot.
    pub(crate) async fn checkpoint_with<F>(&self, checkpoint: impl FnOnce() -> F) -> Result<(), VotingApiError>
    where
        F: Future<Output = Result<(), VotingApiError>>,
    {
        self.pending.set(true);
        checkpoint().await?;
        self.pending.set(false);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn new(callback: js_sys::Function) -> Self {
        Self {
            revision: Revision::default(),
            pending: Cell::new(false),
            callback,
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn checkpoint(&self, db: &zcash_voting::storage::VotingDb) -> Result<(), VotingApiError> {
        self.revision
            .checkpoint(
                || db.serialize_bytes().map_err(|_| VotingApiError::new(VotingErrorCode::PersistenceFailed)),
                |bytes, revision| async move {
                    let copied = js_sys::Uint8Array::from(bytes.as_slice());
                    let result = self
                        .callback
                        .call2(&JsValue::UNDEFINED, &copied, &js_sys::BigInt::from(revision))
                        .map_err(|_| VotingApiError::new(VotingErrorCode::PersistenceFailed))?;
                    wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&result))
                        .await
                        .map_err(|_| VotingApiError::new(VotingErrorCode::PersistenceFailed))?;
                    Ok(())
                },
            )
            .await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
impl Default for Persistence {
    fn default() -> Self {
        Self {
            revision: Revision::default(),
            pending: Cell::new(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn pending_checkpoint_survives_rejection_and_dropped_retries_until_acknowledged() {
        let persistence = Persistence::default();
        assert!(!persistence.has_pending_checkpoint());
        for _ in 0..2 {
            let mut checkpoint = Box::pin(persistence.checkpoint_with(|| {
                assert!(persistence.has_pending_checkpoint());
                std::future::pending::<Result<(), VotingApiError>>()
            }));
            assert!(futures_util::poll!(checkpoint.as_mut()).is_pending());
            drop(checkpoint);
            assert!(persistence.has_pending_checkpoint());
            assert!(
                persistence
                    .checkpoint_with(|| async { Err(VotingApiError::new(VotingErrorCode::PersistenceFailed)) })
                    .await
                    .is_err()
            );
            assert!(persistence.has_pending_checkpoint());
        }
        persistence
            .checkpoint_with(|| async {
                assert!(persistence.has_pending_checkpoint());
                Ok(())
            })
            .await
            .unwrap();
        assert!(!persistence.has_pending_checkpoint());
    }

    #[tokio::test]
    async fn delegation_post_dispatch_persistence_failure_is_unknown() {
        let checkpoints = Cell::new(0);
        let error = checkpointed_dispatch(
            || Ok(()),
            || {
                checkpoints.set(checkpoints.get() + 1);
                std::future::ready(if checkpoints.get() == 1 {
                    Ok(())
                } else {
                    Err(VotingApiError::new(VotingErrorCode::PersistenceFailed))
                })
            },
            || std::future::ready(Ok(())),
            |_| Ok(()),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, VotingErrorCode::SubmissionUnknown);
    }
    #[tokio::test]
    async fn dispatch_future_is_created_only_after_checkpoint() {
        let events = RefCell::new(Vec::new());
        checkpointed_dispatch(
            || {
                events.borrow_mut().push("intent");
                Ok(())
            },
            || {
                events.borrow_mut().push("checkpoint");
                std::future::ready(Ok(()))
            },
            || {
                events.borrow_mut().push("dispatch:create");
                std::future::ready(Ok(()))
            },
            |_| {
                events.borrow_mut().push("result");
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(*events.borrow(), ["intent", "checkpoint", "dispatch:create", "result", "checkpoint"]);
    }
    #[tokio::test]
    async fn checkpoint_before_dispatch_and_after_result() {
        let events = RefCell::new(Vec::new());
        let revision = Revision::default();
        checkpointed_dispatch(
            || {
                events.borrow_mut().push("db:intent".to_owned());
                Ok(())
            },
            || {
                revision.checkpoint(
                    || Ok(vec![1]),
                    |_, rev| {
                        events.borrow_mut().push(format!("checkpoint:{rev}"));
                        std::future::ready(Ok(()))
                    },
                )
            },
            || async {
                events.borrow_mut().push("post".to_owned());
                Ok(())
            },
            |_| {
                events.borrow_mut().push("db:result".to_owned());
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(*events.borrow(), ["db:intent", "checkpoint:1", "post", "db:result", "checkpoint:2"]);
    }
    #[tokio::test]
    async fn failed_checkpoint_never_dispatches() {
        let posted = Cell::new(false);
        let err = checkpointed_dispatch(
            || Ok(()),
            || std::future::ready(Err(VotingApiError::new(VotingErrorCode::PersistenceFailed))),
            || {
                posted.set(true);
                std::future::ready(Ok(()))
            },
            |_| Ok(()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, VotingErrorCode::PersistenceFailed);
        assert!(!posted.get());
    }
    #[tokio::test]
    async fn ambiguity_is_recorded_checkpointed_and_never_retried() {
        let posts = Cell::new(0);
        let checkpoints = Cell::new(0);
        let recorded = Cell::new(false);
        let err = checkpointed_dispatch(
            || Ok(()),
            || {
                checkpoints.set(checkpoints.get() + 1);
                std::future::ready(Ok(()))
            },
            || async {
                posts.set(posts.get() + 1);
                Err::<(), _>(TransportError::Ambiguous)
            },
            |result| {
                recorded.set(matches!(result, Err(TransportError::Ambiguous)));
                Ok(())
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, VotingErrorCode::SubmissionUnknown);
        assert_eq!(posts.get(), 1);
        assert_eq!(checkpoints.get(), 2);
        assert!(recorded.get());
    }
    #[tokio::test]
    async fn rejected_checkpoint_consumes_revision_but_serialization_failure_does_not() {
        let revisions = RefCell::new(Vec::new());
        let revision = Revision::default();
        let fail = || VotingApiError::new(VotingErrorCode::PersistenceFailed);
        assert!(
            revision
                .checkpoint(|| Err(fail()), |_, _| async { panic!("serialization failed") })
                .await
                .is_err()
        );
        for _ in 0..3 {
            assert!(
                revision
                    .checkpoint(
                        || Ok(vec![1]),
                        |_, rev| {
                            revisions.borrow_mut().push(rev);
                            std::future::ready(Err(fail()))
                        }
                    )
                    .await
                    .is_err()
            );
        }
        assert_eq!(*revisions.borrow(), [1, 2, 3]);
    }
}
