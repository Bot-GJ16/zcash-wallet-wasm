use futures_util::future::LocalBoxFuture;
use zcash_voting::{VotingError, proof_executor::ProofExecutor};

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub(crate) struct RayonProofExecutor;
impl ProofExecutor for RayonProofExecutor {
    fn prove<T: Send + 'static, R: Send + 'static>(
        &self,
        input: T,
        prove: impl FnOnce(T) -> Result<R, VotingError> + Send + 'static,
    ) -> LocalBoxFuture<'static, Result<R, VotingError>> {
        #[cfg(target_arch = "wasm32")]
        let (sender, receiver) = futures_channel::oneshot::channel();
        #[cfg(not(target_arch = "wasm32"))]
        let (sender, receiver) = tokio::sync::oneshot::channel();
        rayon::spawn(move || {
            let _ = sender.send(prove(input));
        });
        Box::pin(async move {
            receiver.await.unwrap_or_else(|_| {
                Err(VotingError::ProofFailed {
                    message: "proof execution interrupted".into(),
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn prepare_round_executors_use_owned_inputs_and_initialized_pool() {
        let input = vec![1u64, 2, 3];
        let sequential = zcash_voting::proof_executor::SequentialProofExecutor
            .prove(input.clone(), |values| Ok(values.into_iter().sum::<u64>()))
            .await
            .unwrap();
        let main = std::thread::current().id();
        let parallel = RayonProofExecutor
            .prove(input, move |values| {
                assert!(rayon::current_thread_index().is_some());
                assert_ne!(main, std::thread::current().id());
                Ok(values.into_iter().sum::<u64>())
            })
            .await
            .unwrap();
        assert_eq!(sequential, parallel);
        assert!(
            RayonProofExecutor
                .prove((), |_| Err::<(), _>(VotingError::ProofFailed { message: "fixture".into() }))
                .await
                .is_err()
        );
    }
}
