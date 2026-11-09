//! Execution adapters for the shared helper delivery and recovery policy.

#[cfg(not(target_arch = "wasm32"))]
use super::client::HelperClient;
use super::{
    client::{HelperError, ShareStatus, ShareSubmissionStatus},
    health::HelperHealth,
};
use crate::types::VotingError;
#[cfg(feature = "browser")]
use futures_util::stream::{FuturesUnordered, Stream, StreamExt};
use futures_util::{
    future::{select, Either},
    FutureExt,
};
#[cfg(feature = "browser")]
use std::pin::Pin;
use std::{
    future::Future,
    task::{Context, Poll},
    time::Duration,
};

pub(crate) type PollResult = (String, Result<ShareStatus, HelperError>);

pub(crate) fn checkpoint_error() -> VotingError {
    VotingError::Internal {
        message: "helper checkpoint failed".into(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Moment {
    #[cfg(not(target_arch = "wasm32"))]
    Native(tokio::time::Instant),
    Local(Duration),
}

impl Moment {
    pub(crate) fn checked_add(self, duration: Duration) -> Option<Self> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Self::Native(now) => now.checked_add(duration).map(Self::Native),
            Self::Local(now) => now.checked_add(duration).map(Self::Local),
        }
    }
    pub(crate) fn saturating_duration_since(self, earlier: Self) -> Duration {
        match (self, earlier) {
            #[cfg(not(target_arch = "wasm32"))]
            (Self::Native(now), Self::Native(earlier)) => now.saturating_duration_since(earlier),
            (Self::Local(now), Self::Local(earlier)) => now.saturating_sub(earlier),
            #[cfg(not(target_arch = "wasm32"))]
            _ => Duration::ZERO,
        }
    }
}
impl std::ops::Add<Duration> for Moment {
    type Output = Self;
    fn add(self, duration: Duration) -> Self {
        self.checked_add(duration).expect("bounded SDK duration")
    }
}

pub(crate) trait PollSet {
    fn len(&self) -> usize;
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<PollResult, ()>>>;
    fn abort_all(&mut self);
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn try_join_next(&mut self) -> Option<Result<PollResult, ()>> {
        std::future::poll_fn(|cx| self.poll_next(cx))
            .now_or_never()
            .flatten()
    }
}

pub(crate) async fn join_polls<P: PollSet>(polls: &mut P) -> Option<Result<PollResult, ()>> {
    std::future::poll_fn(|cx| polls.poll_next(cx)).await
}

#[cfg(not(target_arch = "wasm32"))]
impl PollSet for tokio::task::JoinSet<PollResult> {
    fn len(&self) -> usize {
        self.len()
    }
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<PollResult, ()>>> {
        self.poll_join_next(cx)
            .map(|result| result.map(|result| result.map_err(|_| ())))
    }
    fn abort_all(&mut self) {
        tokio::task::JoinSet::abort_all(self);
    }
}

#[cfg(feature = "browser")]
pub(crate) struct LocalPolls<'a> {
    futures: FuturesUnordered<futures_util::future::LocalBoxFuture<'a, PollResult>>,
    completed: std::collections::VecDeque<PollResult>,
}
#[cfg(feature = "browser")]
impl<'a> LocalPolls<'a> {
    pub(crate) fn new() -> Self {
        Self {
            futures: FuturesUnordered::new(),
            completed: Default::default(),
        }
    }
    pub(crate) fn push(&mut self, future: futures_util::future::LocalBoxFuture<'a, PollResult>) {
        self.futures.push(future);
    }
}
#[cfg(feature = "browser")]
impl PollSet for LocalPolls<'_> {
    fn len(&self) -> usize {
        self.futures.len() + self.completed.len()
    }
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<PollResult, ()>>> {
        if let Some(result) = self.completed.pop_front() {
            return Poll::Ready(Some(Ok(result)));
        }
        Pin::new(&mut self.futures)
            .poll_next(cx)
            .map(|result| result.map(Ok))
    }
    fn abort_all(&mut self) {
        // Preserve completions already available at the deadline boundary.
        while let Some(Some(result)) = self.futures.next().now_or_never() {
            self.completed.push_back(result);
        }
        self.futures.clear();
    }
}

pub(crate) trait RuntimeClient {
    type Future<'a, T: 'a>: Future<Output = T> + 'a
    where
        Self: 'a;
    type Polls<'a>: PollSet
    where
        Self: 'a;
    fn health(&self) -> &HelperHealth;
    fn observation_scope(&self) -> crate::ObservationScope {
        crate::ObservationScope::disabled()
    }
    fn now(&self) -> Moment;
    fn sleep_until(&self, deadline: Moment) -> Self::Future<'_, ()>;
    fn checkpoint(&self) -> Self::Future<'_, Result<(), VotingError>>;
    fn submit<'a>(
        &'a self,
        url: &'a str,
        body: &'a str,
        now: u64,
        cancel: &'a (dyn Fn() -> bool + Send + Sync),
        timeout: Duration,
        deadline: Moment,
        before_dispatch: &'a dyn Fn() -> bool,
    ) -> Self::Future<'a, Result<ShareSubmissionStatus, HelperError>>;
    fn resubmit<'a>(
        &'a self,
        url: &'a str,
        body: &'a str,
        now: u64,
        cancel: &'a (dyn Fn() -> bool + Send + Sync),
        before_dispatch: &'a dyn Fn() -> bool,
    ) -> Self::Future<'a, Result<ShareSubmissionStatus, HelperError>>;
    fn new_polls(&self) -> Self::Polls<'_>;
    fn start_poll<'a>(
        &'a self,
        polls: &mut Self::Polls<'a>,
        url: String,
        round: String,
        share: String,
        now: u64,
        deadline: Moment,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    );
}

pub(crate) async fn timeout_at<C: RuntimeClient, F: Future>(
    client: &C,
    deadline: Moment,
    future: F,
) -> Result<F::Output, ()> {
    match select(Box::pin(future), Box::pin(client.sleep_until(deadline))).await {
        Either::Left((result, _)) => Ok(result),
        Either::Right(_) => Err(()),
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl RuntimeClient for HelperClient {
    type Future<'a, T: 'a> = futures_util::future::BoxFuture<'a, T>;
    type Polls<'a> = tokio::task::JoinSet<PollResult>;
    fn health(&self) -> &HelperHealth {
        self.health()
    }
    fn observation_scope(&self) -> crate::ObservationScope {
        HelperClient::observation_scope(self)
    }
    fn now(&self) -> Moment {
        Moment::Native(tokio::time::Instant::now())
    }
    fn sleep_until(&self, deadline: Moment) -> Self::Future<'_, ()> {
        let Moment::Native(deadline) = deadline else {
            unreachable!("native clock")
        };
        Box::pin(tokio::time::sleep_until(deadline))
    }
    fn checkpoint(&self) -> Self::Future<'_, Result<(), VotingError>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn submit<'a>(
        &'a self,
        url: &'a str,
        body: &'a str,
        now: u64,
        cancel: &'a (dyn Fn() -> bool + Send + Sync),
        timeout: Duration,
        deadline: Moment,
        before_dispatch: &'a dyn Fn() -> bool,
    ) -> Self::Future<'a, Result<ShareSubmissionStatus, HelperError>> {
        let Moment::Native(deadline) = deadline else {
            unreachable!("native clock")
        };
        // Native gates already ran without an intervening await. Only the
        // local adapter repeats them after its host checkpoint resolves.
        let _ = before_dispatch;
        Box::pin(self.submit_share_with_timeout(url, body, now, cancel, timeout, Some(deadline)))
    }
    fn resubmit<'a>(
        &'a self,
        url: &'a str,
        body: &'a str,
        now: u64,
        cancel: &'a (dyn Fn() -> bool + Send + Sync),
        before_dispatch: &'a dyn Fn() -> bool,
    ) -> Self::Future<'a, Result<ShareSubmissionStatus, HelperError>> {
        let _ = before_dispatch;
        Box::pin(self.resubmit_share(url, body, now, cancel))
    }
    fn new_polls(&self) -> Self::Polls<'_> {
        tokio::task::JoinSet::new()
    }
    fn start_poll<'a>(
        &'a self,
        polls: &mut Self::Polls<'a>,
        url: String,
        round: String,
        share: String,
        now: u64,
        deadline: Moment,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        let _ = deadline;
        let client = self.clone();
        polls.spawn(async move {
            let result = client
                .share_status(&url, &round, &share, now, &|| {
                    cancelled.load(std::sync::atomic::Ordering::Relaxed)
                })
                .await;
            (url, result)
        });
    }
}
