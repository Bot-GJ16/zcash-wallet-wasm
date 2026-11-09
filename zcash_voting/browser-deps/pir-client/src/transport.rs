use std::{future::Future, pin::Pin};

use anyhow::Result;

/// Marker for transport failures on idempotent requests that may use another endpoint.
#[derive(Debug)]
pub struct RetryableTransportError;

impl std::fmt::Display for RetryableTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PIR request unavailable")
    }
}

impl std::error::Error for RetryableTransportError {}

pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<TransportResponse>> + Send + 'a>>;

pub trait Transport: Send + Sync {
    fn get<'a>(&'a self, url: &'a str) -> TransportFuture<'a>;

    fn post<'a>(&'a self, url: &'a str, body: Vec<u8>) -> TransportFuture<'a>;
}

#[derive(Clone)]
pub struct TransportResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
