//! Compatibility wrapper for browser gRPC-Web responses.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http_body::{Body as HttpBody, Frame, SizeHint};
use tonic::{
    body::Body,
    codegen::{Bytes, Service, http},
};
use tonic_web_wasm_client_upstream as upstream;

pub use upstream::{Error, options};

/// A browser gRPC-Web client that accepts successful, explicitly empty responses.
#[derive(Debug, Clone)]
pub struct Client {
    inner: upstream::Client,
}

impl Client {
    /// Creates a new client.
    pub fn new(base_url: String) -> Self {
        Self {
            inner: upstream::Client::new(base_url),
        }
    }

    /// Creates a new client with fetch options.
    pub fn new_with_options(base_url: String, options: options::FetchOptions) -> Self {
        Self {
            inner: upstream::Client::new_with_options(base_url, options),
        }
    }

    /// Sets the options for the underlying fetch call.
    pub fn with_options(&mut self, options: options::FetchOptions) -> &mut Self {
        self.inner.with_options(options);
        self
    }
}

impl Service<http::Request<Body>> for Client {
    type Response = http::Response<ResponseBody>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let response = self.inner.call(request);

        Box::pin(async move {
            let response = response.await?;
            let allow_empty_response = is_explicit_successful_empty_response(&response);

            Ok(response.map(|body| ResponseBody {
                inner: Box::pin(body),
                allow_empty_response,
                emitted_frame: false,
                completed: false,
            }))
        })
    }
}

fn is_explicit_successful_empty_response<B>(response: &http::Response<B>) -> bool {
    // Some gRPC-Web servers send trailers-only status as response headers. Requiring an
    // explicit zero content length keeps truncated or partially framed streams fail-closed.
    response.status() == http::StatusCode::OK
        && response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(is_grpc_web_content_type)
        && response.headers().get("grpc-status").is_some_and(|value| value.as_bytes() == b"0")
        && response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .is_some_and(|value| value.as_bytes() == b"0")
}

fn is_grpc_web_content_type(value: &str) -> bool {
    value.split(';').map(str::trim).any(|media_type| {
        matches!(
            media_type,
            "application/grpc-web" | "application/grpc-web+proto" | "application/grpc-web-text" | "application/grpc-web-text+proto"
        )
    })
}

/// Response body returned by [`Client`].
pub struct ResponseBody {
    inner: Pin<Box<upstream::ResponseBody>>,
    allow_empty_response: bool,
    emitted_frame: bool,
    completed: bool,
}

impl HttpBody for ResponseBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();

        if this.completed {
            return Poll::Ready(None);
        }

        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.emitted_frame = true;
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) if should_complete_empty_response(this.allow_empty_response, this.emitted_frame, &error) => {
                this.completed = true;
                Poll::Ready(None)
            }
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.completed || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        if self.completed { SizeHint::with_exact(0) } else { self.inner.size_hint() }
    }
}

fn should_complete_empty_response(allow_empty_response: bool, emitted_frame: bool, error: &Error) -> bool {
    allow_empty_response && !emitted_frame && matches!(error, Error::MalformedResponse)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: http::StatusCode, content_type: Option<&str>, grpc_status: Option<&str>, content_length: Option<&str>) -> http::Response<()> {
        let mut response = http::Response::builder().status(status);

        if let Some(content_type) = content_type {
            response = response.header(http::header::CONTENT_TYPE, content_type);
        }
        if let Some(grpc_status) = grpc_status {
            response = response.header("grpc-status", grpc_status);
        }
        if let Some(content_length) = content_length {
            response = response.header(http::header::CONTENT_LENGTH, content_length);
        }

        response.body(()).unwrap()
    }

    #[test]
    fn accepts_zjs_successful_empty_response() {
        let response = response(http::StatusCode::OK, Some("application/grpc-web+proto"), Some("0"), Some("0"));

        assert!(is_explicit_successful_empty_response(&response));
    }

    #[test]
    fn rejects_responses_without_every_empty_success_signal() {
        let cases = [
            response(http::StatusCode::BAD_GATEWAY, Some("application/grpc-web+proto"), Some("0"), Some("0")),
            response(http::StatusCode::OK, Some("application/octet-stream"), Some("0"), Some("0")),
            response(http::StatusCode::OK, Some("application/grpc-web-invalid"), Some("0"), Some("0")),
            response(http::StatusCode::OK, Some("application/grpc-web+proto"), None, Some("0")),
            response(http::StatusCode::OK, Some("application/grpc-web+proto"), Some("13"), Some("0")),
            response(http::StatusCode::OK, Some("application/grpc-web+proto"), Some("0"), None),
            response(http::StatusCode::OK, Some("application/grpc-web+proto"), Some("0"), Some("1")),
        ];

        for response in cases {
            assert!(!is_explicit_successful_empty_response(&response));
        }
    }

    #[test]
    fn only_suppresses_the_empty_body_parse_error_before_any_frame() {
        assert!(should_complete_empty_response(true, false, &Error::MalformedResponse,));
        assert!(!should_complete_empty_response(false, false, &Error::MalformedResponse,));
        assert!(!should_complete_empty_response(true, true, &Error::MalformedResponse,));
        assert!(!should_complete_empty_response(true, false, &Error::HeaderParsingError,));
    }
}
