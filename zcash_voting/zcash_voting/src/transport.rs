//! Built-in HTTP transports for client features.

#[cfg(not(target_arch = "wasm32"))]
pub use crate::http_transport::{
    DirectRoute, HyperTransport, PirHttpFailure, PirHttpFailurePhase, RouteError, RouteFuture,
    RouteHttp, RoutePhase, RouteRequest, RouteResponse,
};
pub use crate::platform::{
    HttpTransport, OwnedHttpRequest, OwnedHttpResponse, RequestKind, TransportError,
    TransportFuture,
};
