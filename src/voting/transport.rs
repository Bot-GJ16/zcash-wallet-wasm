//! Fetch and JavaScript ownership stay on the calling browser thread.

use futures_channel::oneshot;
use futures_util::future::{Either, select};
use futures_util::lock::{Mutex, MutexGuard};
use std::{cell::Cell, sync::LazyLock};
use wasm_bindgen::{JsCast, closure::Closure};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use zcash_voting::platform::{HttpTransport, OwnedHttpRequest, OwnedHttpResponse, TransportError, TransportFuture};

#[derive(Clone, Copy, Debug, Default)]
pub struct BrowserFetchTransport;

static FETCH_SLOTS: LazyLock<[Mutex<()>; 16]> = LazyLock::new(|| std::array::from_fn(|_| Mutex::new(())));

struct ActiveFetch {
    // Struct fields drop in declaration order: abort before waking queued dispatches.
    _cleanup: FetchCleanup,
    _permit: MutexGuard<'static, ()>,
}

impl HttpTransport for BrowserFetchTransport {
    fn execute(&self, request: OwnedHttpRequest) -> TransportFuture {
        if let Err(error) = request.validate() {
            return Box::pin(async move { Err(error) });
        }
        let kind = request.kind;
        let (mut sender, receiver) = oneshot::channel();
        spawn_local(async move {
            let result = match select(Box::pin(sender.cancellation()), Box::pin(fetch(request))).await {
                Either::Left(_) => return,
                Either::Right((result, _)) => result,
            };
            let _ = sender.send(result);
        });
        // Only owned Rust data crosses this Send future. Lost local execution
        // cannot prove that a non-idempotent request was never dispatched.
        Box::pin(async move { receiver.await.unwrap_or_else(|_| Err(TransportError::after_dispatch(kind))) })
    }
}

struct FetchCleanup {
    global: wasm_bindgen::JsValue,
    controller: web_sys::AbortController,
    timeout_id: i32,
    _callback: Closure<dyn FnMut()>,
}

impl Drop for FetchCleanup {
    fn drop(&mut self) {
        self.controller.abort();
        if let Ok(clear_timeout) = method(&self.global, "clearTimeout") {
            let _ = clear_timeout.call1(&self.global, &self.timeout_id.into());
        }
    }
}

fn method(value: &wasm_bindgen::JsValue, name: &str) -> Result<js_sys::Function, ()> {
    js_sys::Reflect::get(value, &name.into()).map_err(|_| ())?.dyn_into().map_err(|_| ())
}

struct ReaderCleanup(wasm_bindgen::JsValue);

impl Drop for ReaderCleanup {
    fn drop(&mut self) {
        if let Ok(cancel) = method(&self.0, "cancel") {
            if let Ok(result) = cancel.call0(&self.0) {
                let promise = js_sys::Promise::resolve(&result);
                spawn_local(async move {
                    let _ = JsFuture::from(promise).await;
                });
            }
        }
        if let Ok(release) = method(&self.0, "releaseLock") {
            let _ = release.call0(&self.0);
        }
    }
}

async fn read_bounded_body(response: &web_sys::Response, request: &OwnedHttpRequest) -> Result<Vec<u8>, TransportError> {
    let failure = || TransportError::after_dispatch(request.kind);
    let stream = js_sys::Reflect::get(response, &"body".into()).map_err(|_| failure())?;
    if stream.is_null() {
        return Ok(Vec::new());
    }
    let options = js_sys::Object::new();
    js_sys::Reflect::set(&options, &"mode".into(), &"byob".into()).map_err(|_| failure())?;
    // Fetch byte streams support BYOB. Reject unsupported streams rather than
    // asking the host to allocate an unbounded complete response or chunk.
    let reader = method(&stream, "getReader")
        .map_err(|_| failure())?
        .call1(&stream, &options)
        .map_err(|_| failure())?;
    let reader = ReaderCleanup(reader);
    let mut body = Vec::new();
    loop {
        let remaining = request.max_response_bytes.saturating_sub(body.len());
        let buffer = js_sys::Uint8Array::new_with_length(remaining.saturating_add(1).min(16 * 1024) as u32);
        let promise: js_sys::Promise = method(&reader.0, "read")
            .map_err(|_| failure())?
            .call1(&reader.0, &buffer)
            .map_err(|_| failure())?
            .dyn_into()
            .map_err(|_| failure())?;
        let result = JsFuture::from(promise).await.map_err(|_| failure())?;
        let value = js_sys::Reflect::get(&result, &"value".into()).map_err(|_| failure())?;
        if !value.is_undefined() {
            let size = js_sys::Reflect::get(&value, &"byteLength".into())
                .map_err(|_| failure())?
                .as_f64()
                .ok_or_else(failure)?;
            let size = request.check_response_size_number(size)?;
            request.check_response_size(body.len().checked_add(size).ok_or_else(failure)?)?;
            let bytes: js_sys::Uint8Array = value.dyn_into().map_err(|_| failure())?;
            body.extend_from_slice(&bytes.to_vec());
        }
        match js_sys::Reflect::get(&result, &"done".into()).map_err(|_| failure())?.as_bool() {
            Some(true) => return Ok(body),
            Some(false) => {}
            None => return Err(failure()),
        }
    }
}

async fn fetch(request: OwnedHttpRequest) -> Result<OwnedHttpResponse, TransportError> {
    let global = js_sys::global();
    let controller = web_sys::AbortController::new().map_err(|_| TransportError::Definite)?;
    let init = web_sys::RequestInit::new();
    init.set_method(&request.method);
    init.set_mode(web_sys::RequestMode::Cors);
    init.set_credentials(web_sys::RequestCredentials::Omit);
    init.set_redirect(web_sys::RequestRedirect::Error);
    init.set_signal(Some(&controller.signal()));
    let headers = web_sys::Headers::new().map_err(|_| TransportError::Definite)?;
    for (name, value) in &request.headers {
        headers.append(name, value).map_err(|_| TransportError::Definite)?;
    }
    init.set_headers(&headers);
    if !request.body.is_empty() {
        let body = js_sys::Uint8Array::from(request.body.as_slice());
        init.set_body(&body);
    }
    let js_request = web_sys::Request::new_with_str_and_init(&request.url, &init).map_err(|_| TransportError::Definite)?;
    let fetch = method(&global, "fetch").map_err(|_| TransportError::Definite)?;

    let (timeout_sender, timeout_receiver) = oneshot::channel::<()>();
    let mut timeout_sender = Some(timeout_sender);
    let abort = controller.clone();
    let timeout_callback = Closure::<dyn FnMut()>::new(move || {
        abort.abort();
        if let Some(sender) = timeout_sender.take() {
            let _ = sender.send(());
        }
    });
    let timeout_id = method(&global, "setTimeout")
        .map_err(|_| TransportError::Definite)?
        .call2(&global, timeout_callback.as_ref().unchecked_ref(), &(request.timeout_ms as f64).into())
        .map_err(|_| TransportError::Definite)?
        .as_f64()
        .ok_or(TransportError::Definite)? as i32;
    let cleanup = FetchCleanup {
        global: global.clone().into(),
        controller,
        timeout_id,
        _callback: timeout_callback,
    };

    let after_dispatch = || TransportError::after_dispatch(request.kind);
    let dispatched = Cell::new(false);
    let response = async {
        // Queue time is covered by the already-running request timer. Capacity
        // follows the local Fetch lifetime, not the Send receiver's lifetime.
        let (permit, _, _) = futures_util::future::select_all(FETCH_SLOTS.iter().map(|slot| Box::pin(slot.lock()))).await;
        let _active = ActiveFetch {
            _cleanup: cleanup,
            _permit: permit,
        };
        // Function.call1 catches synchronous host exceptions, unlike the
        // web-sys Fetch binding. Once invocation begins, non-delivery is unknown.
        dispatched.set(true);
        let promise: js_sys::Promise = fetch
            .call1(&global, &js_request)
            .map_err(|_| after_dispatch())?
            .dyn_into()
            .map_err(|_| after_dispatch())?;
        let value = JsFuture::from(promise).await.map_err(|_| after_dispatch())?;
        let response: web_sys::Response = value.dyn_into().map_err(|_| after_dispatch())?;
        let content_length = response.headers().get("Content-Length").map_err(|_| after_dispatch())?;
        request.check_content_length(content_length.as_deref())?;
        let content_type = response.headers().get("Content-Type").map_err(|_| after_dispatch())?;
        let body = read_bounded_body(&response, &request).await?;
        Ok(OwnedHttpResponse {
            status: response.status(),
            body,
            content_type,
        })
    };
    let result = match select(Box::pin(response), timeout_receiver).await {
        Either::Left((result, _)) => result,
        Either::Right((_, _)) => Err(if dispatched.get() { after_dispatch() } else { TransportError::Definite }),
    };
    result
}

/// Local HTTP fixture entry point, returning `[status, body]` to JavaScript.
#[cfg(debug_assertions)]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = votingTestFetch)]
pub async fn voting_test_fetch(url: String, limit: usize) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue> {
    use zcash_voting::platform::RequestKind;

    let response = BrowserFetchTransport
        .execute(OwnedHttpRequest {
            method: "GET".into(),
            url,
            headers: Vec::new(),
            body: Vec::new(),
            timeout_ms: super::constants::REQUEST_TIMEOUT_MS,
            max_response_bytes: limit,
            kind: RequestKind::Idempotent,
        })
        .await
        .map_err(|error| wasm_bindgen::JsValue::from_str(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&(response.status, response.body)).map_err(|error| wasm_bindgen::JsValue::from_str(&error.to_string()))
}
