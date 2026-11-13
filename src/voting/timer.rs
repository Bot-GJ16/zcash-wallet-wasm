//! Caller-local monotonic helper timer with cancellation-safe browser handles.
use futures_util::future::LocalBoxFuture;
use std::time::Duration;

pub(crate) struct HelperTimer {
    #[cfg(not(target_arch = "wasm32"))]
    origin: tokio::time::Instant,
}

impl Default for HelperTimer {
    fn default() -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            origin: tokio::time::Instant::now(),
        }
    }
}

impl zcash_voting::helper::client::local::Timer for HelperTimer {
    fn now(&self) -> Duration {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.origin.elapsed()
        }
        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen::JsCast;

            let global = js_sys::global();
            let now = js_sys::Reflect::get(&global, &"performance".into())
                .ok()
                .and_then(|performance| {
                    let now = js_sys::Reflect::get(&performance, &"now".into()).ok()?;
                    let now: js_sys::Function = now.dyn_into().ok()?;
                    now.call0(&performance).ok()?.as_f64()
                })
                .unwrap_or(0.0);
            Duration::from_secs_f64(now / 1000.0)
        }
    }

    fn sleep(&self, delay: Duration) -> LocalBoxFuture<'_, ()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Box::pin(tokio::time::sleep(delay))
        }
        #[cfg(target_arch = "wasm32")]
        {
            Box::pin(async move {
                use wasm_bindgen::{JsCast, closure::Closure};
                struct Timeout {
                    global: wasm_bindgen::JsValue,
                    id: i32,
                    _callback: Closure<dyn FnMut()>,
                }
                impl Drop for Timeout {
                    fn drop(&mut self) {
                        if let Ok(clear_timeout) = js_sys::Reflect::get(&self.global, &"clearTimeout".into()) {
                            if let Ok(clear_timeout) = clear_timeout.dyn_into::<js_sys::Function>() {
                                let _ = clear_timeout.call1(&self.global, &self.id.into());
                            }
                        }
                    }
                }
                let global = js_sys::global();
                let Ok(set_timeout) = js_sys::Reflect::get(&global, &"setTimeout".into()) else {
                    return;
                };
                let Ok(set_timeout) = set_timeout.dyn_into::<js_sys::Function>() else {
                    return;
                };
                let (sender, receiver) = futures_channel::oneshot::channel();
                let mut sender = Some(sender);
                let callback = Closure::<dyn FnMut()>::new(move || {
                    if let Some(sender) = sender.take() {
                        let _ = sender.send(());
                    }
                });
                let Ok(id) = set_timeout.call2(&global, callback.as_ref(), &(delay.as_millis().min(i32::MAX as u128) as i32).into()) else {
                    return;
                };
                let Some(id) = id.as_f64() else { return };
                let _timeout = Timeout {
                    global: global.into(),
                    id: id as i32,
                    _callback: callback,
                };
                let _ = receiver.await;
            })
        }
    }
}
