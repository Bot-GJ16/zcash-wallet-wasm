use std::time::{Duration, SystemTime};

use wasm_bindgen::prelude::*;

use super::{WalletClock, transaction_request_is_due};
use zcash_client_backend::util::Clock;

#[wasm_bindgen(js_name = walletTestRequestTiming)]
pub fn request_timing() -> bool {
    let future = SystemTime::from(time::OffsetDateTime::now_utc()) + Duration::from_secs(60);
    let clock_time = WalletClock.now();
    transaction_request_is_due(None)
        && transaction_request_is_due(Some(SystemTime::UNIX_EPOCH))
        && !transaction_request_is_due(Some(future))
        && clock_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .is_ok_and(|elapsed| {
                (elapsed.as_secs_f64() * 1000.0 - js_sys::Date::now()).abs() < 60_000.0
            })
}
