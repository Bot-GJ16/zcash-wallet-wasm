// Portions derived from ChainSafe WebZjs.
// Copyright 2024 ChainSafe Systems
// Modified by NoirWallet; see THIRD_PARTY_NOTICES.md for licensing.

use wasm_bindgen::prelude::*;

use tracing::level_filters::LevelFilter;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

fn set_panic_hook() {
    console_error_panic_hook::set_once();
}

fn setup_tracing() {
    let subscriber = {
        use tracing_subscriber::fmt::format::Pretty;
        use tracing_web::{MakeWebConsoleWriter, performance_layer};

        let default_level = if cfg!(debug_assertions) { LevelFilter::INFO } else { LevelFilter::WARN };

        let filter_layer = EnvFilter::default().add_directive(default_level.into());

        #[cfg(debug_assertions)]
        let filter_layer = filter_layer
            .add_directive("zcash_client_memory=info".parse().unwrap())
            .add_directive("zcash_client_backend::scanning=debug".parse().unwrap())
            .add_directive("zcash_client_backend::sync=debug".parse().unwrap());

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false) // Only partially supported across browsers
            .without_time() // std::time is not available in browsers
            .with_writer(MakeWebConsoleWriter::new()); // write events to the console

        let perf_layer = performance_layer().with_details_from_fields(Pretty::default());

        tracing_subscriber::registry().with(filter_layer).with(fmt_layer).with(perf_layer)
    };

    subscriber.init();
}

#[wasm_bindgen(start)]
pub fn start() {
    set_panic_hook();
    setup_tracing();
}
