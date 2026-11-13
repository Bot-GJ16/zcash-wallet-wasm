pub const STAGE_STATIC_CONFIG_SOURCE: &str = "https://voting.valargroup.dev/pins/stage/17484ebabab92225205a02a962add09f1659c9798c2e2e325bd8eac56ab3bf8f/v2-static-voting-config.json?checksum=sha256:17484ebabab92225205a02a962add09f1659c9798c2e2e325bd8eac56ab3bf8f";
pub const PROD_STATIC_CONFIG_SOURCE: &str = "https://voting.valargroup.dev/pins/prod/28fc9b631091ae8bc2f8635d8930489238ce144174cbd15a03efb0530b301ebe/v2-static-voting-config.json?checksum=sha256:28fc9b631091ae8bc2f8635d8930489238ce144174cbd15a03efb0530b301ebe";
pub(crate) const STAGE_STATIC_CONFIG_DIGEST: &str = "17484ebabab92225205a02a962add09f1659c9798c2e2e325bd8eac56ab3bf8f";
pub(crate) const PROD_STATIC_CONFIG_DIGEST: &str = "28fc9b631091ae8bc2f8635d8930489238ce144174cbd15a03efb0530b301ebe";
pub const CONFIG_LIMIT: usize = 2 * 1024 * 1024;
pub use zcash_voting::platform::API_LIMIT;
pub const PIR_LIMIT: usize = 64 * 1024 * 1024;
pub const HELPER_LIMIT: usize = 2 * 1024 * 1024;
pub const REQUEST_TIMEOUT_MS: u32 = 30_000;
