use std::{collections::BTreeMap, fmt, time::Duration};

use futures_util::{TryStreamExt, future::join_all};
use prost::Message;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tonic::{
    body::Body as TonicBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use zcash_client_backend::{
    proto::{
        compact_formats::CompactBlock,
        service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
    },
    sync::CompactBlockSource,
};
use zcash_primitives::block::BlockHash;

use crate::Network;

const FORMAT_VERSION: u32 = 1;
const PROFILE: &str = "shielded-default";
const DEFAULT_TIMEOUT_MS: u32 = 30_000;
const DEFAULT_MAX_CHUNK_BYTES: usize = 128 * 1024 * 1024;
const DEFAULT_MAX_CONCURRENT_CHUNK_REQUESTS: usize = 4;
const MAX_CONCURRENT_CHUNK_REQUESTS: usize = 8;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_INDEX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct CompactBlockCdnConfig {
    base_url: String,
    request_timeout: Duration,
    max_chunk_bytes: usize,
    max_concurrent_chunk_requests: usize,
}

impl CompactBlockCdnConfig {
    pub fn new(
        base_url: String,
        request_timeout_ms: Option<u32>,
        max_chunk_bytes: Option<usize>,
        max_concurrent_chunk_requests: Option<usize>,
    ) -> Result<Self, String> {
        let base_url = base_url.trim_end_matches('/').to_owned();
        if !(base_url.starts_with("https://") || base_url.starts_with("http://")) {
            return Err("compact block CDN baseUrl must use http:// or https://".to_owned());
        }
        if base_url.contains('#') || base_url.contains('?') {
            return Err("compact block CDN baseUrl cannot contain a query or fragment".to_owned());
        }

        let request_timeout_ms = request_timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        if request_timeout_ms == 0 {
            return Err("compact block CDN requestTimeoutMs must be positive".to_owned());
        }
        let max_chunk_bytes = max_chunk_bytes.unwrap_or(DEFAULT_MAX_CHUNK_BYTES);
        if max_chunk_bytes == 0 {
            return Err("compact block CDN maxChunkBytes must be positive".to_owned());
        }
        let max_concurrent_chunk_requests = max_concurrent_chunk_requests.unwrap_or(DEFAULT_MAX_CONCURRENT_CHUNK_REQUESTS);
        if !(1..=MAX_CONCURRENT_CHUNK_REQUESTS).contains(&max_concurrent_chunk_requests) {
            return Err(format!(
                "compact block CDN maxConcurrentChunkRequests must be between 1 and {MAX_CONCURRENT_CHUNK_REQUESTS}"
            ));
        }

        Ok(Self {
            base_url,
            request_timeout: Duration::from_millis(u64::from(request_timeout_ms)),
            max_chunk_bytes,
            max_concurrent_chunk_requests,
        })
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct CompactBlockChunk {
    #[prost(uint32, tag = "1")]
    pub format_version: u32,
    #[prost(string, tag = "2")]
    pub network: String,
    #[prost(bytes = "vec", tag = "3")]
    pub genesis_hash: Vec<u8>,
    #[prost(string, tag = "4")]
    pub profile: String,
    #[prost(uint64, tag = "5")]
    pub start_height: u64,
    #[prost(uint64, tag = "6")]
    pub end_height_exclusive: u64,
    #[prost(bytes = "vec", tag = "7")]
    pub first_block_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub last_block_hash: Vec<u8>,
    #[prost(message, repeated, tag = "9")]
    pub blocks: Vec<CompactBlock>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    format_version: u32,
    network: String,
    genesis_hash: String,
    profile: String,
    pool_types: Vec<i32>,
    chunk_size: u64,
    first_height: u64,
    published_through: u64,
    indexes: Vec<IndexRef>,
}

#[derive(Debug, Deserialize)]
struct IndexRef {
    start_height: u64,
    end_height_exclusive: u64,
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct ChunkIndex {
    format_version: u32,
    network: String,
    profile: String,
    start_height: u64,
    end_height_exclusive: u64,
    chunks: Vec<ChunkRef>,
}

#[derive(Clone, Debug, Deserialize)]
struct ChunkRef {
    start_height: u64,
    end_height_exclusive: u64,
    path: String,
    sha256: String,
    uncompressed_size: usize,
    first_block_hash: String,
    last_block_hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceSegment {
    Lightwalletd {
        start: u64,
        end_exclusive: u64,
    },
    Cdn {
        start: u64,
        end_exclusive: u64,
        chunk_start: u64,
        chunk_end_exclusive: u64,
    },
}

#[derive(Debug)]
enum CdnError {
    Http(String),
    Invalid(String),
    Unsupported(String),
}

impl fmt::Display for CdnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(message) => write!(f, "HTTP error: {message}"),
            Self::Invalid(message) => write!(f, "invalid CDN data: {message}"),
            Self::Unsupported(message) => write!(f, "unsupported CDN data: {message}"),
        }
    }
}

pub struct CdnFallbackBlockSource {
    network: &'static str,
    config: Option<CompactBlockCdnConfig>,
    manifest: Option<Manifest>,
    indexes: BTreeMap<String, ChunkIndex>,
    disabled: bool,
    failures: u8,
}

impl CdnFallbackBlockSource {
    pub fn new(network: Network, config: Option<CompactBlockCdnConfig>) -> Self {
        let network = match network {
            Network::MainNetwork => "main",
            Network::TestNetwork => "test",
        };
        Self {
            network,
            config,
            manifest: None,
            indexes: BTreeMap::new(),
            disabled: false,
            failures: 0,
        }
    }

    async fn fetch_range<ChT>(
        &mut self,
        client: &mut CompactTxStreamerClient<ChT>,
        range: service::BlockRange,
        expected_prev_hash: Option<BlockHash>,
    ) -> Result<Vec<CompactBlock>, tonic::Status>
    where
        ChT: GrpcService<TonicBody>,
        ChT::Error: Into<StdError>,
        ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        let (start, end_exclusive) = range_bounds(&range)?;
        if self.config.is_none() || self.disabled || !range.pool_types.is_empty() || start >= end_exclusive {
            return fetch_lightwalletd(client, range).await;
        }

        if self.manifest.is_none()
            && let Err(error) = self.load_manifest().await
        {
            tracing::warn!("Compact block CDN disabled for this sync: {error}");
            self.disabled = true;
            return fetch_lightwalletd(client, range).await;
        }

        let result = self.fetch_mixed(client, start, end_exclusive).await.and_then(|blocks| {
            validate_sequence(&blocks, start, end_exclusive, expected_prev_hash)?;
            Ok(blocks)
        });

        match result {
            Ok(blocks) => Ok(blocks),
            Err(error) => {
                tracing::warn!("Compact block CDN batch rejected; retrying from lightwalletd: {error}");
                self.record_failure();
                let blocks = fetch_lightwalletd(client, range).await?;
                validate_sequence(&blocks, start, end_exclusive, expected_prev_hash).map_err(|error| tonic::Status::data_loss(error.to_string()))?;
                Ok(blocks)
            }
        }
    }

    async fn fetch_mixed<ChT>(&mut self, client: &mut CompactTxStreamerClient<ChT>, start: u64, end_exclusive: u64) -> Result<Vec<CompactBlock>, CdnError>
    where
        ChT: GrpcService<TonicBody>,
        ChT::Error: Into<StdError>,
        ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        let (first_height, published_end, chunk_size) = {
            let manifest = self.manifest.as_ref().ok_or_else(|| CdnError::Invalid("manifest was not loaded".to_owned()))?;
            (manifest.first_height, manifest.published_through.saturating_add(1), manifest.chunk_size)
        };

        let segments = plan_source_segments(start, end_exclusive, first_height, published_end, chunk_size)?;
        let capacity = usize::try_from(end_exclusive - start).map_err(|_| CdnError::Invalid("requested range is too large".to_owned()))?;
        let mut blocks = Vec::with_capacity(capacity);
        let mut segment_index = 0;
        while segment_index < segments.len() {
            match segments[segment_index] {
                SourceSegment::Lightwalletd { start, end_exclusive } => {
                    blocks.extend(
                        fetch_lightwalletd_bounds(client, start, end_exclusive)
                            .await
                            .map_err(|error| CdnError::Http(error.to_string()))?,
                    );
                    segment_index += 1;
                }
                SourceSegment::Cdn { .. } if self.disabled => {
                    let (start, end_exclusive, consumed) = contiguous_cdn_range(&segments[segment_index..]);
                    blocks.extend(
                        fetch_lightwalletd_bounds(client, start, end_exclusive)
                            .await
                            .map_err(|error| CdnError::Http(error.to_string()))?,
                    );
                    segment_index += consumed;
                }
                SourceSegment::Cdn { .. } => {
                    let concurrency = self.config.as_ref().expect("checked by caller").max_concurrent_chunk_requests;
                    let tentative_end = (segment_index + concurrency).min(segments.len());
                    let group_end = segments[segment_index..tentative_end]
                        .iter()
                        .position(|segment| matches!(segment, SourceSegment::Lightwalletd { .. }))
                        .map_or(tentative_end, |offset| segment_index + offset);

                    let mut prepared = Vec::with_capacity(group_end - segment_index);
                    for segment in &segments[segment_index..group_end] {
                        let SourceSegment::Cdn {
                            start,
                            end_exclusive,
                            chunk_start,
                            chunk_end_exclusive,
                        } = *segment
                        else {
                            unreachable!("CDN group contains a lightwalletd segment");
                        };
                        prepared.push((
                            start,
                            end_exclusive,
                            chunk_start,
                            chunk_end_exclusive,
                            self.prepare_chunk(chunk_start, chunk_end_exclusive).await,
                        ));
                    }

                    let config = self.config.as_ref().expect("checked by caller").clone();
                    let network = self.network;
                    let expected_genesis_hash = self.expected_genesis_hash()?;
                    let results = join_all(prepared.into_iter().map(|(start, end_exclusive, chunk_start, chunk_end_exclusive, prepared)| {
                        let config = &config;
                        let expected_genesis_hash = &expected_genesis_hash;
                        async move {
                            let result = match prepared {
                                Ok(chunk_ref) => fetch_prepared_chunk(config, network, expected_genesis_hash, &chunk_ref).await,
                                Err(error) => Err(error),
                            };
                            (start, end_exclusive, chunk_start, chunk_end_exclusive, result)
                        }
                    }))
                    .await;

                    for (start, end_exclusive, chunk_start, chunk_end_exclusive, result) in results {
                        match result {
                            Ok(chunk) => blocks.extend(chunk.blocks.into_iter().filter(|block| block.height >= start && block.height < end_exclusive)),
                            Err(error) => {
                                tracing::warn!(
                                    "Compact block CDN chunk [{chunk_start}, \
                                     {chunk_end_exclusive}) unavailable; using lightwalletd for \
                                     [{start}, {end_exclusive}): {error}"
                                );
                                self.record_failure();
                                blocks.extend(
                                    fetch_lightwalletd_bounds(client, start, end_exclusive)
                                        .await
                                        .map_err(|grpc_error| CdnError::Http(grpc_error.to_string()))?,
                                );
                            }
                        }
                    }
                    segment_index = group_end;
                }
            }
        }

        Ok(blocks)
    }

    async fn load_manifest(&mut self) -> Result<(), CdnError> {
        let config = self.config.as_ref().expect("checked by caller");
        let url = format!("{}/{}/{}/manifest.json", config.base_url, self.network, PROFILE);
        let bytes = fetch_bytes(&url, config.request_timeout, MAX_MANIFEST_BYTES).await?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|error| CdnError::Invalid(format!("manifest JSON: {error}")))?;
        validate_manifest(&manifest, self.network)?;
        self.manifest = Some(manifest);
        Ok(())
    }

    fn expected_genesis_hash(&self) -> Result<Vec<u8>, CdnError> {
        let manifest = self.manifest.as_ref().ok_or_else(|| CdnError::Invalid("manifest was not loaded".to_owned()))?;
        hex::decode(&manifest.genesis_hash).map_err(|_| CdnError::Invalid("invalid manifest genesis hash".to_owned()))
    }

    async fn prepare_chunk(&mut self, chunk_start: u64, chunk_end: u64) -> Result<ChunkRef, CdnError> {
        let index_path = self
            .manifest
            .as_ref()
            .ok_or_else(|| CdnError::Invalid("manifest was not loaded".to_owned()))?
            .indexes
            .iter()
            .find(|index| index.start_height <= chunk_start && index.end_height_exclusive >= chunk_end)
            .ok_or_else(|| CdnError::Invalid(format!("no index covers chunk [{chunk_start}, {chunk_end})")))?
            .path
            .clone();

        if !self.indexes.contains_key(&index_path) {
            let index = self.load_index(&index_path).await?;
            self.indexes.insert(index_path.clone(), index);
        }

        self.indexes
            .get(&index_path)
            .and_then(|index| {
                index
                    .chunks
                    .iter()
                    .find(|chunk| chunk.start_height == chunk_start && chunk.end_height_exclusive == chunk_end)
            })
            .cloned()
            .ok_or_else(|| CdnError::Invalid(format!("index has no chunk [{chunk_start}, {chunk_end})")))
    }

    async fn load_index(&self, path: &str) -> Result<ChunkIndex, CdnError> {
        let config = self.config.as_ref().expect("checked by caller");
        let index_ref = self
            .manifest
            .as_ref()
            .and_then(|manifest| manifest.indexes.iter().find(|index| index.path == path))
            .ok_or_else(|| CdnError::Invalid(format!("unknown index path {path}")))?;
        let url = join_object_url(&config.base_url, self.network, path)?;
        let bytes = fetch_bytes(&url, config.request_timeout, MAX_INDEX_BYTES).await?;
        verify_sha256(&bytes, &index_ref.sha256, "index")?;
        let index: ChunkIndex = serde_json::from_slice(&bytes).map_err(|error| CdnError::Invalid(format!("index JSON: {error}")))?;
        validate_index(&index, index_ref, self.network)?;
        Ok(index)
    }

    fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= 2 {
            self.disabled = true;
            tracing::warn!("Compact block CDN circuit opened for this sync");
        }
    }
}

fn plan_source_segments(start: u64, end_exclusive: u64, first_height: u64, published_end: u64, chunk_size: u64) -> Result<Vec<SourceSegment>, CdnError> {
    if chunk_size == 0 {
        return Err(CdnError::Invalid("manifest chunk size is zero".to_owned()));
    }

    let mut segments = Vec::new();
    let mut cursor = start;
    while cursor < end_exclusive {
        if cursor < first_height {
            let segment_end = end_exclusive.min(first_height);
            segments.push(SourceSegment::Lightwalletd {
                start: cursor,
                end_exclusive: segment_end,
            });
            cursor = segment_end;
        } else if cursor >= published_end {
            segments.push(SourceSegment::Lightwalletd { start: cursor, end_exclusive });
            break;
        } else {
            let chunk_start = (cursor / chunk_size) * chunk_size;
            let chunk_end_exclusive = chunk_start
                .checked_add(chunk_size)
                .ok_or_else(|| CdnError::Invalid("chunk range overflows".to_owned()))?;
            let segment_end = end_exclusive.min(chunk_end_exclusive).min(published_end);
            segments.push(SourceSegment::Cdn {
                start: cursor,
                end_exclusive: segment_end,
                chunk_start,
                chunk_end_exclusive,
            });
            cursor = segment_end;
        }
    }
    Ok(segments)
}

fn contiguous_cdn_range(segments: &[SourceSegment]) -> (u64, u64, usize) {
    let SourceSegment::Cdn { start, mut end_exclusive, .. } = segments[0] else {
        unreachable!("range must start with a CDN segment");
    };
    let mut consumed = 1;
    for segment in &segments[1..] {
        let SourceSegment::Cdn {
            start: next_start,
            end_exclusive: next_end,
            ..
        } = *segment
        else {
            break;
        };
        if next_start != end_exclusive {
            break;
        }
        end_exclusive = next_end;
        consumed += 1;
    }
    (start, end_exclusive, consumed)
}

async fn fetch_prepared_chunk(
    config: &CompactBlockCdnConfig,
    network: &str,
    expected_genesis_hash: &[u8],
    chunk_ref: &ChunkRef,
) -> Result<CompactBlockChunk, CdnError> {
    if chunk_ref.uncompressed_size > config.max_chunk_bytes {
        return Err(CdnError::Invalid(format!(
            "chunk declares {} bytes, exceeding limit {}",
            chunk_ref.uncompressed_size, config.max_chunk_bytes
        )));
    }
    let url = join_object_url(&config.base_url, network, &chunk_ref.path)?;
    let bytes = fetch_bytes(&url, config.request_timeout, config.max_chunk_bytes).await?;
    if bytes.len() != chunk_ref.uncompressed_size {
        return Err(CdnError::Invalid(format!(
            "chunk size mismatch: expected {}, received {}",
            chunk_ref.uncompressed_size,
            bytes.len()
        )));
    }
    verify_sha256(&bytes, &chunk_ref.sha256, "chunk")?;
    let chunk = CompactBlockChunk::decode(bytes.as_slice()).map_err(|error| CdnError::Invalid(format!("chunk protobuf: {error}")))?;
    validate_chunk(&chunk, chunk_ref, network, expected_genesis_hash)?;
    Ok(chunk)
}

#[async_trait::async_trait(?Send)]
impl<ChT> CompactBlockSource<ChT> for CdnFallbackBlockSource
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    async fn get_block_range(
        &mut self,
        client: &mut CompactTxStreamerClient<ChT>,
        range: service::BlockRange,
        expected_prev_hash: Option<BlockHash>,
    ) -> Result<Vec<CompactBlock>, tonic::Status> {
        self.fetch_range(client, range, expected_prev_hash).await
    }
}

fn range_bounds(range: &service::BlockRange) -> Result<(u64, u64), tonic::Status> {
    let start = range
        .start
        .as_ref()
        .ok_or_else(|| tonic::Status::invalid_argument("block range start is missing"))?;
    let end = range
        .end
        .as_ref()
        .ok_or_else(|| tonic::Status::invalid_argument("block range end is missing"))?;
    if !start.hash.is_empty() || !end.hash.is_empty() {
        return Err(tonic::Status::invalid_argument("compact block source only supports height ranges"));
    }
    let end_exclusive = end
        .height
        .checked_add(1)
        .ok_or_else(|| tonic::Status::invalid_argument("block range end overflows"))?;
    Ok((start.height, end_exclusive))
}

async fn fetch_lightwalletd<ChT>(client: &mut CompactTxStreamerClient<ChT>, range: service::BlockRange) -> Result<Vec<CompactBlock>, tonic::Status>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    client.get_block_range(range).await?.into_inner().try_collect().await
}

async fn fetch_lightwalletd_bounds<ChT>(client: &mut CompactTxStreamerClient<ChT>, start: u64, end_exclusive: u64) -> Result<Vec<CompactBlock>, tonic::Status>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    fetch_lightwalletd(
        client,
        service::BlockRange {
            start: Some(service::BlockId { height: start, hash: vec![] }),
            end: Some(service::BlockId {
                height: end_exclusive - 1,
                hash: vec![],
            }),
            pool_types: vec![],
        },
    )
    .await
}

fn validate_manifest(manifest: &Manifest, network: &str) -> Result<(), CdnError> {
    if manifest.format_version != FORMAT_VERSION {
        return Err(CdnError::Unsupported(format!("manifest format version {}", manifest.format_version)));
    }
    if manifest.network != network {
        return Err(CdnError::Invalid(format!("manifest network {} does not match {network}", manifest.network)));
    }
    if manifest.profile != PROFILE || !manifest.pool_types.is_empty() {
        return Err(CdnError::Unsupported("manifest does not provide the shielded-default profile".to_owned()));
    }
    validate_hash_text(&manifest.genesis_hash, "manifest genesis")?;
    if manifest.chunk_size == 0 {
        return Err(CdnError::Invalid("manifest chunk size is zero".to_owned()));
    }
    if manifest.first_height > manifest.published_through {
        return Err(CdnError::Invalid("manifest published range is empty".to_owned()));
    }
    let published_end = manifest
        .published_through
        .checked_add(1)
        .ok_or_else(|| CdnError::Invalid("manifest published range overflows".to_owned()))?;
    if !manifest.first_height.is_multiple_of(manifest.chunk_size) || !published_end.is_multiple_of(manifest.chunk_size) {
        return Err(CdnError::Invalid("manifest published range is not chunk-aligned".to_owned()));
    }
    for index in &manifest.indexes {
        validate_object_path(&index.path)?;
        validate_sha256_text(&index.sha256, "index")?;
        if index.start_height >= index.end_height_exclusive {
            return Err(CdnError::Invalid("manifest contains an empty index".to_owned()));
        }
        if index.start_height < manifest.first_height || index.end_height_exclusive > published_end {
            return Err(CdnError::Invalid("manifest index lies outside the published range".to_owned()));
        }
    }
    Ok(())
}

fn validate_index(index: &ChunkIndex, index_ref: &IndexRef, network: &str) -> Result<(), CdnError> {
    if index.format_version != FORMAT_VERSION || index.network != network || index.profile != PROFILE {
        return Err(CdnError::Invalid("index metadata mismatch".to_owned()));
    }
    if index.start_height != index_ref.start_height || index.end_height_exclusive != index_ref.end_height_exclusive {
        return Err(CdnError::Invalid("index range mismatch".to_owned()));
    }
    for chunk in &index.chunks {
        validate_object_path(&chunk.path)?;
        validate_sha256_text(&chunk.sha256, "chunk")?;
        validate_hash_text(&chunk.first_block_hash, "first block")?;
        validate_hash_text(&chunk.last_block_hash, "last block")?;
        if chunk.start_height >= chunk.end_height_exclusive
            || chunk.start_height < index.start_height
            || chunk.end_height_exclusive > index.end_height_exclusive
        {
            return Err(CdnError::Invalid("index contains an invalid chunk range".to_owned()));
        }
    }
    Ok(())
}

fn validate_chunk(chunk: &CompactBlockChunk, chunk_ref: &ChunkRef, network: &str, expected_genesis_hash: &[u8]) -> Result<(), CdnError> {
    if chunk.format_version != FORMAT_VERSION || chunk.network != network || chunk.profile != PROFILE {
        return Err(CdnError::Invalid("chunk metadata mismatch".to_owned()));
    }
    if chunk.genesis_hash != expected_genesis_hash {
        return Err(CdnError::Invalid("chunk genesis hash does not match manifest".to_owned()));
    }
    if chunk.start_height != chunk_ref.start_height || chunk.end_height_exclusive != chunk_ref.end_height_exclusive {
        return Err(CdnError::Invalid("chunk range mismatch".to_owned()));
    }
    validate_sequence(&chunk.blocks, chunk.start_height, chunk.end_height_exclusive, None)?;
    let first = chunk.blocks.first().ok_or_else(|| CdnError::Invalid("chunk has no blocks".to_owned()))?;
    let last = chunk.blocks.last().ok_or_else(|| CdnError::Invalid("chunk has no blocks".to_owned()))?;
    if chunk.first_block_hash != first.hash
        || chunk.last_block_hash != last.hash
        || hex::encode(&chunk.first_block_hash) != chunk_ref.first_block_hash.to_lowercase()
        || hex::encode(&chunk.last_block_hash) != chunk_ref.last_block_hash.to_lowercase()
    {
        return Err(CdnError::Invalid("chunk boundary hash mismatch".to_owned()));
    }
    Ok(())
}

fn validate_sequence(blocks: &[CompactBlock], start: u64, end_exclusive: u64, expected_prev_hash: Option<BlockHash>) -> Result<(), CdnError> {
    let expected_len = end_exclusive
        .checked_sub(start)
        .ok_or_else(|| CdnError::Invalid("descending block range".to_owned()))?;
    if blocks.len() as u64 != expected_len {
        return Err(CdnError::Invalid(format!("expected {expected_len} blocks, received {}", blocks.len())));
    }

    for (offset, block) in blocks.iter().enumerate() {
        let expected_height = start + offset as u64;
        if block.height != expected_height {
            return Err(CdnError::Invalid(format!("expected height {expected_height}, received {}", block.height)));
        }
        if block.hash.len() != 32 || block.prev_hash.len() != 32 {
            return Err(CdnError::Invalid(format!("block {expected_height} has an invalid hash length")));
        }
        if offset == 0 {
            if let Some(expected) = expected_prev_hash
                && block.prev_hash.as_slice() != expected.0
            {
                return Err(CdnError::Invalid(format!(
                    "block {expected_height} does not connect to lightwalletd tree state"
                )));
            }
        } else if block.prev_hash != blocks[offset - 1].hash {
            return Err(CdnError::Invalid(format!("block {expected_height} has a discontinuous previous hash")));
        }
    }
    Ok(())
}

fn join_object_url(base_url: &str, network: &str, path: &str) -> Result<String, CdnError> {
    validate_object_path(path)?;
    Ok(format!("{base_url}/{network}/{PROFILE}/{path}"))
}

fn validate_object_path(path: &str) -> Result<(), CdnError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains('?')
        || path.contains('#')
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(CdnError::Invalid(format!("unsafe object path {path:?}")));
    }
    Ok(())
}

fn verify_sha256(bytes: &[u8], expected: &str, kind: &str) -> Result<(), CdnError> {
    validate_sha256_text(expected, kind)?;
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != expected.to_lowercase() {
        return Err(CdnError::Invalid(format!("{kind} SHA-256 mismatch")));
    }
    Ok(())
}

fn validate_sha256_text(value: &str, kind: &str) -> Result<(), CdnError> {
    if value.len() != 64 || hex::decode(value).is_err() {
        return Err(CdnError::Invalid(format!("invalid {kind} SHA-256")));
    }
    Ok(())
}

fn validate_hash_text(value: &str, kind: &str) -> Result<(), CdnError> {
    if value.len() != 64 || hex::decode(value).is_err() {
        return Err(CdnError::Invalid(format!("invalid {kind} hash")));
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn fetch_bytes(url: &str, timeout: Duration, max_bytes: usize) -> Result<Vec<u8>, CdnError> {
    use js_sys::{Function, Promise, Reflect, Uint8Array};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let global = js_sys::global();
    let fetch = Reflect::get(&global, &JsValue::from_str("fetch"))
        .map_err(|error| CdnError::Http(format!("fetch lookup failed: {error:?}")))?
        .dyn_into::<Function>()
        .map_err(|_| CdnError::Http("global fetch is unavailable".to_owned()))?;
    let promise = fetch
        .call1(&global, &JsValue::from_str(url))
        .map_err(|error| CdnError::Http(format!("fetch call failed: {error:?}")))?
        .dyn_into::<Promise>()
        .map_err(|_| CdnError::Http("fetch did not return a Promise".to_owned()))?;
    let response = tokio_with_wasm::alias::time::timeout(timeout, JsFuture::from(promise))
        .await
        .map_err(|_| CdnError::Http("request timed out".to_owned()))?
        .map_err(|error| CdnError::Http(format!("request rejected: {error:?}")))?;
    let status = Reflect::get(&response, &JsValue::from_str("status"))
        .map_err(|error| CdnError::Http(format!("status lookup failed: {error:?}")))?
        .as_f64()
        .ok_or_else(|| CdnError::Http("response status is not numeric".to_owned()))? as u16;
    if status != 200 {
        return Err(CdnError::Http(format!("GET {url} returned {status}")));
    }

    let array_buffer = Reflect::get(&response, &JsValue::from_str("arrayBuffer"))
        .map_err(|error| CdnError::Http(format!("arrayBuffer lookup failed: {error:?}")))?
        .dyn_into::<Function>()
        .map_err(|_| CdnError::Http("response.arrayBuffer is unavailable".to_owned()))?;
    let promise = array_buffer
        .call0(&response)
        .map_err(|error| CdnError::Http(format!("arrayBuffer call failed: {error:?}")))?
        .dyn_into::<Promise>()
        .map_err(|_| CdnError::Http("arrayBuffer did not return a Promise".to_owned()))?;
    let buffer = tokio_with_wasm::alias::time::timeout(timeout, JsFuture::from(promise))
        .await
        .map_err(|_| CdnError::Http("response body timed out".to_owned()))?
        .map_err(|error| CdnError::Http(format!("response body failed: {error:?}")))?;
    let bytes = Uint8Array::new(&buffer);
    if bytes.length() as usize > max_bytes {
        return Err(CdnError::Invalid(format!(
            "response contains {} bytes, exceeding limit {max_bytes}",
            bytes.length()
        )));
    }
    Ok(bytes.to_vec())
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_bytes(_url: &str, _timeout: Duration, _max_bytes: usize) -> Result<Vec<u8>, CdnError> {
    Err(CdnError::Unsupported("CDN HTTP fetch is only available in WASM builds".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(height: u64, hash_byte: u8, prev_hash_byte: u8) -> CompactBlock {
        CompactBlock {
            height,
            hash: vec![hash_byte; 32],
            prev_hash: vec![prev_hash_byte; 32],
            ..Default::default()
        }
    }

    #[test]
    fn validates_a_contiguous_range_anchored_to_tree_state() {
        let blocks = vec![block(10, 2, 1), block(11, 3, 2)];
        assert!(validate_sequence(&blocks, 10, 12, Some(BlockHash([1; 32]))).is_ok());
    }

    #[test]
    fn plans_lightwalletd_and_cdn_segments_across_coverage_boundaries() {
        let segments = plan_source_segments(2_750, 4_250, 3_000, 4_000, 500).unwrap();
        assert_eq!(
            segments,
            vec![
                SourceSegment::Lightwalletd {
                    start: 2_750,
                    end_exclusive: 3_000,
                },
                SourceSegment::Cdn {
                    start: 3_000,
                    end_exclusive: 3_500,
                    chunk_start: 3_000,
                    chunk_end_exclusive: 3_500,
                },
                SourceSegment::Cdn {
                    start: 3_500,
                    end_exclusive: 4_000,
                    chunk_start: 3_500,
                    chunk_end_exclusive: 4_000,
                },
                SourceSegment::Lightwalletd {
                    start: 4_000,
                    end_exclusive: 4_250,
                },
            ]
        );
    }

    #[test]
    fn plans_partial_first_and_last_cdn_chunks() {
        let segments = plan_source_segments(3_250, 3_750, 3_000, 4_000, 500).unwrap();
        assert_eq!(
            segments,
            vec![
                SourceSegment::Cdn {
                    start: 3_250,
                    end_exclusive: 3_500,
                    chunk_start: 3_000,
                    chunk_end_exclusive: 3_500,
                },
                SourceSegment::Cdn {
                    start: 3_500,
                    end_exclusive: 3_750,
                    chunk_start: 3_500,
                    chunk_end_exclusive: 4_000,
                },
            ]
        );
    }

    #[test]
    fn validates_chunk_request_concurrency() {
        let config = CompactBlockCdnConfig::new("https://cdn.example/compact-blocks/v1".to_owned(), None, None, None).unwrap();
        assert_eq!(config.max_concurrent_chunk_requests, 4);

        for invalid in [0, 9] {
            let error = CompactBlockCdnConfig::new("https://cdn.example/compact-blocks/v1".to_owned(), None, None, Some(invalid))
                .expect_err("out-of-range concurrency must fail");
            assert!(error.contains("between 1 and 8"));
        }
    }

    #[test]
    fn rejects_wrong_tree_state_boundary() {
        let blocks = vec![block(10, 2, 1), block(11, 3, 2)];
        let error = validate_sequence(&blocks, 10, 12, Some(BlockHash([9; 32]))).expect_err("boundary mismatch must fail");
        assert!(error.to_string().contains("tree state"));
    }

    #[test]
    fn rejects_internal_hash_discontinuity() {
        let blocks = vec![block(10, 2, 1), block(11, 3, 7)];
        let error = validate_sequence(&blocks, 10, 12, None).expect_err("hash discontinuity must fail");
        assert!(error.to_string().contains("discontinuous"));
    }

    #[test]
    fn rejects_unsafe_object_paths() {
        for path in ["/chunk.pb", "../chunk.pb", "chunks/../chunk.pb", "chunk.pb?x=1"] {
            assert!(validate_object_path(path).is_err(), "accepted {path}");
        }
        assert!(validate_object_path("chunks/1000-2000-deadbeef.pb").is_ok());
    }

    #[test]
    fn rejects_manifest_height_overflow() {
        let manifest = Manifest {
            format_version: FORMAT_VERSION,
            network: "test".to_owned(),
            genesis_hash: hex::encode([9; 32]),
            profile: PROFILE.to_owned(),
            pool_types: vec![],
            chunk_size: 1,
            first_height: 0,
            published_through: u64::MAX,
            indexes: vec![],
        };
        assert!(validate_manifest(&manifest, "test").is_err());
    }

    #[test]
    fn parses_the_flat_manifest_shape() {
        let flat = serde_json::json!({
            "format_version": FORMAT_VERSION,
            "network": "test",
            "genesis_hash": hex::encode([9; 32]),
            "profile": PROFILE,
            "pool_types": [],
            "chunk_size": 500,
            "index_span": 100000,
            "first_height": 1000,
            "published_through": 1499,
            "publication_lag": 100,
            "generated_at_unix_seconds": 0,
            "indexes": []
        });
        let manifest = serde_json::from_value::<Manifest>(flat).unwrap();
        assert_eq!(manifest.first_height, 1000);
        assert_eq!(manifest.published_through, 1499);
    }

    #[test]
    fn rejects_chunk_from_another_genesis() {
        let chunk = CompactBlockChunk {
            format_version: FORMAT_VERSION,
            network: "test".to_owned(),
            genesis_hash: vec![8; 32],
            profile: PROFILE.to_owned(),
            start_height: 10,
            end_height_exclusive: 12,
            first_block_hash: vec![2; 32],
            last_block_hash: vec![3; 32],
            blocks: vec![block(10, 2, 1), block(11, 3, 2)],
        };
        let chunk_ref = ChunkRef {
            start_height: 10,
            end_height_exclusive: 12,
            path: "chunks/10-12-hash.pb".to_owned(),
            sha256: hex::encode([0; 32]),
            uncompressed_size: chunk.encoded_len(),
            first_block_hash: hex::encode([2; 32]),
            last_block_hash: hex::encode([3; 32]),
        };

        let error = validate_chunk(&chunk, &chunk_ref, "test", &[9; 32]).expect_err("genesis mismatch must fail");
        assert!(error.to_string().contains("genesis"));
    }

    #[test]
    fn chunk_wire_format_round_trips() {
        let chunk = CompactBlockChunk {
            format_version: FORMAT_VERSION,
            network: "test".to_owned(),
            genesis_hash: vec![9; 32],
            profile: PROFILE.to_owned(),
            start_height: 10,
            end_height_exclusive: 12,
            first_block_hash: vec![2; 32],
            last_block_hash: vec![3; 32],
            blocks: vec![block(10, 2, 1), block(11, 3, 2)],
        };
        let decoded = CompactBlockChunk::decode(chunk.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, chunk);
    }
}
