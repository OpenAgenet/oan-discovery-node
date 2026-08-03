// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use jieba_rs::Jieba;
use oan_core::{
    CryptoSuite, DidDocument, ImplementationLink, OanMetadata, ProtocolBinding,
    ResourceDescription, ResourceType, ServiceEndpoint, VerificationMethod,
};
use oan_crypto::{hash_json_with_suite, sha256_hex, signing_key_from_bytes};
use oan_package::{
    hash_resource_metadata_with_suite, ResourceMetadata, ResourcePackage, ResourcePackageClaims,
    RootProof,
};
use oan_protocol::{
    HealthResponse, ResourceDiscoveryCandidate, ResourceDiscoveryQuery, ResourceDiscoveryResponse,
};
use oan_semantic_recommender::{
    DiscoverySuggestionContext, DiscoverySuggestionInput, SemanticRecommender,
};
use oan_storage::{DatabaseBackend, DatabaseConfig, JsonStore, PostgresJsonStore, SqliteJsonStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Postgres, QueryBuilder, Row, Sqlite};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::{Duration as StdDuration, Instant},
};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration as TokioDuration};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

const DISCOVERY_SYNC_STATE_TABLE: &str = "discovery_sync_state";
const DISCOVERY_PACKAGE_TABLE: &str = "discovery_packages";
const DISCOVERY_REJECTED_TABLE: &str = "discovery_rejected_packages";
const DISCOVERY_SEMANTIC_INDEX_TABLE: &str = "discovery_semantic_index";
const DISCOVERY_INTENT_INDEX_TABLE: &str = "discovery_intent_index";
const DISCOVERY_INDEX_STATS_CACHE_TTL_MS: u64 = 500;
const DISCOVERY_CDN_CURSOR_KEY: &str = "cdn_publication_cursor";
const DEFAULT_SEMANTIC_DIMENSION: usize = 64;
const SEMANTIC_ALIASES_JSON: &str = include_str!("semantic_aliases.v1.json");

#[derive(Clone, Debug, Default, Deserialize)]
struct DiscoverySyncRequest {
    #[serde(rename = "maxPublications", default)]
    max_publications: Option<usize>,
    #[serde(rename = "cursorHint", default)]
    cursor_hint: Option<i64>,
    #[serde(default)]
    items: Vec<DiscoveryNotificationItem>,
}

#[derive(Clone, Debug, Deserialize)]
struct DiscoveryNotificationItem {
    #[serde(rename = "resourceDid")]
    resource_did: String,
    // Kept in the notification contract for audit/compatibility. The discovery
    // node indexes the current CDN package and validates the package itself.
    #[allow(dead_code)]
    #[serde(rename = "packageVersion")]
    package_version: String,
    #[serde(rename = "publicationCursor")]
    publication_cursor: i64,
    #[allow(dead_code)]
    #[serde(rename = "packageHash")]
    package_hash: String,
    #[allow(dead_code)]
    #[serde(rename = "metadataHash")]
    metadata_hash: String,
    #[allow(dead_code)]
    #[serde(rename = "didDocumentHash")]
    did_document_hash: String,
    #[serde(rename = "resourceType", default)]
    resource_type: Option<String>,
    #[serde(rename = "capabilityTags", default)]
    capability_tags: Vec<String>,
    #[serde(rename = "authorizedDomains", default)]
    authorized_domains: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct RejectedPackageBackfillRequest {
    #[serde(rename = "maxItems", default)]
    max_items: Option<usize>,
    #[serde(rename = "resourceDids", default)]
    resource_dids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ResolvedRejectedPackageCleanupRequest {
    #[serde(rename = "dryRun", default = "default_true")]
    dry_run: bool,
    #[serde(rename = "maxItems", default)]
    max_items: Option<usize>,
    #[serde(rename = "resourceDids", default)]
    resource_dids: Vec<String>,
}

impl Default for ResolvedRejectedPackageCleanupRequest {
    fn default() -> Self {
        Self {
            dry_run: true,
            max_items: None,
            resource_dids: vec![],
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct IndexedResourceVisibilityRequest {
    #[serde(rename = "resourceDids")]
    resource_dids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    #[serde(default)]
    cors: CorsConfig,
    #[serde(default)]
    debug: DebugConfig,
    #[serde(default, rename = "semanticSearch")]
    semantic_search: SemanticSearchConfig,
    upstream: UpstreamConfig,
    paths: PathConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerConfig {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct CorsConfig {
    #[serde(default)]
    allowed_origins: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct DebugConfig {
    #[serde(default)]
    export_snapshots: bool,
    #[serde(default = "default_debug_export_interval_ms")]
    export_interval_ms: u64,
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            export_snapshots: false,
            export_interval_ms: default_debug_export_interval_ms(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct UpstreamConfig {
    root_endpoint: String,
    #[serde(default)]
    cdn_endpoint: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct PathConfig {
    data_dir: PathBuf,
    index_dir: PathBuf,
    keys_dir: PathBuf,
    #[serde(default)]
    database_url: Option<String>,
}

fn default_debug_export_interval_ms() -> u64 {
    2_000
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize)]
struct SemanticSearchConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_semantic_engine")]
    engine: String,
    #[serde(default = "default_semantic_fallback")]
    fallback: String,
    #[serde(default = "default_semantic_mode", rename = "defaultMode")]
    default_mode: String,
    #[serde(
        default = "default_semantic_candidate_multiplier",
        rename = "candidateMultiplier"
    )]
    candidate_multiplier: u32,
    #[serde(default = "default_semantic_max_candidates", rename = "maxCandidates")]
    max_candidates: u32,
    #[serde(
        default = "default_semantic_explain_enabled",
        rename = "explainEnabled"
    )]
    explain_enabled: bool,
    #[serde(default)]
    embedding: SemanticEmbeddingConfig,
    #[serde(default)]
    filters: SemanticFilterConfig,
}

impl Default for SemanticSearchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            engine: default_semantic_engine(),
            fallback: default_semantic_fallback(),
            default_mode: default_semantic_mode(),
            candidate_multiplier: default_semantic_candidate_multiplier(),
            max_candidates: default_semantic_max_candidates(),
            explain_enabled: default_semantic_explain_enabled(),
            embedding: SemanticEmbeddingConfig::default(),
            filters: SemanticFilterConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct SemanticEmbeddingConfig {
    #[serde(default = "default_semantic_embedding_provider")]
    provider: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default, rename = "healthEndpoint")]
    health_endpoint: Option<String>,
    #[serde(default, rename = "modelPath")]
    model_path: Option<String>,
    #[serde(default = "default_semantic_embedding_model", rename = "modelName")]
    model_name: String,
    #[serde(default, rename = "modelVersion")]
    model_version: Option<String>,
    #[serde(default, rename = "strictModelVersion")]
    strict_model_version: bool,
    #[serde(default, rename = "dtype")]
    dtype: Option<String>,
    #[serde(default = "default_semantic_dimension")]
    dimension: usize,
    #[serde(
        default = "default_semantic_embedding_timeout_ms",
        rename = "timeoutMs"
    )]
    timeout_ms: u64,
    #[serde(
        default = "default_semantic_embedding_batch_size",
        rename = "batchSize"
    )]
    batch_size: usize,
    #[serde(
        default = "default_semantic_embedding_max_input_chars",
        rename = "maxInputChars"
    )]
    max_input_chars: usize,
}

impl Default for SemanticEmbeddingConfig {
    fn default() -> Self {
        Self {
            provider: default_semantic_embedding_provider(),
            endpoint: None,
            health_endpoint: None,
            model_path: None,
            model_name: default_semantic_embedding_model(),
            model_version: None,
            strict_model_version: false,
            dtype: None,
            dimension: default_semantic_dimension(),
            timeout_ms: default_semantic_embedding_timeout_ms(),
            batch_size: default_semantic_embedding_batch_size(),
            max_input_chars: default_semantic_embedding_max_input_chars(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct SemanticFilterConfig {
    #[serde(
        default = "default_semantic_resource_type_filter",
        rename = "resourceType"
    )]
    resource_type: String,
    #[serde(
        default = "default_semantic_capability_tags_filter",
        rename = "capabilityTags"
    )]
    capability_tags: String,
    #[serde(default = "default_semantic_protocol_filter")]
    protocol: String,
}

impl Default for SemanticFilterConfig {
    fn default() -> Self {
        Self {
            resource_type: default_semantic_resource_type_filter(),
            capability_tags: default_semantic_capability_tags_filter(),
            protocol: default_semantic_protocol_filter(),
        }
    }
}

fn default_semantic_engine() -> String {
    "pgvector".to_owned()
}

fn default_semantic_fallback() -> String {
    "keyword".to_owned()
}

fn default_semantic_mode() -> String {
    "hybrid".to_owned()
}

fn default_semantic_candidate_multiplier() -> u32 {
    8
}

fn default_semantic_max_candidates() -> u32 {
    500
}

fn default_semantic_explain_enabled() -> bool {
    true
}

fn default_semantic_embedding_provider() -> String {
    "deterministic-local".to_owned()
}

fn default_semantic_embedding_model() -> String {
    "oan-deterministic-local-v1".to_owned()
}

fn default_semantic_dimension() -> usize {
    DEFAULT_SEMANTIC_DIMENSION
}

fn default_semantic_embedding_timeout_ms() -> u64 {
    2_000
}

fn default_semantic_embedding_batch_size() -> usize {
    32
}

fn default_semantic_embedding_max_input_chars() -> usize {
    6_000
}

fn default_semantic_evaluation_package_version() -> String {
    "1".to_owned()
}

fn default_semantic_resource_type_filter() -> String {
    "hard".to_owned()
}

fn default_semantic_capability_tags_filter() -> String {
    "hard".to_owned()
}

fn default_semantic_protocol_filter() -> String {
    "hard".to_owned()
}

#[derive(Clone, Debug, Deserialize)]
struct DevKeyFile {
    algorithm: String,
    #[serde(rename = "privateKeyJwk")]
    private_key_jwk: PrivateKeyJwk,
}

#[derive(Clone, Debug, Deserialize)]
struct PrivateKeyJwk {
    d: String,
}

#[derive(Clone)]
struct AppState {
    data: JsonStore,
    index: JsonStore,
    config: Config,
    did: String,
    sqlite: Option<SqliteJsonStore>,
    postgres: Option<PostgresJsonStore>,
    semantic: SemanticRuntimeState,
    recommender: Arc<SemanticRecommender>,
    client: reqwest::Client,
    resource_sync_lock: Arc<Mutex<()>>,
    index_stats_cache: Arc<Mutex<Option<CachedIndexStats>>>,
}

#[derive(Clone, Debug)]
struct SemanticRuntimeState {
    enabled: bool,
    healthy: bool,
    backend: String,
    fallback_reason: Option<String>,
    embedding_model: String,
    embedding_version: String,
    embedding_dtype: Option<String>,
    dimension: usize,
}

impl SemanticRuntimeState {
    fn disabled(reason: impl Into<String>, config: &SemanticSearchConfig) -> Self {
        Self {
            enabled: false,
            healthy: false,
            backend: config.engine.clone(),
            fallback_reason: Some(reason.into()),
            embedding_model: config.embedding.model_name.clone(),
            embedding_version: semantic_embedding_version(config),
            embedding_dtype: config.embedding.dtype.clone(),
            dimension: config.embedding.dimension,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiscoverySearchEngine {
    PgVector,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SemanticRebuildStage {
    Both,
    Context,
    Intent,
}

impl SemanticRebuildStage {
    fn from_arg(value: &str) -> Result<Self> {
        match value {
            "both" => Ok(Self::Both),
            "context" => Ok(Self::Context),
            "intent" => Ok(Self::Intent),
            value => Err(anyhow!("unsupported_semantic_rebuild_stage:{value}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Context => "context",
            Self::Intent => "intent",
        }
    }

    fn includes_context(self) -> bool {
        matches!(self, Self::Both | Self::Context)
    }

    fn includes_intent(self) -> bool {
        matches!(self, Self::Both | Self::Intent)
    }
}

impl DiscoverySearchEngine {
    fn from_config(config: &SemanticSearchConfig) -> Result<Self> {
        match config.engine.as_str() {
            "pgvector" => Ok(Self::PgVector),
            "grail" => Err(anyhow!("grail_engine_not_implemented")),
            value => Err(anyhow!("unsupported_semantic_engine:{value}")),
        }
    }

    async fn initialize(
        &self,
        postgres: &PostgresJsonStore,
        config: &SemanticSearchConfig,
    ) -> Result<()> {
        match self {
            Self::PgVector => initialize_semantic_postgres(postgres, config).await,
        }
    }

    async fn upsert_batch(
        &self,
        state: &AppState,
        projected: &[DiscoveryProjectedPackage<'_>],
        stage: SemanticRebuildStage,
    ) -> Result<()> {
        match self {
            Self::PgVector => upsert_pgvector_semantic_index_batch(state, projected, stage).await,
        }
    }

    async fn query(
        &self,
        state: &AppState,
        query: &ResourceDiscoveryQuery,
    ) -> Result<Option<Vec<SemanticQueryHit>>> {
        match self {
            Self::PgVector => query_pgvector_semantic_index(state, query).await,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EmbeddingProviderKind {
    DeterministicLocal,
    HttpEmbedding,
}

impl EmbeddingProviderKind {
    fn from_config(config: &SemanticEmbeddingConfig) -> Result<Self> {
        match config.provider.as_str() {
            "deterministic-local" => Ok(Self::DeterministicLocal),
            "http-embedding" => Ok(Self::HttpEmbedding),
            "local" | "local-model" => Err(anyhow!("local_embedding_provider_not_wired")),
            value => Err(anyhow!("unsupported_embedding_provider:{value}")),
        }
    }
}

#[derive(Debug, Serialize)]
struct HttpEmbeddingRequest {
    model: String,
    input: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HttpEmbeddingResponse {
    model: String,
    #[serde(rename = "embeddingVersion", alias = "embedding_version")]
    embedding_version: String,
    #[serde(default)]
    dtype: Option<String>,
    dimension: usize,
    vectors: Vec<Vec<f32>>,
}

#[derive(Debug, Deserialize)]
struct HttpEmbeddingHealthResponse {
    model: String,
    #[serde(rename = "embeddingVersion", alias = "embedding_version")]
    embedding_version: Option<String>,
    #[serde(default)]
    dtype: Option<String>,
    dimension: usize,
    #[serde(default)]
    ready: bool,
}

#[derive(Clone, Debug)]
struct CachedIndexStats {
    captured_at: Instant,
    body: Value,
}

#[derive(Clone, Debug)]
struct DiscoveryPackageProjection {
    resource_type: String,
    lifecycle_state: String,
    capability_tags: Vec<String>,
    protocols: Vec<String>,
    service_endpoints: Vec<String>,
    tag_text: String,
    search_text: String,
}

struct DiscoveryProjectedPackage<'a> {
    cursor: i64,
    package: &'a ResourcePackage,
    package_json: Value,
    projection: DiscoveryPackageProjection,
}

#[derive(Clone, Debug)]
struct SearchDocument {
    resource_did: String,
    cursor: i64,
    package_version: String,
    did_document_hash: String,
    metadata_hash: String,
    package_hash: String,
    resource_type: String,
    lifecycle_state: String,
    capability_tags: Vec<String>,
    protocols: Vec<String>,
    service_endpoints: Vec<String>,
    name: String,
    description: String,
    examples: Vec<String>,
    use_cases: Vec<String>,
    tag_text: String,
    search_text: String,
    semantic_source_hash: String,
}

#[derive(Clone, Debug)]
struct IntentDocument {
    resource_did: String,
    intent_id: String,
    intent_kind: String,
    intent_text: String,
    resource_type: String,
    lifecycle_state: String,
    semantic_source_hash: String,
}

#[derive(Clone, Debug)]
struct SemanticQueryHit {
    package: ResourcePackage,
    semantic_score: f32,
    bm25_score: f32,
    tag_score: f32,
    context_score: f32,
    intent_score: f32,
    structured_score: f32,
    final_score: f32,
    matched_intent: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SemanticAliasFile {
    groups: Vec<SemanticAliasGroup>,
}

#[derive(Debug, Deserialize)]
struct SemanticAliasGroup {
    canonical: String,
    terms: Vec<String>,
}

#[derive(Clone, Debug)]
struct SemanticAliasCatalog {
    phrase_to_canonical: Vec<(String, String)>,
    canonical_to_terms: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug)]
struct SemanticQueryProjection {
    expanded_tokens: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct SemanticSearchDiagnostics {
    enabled: bool,
    healthy: bool,
    backend: String,
    embedding_model: String,
    embedding_version: String,
    embedding_dtype: Option<String>,
    dimension: usize,
    fallback_used: bool,
    fallback_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct DiscoveryQueryMetrics {
    backend: String,
    candidate_count: usize,
    returned_count: usize,
    elapsed_ms: u128,
    used_indexed_prefilter: bool,
}

#[derive(Debug, Serialize)]
struct SemanticRebuildReport {
    stage: String,
    phase: String,
    backend: String,
    semantic_enabled: bool,
    package_count: usize,
    context_indexed_count: usize,
    intent_indexed_count: usize,
    skipped_packages: usize,
    recovered_packages: usize,
    retries: usize,
    last_cursor: Option<i64>,
    safe_to_delete_old_indexes: bool,
    skipped_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct SemanticRebuildProgressRecord {
    #[serde(default)]
    stage: String,
    #[serde(default)]
    phase: String,
    #[serde(default)]
    last_cursor: Option<i64>,
    #[serde(default)]
    processed: usize,
    #[serde(default)]
    total: usize,
    #[serde(default)]
    skipped_packages: usize,
    #[serde(default)]
    retries: usize,
    #[serde(default)]
    batch_size: usize,
    #[serde(default)]
    updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct SemanticRebuildSkipRecord {
    #[serde(default)]
    stage: String,
    #[serde(rename = "resourceDid", default)]
    resource_did: String,
    #[serde(default)]
    cursor: i64,
    #[serde(default)]
    reason: String,
    #[serde(rename = "updatedAt", default)]
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct SemanticEvaluationSuite {
    suite: String,
    #[serde(default, rename = "seedPackages")]
    seed_packages: Vec<ResourcePackage>,
    #[serde(default, rename = "seedResources")]
    seed_resources: Vec<SemanticEvaluationSeedResource>,
    cases: Vec<SemanticEvaluationCase>,
}

#[derive(Clone, Debug, Deserialize)]
struct SemanticEvaluationSeedResource {
    #[serde(rename = "resourceDid")]
    resource_did: String,
    #[serde(rename = "resourceType")]
    resource_type: ResourceType,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(rename = "capabilityDescription", default)]
    capability_description: String,
    #[serde(rename = "capabilityTags", default)]
    capability_tags: Vec<String>,
    #[serde(rename = "authorizedDomains", default)]
    authorized_domains: Vec<String>,
    #[serde(default)]
    protocols: Vec<String>,
    #[serde(rename = "serviceEndpoint", default)]
    service_endpoint: Option<String>,
    #[serde(rename = "useCaseExamples", default)]
    use_case_examples: Vec<String>,
    #[serde(default)]
    examples: Vec<Value>,
    #[serde(
        default = "default_semantic_evaluation_package_version",
        rename = "packageVersion"
    )]
    package_version: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SemanticEvaluationCase {
    id: String,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    description: Option<String>,
    query: ResourceDiscoveryQuery,
    #[serde(rename = "expectedDids")]
    expected_dids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SemanticEvaluationReport {
    suite: String,
    case_count: usize,
    seed_package_count: usize,
    recall_at_5: f32,
    recall_at_10: f32,
    mrr_at_10: f32,
    cases: Vec<SemanticEvaluationCaseReport>,
}

#[derive(Debug, Serialize)]
struct SemanticEvaluationCaseReport {
    id: String,
    language: Option<String>,
    description: Option<String>,
    passed: bool,
    reciprocal_rank: f32,
    returned_dids: Vec<String>,
    expected_dids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

fn crypto_suite_from_algorithm(value: &str) -> Result<CryptoSuite> {
    match value {
        "Ed25519" => Ok(CryptoSuite::Ed25519Sha256),
        "SM2" => Ok(CryptoSuite::Sm2Sm3),
        other => Err(anyhow::anyhow!("unsupported_algorithm: {other}")),
    }
}

impl ApiError {
    fn internal(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<Json<T>, ApiError>;

fn parse_semantic_cli_args(args: &[String]) -> Result<(String, SemanticRebuildStage, bool)> {
    let mut config_path = "services/discovery-node/config.example.toml".to_owned();
    let mut stage = SemanticRebuildStage::Both;
    let mut reset = false;
    let mut index = 1usize;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--reset" => {
                reset = true;
                index += 1;
            }
            "--stage" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| anyhow!("missing_semantic_rebuild_stage"))?;
                stage = SemanticRebuildStage::from_arg(value)?;
                index += 2;
            }
            value if value.starts_with("--stage=") => {
                let value = value.split_once('=').map(|(_, rhs)| rhs).unwrap_or("");
                stage = SemanticRebuildStage::from_arg(value)?;
                index += 1;
            }
            value if value.starts_with("--") => {
                index += 1;
            }
            value => {
                config_path = value.to_owned();
                index += 1;
            }
        }
    }
    Ok((config_path, stage, reset))
}

fn semantic_rebuild_progress_key(stage: SemanticRebuildStage) -> String {
    format!("semantic_rebuild_progress:{}", stage.as_str())
}

fn semantic_rebuild_skip_prefix(stage: Option<SemanticRebuildStage>) -> String {
    match stage {
        Some(stage) => format!("semantic_rebuild_skip:{}:", stage.as_str()),
        None => "semantic_rebuild_skip:".to_owned(),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args
        .first()
        .is_some_and(|value| value == "semantic-rebuild")
    {
        let (config_path, stage, reset) = parse_semantic_cli_args(&args)?;
        let state = build_app_state(load_config(config_path)?).await?;
        let report = rebuild_semantic_indexes(&state, reset, stage).await?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if args
        .first()
        .is_some_and(|value| value == "semantic-backfill-skipped")
    {
        let (config_path, stage, _) = parse_semantic_cli_args(&args)?;
        let state = build_app_state(load_config(config_path)?).await?;
        let report = backfill_skipped_semantic_indexes(&state, stage).await?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if args
        .first()
        .is_some_and(|value| value == "semantic-evaluate")
    {
        let config_path = args
            .get(1)
            .cloned()
            .unwrap_or_else(|| "services/discovery-node/config.example.toml".to_owned());
        let suite_path = args.get(2).cloned().unwrap_or_else(|| {
            "services/discovery-node/evaluation/real-resource-smoke.v1.json".to_owned()
        });
        let state = build_app_state(load_config(config_path)?).await?;
        let report = evaluate_semantic_discovery(&state, &PathBuf::from(suite_path)).await?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if args
        .first()
        .is_some_and(|value| value == "semantic-rebuild-evaluate")
    {
        let config_path = args
            .get(1)
            .cloned()
            .unwrap_or_else(|| "services/discovery-node/config.example.toml".to_owned());
        let suite_path = args.get(2).cloned().unwrap_or_else(|| {
            "services/discovery-node/evaluation/real-resource-smoke.v1.json".to_owned()
        });
        let state = build_app_state(load_config(config_path)?).await?;
        let suite_path = PathBuf::from(suite_path);
        let seed_count = seed_semantic_evaluation_packages(&state, &suite_path).await?;
        let rebuild = rebuild_semantic_indexes(&state, true, SemanticRebuildStage::Both).await?;
        let evaluation = evaluate_semantic_discovery(&state, &suite_path).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "seedPackageCount": seed_count,
                "rebuild": rebuild,
                "evaluation": evaluation
            }))?
        );
        return Ok(());
    }
    let config_path = args
        .first()
        .cloned()
        .unwrap_or_else(|| "services/discovery-node/config.example.toml".to_owned());
    let config = load_config(config_path)?;
    let state = build_app_state(config.clone()).await?;

    let app = Router::new()
        .route("/health", get(health))
        .route("/discovery/did", get(discovery_did_document))
        .route("/routes/{did}", get(route_lookup))
        .route("/discovery/status", get(api_status))
        .route("/discovery/root-authorization", get(api_root_authorization))
        .route("/discovery/authorized-domains", get(api_authorized_domains))
        .route(
            "/discovery/resources/sync-authorized",
            post(sync_resources_from_authorized_summary),
        )
        .route("/discovery/sync/history", get(api_sync_history))
        .route("/discovery/index/stats", get(api_index_stats))
        .route("/discovery/index/resources", get(api_index_resources))
        .route(
            "/discovery/index/resources/visibility",
            post(api_index_resource_visibility),
        )
        .route(
            "/discovery/index/resources/{did}",
            get(api_index_resource_detail),
        )
        .route("/discovery/resources/query", post(resource_query))
        .route("/discovery/query/suggestions", post(api_query_suggestions))
        .route("/discovery/query/explain", post(api_query_explain))
        .route("/discovery/rejected-packages", get(api_rejected_packages))
        .route(
            "/discovery/rejected-packages/backfill",
            post(api_backfill_rejected_packages),
        )
        .route(
            "/discovery/rejected-packages/resolved/audit",
            post(api_audit_resolved_rejected_packages),
        )
        .route("/discovery/capability-tree", get(api_capability_tree))
        .layer(build_cors_layer(&config.cors)?)
        .with_state(state.clone());

    if (state.sqlite.is_some() || state.postgres.is_some()) && state.config.debug.export_snapshots {
        let debug_state = state.clone();
        tokio::spawn(async move {
            discovery_debug_export_loop(debug_state).await;
        });
    }

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    println!("discovery-node listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn build_app_state(config: Config) -> Result<AppState> {
    let did_doc: DidDocument = JsonStore::new(&config.paths.data_dir).read("did-document.json")?;
    let key: DevKeyFile = JsonStore::new(".").read(config.paths.keys_dir.join("keypair.json"))?;
    let crypto_suite = crypto_suite_from_algorithm(&key.algorithm)?;
    let _signing_key = signing_key_from_bytes(
        crypto_suite,
        &URL_SAFE_NO_PAD.decode(key.private_key_jwk.d)?,
    )?;
    let mut semantic = SemanticRuntimeState::disabled("semantic_disabled", &config.semantic_search);
    let (sqlite, postgres) = match config.paths.database_url.as_deref() {
        Some(url) if !url.is_empty() => {
            let database = DatabaseConfig::parse(url)?;
            match database.backend() {
                DatabaseBackend::Sqlite => {
                    let sqlite = SqliteJsonStore::connect(url).await?;
                    initialize_discovery_sqlite(&sqlite).await?;
                    if config.semantic_search.enabled {
                        semantic = SemanticRuntimeState::disabled(
                            "semantic_search_requires_postgres",
                            &config.semantic_search,
                        );
                    }
                    (Some(sqlite), None)
                }
                DatabaseBackend::Postgres => {
                    let postgres = PostgresJsonStore::connect(url).await?;
                    initialize_discovery_postgres(&postgres).await?;
                    semantic = initialize_semantic_runtime(&config, Some(&postgres)).await;
                    (None, Some(postgres))
                }
            }
        }
        _ => {
            if config.semantic_search.enabled {
                semantic = SemanticRuntimeState::disabled(
                    "semantic_search_requires_postgres",
                    &config.semantic_search,
                );
            }
            (None, None)
        }
    };
    let state = AppState {
        data: JsonStore::new(&config.paths.data_dir),
        index: JsonStore::new(&config.paths.index_dir),
        config: config.clone(),
        did: did_doc.id,
        sqlite,
        postgres,
        semantic,
        recommender: Arc::new(SemanticRecommender::new()?),
        client: reqwest::Client::new(),
        resource_sync_lock: Arc::new(Mutex::new(())),
        index_stats_cache: Arc::new(Mutex::new(None)),
    };
    Ok(state)
}

fn load_config(path: String) -> Result<Config> {
    let path = PathBuf::from(path);
    let mut config: Config = toml::from_str(&std::fs::read_to_string(&path)?)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.paths.data_dir = resolve_relative(base, &config.paths.data_dir);
    config.paths.index_dir = resolve_relative(base, &config.paths.index_dir);
    config.paths.keys_dir = resolve_relative(base, &config.paths.keys_dir);
    if let Some(database_url) = config.paths.database_url.as_mut() {
        *database_url = resolve_database_url(base, database_url);
    }
    Ok(config)
}

async fn initialize_discovery_sqlite(sqlite: &SqliteJsonStore) -> Result<()> {
    sqlite
        .execute_batch(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {DISCOVERY_SYNC_STATE_TABLE} (
                state_key TEXT PRIMARY KEY,
                state_value TEXT NOT NULL,
                sync_key TEXT UNIQUE,
                sync_value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {DISCOVERY_PACKAGE_TABLE} (
                resource_did TEXT PRIMARY KEY,
                cursor INTEGER NOT NULL,
                version TEXT NOT NULL,
                resource_type TEXT NOT NULL DEFAULT '',
                lifecycle_state TEXT NOT NULL DEFAULT '',
                capability_tags TEXT NOT NULL DEFAULT '[]',
                protocols TEXT NOT NULL DEFAULT '[]',
                service_endpoints TEXT NOT NULL DEFAULT '[]',
                tag_text TEXT NOT NULL DEFAULT '',
                search_text TEXT NOT NULL DEFAULT '',
                package_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {DISCOVERY_REJECTED_TABLE} (
                reject_key TEXT PRIMARY KEY,
                item_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#
        ))
        .await?;
    sqlite_add_column_if_missing(
        sqlite,
        DISCOVERY_PACKAGE_TABLE,
        "resource_type",
        "resource_type TEXT NOT NULL DEFAULT ''",
    )
    .await?;
    sqlite_add_column_if_missing(
        sqlite,
        DISCOVERY_PACKAGE_TABLE,
        "lifecycle_state",
        "lifecycle_state TEXT NOT NULL DEFAULT ''",
    )
    .await?;
    sqlite_add_column_if_missing(
        sqlite,
        DISCOVERY_PACKAGE_TABLE,
        "capability_tags",
        "capability_tags TEXT NOT NULL DEFAULT '[]'",
    )
    .await?;
    sqlite_add_column_if_missing(
        sqlite,
        DISCOVERY_PACKAGE_TABLE,
        "protocols",
        "protocols TEXT NOT NULL DEFAULT '[]'",
    )
    .await?;
    sqlite_add_column_if_missing(
        sqlite,
        DISCOVERY_PACKAGE_TABLE,
        "service_endpoints",
        "service_endpoints TEXT NOT NULL DEFAULT '[]'",
    )
    .await?;
    sqlite_add_column_if_missing(
        sqlite,
        DISCOVERY_PACKAGE_TABLE,
        "tag_text",
        "tag_text TEXT NOT NULL DEFAULT ''",
    )
    .await?;
    sqlite_add_column_if_missing(
        sqlite,
        DISCOVERY_PACKAGE_TABLE,
        "search_text",
        "search_text TEXT NOT NULL DEFAULT ''",
    )
    .await?;
    sqlite_add_column_if_missing(
        sqlite,
        DISCOVERY_SYNC_STATE_TABLE,
        "state_key",
        "state_key TEXT",
    )
    .await?;
    sqlite_add_column_if_missing(
        sqlite,
        DISCOVERY_SYNC_STATE_TABLE,
        "state_value",
        "state_value TEXT",
    )
    .await?;
    sqlite_add_column_if_missing(
        sqlite,
        DISCOVERY_SYNC_STATE_TABLE,
        "sync_key",
        "sync_key TEXT",
    )
    .await?;
    sqlite_add_column_if_missing(
        sqlite,
        DISCOVERY_SYNC_STATE_TABLE,
        "sync_value",
        "sync_value TEXT",
    )
    .await?;
    sqlite
        .execute_batch(&format!(
            r#"
            UPDATE {DISCOVERY_SYNC_STATE_TABLE}
            SET state_key = COALESCE(state_key, sync_key),
                state_value = COALESCE(state_value, sync_value),
                sync_key = COALESCE(sync_key, state_key),
                sync_value = COALESCE(sync_value, state_value)
            WHERE state_key IS NULL
               OR state_value IS NULL
               OR sync_key IS NULL
               OR sync_value IS NULL;
            "#
        ))
        .await?;
    Ok(())
}

async fn sqlite_add_column_if_missing(
    sqlite: &SqliteJsonStore,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let escaped_table = table.replace('\'', "''");
    let rows = sqlx::query(&format!("PRAGMA table_info('{escaped_table}')"))
        .fetch_all(sqlite.pool())
        .await?;
    let exists = rows
        .iter()
        .any(|row| row.get::<String, _>("name") == column);
    if !exists {
        sqlx::query(&format!("ALTER TABLE {table} ADD COLUMN {definition}"))
            .execute(sqlite.pool())
            .await?;
    }
    Ok(())
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn resolve_database_url(base: &Path, url: &str) -> String {
    let Some(raw_path) = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
    else {
        return url.to_owned();
    };
    let resolved = resolve_relative(base, Path::new(raw_path));
    format!("sqlite:{}", resolved.display())
}

async fn initialize_discovery_postgres(postgres: &PostgresJsonStore) -> Result<()> {
    postgres
        .execute_batch(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {DISCOVERY_SYNC_STATE_TABLE} (
                state_key TEXT PRIMARY KEY,
                state_value JSONB NOT NULL,
                sync_key TEXT UNIQUE,
                sync_value JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {DISCOVERY_PACKAGE_TABLE} (
                resource_did TEXT PRIMARY KEY,
                cursor BIGINT NOT NULL,
                version TEXT NOT NULL,
                resource_type TEXT NOT NULL DEFAULT '',
                lifecycle_state TEXT NOT NULL DEFAULT '',
                capability_tags TEXT[] NOT NULL DEFAULT '{{}}',
                protocols TEXT[] NOT NULL DEFAULT '{{}}',
                service_endpoints TEXT[] NOT NULL DEFAULT '{{}}',
                tag_text TEXT NOT NULL DEFAULT '',
                search_text TEXT NOT NULL DEFAULT '',
                package_json JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            );
            ALTER TABLE {DISCOVERY_PACKAGE_TABLE}
                ADD COLUMN IF NOT EXISTS resource_type TEXT NOT NULL DEFAULT '';
            ALTER TABLE {DISCOVERY_PACKAGE_TABLE}
                ADD COLUMN IF NOT EXISTS lifecycle_state TEXT NOT NULL DEFAULT '';
            ALTER TABLE {DISCOVERY_PACKAGE_TABLE}
                ADD COLUMN IF NOT EXISTS capability_tags TEXT[] NOT NULL DEFAULT '{{}}';
            ALTER TABLE {DISCOVERY_PACKAGE_TABLE}
                ADD COLUMN IF NOT EXISTS protocols TEXT[] NOT NULL DEFAULT '{{}}';
            ALTER TABLE {DISCOVERY_PACKAGE_TABLE}
                ADD COLUMN IF NOT EXISTS service_endpoints TEXT[] NOT NULL DEFAULT '{{}}';
            ALTER TABLE {DISCOVERY_PACKAGE_TABLE}
                ADD COLUMN IF NOT EXISTS tag_text TEXT NOT NULL DEFAULT '';
            ALTER TABLE {DISCOVERY_PACKAGE_TABLE}
                ADD COLUMN IF NOT EXISTS search_text TEXT NOT NULL DEFAULT '';
            CREATE TABLE IF NOT EXISTS {DISCOVERY_REJECTED_TABLE} (
                reject_key TEXT PRIMARY KEY,
                item_json JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_discovery_packages_cursor
            ON {DISCOVERY_PACKAGE_TABLE}(cursor DESC);
            CREATE INDEX IF NOT EXISTS idx_discovery_packages_updated
            ON {DISCOVERY_PACKAGE_TABLE}(updated_at, resource_did);
            CREATE INDEX IF NOT EXISTS idx_discovery_packages_type_state
            ON {DISCOVERY_PACKAGE_TABLE}(resource_type, lifecycle_state);
            CREATE INDEX IF NOT EXISTS idx_discovery_packages_capability_tags
            ON {DISCOVERY_PACKAGE_TABLE} USING GIN(capability_tags);
            CREATE INDEX IF NOT EXISTS idx_discovery_packages_protocols
            ON {DISCOVERY_PACKAGE_TABLE} USING GIN(protocols);
            CREATE INDEX IF NOT EXISTS idx_discovery_packages_tag_text
            ON {DISCOVERY_PACKAGE_TABLE} USING GIN(to_tsvector('simple', tag_text));
            CREATE INDEX IF NOT EXISTS idx_discovery_packages_search_text
            ON {DISCOVERY_PACKAGE_TABLE} USING GIN(to_tsvector('simple', search_text));
            CREATE INDEX IF NOT EXISTS idx_discovery_rejected_updated
            ON {DISCOVERY_REJECTED_TABLE}(updated_at, reject_key);
            "#
        ))
        .await?;
    postgres
        .execute_batch(&format!(
            r#"
            ALTER TABLE {DISCOVERY_SYNC_STATE_TABLE} ADD COLUMN IF NOT EXISTS state_key TEXT;
            ALTER TABLE {DISCOVERY_SYNC_STATE_TABLE} ADD COLUMN IF NOT EXISTS state_value JSONB;
            ALTER TABLE {DISCOVERY_SYNC_STATE_TABLE} ADD COLUMN IF NOT EXISTS sync_key TEXT;
            ALTER TABLE {DISCOVERY_SYNC_STATE_TABLE} ADD COLUMN IF NOT EXISTS sync_value JSONB;
            UPDATE {DISCOVERY_SYNC_STATE_TABLE}
            SET state_key = COALESCE(state_key, sync_key),
                state_value = COALESCE(state_value, sync_value),
                sync_key = COALESCE(sync_key, state_key),
                sync_value = COALESCE(sync_value, state_value)
            WHERE state_key IS NULL
               OR state_value IS NULL
               OR sync_key IS NULL
               OR sync_value IS NULL;
            "#
        ))
        .await?;
    Ok(())
}

async fn initialize_semantic_runtime(
    config: &Config,
    postgres: Option<&PostgresJsonStore>,
) -> SemanticRuntimeState {
    if !config.semantic_search.enabled {
        return SemanticRuntimeState::disabled("semantic_disabled", &config.semantic_search);
    }
    let engine = match DiscoverySearchEngine::from_config(&config.semantic_search) {
        Ok(engine) => engine,
        Err(err) => {
            return SemanticRuntimeState::disabled(err.to_string(), &config.semantic_search);
        }
    };
    if let Err(err) =
        validate_embedding_provider(&config.semantic_search, &reqwest::Client::new()).await
    {
        return SemanticRuntimeState::disabled(err.to_string(), &config.semantic_search);
    }
    let Some(postgres) = postgres else {
        return SemanticRuntimeState::disabled(
            "semantic_search_requires_postgres",
            &config.semantic_search,
        );
    };
    match engine.initialize(postgres, &config.semantic_search).await {
        Ok(()) => SemanticRuntimeState {
            enabled: true,
            healthy: true,
            backend: config.semantic_search.engine.clone(),
            fallback_reason: None,
            embedding_model: config.semantic_search.embedding.model_name.clone(),
            embedding_version: semantic_embedding_version(&config.semantic_search),
            embedding_dtype: config.semantic_search.embedding.dtype.clone(),
            dimension: config.semantic_search.embedding.dimension,
        },
        Err(err) => {
            eprintln!("semantic search disabled: {err}");
            SemanticRuntimeState::disabled(
                format!("semantic_initialization_failed:{err}"),
                &config.semantic_search,
            )
        }
    }
}

async fn initialize_semantic_postgres(
    postgres: &PostgresJsonStore,
    config: &SemanticSearchConfig,
) -> Result<()> {
    let dimension = config.embedding.dimension;
    if dimension == 0 || dimension > 4096 {
        return Err(anyhow!("invalid_semantic_embedding_dimension"));
    }
    postgres
        .execute_batch("CREATE EXTENSION IF NOT EXISTS vector;")
        .await?;
    postgres
        .execute_batch(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {DISCOVERY_SEMANTIC_INDEX_TABLE} (
                resource_did TEXT PRIMARY KEY,
                cursor BIGINT NOT NULL,
                package_version TEXT NOT NULL,
                did_document_hash TEXT NOT NULL,
                metadata_hash TEXT NOT NULL,
                package_hash TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                capability_tags TEXT[] NOT NULL DEFAULT '{{}}',
                protocols TEXT[] NOT NULL DEFAULT '{{}}',
                service_endpoints TEXT[] NOT NULL DEFAULT '{{}}',
                name TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                examples JSONB NOT NULL DEFAULT '[]'::jsonb,
                use_cases JSONB NOT NULL DEFAULT '[]'::jsonb,
                tag_text TEXT NOT NULL DEFAULT '',
                search_text TEXT NOT NULL DEFAULT '',
                semantic_source_hash TEXT NOT NULL,
                embedding VECTOR({dimension}),
                embedding_model TEXT NOT NULL,
                embedding_version TEXT NOT NULL DEFAULT '1',
                updated_at TIMESTAMPTZ NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_discovery_semantic_cursor
            ON {DISCOVERY_SEMANTIC_INDEX_TABLE}(cursor DESC);
            CREATE INDEX IF NOT EXISTS idx_discovery_semantic_type_state
            ON {DISCOVERY_SEMANTIC_INDEX_TABLE}(resource_type, lifecycle_state);
            CREATE INDEX IF NOT EXISTS idx_discovery_semantic_tags
            ON {DISCOVERY_SEMANTIC_INDEX_TABLE} USING GIN(capability_tags);
            CREATE INDEX IF NOT EXISTS idx_discovery_semantic_protocols
            ON {DISCOVERY_SEMANTIC_INDEX_TABLE} USING GIN(protocols);
            CREATE INDEX IF NOT EXISTS idx_discovery_semantic_tag_text
            ON {DISCOVERY_SEMANTIC_INDEX_TABLE} USING GIN(to_tsvector('simple', tag_text));
            CREATE INDEX IF NOT EXISTS idx_discovery_semantic_search_text
            ON {DISCOVERY_SEMANTIC_INDEX_TABLE} USING GIN(to_tsvector('simple', search_text));
            CREATE INDEX IF NOT EXISTS idx_discovery_semantic_embedding
            ON {DISCOVERY_SEMANTIC_INDEX_TABLE}
            USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 100);

            CREATE TABLE IF NOT EXISTS {DISCOVERY_INTENT_INDEX_TABLE} (
                resource_did TEXT NOT NULL,
                intent_id TEXT NOT NULL,
                intent_kind TEXT NOT NULL,
                intent_text TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                semantic_source_hash TEXT NOT NULL,
                embedding VECTOR({dimension}),
                embedding_model TEXT NOT NULL,
                embedding_version TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                PRIMARY KEY(resource_did, intent_id, embedding_model, embedding_version)
            );
            CREATE INDEX IF NOT EXISTS idx_discovery_intent_resource
            ON {DISCOVERY_INTENT_INDEX_TABLE}(resource_did);
            CREATE INDEX IF NOT EXISTS idx_discovery_intent_type_state
            ON {DISCOVERY_INTENT_INDEX_TABLE}(resource_type, lifecycle_state);
            CREATE INDEX IF NOT EXISTS idx_discovery_intent_embedding
            ON {DISCOVERY_INTENT_INDEX_TABLE}
            USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 100);
            "#,
        ))
        .await?;
    Ok(())
}

fn semantic_embedding_version(config: &SemanticSearchConfig) -> String {
    config.embedding.model_version.clone().unwrap_or_else(|| {
        format!(
            "1:{}:{}",
            config.embedding.provider, config.embedding.dimension
        )
    })
}

fn semantic_search_available(state: &AppState) -> bool {
    state.config.semantic_search.enabled
        && state.semantic.enabled
        && state.semantic.healthy
        && state.postgres.is_some()
}

fn semantic_diagnostics(
    state: &AppState,
    fallback_used: bool,
    fallback_reason: Option<String>,
) -> SemanticSearchDiagnostics {
    SemanticSearchDiagnostics {
        enabled: state.semantic.enabled,
        healthy: state.semantic.healthy,
        backend: state.semantic.backend.clone(),
        embedding_model: state.semantic.embedding_model.clone(),
        embedding_version: state.semantic.embedding_version.clone(),
        embedding_dtype: state.semantic.embedding_dtype.clone(),
        dimension: state.semantic.dimension,
        fallback_used,
        fallback_reason: fallback_reason.or_else(|| state.semantic.fallback_reason.clone()),
    }
}

fn semantic_status_json(
    state: &AppState,
    fallback_used: bool,
    fallback_reason: Option<String>,
) -> Value {
    let diagnostics = semantic_diagnostics(state, fallback_used, fallback_reason);
    json!({
        "enabled": diagnostics.enabled,
        "healthy": diagnostics.healthy,
        "backend": diagnostics.backend,
        "fallback": state.config.semantic_search.fallback,
        "defaultMode": state.config.semantic_search.default_mode,
        "explainEnabled": state.config.semantic_search.explain_enabled,
        "embeddingProvider": state.config.semantic_search.embedding.provider,
        "embeddingModel": diagnostics.embedding_model,
        "embeddingVersion": diagnostics.embedding_version,
        "embeddingDtype": diagnostics.embedding_dtype,
        "modelPath": state.config.semantic_search.embedding.model_path,
        "dimension": diagnostics.dimension,
        "timeoutMs": state.config.semantic_search.embedding.timeout_ms,
        "batchSize": state.config.semantic_search.embedding.batch_size,
        "filters": {
            "resourceType": state.config.semantic_search.filters.resource_type,
            "capabilityTags": state.config.semantic_search.filters.capability_tags,
            "protocol": state.config.semantic_search.filters.protocol
        },
        "fallbackUsed": diagnostics.fallback_used,
        "fallbackReason": diagnostics.fallback_reason,
    })
}

fn normalize_semantic_text(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_owned()
}

fn push_unique_text(values: &mut Vec<String>, value: impl AsRef<str>) {
    let normalized = normalize_semantic_text(value.as_ref());
    if !normalized.is_empty() && !values.iter().any(|existing| existing == &normalized) {
        values.push(normalized);
    }
}

fn json_example_to_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            let normalized = normalize_semantic_text(text);
            (!normalized.is_empty()).then_some(normalized)
        }
        Value::Object(_) | Value::Array(_) => {
            let text = value.to_string();
            let normalized = normalize_semantic_text(&text);
            (!normalized.is_empty()).then_some(normalized.chars().take(1_000).collect())
        }
        _ => None,
    }
}

fn search_document_from_package(
    cursor: i64,
    package: &ResourcePackage,
    projection: &DiscoveryPackageProjection,
) -> SearchDocument {
    let mut descriptions = Vec::new();
    push_unique_text(&mut descriptions, &package.metadata.description);
    let mut examples = Vec::new();
    let mut use_cases = Vec::new();
    let mut tags = package.metadata.capability_tags.clone();

    if let Some(metadata) = &package.did_document.oan_metadata {
        tags.extend(metadata.capability_tags.iter().cloned());
        if let Some(description) = &metadata.resource_description {
            if let Some(name) = &description.name {
                push_unique_text(&mut descriptions, name);
            }
            if let Some(text) = &description.description {
                push_unique_text(&mut descriptions, text);
            }
            if let Some(text) = &description.capability_description {
                push_unique_text(&mut descriptions, text);
            }
            tags.extend(description.capability_tags.iter().cloned());
            for item in description.use_case_examples.iter().take(20) {
                push_unique_text(&mut use_cases, item);
            }
            for value in description.examples.iter().take(20) {
                if let Some(text) = json_example_to_text(value) {
                    push_unique_text(&mut examples, text);
                }
            }
        }
        if let Some(description) = &metadata.agent_description {
            push_unique_text(&mut descriptions, &description.capability_description);
            tags.extend(description.capability_tags.iter().cloned());
            for item in description.use_case_examples.iter().take(20) {
                push_unique_text(&mut use_cases, item);
            }
        }
    }

    tags.sort();
    tags.dedup();
    let description = descriptions.join("\n");
    let name = package
        .did_document
        .oan_metadata
        .as_ref()
        .and_then(|metadata| metadata.resource_description.as_ref())
        .and_then(|description| description.name.clone())
        .unwrap_or_else(|| package.metadata.name.clone());
    let embedding_text = semantic_embedding_text(&SemanticEmbeddingTextInput {
        name: &name,
        resource_type: &projection.resource_type,
        description: &description,
        capability_tags: &tags,
        protocols: &projection.protocols,
        service_endpoints: &projection.service_endpoints,
        examples: &examples,
        use_cases: &use_cases,
    });
    SearchDocument {
        resource_did: package.resource_did.clone(),
        cursor,
        package_version: package.package_version.clone(),
        did_document_hash: package.did_document_hash.clone(),
        metadata_hash: package.metadata_hash.clone(),
        package_hash: package.package_hash.clone(),
        resource_type: projection.resource_type.clone(),
        lifecycle_state: projection.lifecycle_state.clone(),
        capability_tags: tags,
        protocols: projection.protocols.clone(),
        service_endpoints: projection.service_endpoints.clone(),
        name,
        description,
        examples,
        use_cases,
        tag_text: projection.tag_text.clone(),
        search_text: projection.search_text.clone(),
        semantic_source_hash: format!("sha256:{}", sha256_hex(embedding_text.as_bytes())),
    }
}

fn semantic_search_text(values: &[String]) -> String {
    let raw_text = values
        .iter()
        .map(|value| normalize_semantic_text(value))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let tokens = semantic_tokens(&raw_text);
    normalize_semantic_text(&format!("{} {}", raw_text.to_lowercase(), tokens.join(" ")))
}

struct SemanticEmbeddingTextInput<'a> {
    name: &'a str,
    resource_type: &'a str,
    description: &'a str,
    capability_tags: &'a [String],
    protocols: &'a [String],
    service_endpoints: &'a [String],
    examples: &'a [String],
    use_cases: &'a [String],
}

fn semantic_embedding_text(input: &SemanticEmbeddingTextInput<'_>) -> String {
    let mut text = String::new();
    text.push_str("Name:\n");
    text.push_str(input.name);
    text.push_str("\n\nResource type:\n");
    text.push_str(input.resource_type);
    text.push_str("\n\nDescription:\n");
    text.push_str(input.description);
    text.push_str("\n\nCapability tags:\n");
    text.push_str(&input.capability_tags.join(", "));
    text.push_str("\n\nProtocols:\n");
    text.push_str(&input.protocols.join(", "));
    text.push_str("\n\nServices:\n");
    text.push_str(&input.service_endpoints.join("\n"));
    text.push_str("\n\nExamples:\n");
    text.push_str(&input.examples.join("\n"));
    text.push_str("\n\nUse cases:\n");
    text.push_str(&input.use_cases.join("\n"));
    text.push_str("\n\nTag view:\n");
    for tag in input.capability_tags {
        text.push_str("capability ");
        text.push_str(tag);
        text.push('\n');
    }
    text.push_str("\nContext view:\n");
    text.push_str(input.name);
    text.push_str(" provides ");
    text.push_str(input.resource_type);
    text.push_str(" capabilities for ");
    text.push_str(input.description);
    text.push_str("\n\nIntent view:\n");
    for use_case in input.use_cases {
        text.push_str("User wants to ");
        text.push_str(use_case);
        text.push('\n');
    }
    for example in input.examples {
        text.push_str("Example request: ");
        text.push_str(example);
        text.push('\n');
    }
    text.chars().take(8_000).collect()
}

fn semantic_document_text(doc: &SearchDocument) -> String {
    semantic_embedding_text(&SemanticEmbeddingTextInput {
        name: &doc.name,
        resource_type: &doc.resource_type,
        description: &doc.description,
        capability_tags: &doc.capability_tags,
        protocols: &doc.protocols,
        service_endpoints: &doc.service_endpoints,
        examples: &doc.examples,
        use_cases: &doc.use_cases,
    })
}

fn semantic_alias_catalog() -> &'static SemanticAliasCatalog {
    static CATALOG: OnceLock<SemanticAliasCatalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let alias_file: SemanticAliasFile =
            serde_json::from_str(SEMANTIC_ALIASES_JSON).expect("semantic_aliases.v1.json is valid");
        let mut phrase_to_canonical = Vec::new();
        let mut canonical_to_terms = BTreeMap::new();
        for group in alias_file.groups {
            let canonical = normalize_semantic_token(&group.canonical);
            let mut terms = Vec::new();
            push_unique_text(&mut terms, &canonical);
            for term in group.terms {
                push_unique_text(&mut terms, term);
            }
            for term in &terms {
                phrase_to_canonical.push((term.to_lowercase(), canonical.clone()));
            }
            canonical_to_terms.insert(canonical, terms);
        }
        phrase_to_canonical.sort_by(|a, b| b.0.chars().count().cmp(&a.0.chars().count()));
        SemanticAliasCatalog {
            phrase_to_canonical,
            canonical_to_terms,
        }
    })
}

fn semantic_jieba() -> &'static Jieba {
    static JIEBA: OnceLock<Jieba> = OnceLock::new();
    JIEBA.get_or_init(Jieba::new)
}

fn normalize_semantic_token(token: &str) -> String {
    token.trim().to_lowercase()
}

fn technical_semantic_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| {
        !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | ':' | '_' | '-' | '/' | '#'))
    })
    .filter_map(|token| {
        let token = normalize_semantic_token(token)
            .trim_matches(|ch: char| matches!(ch, '.' | ':' | '_' | '-' | '/' | '#'))
            .to_owned();
        (token.len() >= 2).then_some(token)
    })
    .collect()
}

fn expand_semantic_aliases(tokens: &[String], raw_text: &str) -> Vec<String> {
    let catalog = semantic_alias_catalog();
    let lower_text = raw_text.to_lowercase();
    let mut expanded = tokens.to_vec();
    let mut seen = expanded.iter().cloned().collect::<HashSet<_>>();
    for (phrase, canonical) in &catalog.phrase_to_canonical {
        if lower_text.contains(phrase) || tokens.iter().any(|token| token == phrase) {
            if seen.insert(canonical.clone()) {
                expanded.push(canonical.clone());
            }
            if let Some(terms) = catalog.canonical_to_terms.get(canonical) {
                for term in terms.iter().take(8) {
                    for token in semantic_tokens_without_alias_expansion(term) {
                        if seen.insert(token.clone()) {
                            expanded.push(token);
                        }
                    }
                }
            }
        }
    }
    expanded
}

fn semantic_tokens_without_alias_expansion(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut seen = HashSet::new();
    for token in technical_semantic_tokens(text) {
        if seen.insert(token.clone()) {
            tokens.push(token);
        }
    }
    for token in semantic_jieba().cut(text, false) {
        let normalized = normalize_semantic_token(token);
        if normalized.chars().count() >= 2 && seen.insert(normalized.clone()) {
            tokens.push(normalized);
        }
    }
    tokens
}

fn deterministic_embedding(text: &str, dimension: usize) -> Vec<f32> {
    let dimension = dimension.max(1);
    let mut vector = vec![0.0_f32; dimension];
    let mut seen = HashSet::new();
    for token in semantic_tokens(text) {
        if !seen.insert(token.clone()) {
            continue;
        }
        let hash = sha256_hex(token.as_bytes());
        let index = usize::from_str_radix(&hash[0..8], 16).unwrap_or(0) % dimension;
        vector[index] += 1.0;
    }
    normalize_vector(vector)
}

async fn validate_embedding_provider(
    config: &SemanticSearchConfig,
    client: &reqwest::Client,
) -> Result<()> {
    match EmbeddingProviderKind::from_config(&config.embedding)? {
        EmbeddingProviderKind::DeterministicLocal => {
            let probe = deterministic_embedding("oan semantic probe", config.embedding.dimension);
            validate_embedding_vector(&probe, config.embedding.dimension)?;
            Ok(())
        }
        EmbeddingProviderKind::HttpEmbedding => {
            let health_endpoint = config
                .embedding
                .health_endpoint
                .as_deref()
                .ok_or_else(|| anyhow!("http_embedding_health_endpoint_required"))?;
            let health = client
                .get(health_endpoint)
                .timeout(StdDuration::from_millis(config.embedding.timeout_ms))
                .send()
                .await?
                .error_for_status()?
                .json::<HttpEmbeddingHealthResponse>()
                .await?;
            if !health.ready {
                return Err(anyhow!("http_embedding_provider_not_ready"));
            }
            if health.model != config.embedding.model_name {
                return Err(anyhow!("http_embedding_model_mismatch:{}", health.model));
            }
            if health.dimension != config.embedding.dimension {
                return Err(anyhow!(
                    "http_embedding_dimension_mismatch:{}",
                    health.dimension
                ));
            }
            if config.embedding.strict_model_version {
                let expected = config
                    .embedding
                    .model_version
                    .as_deref()
                    .ok_or_else(|| anyhow!("strict_model_version_requires_modelVersion"))?;
                let actual = health
                    .embedding_version
                    .as_deref()
                    .ok_or_else(|| anyhow!("http_embedding_version_missing"))?;
                if actual != expected {
                    return Err(anyhow!("http_embedding_version_mismatch:{actual}"));
                }
            }
            if let Some(expected) = config.embedding.dtype.as_deref() {
                let actual = health
                    .dtype
                    .as_deref()
                    .ok_or_else(|| anyhow!("http_embedding_dtype_missing"))?;
                if actual != expected {
                    return Err(anyhow!("http_embedding_dtype_mismatch:{actual}"));
                }
            }
            let probe = embed_semantic_text(config, client, "oan semantic probe").await?;
            validate_embedding_vector(&probe, config.embedding.dimension)
        }
    }
}

async fn embed_semantic_text(
    config: &SemanticSearchConfig,
    client: &reqwest::Client,
    text: &str,
) -> Result<Vec<f32>> {
    let text = bounded_embedding_text(text, config.embedding.max_input_chars);
    match EmbeddingProviderKind::from_config(&config.embedding)? {
        EmbeddingProviderKind::DeterministicLocal => {
            Ok(deterministic_embedding(&text, config.embedding.dimension))
        }
        EmbeddingProviderKind::HttpEmbedding => {
            let endpoint = config
                .embedding
                .endpoint
                .as_deref()
                .ok_or_else(|| anyhow!("http_embedding_endpoint_required"))?;
            let response = client
                .post(endpoint)
                .timeout(StdDuration::from_millis(config.embedding.timeout_ms))
                .json(&HttpEmbeddingRequest {
                    model: config.embedding.model_name.clone(),
                    input: vec![text],
                })
                .send()
                .await?
                .error_for_status()?
                .json::<HttpEmbeddingResponse>()
                .await?;
            if response.model != config.embedding.model_name {
                return Err(anyhow!("http_embedding_model_mismatch:{}", response.model));
            }
            if response.dimension != config.embedding.dimension {
                return Err(anyhow!(
                    "http_embedding_dimension_mismatch:{}",
                    response.dimension
                ));
            }
            if config.embedding.strict_model_version {
                let expected = config
                    .embedding
                    .model_version
                    .as_deref()
                    .ok_or_else(|| anyhow!("strict_model_version_requires_modelVersion"))?;
                if response.embedding_version != expected {
                    return Err(anyhow!(
                        "http_embedding_version_mismatch:{}",
                        response.embedding_version
                    ));
                }
            }
            if let Some(expected) = config.embedding.dtype.as_deref() {
                let actual = response
                    .dtype
                    .as_deref()
                    .ok_or_else(|| anyhow!("http_embedding_response_dtype_missing"))?;
                if actual != expected {
                    return Err(anyhow!("http_embedding_response_dtype_mismatch:{actual}"));
                }
            }
            let vector = response
                .vectors
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("http_embedding_vector_missing"))?;
            validate_embedding_vector(&vector, config.embedding.dimension)?;
            Ok(normalize_vector(vector))
        }
    }
}

fn bounded_embedding_text(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars.max(1)).collect()
}

fn validate_embedding_vector(vector: &[f32], dimension: usize) -> Result<()> {
    if vector.len() != dimension {
        return Err(anyhow!(
            "embedding_dimension_mismatch:{}:{}",
            vector.len(),
            dimension
        ));
    }
    if vector.iter().any(|value| !value.is_finite()) {
        return Err(anyhow!("embedding_vector_contains_non_finite_value"));
    }
    Ok(())
}

fn semantic_tokens(text: &str) -> Vec<String> {
    let tokens = semantic_tokens_without_alias_expansion(text);
    expand_semantic_aliases(&tokens, text)
}

fn semantic_query_projection(query: &ResourceDiscoveryQuery) -> SemanticQueryProjection {
    let raw_text = query.query.as_deref().unwrap_or_default().trim().to_owned();
    let mut explicit_terms = HashSet::new();
    if let Some(resource_type) = &query.resource_type {
        explicit_terms.insert(resource_type.as_str().to_owned());
    }
    if let Some(protocol) = &query.protocol {
        explicit_terms.insert(protocol.to_ascii_lowercase());
    }
    explicit_terms.extend(
        query
            .capability_tags
            .iter()
            .map(|tag| tag.to_ascii_lowercase()),
    );

    let tokens = semantic_tokens_without_alias_expansion(&raw_text);
    let mut expanded_tokens = expand_semantic_aliases(&tokens, &raw_text);
    for term in &explicit_terms {
        for token in semantic_tokens(term) {
            if !expanded_tokens.iter().any(|existing| existing == &token) {
                expanded_tokens.push(token);
            }
        }
    }
    SemanticQueryProjection { expanded_tokens }
}

fn semantic_query_tag_tokens(query: &ResourceDiscoveryQuery) -> Vec<String> {
    let mut tokens = Vec::new();
    if let Some(resource_type) = &query.resource_type {
        tokens.extend(semantic_tokens(resource_type.as_str()));
    }
    if let Some(protocol) = &query.protocol {
        tokens.extend(semantic_tokens(protocol));
    }
    for tag in &query.capability_tags {
        tokens.extend(semantic_tokens(tag));
    }
    let query_text = query.query.as_deref().unwrap_or_default();
    if !query_text.trim().is_empty() {
        tokens.extend(semantic_tokens(query_text));
    }
    let mut seen = HashSet::new();
    tokens
        .into_iter()
        .filter(|token| seen.insert(token.clone()))
        .collect()
}

fn semantic_tag_text(doc: &SearchDocument) -> String {
    [
        doc.resource_did.as_str(),
        doc.resource_type.as_str(),
        &doc.capability_tags.join(" "),
        &doc.protocols.join(" "),
        &doc.service_endpoints.join(" "),
        doc.tag_text.as_str(),
    ]
    .join(" ")
}

fn semantic_context_text(doc: &SearchDocument) -> String {
    [
        doc.name.as_str(),
        doc.resource_type.as_str(),
        doc.description.as_str(),
        &doc.capability_tags.join(" "),
        &doc.protocols.join(" "),
        &doc.use_cases.join(" "),
        &doc.examples.join(" "),
        doc.search_text.as_str(),
    ]
    .join(" ")
}

fn semantic_lexical_text(doc: &SearchDocument) -> String {
    let tag_text = semantic_tag_text(doc);
    let context_text = semantic_context_text(doc);
    format!("{tag_text} {tag_text} {context_text}")
}

fn semantic_intent_texts(doc: &SearchDocument) -> Vec<String> {
    let mut texts = Vec::new();
    for value in &doc.use_cases {
        push_unique_text(&mut texts, value);
    }
    for value in &doc.examples {
        push_unique_text(&mut texts, value);
    }
    if !doc.description.is_empty() {
        push_unique_text(
            &mut texts,
            format!("Find a {} for {}", doc.resource_type, doc.description),
        );
        push_unique_text(
            &mut texts,
            format!("Use {} to {}", doc.name, doc.description),
        );
    }
    for tag in &doc.capability_tags {
        push_unique_text(&mut texts, format!("Find a resource for capability {tag}"));
    }
    texts.into_iter().take(16).collect()
}

fn semantic_intent_documents(doc: &SearchDocument) -> Vec<IntentDocument> {
    semantic_intent_texts(doc)
        .into_iter()
        .enumerate()
        .map(|(index, intent_text)| {
            let intent_kind = if doc.use_cases.iter().any(|value| value == &intent_text) {
                "use_case"
            } else if doc.examples.iter().any(|value| value == &intent_text) {
                "example"
            } else {
                "pseudo_query"
            };
            let intent_id = format!("intent-{:02}", index + 1);
            IntentDocument {
                resource_did: doc.resource_did.clone(),
                intent_id,
                intent_kind: intent_kind.to_owned(),
                semantic_source_hash: format!("sha256:{}", sha256_hex(intent_text.as_bytes())),
                intent_text,
                resource_type: doc.resource_type.clone(),
                lifecycle_state: doc.lifecycle_state.clone(),
            }
        })
        .collect()
}

fn token_counts(tokens: &[String]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for token in tokens {
        *counts.entry(token.clone()).or_insert(0) += 1;
    }
    counts
}

fn weighted_token_similarity(query_tokens: &[String], text: &str) -> f32 {
    if query_tokens.is_empty() {
        return 0.0;
    }
    let doc_tokens = semantic_tokens(text);
    if doc_tokens.is_empty() {
        return 0.0;
    }
    let doc_counts = token_counts(&doc_tokens);
    let matched = query_tokens
        .iter()
        .filter(|token| doc_counts.contains_key(*token))
        .count();
    (matched as f32 / query_tokens.len() as f32).clamp(0.0, 1.0)
}

fn bm25_like_score(query_tokens: &[String], documents: &[Vec<String>], index: usize) -> f32 {
    if query_tokens.is_empty() || documents.is_empty() || index >= documents.len() {
        return 0.0;
    }
    let doc_tokens = &documents[index];
    if doc_tokens.is_empty() {
        return 0.0;
    }
    let doc_counts = token_counts(doc_tokens);
    let avg_len = documents
        .iter()
        .map(|tokens| tokens.len() as f32)
        .sum::<f32>()
        / documents.len() as f32;
    let doc_len = doc_tokens.len() as f32;
    let k1 = 1.2_f32;
    let b = 0.75_f32;
    let mut score = 0.0;
    let mut unique_query_terms = HashSet::new();
    for token in query_tokens {
        if !unique_query_terms.insert(token) {
            continue;
        }
        let Some(tf) = doc_counts.get(token).copied() else {
            continue;
        };
        let doc_freq = documents
            .iter()
            .filter(|tokens| tokens.iter().any(|candidate| *candidate == *token))
            .count() as f32;
        let idf = (((documents.len() as f32 - doc_freq + 0.5) / (doc_freq + 0.5)) + 1.0).ln();
        let tf = tf as f32;
        score += idf * (tf * (k1 + 1.0)) / (tf + k1 * (1.0 - b + b * doc_len / avg_len.max(1.0)));
    }
    (score / (score + 3.0)).clamp(0.0, 1.0)
}

fn semantic_resource_scores(
    package: &ResourcePackage,
    query: &ResourceDiscoveryQuery,
    query_projection: &SemanticQueryProjection,
    bm25_score: f32,
) -> SemanticQueryHit {
    let projection = discovery_package_projection(package);
    let doc = search_document_from_package(0, package, &projection);
    let tag_score = weighted_token_similarity(&query_projection.expanded_tokens, &semantic_tag_text(&doc));
    let context_score = weighted_token_similarity(
        &query_projection.expanded_tokens,
        &semantic_context_text(&doc),
    );
    let (intent_score, matched_intent) = semantic_intent_texts(&doc)
        .into_iter()
        .map(|intent| {
            let score = weighted_token_similarity(&query_projection.expanded_tokens, &intent);
            (score, intent)
        })
        .max_by(|a, b| a.0.total_cmp(&b.0))
        .filter(|(score, _)| *score > 0.0)
        .map(|(score, intent)| (score, Some(intent)))
        .unwrap_or((0.0, None));
    let structured_score = semantic_structured_score(package, query);
    let (tag_weight, context_weight, tag_bonus) = if query.resource_type.is_some() {
        (0.25, 0.25, 0.0)
    } else {
        let tag_bonus = if tag_score > 0.0 { 0.04 } else { 0.0 };
        (0.34, 0.16, tag_bonus)
    };
    let semantic_score =
        (0.30 * bm25_score) + (tag_weight * tag_score) + (context_weight * context_score) + (0.20 * intent_score);
    let final_score = (semantic_score + structured_score + tag_bonus).clamp(0.0, 1.0);
    SemanticQueryHit {
        package: package.clone(),
        semantic_score,
        bm25_score,
        tag_score,
        context_score,
        intent_score,
        structured_score,
        final_score,
        matched_intent,
    }
}

fn text_has_cjk(text: &str) -> bool {
    text.chars()
        .any(|ch| ('\u{4e00}'..='\u{9fff}').contains(&ch))
}

fn should_use_sql_text_prefilter(query: &ResourceDiscoveryQuery) -> bool {
    query
        .query
        .as_deref()
        .map(|text| {
            let trimmed = text.trim();
            !trimmed.is_empty() && !text_has_cjk(trimmed)
        })
        .unwrap_or(false)
}

fn rank_resource_packages_semantically(
    packages: Vec<ResourcePackage>,
    query: &ResourceDiscoveryQuery,
) -> Vec<SemanticQueryHit> {
    let query_projection = semantic_query_projection(query);
    let doc_tokens = packages
        .iter()
        .map(|package| {
            let projection = discovery_package_projection(package);
            let doc = search_document_from_package(0, package, &projection);
            semantic_tokens(&semantic_lexical_text(&doc))
        })
        .collect::<Vec<_>>();
    let has_semantic_terms = !query_projection.expanded_tokens.is_empty();
    let mut hits = packages
        .iter()
        .enumerate()
        .filter(|(_, package)| resource_matches_explicit_constraints(package, query))
        .map(|(index, package)| {
            let bm25_score = bm25_like_score(&query_projection.expanded_tokens, &doc_tokens, index);
            semantic_resource_scores(package, query, &query_projection, bm25_score)
        })
        .filter(|hit| !has_semantic_terms || hit.final_score > 0.0)
        .collect::<Vec<_>>();
    hits.sort_by(|a, b| {
        b.final_score
            .total_cmp(&a.final_score)
            .then_with(|| {
                b.package
                    .metadata
                    .updated_at
                    .cmp(&a.package.metadata.updated_at)
            })
            .then_with(|| a.package.resource_did.cmp(&b.package.resource_did))
    });
    hits
}

fn semantic_match_reason(hit: &SemanticQueryHit) -> String {
    let mut reasons = Vec::new();
    if hit.bm25_score > 0.0 {
        reasons.push("lexical terms");
    }
    if hit.tag_score > 0.0 {
        reasons.push("capability tags or protocols");
    }
    if hit.context_score > 0.0 {
        reasons.push("resource context");
    }
    if hit.intent_score > 0.0 {
        reasons.push("examples or use cases");
    }
    if hit.structured_score > 0.0 {
        reasons.push("explicit filters");
    }
    if reasons.is_empty() {
        "No semantic match above zero; returned only by structured eligibility.".to_owned()
    } else {
        format!("Matched by {}.", reasons.join(", "))
    }
}

fn normalize_vector(mut vector: Vec<f32>) -> Vec<f32> {
    let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    if norm > 0.0 {
        for value in &mut vector {
            *value /= norm;
        }
    }
    vector
}

fn pgvector_literal(vector: &[f32]) -> String {
    format!(
        "'[{}]'",
        vector
            .iter()
            .map(|value| format!("{value:.8}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn semantic_structured_score(package: &ResourcePackage, query: &ResourceDiscoveryQuery) -> f32 {
    let mut score = 0.0;
    if query
        .resource_type
        .as_ref()
        .is_some_and(|resource_type| resource_type == &package.resource_type)
    {
        score += 0.10;
    }
    if !query.capability_tags.is_empty() {
        let overlap = query
            .capability_tags
            .iter()
            .filter(|tag| package.metadata.capability_tags.contains(tag))
            .count();
        score += (overlap as f32 / query.capability_tags.len() as f32) * 0.15;
    }
    if query.protocol.as_ref().is_some_and(|protocol| {
        package.metadata.services.iter().any(|service| {
            service
                .protocol
                .as_ref()
                .map(|candidate| candidate.eq_ignore_ascii_case(protocol))
                .unwrap_or(false)
        }) || package.metadata.protocol_bindings.iter().any(|binding| {
            binding["protocol"]
                .as_str()
                .map(|candidate| candidate.eq_ignore_ascii_case(protocol))
                .unwrap_or(false)
        })
    }) {
        score += 0.05;
    }
    score
}

fn is_user_consumable_resource_type(resource_type: &ResourceType) -> bool {
    matches!(
        resource_type,
        ResourceType::AgentService
            | ResourceType::Skill
            | ResourceType::McpServer
            | ResourceType::ToolApi
    )
}

fn should_search_resource_type(package: &ResourcePackage, query: &ResourceDiscoveryQuery) -> bool {
    query.resource_type.is_some() || is_user_consumable_resource_type(&package.resource_type)
}

fn default_discoverable_resource_type_names() -> Vec<String> {
    ["agent_service", "skill", "mcp_server", "tool_api"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
}

fn build_cors_layer(config: &CorsConfig) -> Result<CorsLayer> {
    let origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .map(|origin| HeaderValue::from_str(origin))
        .collect::<std::result::Result<_, _>>()?;
    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers(AllowHeaders::any()))
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        node_type: "discovery".to_owned(),
        did: Some(state.did),
    })
}

async fn discovery_did_document(State(state): State<AppState>) -> ApiResult<DidDocument> {
    state
        .data
        .read("did-document.json")
        .map(Json)
        .map_err(|err| ApiError::internal(err.into()))
}

async fn discovery_debug_export_loop(state: AppState) {
    loop {
        if let Err(err) = export_discovery_debug_snapshot(&state).await {
            eprintln!("discovery debug export failed: {err}");
        }
        sleep(TokioDuration::from_millis(
            state.config.debug.export_interval_ms.max(100),
        ))
        .await;
    }
}

async fn sync_resources_from_authorized_summary(
    State(state): State<AppState>,
    Json(request): Json<DiscoverySyncRequest>,
) -> ApiResult<Value> {
    if request.items.is_empty() {
        return Err(ApiError::bad_request("empty_authorized_summary_items"));
    }
    let _sync_guard = state.resource_sync_lock.lock().await;
    let cdn_base = state
        .config
        .upstream
        .cdn_endpoint
        .clone()
        .unwrap_or_else(|| state.config.upstream.root_endpoint.clone())
        .trim_end_matches('/')
        .to_owned();
    sync_resources_from_cdn_items(state.clone(), cdn_base, request, Instant::now()).await
}

async fn sync_resources_from_cdn_items(
    state: AppState,
    cdn_base: String,
    request: DiscoverySyncRequest,
    started: Instant,
) -> ApiResult<Value> {
    let start_cursor = read_sync_cursor(&state)
        .await
        .map_err(ApiError::internal)?
        .max(0);
    let target_cursor = request.cursor_hint.unwrap_or_else(|| {
        request
            .items
            .iter()
            .map(|item| item.publication_cursor)
            .max()
            .unwrap_or(start_cursor)
    });
    let max_publications = request.max_publications.unwrap_or(10_000).max(1);
    let mut rejected = Vec::new();
    let mut accepted = Vec::<(i64, ResourcePackage)>::new();
    let mut fetched_count = 0usize;
    let mut cursor = start_cursor;
    let mut blocked_cursor: Option<i64> = None;
    let discovery_domains =
        local_discovery_authorized_domains(&state).map_err(ApiError::internal)?;

    let mut items = request.items;
    items.sort_by_key(|item| item.publication_cursor);
    let candidate_items = items
        .into_iter()
        .take(max_publications)
        .filter(|item| item.publication_cursor > start_cursor)
        .take_while(|item| item.publication_cursor <= target_cursor)
        .collect::<Vec<_>>();
    let batch_packages = fetch_cdn_resource_packages_batch(&state, &cdn_base, &candidate_items)
        .await
        .unwrap_or_default();
    for item in candidate_items {
        if item.publication_cursor <= start_cursor {
            continue;
        }
        if item.publication_cursor > target_cursor {
            break;
        }
        fetched_count += 1;
        cursor = cursor.max(item.publication_cursor);
        let package = if let Some(package) = batch_packages.get(&item.resource_did) {
            package.clone()
        } else {
            match fetch_cdn_resource_package(&state, &cdn_base, &item.resource_did).await {
                Ok(Some(package)) => package,
                Ok(None) => {
                    rejected.push(json!({
                        "resourceDid": item.resource_did,
                        "cursor": item.publication_cursor,
                        "reason": "resource_package_unavailable"
                    }));
                    blocked_cursor.get_or_insert(item.publication_cursor);
                    continue;
                }
                Err(err) => return Err(ApiError::internal(err)),
            }
        };
        if package.resource_did != item.resource_did {
            rejected.push(json!({
                "resourceDid": item.resource_did,
                "cursor": item.publication_cursor,
                "reason": "resource_did_mismatch"
            }));
            blocked_cursor.get_or_insert(item.publication_cursor);
            continue;
        }
        if let Err(reason) = validate_notified_resource_package(&item, &package) {
            rejected.push(json!({
                "resourceDid": item.resource_did,
                "cursor": item.publication_cursor,
                "reason": reason
            }));
            blocked_cursor.get_or_insert(item.publication_cursor);
            continue;
        }
        if !authorized_domains_cover(&discovery_domains, &package.metadata.authorized_domains) {
            rejected.push(json!({
                "resourceDid": package.resource_did,
                "cursor": item.publication_cursor,
                "reason": "unauthorized_domains"
            }));
            blocked_cursor.get_or_insert(item.publication_cursor);
            continue;
        }
        if let Err(reason) = validate_resource_package_for_index(&package) {
            rejected.push(json!({
                "resourceDid": package.resource_did,
                "cursor": item.publication_cursor,
                "reason": reason
            }));
            blocked_cursor.get_or_insert(item.publication_cursor);
            continue;
        }
        accepted.push((item.publication_cursor, package));
    }

    let accepted_dids = accepted
        .iter()
        .map(|(_, package)| package.resource_did.as_str())
        .collect::<HashSet<_>>();
    rejected.retain(|item| !accepted_dids.contains(rejected_package_resource_did(item)));
    blocked_cursor = rejected
        .iter()
        .filter_map(|item| item.get("cursor").and_then(Value::as_i64))
        .min();

    let synced = accepted.len();
    upsert_indexed_resource_packages_batch(&state, &accepted)
        .await
        .map_err(ApiError::internal)?;
    write_sync_cursor(&state, cursor)
        .await
        .map_err(ApiError::internal)?;
    let history = json!({
        "syncedAt": Utc::now(),
        "status": "synced",
        "syncMode": "authorized-summary",
        "syncedResourceCount": synced,
        "rejectedCount": rejected.len(),
        "elapsedMs": started.elapsed().as_millis(),
        "fromCursor": start_cursor,
        "toCursor": cursor,
        "targetCursor": target_cursor,
        "pagesFetched": 0,
        "itemsFetched": fetched_count,
        "blockedCursor": blocked_cursor,
        "cursorLag": (target_cursor - cursor).max(0),
        "backend": if state.postgres.is_some() { "postgres" } else if state.sqlite.is_some() { "sqlite" } else { "json" },
        "deltaUpsert": true
    });
    write_sync_history_store(&state, history)
        .await
        .map_err(ApiError::internal)?;
    write_rejected_packages(&state, &rejected)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "status": "synced",
        "syncMode": "authorized-summary",
        "syncedResourceCount": synced,
        "rejectedCount": rejected.len(),
        "elapsedMs": started.elapsed().as_millis(),
        "fromCursor": start_cursor,
        "toCursor": cursor,
        "targetCursor": target_cursor,
        "pagesFetched": 0,
        "itemsFetched": fetched_count,
        "blockedCursor": blocked_cursor,
        "cursorLag": (target_cursor - cursor).max(0),
        "deltaUpsert": true,
        "rejected": rejected
    })))
}

async fn fetch_cdn_resource_packages_batch(
    state: &AppState,
    cdn_base: &str,
    items: &[DiscoveryNotificationItem],
) -> Result<BTreeMap<String, ResourcePackage>> {
    if items.is_empty() {
        return Ok(BTreeMap::new());
    }
    let resource_dids = items
        .iter()
        .map(|item| item.resource_did.clone())
        .collect::<Vec<_>>();
    let response = state
        .client
        .post(format!("{cdn_base}/cdn/resources/batch-get"))
        .json(&json!({ "resourceDids": resource_dids }))
        .send()
        .await?;
    if !response.status().is_success() {
        return Ok(BTreeMap::new());
    }
    let value: Value = response.json().await?;
    let mut packages = BTreeMap::new();
    for item in value
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let Some(resource_did) = item.get("resourceDid").and_then(Value::as_str) else {
            continue;
        };
        let Some(package_value) = item.get("package") else {
            continue;
        };
        let package = serde_json::from_value::<ResourcePackage>(package_value.clone())?;
        packages.insert(resource_did.to_owned(), package);
    }
    Ok(packages)
}

async fn fetch_cdn_resource_package(
    state: &AppState,
    cdn_base: &str,
    resource_did: &str,
) -> Result<Option<ResourcePackage>> {
    let encoded_did =
        url::form_urlencoded::byte_serialize(resource_did.as_bytes()).collect::<String>();
    let response = state
        .client
        .get(format!("{cdn_base}/cdn/resources/{encoded_did}"))
        .send()
        .await?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(anyhow!(
            "resource_package_unavailable:{}",
            response.status()
        ));
    }
    Ok(Some(response.json::<ResourcePackage>().await?))
}

fn validate_notified_resource_package(
    item: &DiscoveryNotificationItem,
    package: &ResourcePackage,
) -> std::result::Result<(), String> {
    if package.resource_did != item.resource_did {
        return Err("resource_did_mismatch".to_owned());
    }
    if let Some(resource_type) = item.resource_type.as_deref() {
        let package_resource_type = serde_json::to_value(&package.resource_type)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_default();
        if package_resource_type != resource_type {
            return Err("resource_type_mismatch".to_owned());
        }
    }
    if !item.capability_tags.is_empty() && package.metadata.capability_tags != item.capability_tags
    {
        return Err("capability_tags_mismatch".to_owned());
    }
    if item.authorized_domains.is_empty() {
        return Err("resource_domains_required".to_owned());
    }
    validate_authorized_domain_list(&item.authorized_domains)?;
    if package.metadata.authorized_domains != item.authorized_domains {
        return Err("authorized_domains_mismatch".to_owned());
    }
    Ok(())
}

async fn resource_query(
    State(state): State<AppState>,
    Json(query): Json<ResourceDiscoveryQuery>,
) -> ApiResult<ResourceDiscoveryResponse> {
    let started = Instant::now();
    if let Some(resource_did) = query_resource_did(&query) {
        let package = read_indexed_resource_package(&state, resource_did)
            .await
            .map_err(ApiError::internal)?;
        let allowed_domains =
            local_discovery_authorized_domains(&state).map_err(ApiError::internal)?;
        let candidates = package
            .filter(|package| {
                resource_matches_exact_did_query(package, &query)
                    && authorized_domains_cover(
                        &allowed_domains,
                        &package.metadata.authorized_domains,
                    )
            })
            .map(|package| discovery_candidate_from_package(package, 1.0))
            .into_iter()
            .collect::<Vec<_>>();
        println!(
            "discovery_query backend=exact-did indexed=true candidates={} returned={} elapsed_ms={}",
            candidates.len(),
            candidates.len(),
            started.elapsed().as_millis()
        );
        return Ok(Json(ResourceDiscoveryResponse {
            discovery_did: state.did,
            candidates,
            created_at: Utc::now(),
            proof: None,
        }));
    }
    let semantic_result = query_semantic_index(&state, &query).await;
    let (mut candidates, candidate_count, prefiltered, backend) = match semantic_result {
        Ok(Some(hits)) if !hits.is_empty() => {
            let candidate_count = hits.len();
            (
                hits.into_iter()
                    .map(|hit| discovery_candidate_from_package(hit.package, hit.final_score))
                    .collect::<Vec<_>>(),
                candidate_count,
                true,
                "semantic-pgvector".to_owned(),
            )
        }
        Ok(Some(_)) => {
            let (candidates, candidate_count, prefiltered) =
                keyword_discovery_candidates(&state, &query)
                    .await
                    .map_err(ApiError::internal)?;
            (
                candidates,
                candidate_count,
                prefiltered,
                discovery_backend_name(&state),
            )
        }
        Ok(None) => {
            let (candidates, candidate_count, prefiltered) =
                keyword_discovery_candidates(&state, &query)
                    .await
                    .map_err(ApiError::internal)?;
            (
                candidates,
                candidate_count,
                prefiltered,
                discovery_backend_name(&state),
            )
        }
        Err(err) => {
            eprintln!("semantic query failed: {err}");
            let (candidates, candidate_count, prefiltered) =
                keyword_discovery_candidates(&state, &query)
                    .await
                    .map_err(ApiError::internal)?;
            (
                candidates,
                candidate_count,
                prefiltered,
                discovery_backend_name(&state),
            )
        }
    };
    candidates.sort_by(|a, b| b.score.total_cmp(&a.score));
    candidates.truncate(query.limit as usize);
    let metrics = DiscoveryQueryMetrics {
        backend,
        candidate_count,
        returned_count: candidates.len(),
        elapsed_ms: started.elapsed().as_millis(),
        used_indexed_prefilter: prefiltered,
    };
    println!(
        "discovery_query backend={} indexed={} candidates={} returned={} elapsed_ms={}",
        metrics.backend,
        metrics.used_indexed_prefilter,
        metrics.candidate_count,
        metrics.returned_count,
        metrics.elapsed_ms
    );
    Ok(Json(ResourceDiscoveryResponse {
        discovery_did: state.did,
        candidates,
        created_at: Utc::now(),
        proof: None,
    }))
}

async fn run_resource_query(
    state: &AppState,
    query: &ResourceDiscoveryQuery,
) -> Result<ResourceDiscoveryResponse> {
    resource_query(State(state.clone()), Json(query.clone()))
        .await
        .map(|response| response.0)
        .map_err(|err| anyhow!(err.message))
}

async fn evaluate_semantic_discovery(
    state: &AppState,
    suite_path: &Path,
) -> Result<SemanticEvaluationReport> {
    let suite: SemanticEvaluationSuite =
        serde_json::from_str(&read_utf8_text_allowing_bom(suite_path)?)?;
    if suite.cases.is_empty() {
        return Err(anyhow!("semantic_evaluation_suite_empty"));
    }
    let mut reports = Vec::new();
    let mut recall5_hits = 0usize;
    let mut recall10_hits = 0usize;
    let mut reciprocal_rank_sum = 0.0_f32;
    for case in &suite.cases {
        let response = run_resource_query(state, &case.query).await?;
        let returned_dids = response
            .candidates
            .iter()
            .map(|candidate| candidate.resource_did.clone())
            .collect::<Vec<_>>();
        let first_rank = returned_dids
            .iter()
            .position(|did| case.expected_dids.iter().any(|expected| expected == did))
            .map(|index| index + 1);
        let recall_at_5 = first_rank.is_some_and(|rank| rank <= 5);
        let recall_at_10 = first_rank.is_some_and(|rank| rank <= 10);
        if recall_at_5 {
            recall5_hits += 1;
        }
        if recall_at_10 {
            recall10_hits += 1;
        }
        let reciprocal_rank = first_rank
            .filter(|rank| *rank <= 10)
            .map(|rank| 1.0 / rank as f32)
            .unwrap_or(0.0);
        reciprocal_rank_sum += reciprocal_rank;
        reports.push(SemanticEvaluationCaseReport {
            id: case.id.clone(),
            language: case.language.clone(),
            description: case.description.clone(),
            passed: recall_at_10,
            reciprocal_rank,
            returned_dids,
            expected_dids: case.expected_dids.clone(),
        });
    }
    let case_count = reports.len().max(1);
    Ok(SemanticEvaluationReport {
        suite: suite.suite,
        case_count: reports.len(),
        seed_package_count: suite.seed_packages.len() + suite.seed_resources.len(),
        recall_at_5: recall5_hits as f32 / case_count as f32,
        recall_at_10: recall10_hits as f32 / case_count as f32,
        mrr_at_10: reciprocal_rank_sum / case_count as f32,
        cases: reports,
    })
}

fn query_resource_did(query: &ResourceDiscoveryQuery) -> Option<&str> {
    let value = query.query.as_ref()?.trim();
    if value.starts_with("did:oan:") && !value.chars().any(char::is_whitespace) {
        Some(value)
    } else {
        None
    }
}

async fn keyword_discovery_candidates(
    state: &AppState,
    query: &ResourceDiscoveryQuery,
) -> Result<(Vec<ResourceDiscoveryCandidate>, usize, bool)> {
    let (packages, prefiltered) = query_indexed_resource_packages(state, query).await?;
    let allowed_domains = local_discovery_authorized_domains(state)?;
    let packages = packages
        .into_iter()
        .filter(|package| {
            authorized_domains_cover(&allowed_domains, &package.metadata.authorized_domains)
        })
        .collect::<Vec<_>>();
    let candidate_count = packages.len();
    let hits = rank_resource_packages_semantically(packages, query);
    let candidates = hits
        .into_iter()
        .filter(|hit| prefiltered || hit.final_score > 0.0 || query.query.is_none())
        .map(|hit| discovery_candidate_from_package(hit.package, hit.final_score))
        .collect::<Vec<_>>();
    Ok((candidates, candidate_count, prefiltered))
}

fn discovery_candidate_from_package(
    package: ResourcePackage,
    score: f32,
) -> ResourceDiscoveryCandidate {
    ResourceDiscoveryCandidate {
        resource_did: package.resource_did.clone(),
        resource_type: package.resource_type.clone(),
        score,
        version: Some(package.package_version.clone()),
        lifecycle_state: Some(package.metadata.lifecycle_state.clone()),
        capability_tags: package.metadata.capability_tags.clone(),
        authorized_domains: package.metadata.authorized_domains.clone(),
        services: package.metadata.services.clone(),
        protocol_bindings: package.metadata.protocol_bindings.clone(),
        package_info: package
            .did_document
            .oan_metadata
            .as_ref()
            .and_then(|metadata| metadata.package_info.as_ref())
            .and_then(|info| serde_json::to_value(info).ok()),
        root_proof: serde_json::to_value(&package.root_proof).ok(),
    }
}

fn discovery_backend_name(state: &AppState) -> String {
    if state.postgres.is_some() {
        "postgres".to_owned()
    } else if state.sqlite.is_some() {
        "sqlite".to_owned()
    } else {
        "json".to_owned()
    }
}

async fn route_lookup(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<serde_json::Value> {
    let package = read_indexed_resource_package(&state, &did)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(match package {
        Some(package) => json!({
            "resourceDid": package.resource_did,
            "resourceType": package.resource_type,
            "lifecycleState": package.metadata.lifecycle_state,
            "services": package.metadata.services
        }),
        None => json!({"resourceDid": did, "status": "not-found"}),
    }))
}

async fn api_status(State(state): State<AppState>) -> ApiResult<Value> {
    let indexed_resource_count = count_indexed_resource_packages(&state)
        .await
        .map_err(ApiError::internal)?;
    let history = read_sync_history(&state)
        .await
        .map_err(ApiError::internal)?;
    let bulletin = fetch_bulletin(&state).await.ok();
    Ok(Json(json!({
        "discoveryDid": state.did,
        "rootEndpoint": state.config.upstream.root_endpoint,
        "cdnEndpoint": state.config.upstream.cdn_endpoint,
        "indexedResourceCount": indexed_resource_count,
        "lastSync": history.last(),
        "rootAuthorizationStatus": bulletin.as_ref().map(|b| discovery_authorization_status(b, &state.did)).unwrap_or_else(|| "unknown".to_owned()),
        "semanticSearch": semantic_status_json(&state, false, None)
    })))
}

async fn api_root_authorization(State(state): State<AppState>) -> ApiResult<Value> {
    let bulletin = fetch_bulletin(&state).await;
    match bulletin {
        Ok(bulletin) => Ok(Json(json!({
            "discoveryDid": state.did,
            "rootReachable": true,
            "status": discovery_authorization_status(&bulletin, &state.did),
            "authorizedDomains": discovery_authorized_domains(&bulletin, &state.did)
        }))),
        Err(err) => Ok(Json(json!({
            "discoveryDid": state.did,
            "rootReachable": false,
            "status": "unknown",
            "error": err.to_string()
        }))),
    }
}

async fn api_authorized_domains(State(state): State<AppState>) -> ApiResult<Value> {
    let bulletin = fetch_bulletin(&state).await.map_err(ApiError::internal)?;
    let domains = discovery_authorized_domains(&bulletin, &state.did);
    Ok(Json(json!({
        "discoveryDid": state.did,
        "authorizedDomains": domains
    })))
}

async fn api_sync_history(State(state): State<AppState>) -> ApiResult<Value> {
    let history = read_sync_history(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": history, "count": history.len() })))
}

async fn api_index_stats(State(state): State<AppState>) -> ApiResult<Value> {
    if let Ok(cache) = state.index_stats_cache.try_lock() {
        if let Some(cached) = cache.as_ref() {
            if cached.captured_at.elapsed()
                <= StdDuration::from_millis(DISCOVERY_INDEX_STATS_CACHE_TTL_MS)
            {
                return Ok(Json(cached.body.clone()));
            }
        }
    }
    let sync_cursor = read_sync_cursor(&state).await.map_err(ApiError::internal)?;
    let mut body = if let Some(postgres) = &state.postgres {
        let total_row = sqlx::query(&format!("SELECT COUNT(*) FROM {DISCOVERY_PACKAGE_TABLE}"))
            .fetch_one(postgres.pool())
            .await
            .map_err(|err| ApiError::internal(err.into()))?;
        let type_rows = sqlx::query(&format!(
            "SELECT resource_type, COUNT(*) FROM {DISCOVERY_PACKAGE_TABLE} GROUP BY resource_type"
        ))
        .fetch_all(postgres.pool())
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
        let tag_rows = sqlx::query(&format!(
            "SELECT tag, COUNT(*) FROM {DISCOVERY_PACKAGE_TABLE}, unnest(capability_tags) AS tag GROUP BY tag"
        ))
        .fetch_all(postgres.pool())
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
        let mut resource_type_counts = serde_json::Map::new();
        for row in type_rows {
            resource_type_counts.insert(row.get::<String, _>(0), json!(row.get::<i64, _>(1)));
        }
        let mut tag_counts = serde_json::Map::new();
        for row in tag_rows {
            tag_counts.insert(row.get::<String, _>(0), json!(row.get::<i64, _>(1)));
        }
        json!({
            "indexedResourceCount": total_row.get::<i64, _>(0),
            "resourceTypeCounts": resource_type_counts,
            "capabilityTagCounts": tag_counts,
            "backend": "postgres",
            "indexedStats": true,
            "syncCursor": sync_cursor
        })
    } else {
        let packages = read_indexed_resource_packages(&state)
            .await
            .map_err(ApiError::internal)?;
        let mut tag_counts = serde_json::Map::new();
        let mut resource_type_counts = serde_json::Map::new();
        for package in &packages {
            let resource_type = package.resource_type.as_str();
            let next_type = resource_type_counts
                .get(resource_type)
                .and_then(Value::as_u64)
                .unwrap_or(0)
                + 1;
            resource_type_counts.insert(resource_type.to_owned(), json!(next_type));
            for tag in &package.metadata.capability_tags {
                let next = tag_counts.get(tag).and_then(Value::as_u64).unwrap_or(0) + 1;
                tag_counts.insert(tag.clone(), json!(next));
            }
        }
        json!({
            "indexedResourceCount": packages.len(),
            "resourceTypeCounts": resource_type_counts,
            "capabilityTagCounts": tag_counts,
            "backend": if state.sqlite.is_some() { "sqlite" } else { "json" },
            "indexedStats": state.sqlite.is_some(),
            "syncCursor": sync_cursor
        })
    };
    if let Value::Object(map) = &mut body {
        map.insert(
            "semanticSearch".to_owned(),
            semantic_status_json(&state, false, None),
        );
        map.insert(
            "semanticIndexedCount".to_owned(),
            match count_semantic_indexed_resources(&state).await {
                Ok(Some(count)) => json!(count),
                Ok(None) => Value::Null,
                Err(err) => json!({ "error": err.to_string() }),
            },
        );
    }
    if let Ok(mut cache) = state.index_stats_cache.try_lock() {
        *cache = Some(CachedIndexStats {
            captured_at: Instant::now(),
            body: body.clone(),
        });
    }
    Ok(Json(body))
}

async fn api_index_resources(State(state): State<AppState>) -> ApiResult<Value> {
    let packages = read_indexed_resource_packages(&state)
        .await
        .map_err(ApiError::internal)?;
    let items = packages
        .into_iter()
        .map(|package| {
            json!({
                "resourceDid": package.resource_did,
                "resourceType": package.resource_type,
                "name": package.metadata.name,
                "description": package.metadata.description,
                "capabilityTags": package.metadata.capability_tags,
                "services": package.metadata.services,
                "lifecycleState": package.metadata.lifecycle_state,
                "version": package.package_version,
                "updatedAt": package.metadata.updated_at
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "items": items, "count": items.len() })))
}

async fn api_index_resource_visibility(
    State(state): State<AppState>,
    Json(request): Json<IndexedResourceVisibilityRequest>,
) -> ApiResult<Value> {
    let visible = indexed_resource_visibility(&state, &request.resource_dids)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "resourceDids": request.resource_dids,
        "visible": visible,
        "visibleCount": visible.len()
    })))
}

async fn api_index_resource_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let package = read_indexed_resource_package(&state, &did)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "resourceDid": did, "package": package })))
}

async fn api_query_suggestions(
    State(state): State<AppState>,
    Json(input): Json<DiscoverySuggestionInput>,
) -> ApiResult<Value> {
    let result = state
        .recommender
        .suggest_discovery_query(
            input,
            DiscoverySuggestionContext {
                discovery_did: state.did.clone(),
                searchable_domains: local_discovery_authorized_domains(&state)
                    .map_err(ApiError::internal)?,
                max_authorized_domain_hints: 8,
                max_capability_tag_candidates: 12,
            },
        )
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    Ok(Json(
        serde_json::to_value(result).map_err(|err| ApiError::internal(anyhow!(err)))?,
    ))
}

async fn api_query_explain(
    State(state): State<AppState>,
    Json(query): Json<ResourceDiscoveryQuery>,
) -> ApiResult<Value> {
    if state.config.semantic_search.explain_enabled {
        match query_semantic_index(&state, &query).await {
            Ok(Some(hits)) if !hits.is_empty() => {
                let items = hits
                    .iter()
                    .map(|hit| {
                        json!({
                            "resourceDid": hit.package.resource_did,
                            "resourceType": hit.package.resource_type,
                            "matched": true,
                            "score": hit.final_score,
                            "semanticScore": hit.semantic_score,
                            "bm25Score": hit.bm25_score,
                            "tagScore": hit.tag_score,
                            "contextScore": hit.context_score,
                            "intentMaxSimScore": hit.intent_score,
                            "structuredScore": hit.structured_score,
                            "finalScore": hit.final_score,
                            "matchedIntent": hit.matched_intent,
                            "capabilityTagOverlap": query.capability_tags.iter()
                                .filter(|tag| hit.package.metadata.capability_tags.iter().any(|candidate| candidate == *tag))
                                .cloned()
                                .collect::<Vec<_>>(),
                            "resourceTypeMatched": query.resource_type.as_ref().map(|resource_type| {
                                resource_type == &hit.package.resource_type
                            }),
                            "protocolMatched": query.protocol.as_ref().map(|protocol| {
                                hit.package.metadata.services.iter().any(|service| {
                                    service
                                        .protocol
                                        .as_ref()
                                        .map(|candidate| candidate.eq_ignore_ascii_case(protocol))
                                        .unwrap_or(false)
                                }) || hit.package.metadata.protocol_bindings.iter().any(|binding| {
                                    binding["protocol"]
                                        .as_str()
                                        .map(|candidate| candidate.eq_ignore_ascii_case(protocol))
                                        .unwrap_or(false)
                                })
                            }),
                            "matchReason": semantic_match_reason(hit)
                        })
                    })
                    .collect::<Vec<_>>();
                return Ok(Json(json!({
                    "query": query,
                    "items": items,
                    "candidateCount": items.len(),
                    "usedIndexedPrefilter": true,
                    "semanticSearch": semantic_status_json(&state, false, None)
                })));
            }
            Ok(Some(_)) => {}
            Ok(None) => {}
            Err(err) => {
                eprintln!("semantic explain failed: {err}");
            }
        }
    }
    let (packages, prefiltered) = query_indexed_resource_packages(&state, &query)
        .await
        .map_err(ApiError::internal)?;
    let hits = rank_resource_packages_semantically(packages, &query);
    let explanations = hits
        .iter()
        .map(|hit| {
            let package = &hit.package;
            let matched = hit.final_score > 0.0 || query.query.is_none();
            json!({
                "resourceDid": package.resource_did,
                "resourceType": package.resource_type,
                "matched": matched,
                "score": if matched { hit.final_score } else { 0.0 },
                "textMatched": query.query.as_ref().map(|text| {
                    let needle = text.to_ascii_lowercase();
                    package.resource_did.to_ascii_lowercase().contains(&needle)
                        || package.metadata.name.to_ascii_lowercase().contains(&needle)
                        || package.metadata.description.to_ascii_lowercase().contains(&needle)
                        || package.metadata.capability_tags.iter().any(|tag| tag.to_ascii_lowercase().contains(&needle))
                }),
                "capabilityTagOverlap": query.capability_tags.iter()
                    .filter(|tag| package.metadata.capability_tags.iter().any(|candidate| candidate == *tag))
                    .cloned()
                    .collect::<Vec<_>>(),
                "resourceTypeMatched": query.resource_type.as_ref().map(|resource_type| {
                    resource_type == &package.resource_type
                }),
                "protocolMatched": query.protocol.as_ref().map(|protocol| {
                    package.metadata.services.iter().any(|service| {
                        service
                            .protocol
                            .as_ref()
                            .map(|candidate| candidate.eq_ignore_ascii_case(protocol))
                            .unwrap_or(false)
                    })
                }),
                "semanticScore": hit.semantic_score,
                "bm25Score": hit.bm25_score,
                "tagScore": hit.tag_score,
                "contextScore": hit.context_score,
                "intentMaxSimScore": hit.intent_score,
                "structuredScore": hit.structured_score,
                "finalScore": hit.final_score,
                "matchedIntent": hit.matched_intent,
                "matchReason": semantic_match_reason(hit),
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "query": query,
        "items": explanations,
        "candidateCount": explanations.len(),
        "usedIndexedPrefilter": prefiltered,
        "semanticSearch": semantic_status_json(&state, true, Some("keyword_explain_fallback".to_owned()))
    })))
}

async fn api_rejected_packages(State(state): State<AppState>) -> ApiResult<Value> {
    let items = read_rejected_packages(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": items, "count": items.len() })))
}

async fn api_backfill_rejected_packages(
    State(state): State<AppState>,
    Json(request): Json<RejectedPackageBackfillRequest>,
) -> ApiResult<Value> {
    let _sync_guard = state.resource_sync_lock.lock().await;
    let cdn_base = state
        .config
        .upstream
        .cdn_endpoint
        .clone()
        .unwrap_or_else(|| state.config.upstream.root_endpoint.clone())
        .trim_end_matches('/')
        .to_owned();
    backfill_rejected_resource_packages(&state, &cdn_base, request)
        .await
        .map(Json)
        .map_err(ApiError::internal)
}

async fn api_audit_resolved_rejected_packages(
    State(state): State<AppState>,
    Json(request): Json<ResolvedRejectedPackageCleanupRequest>,
) -> ApiResult<Value> {
    audit_resolved_rejected_packages(&state, request)
        .await
        .map(Json)
        .map_err(ApiError::internal)
}

async fn backfill_rejected_resource_packages(
    state: &AppState,
    cdn_base: &str,
    request: RejectedPackageBackfillRequest,
) -> Result<Value> {
    let max_items = request.max_items.unwrap_or(100).max(1);
    let requested_dids = request.resource_dids.into_iter().collect::<BTreeSet<_>>();
    let discovery_domains = local_discovery_authorized_domains(state)?;
    let rejected = read_rejected_packages(state).await?;
    let mut attempted = 0usize;
    let mut recovered = Vec::<Value>::new();
    let mut failed = Vec::<Value>::new();
    let mut skipped = 0usize;
    let mut accepted = Vec::<(i64, ResourcePackage)>::new();
    let mut resolved_reject_keys = Vec::<String>::new();
    let mut replacement_rejections = Vec::<Value>::new();

    for item in rejected.iter() {
        let reason = item
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let resource_did = item
            .get("resourceDid")
            .or_else(|| item.get("did"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if reason != "resource_package_unavailable"
            || resource_did.is_empty()
            || (!requested_dids.is_empty() && !requested_dids.contains(resource_did))
        {
            skipped += 1;
            continue;
        }
        if attempted >= max_items {
            skipped += 1;
            continue;
        }
        attempted += 1;
        let cursor = item
            .get("cursor")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        match fetch_cdn_resource_package(state, cdn_base, resource_did).await {
            Ok(Some(package)) => {
                let reject_reason = if package.resource_did != resource_did {
                    Some("resource_did_mismatch".to_owned())
                } else if !authorized_domains_cover(
                    &discovery_domains,
                    &package.metadata.authorized_domains,
                ) {
                    Some("unauthorized_domains".to_owned())
                } else {
                    validate_resource_package_for_index(&package).err()
                };
                if let Some(reason) = reject_reason {
                    let replacement = json!({
                        "resourceDid": resource_did,
                        "cursor": cursor,
                        "reason": reason
                    });
                    failed.push(replacement.clone());
                    replacement_rejections.push(replacement);
                    resolved_reject_keys.push(rejected_package_key(item));
                    continue;
                }
                recovered.push(json!({
                    "resourceDid": resource_did,
                    "cursor": cursor
                }));
                resolved_reject_keys.push(rejected_package_key(item));
                accepted.push((cursor, package));
            }
            Ok(None) => failed.push(json!({
                "resourceDid": resource_did,
                "cursor": cursor,
                "reason": "resource_package_unavailable"
            })),
            Err(err) => failed.push(json!({
                "resourceDid": resource_did,
                "cursor": cursor,
                "reason": "cdn_fetch_failed",
                "error": err.to_string()
            })),
        }
    }

    upsert_indexed_resource_packages_batch(state, &accepted).await?;
    delete_rejected_packages(state, &resolved_reject_keys).await?;
    write_rejected_packages(state, &replacement_rejections).await?;
    let remaining_rejected_count = read_rejected_packages(state).await?.len();

    Ok(json!({
        "status": "backfilled",
        "reason": "resource_package_unavailable",
        "attemptedCount": attempted,
        "recoveredCount": recovered.len(),
        "skippedCount": skipped,
        "failedCount": failed.len(),
        "remainingRejectedCount": remaining_rejected_count,
        "recovered": recovered,
        "failed": failed
    }))
}

async fn audit_resolved_rejected_packages(
    state: &AppState,
    request: ResolvedRejectedPackageCleanupRequest,
) -> Result<Value> {
    let max_items = request.max_items.unwrap_or(1_000).max(1);
    let requested_dids = request.resource_dids.into_iter().collect::<BTreeSet<_>>();
    let discovery_domains = local_discovery_authorized_domains(state)?;
    let visible_dids = read_indexed_resource_packages(state)
        .await?
        .into_iter()
        .filter(|package| {
            package.metadata.lifecycle_state == "active"
                && is_user_consumable_resource_type(&package.resource_type)
                && authorized_domains_cover(&discovery_domains, &package.metadata.authorized_domains)
        })
        .map(|package| package.resource_did)
        .collect::<HashSet<_>>();
    let rejected = read_rejected_packages(state).await?;
    let mut resolved = Vec::new();
    let mut reject_keys = Vec::new();

    for item in rejected.iter() {
        if resolved.len() >= max_items {
            break;
        }
        let reason = item
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !is_resolvable_historical_reject_reason(reason) {
            continue;
        }
        let resource_did = rejected_package_resource_did(item);
        if resource_did.is_empty()
            || !visible_dids.contains(resource_did)
            || (!requested_dids.is_empty() && !requested_dids.contains(resource_did))
        {
            continue;
        }
        resolved.push(json!({
            "resourceDid": resource_did,
            "cursor": item.get("cursor").cloned().unwrap_or(Value::Null),
            "reason": reason,
            "rejectKey": rejected_package_key(item)
        }));
        reject_keys.push(rejected_package_key(item));
    }

    if !request.dry_run {
        delete_rejected_packages(state, &reject_keys).await?;
    }

    Ok(json!({
        "status": if request.dry_run { "audited" } else { "cleaned" },
        "dryRun": request.dry_run,
        "resolvedRejectedCount": resolved.len(),
        "deletedCount": if request.dry_run { 0 } else { reject_keys.len() },
        "reasons": resolvable_historical_reject_reasons(),
        "items": resolved
    }))
}

fn resolvable_historical_reject_reasons() -> &'static [&'static str] {
    &[
        "package_version_mismatch",
        "capability_tags_mismatch",
        "package_hash_mismatch",
    ]
}

fn is_resolvable_historical_reject_reason(reason: &str) -> bool {
    resolvable_historical_reject_reasons().contains(&reason)
}

async fn api_capability_tree(State(state): State<AppState>) -> ApiResult<Value> {
    let response = state
        .client
        .get(format!(
            "{}/root/capability-tree",
            state.config.upstream.root_endpoint.trim_end_matches('/')
        ))
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {
            let value = response
                .json()
                .await
                .map_err(|err| ApiError::internal(err.into()))?;
            Ok(Json(value))
        }
        Ok(response) => Ok(Json(json!({
            "source": "root",
            "status": "unavailable",
            "statusCode": response.status().as_u16()
        }))),
        Err(err) => Ok(Json(json!({
            "source": "root",
            "status": "unavailable",
            "error": err.to_string()
        }))),
    }
}

async fn fetch_bulletin(state: &AppState) -> Result<Value> {
    state
        .client
        .get(format!(
            "{}/bulletin",
            state.config.upstream.root_endpoint.trim_end_matches('/')
        ))
        .send()
        .await
        .context("fetch_root_bulletin_failed")?
        .json()
        .await
        .context("decode_root_bulletin_failed")
}

fn discovery_authorization_status(bulletin: &Value, discovery_did: &str) -> String {
    if bulletin["events"]
        .as_array()
        .map(|events| {
            events.iter().any(|event| {
                event["subjectDid"] == discovery_did
                    && event["eventType"] == "DISCOVERY_NODE_REVOKED"
            })
        })
        .unwrap_or(false)
    {
        "revoked".to_owned()
    } else {
        "active".to_owned()
    }
}

#[cfg(test)]
async fn upsert_indexed_resource_package(
    state: &AppState,
    cursor: i64,
    package: &ResourcePackage,
) -> Result<()> {
    upsert_indexed_resource_packages_batch(state, &[(cursor, package.clone())]).await
}

async fn upsert_indexed_resource_packages_batch(
    state: &AppState,
    packages: &[(i64, ResourcePackage)],
) -> Result<()> {
    if packages.is_empty() {
        return Ok(());
    }
    let packages = latest_resource_packages_by_did(packages);
    let accepted_dids = packages
        .iter()
        .map(|(_, package)| package.resource_did.clone())
        .collect::<Vec<_>>();
    let updated_at = Utc::now();
    let updated_at_text = updated_at.to_rfc3339();
    if let Some(sqlite) = &state.sqlite {
        let rows = packages
            .iter()
            .map(|(cursor, package)| {
                Ok::<_, anyhow::Error>((
                    package.resource_did.clone(),
                    *cursor,
                    package.package_version.clone(),
                    serde_json::to_string(package)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut tx = sqlite.pool().begin().await?;
        for chunk in rows.chunks(250) {
            let mut builder = QueryBuilder::<Sqlite>::new(format!(
                "INSERT INTO {DISCOVERY_PACKAGE_TABLE}(resource_did, cursor, version, package_json, updated_at) "
            ));
            builder.push_values(
                chunk,
                |mut row, (resource_did, cursor, version, package_json)| {
                    row.push_bind(resource_did)
                        .push_bind(cursor)
                        .push_bind(version)
                        .push_bind(package_json)
                        .push_bind(&updated_at_text);
                },
            );
            builder.push(
                r#"
                ON CONFLICT(resource_did)
                DO UPDATE SET
                    cursor = excluded.cursor,
                    version = excluded.version,
                    package_json = excluded.package_json,
                    updated_at = excluded.updated_at
                "#,
            );
            builder.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        delete_rejected_packages_by_did(state, &accepted_dids).await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        let projected = packages
            .iter()
            .map(|(cursor, package)| {
                Ok::<_, anyhow::Error>(DiscoveryProjectedPackage {
                    cursor: *cursor,
                    package,
                    package_json: serde_json::to_value(package)?,
                    projection: discovery_package_projection(package),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut tx = postgres.pool().begin().await?;
        for chunk in projected.chunks(250) {
            let mut builder = QueryBuilder::<Postgres>::new(format!(
                r#"
                INSERT INTO {DISCOVERY_PACKAGE_TABLE}(
                    resource_did, cursor, version, resource_type, lifecycle_state,
                    capability_tags, protocols, service_endpoints, tag_text, search_text,
                    package_json, updated_at
                )
                "#
            ));
            builder.push_values(chunk, |mut row, item| {
                row.push_bind(&item.package.resource_did)
                    .push_bind(item.cursor)
                    .push_bind(&item.package.package_version)
                    .push_bind(&item.projection.resource_type)
                    .push_bind(&item.projection.lifecycle_state)
                    .push_bind(&item.projection.capability_tags)
                    .push_bind(&item.projection.protocols)
                    .push_bind(&item.projection.service_endpoints)
                    .push_bind(&item.projection.tag_text)
                    .push_bind(&item.projection.search_text)
                    .push_bind(&item.package_json)
                    .push_bind(updated_at);
            });
            builder.push(
                r#"
                ON CONFLICT(resource_did)
                DO UPDATE SET
                    cursor = excluded.cursor,
                    version = excluded.version,
                    resource_type = excluded.resource_type,
                    lifecycle_state = excluded.lifecycle_state,
                    capability_tags = excluded.capability_tags,
                    protocols = excluded.protocols,
                    service_endpoints = excluded.service_endpoints,
                    tag_text = excluded.tag_text,
                    search_text = excluded.search_text,
                    package_json = excluded.package_json,
                    updated_at = excluded.updated_at
                "#,
            );
            builder.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        delete_rejected_packages_by_did(state, &accepted_dids).await?;
        if semantic_search_available(state) {
            if let Err(err) =
                upsert_semantic_index_batch(state, &projected, SemanticRebuildStage::Both).await
            {
                eprintln!("semantic index upsert failed: {err}");
            }
        }
        return Ok(());
    }
    let mut indexed = read_indexed_resource_packages(state).await?;
    for (_, package) in packages {
        indexed.retain(|candidate| candidate.resource_did != package.resource_did);
        indexed.push(package.clone());
    }
    state.index.write("resource-capabilities.json", &indexed)?;
    delete_rejected_packages_by_did(state, &accepted_dids).await?;
    Ok(())
}

fn latest_resource_packages_by_did(
    packages: &[(i64, ResourcePackage)],
) -> Vec<(i64, ResourcePackage)> {
    let mut latest = BTreeMap::<String, (i64, ResourcePackage)>::new();
    for (cursor, package) in packages {
        latest
            .entry(package.resource_did.clone())
            .and_modify(|existing| {
                if *cursor >= existing.0 {
                    *existing = (*cursor, package.clone());
                }
            })
            .or_insert_with(|| (*cursor, package.clone()));
    }
    latest.into_values().collect()
}

async fn upsert_semantic_index_batch(
    state: &AppState,
    projected: &[DiscoveryProjectedPackage<'_>],
    stage: SemanticRebuildStage,
) -> Result<()> {
    let engine = DiscoverySearchEngine::from_config(&state.config.semantic_search)?;
    engine.upsert_batch(state, projected, stage).await
}

async fn upsert_pgvector_semantic_index_batch(
    state: &AppState,
    projected: &[DiscoveryProjectedPackage<'_>],
    stage: SemanticRebuildStage,
) -> Result<()> {
    let Some(postgres) = &state.postgres else {
        return Ok(());
    };
    if !semantic_search_available(state) || projected.is_empty() {
        return Ok(());
    }

    let updated_at = Utc::now();
    let docs = projected
        .iter()
        .map(|item| search_document_from_package(item.cursor, item.package, &item.projection))
        .collect::<Vec<_>>();
    let existing_hashes = read_semantic_source_hashes(state, &docs).await?;

    for chunk in docs.chunks(100) {
        let changed = chunk
            .iter()
            .filter(|doc| {
                existing_hashes
                    .get(&doc.resource_did)
                    .map(|hash| hash != &doc.semantic_source_hash)
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        if changed.is_empty() {
            continue;
        }
        let mut embedded = Vec::new();
        for doc in changed {
            let embedding = embed_semantic_text(
                &state.config.semantic_search,
                &state.client,
                &semantic_document_text(doc),
            )
            .await?;
            embedded.push((doc, embedding));
        }

        let mut builder = QueryBuilder::<Postgres>::new(format!(
            r#"
            INSERT INTO {DISCOVERY_SEMANTIC_INDEX_TABLE}(
                resource_did, cursor, package_version, did_document_hash, metadata_hash,
                package_hash, resource_type, lifecycle_state, capability_tags, protocols,
                service_endpoints, name, description, examples, use_cases, search_text,
                tag_text,
                semantic_source_hash, embedding, embedding_model, embedding_version, updated_at
            )
            "#
        ));
        builder.push_values(embedded, |mut row, (doc, embedding)| {
            row.push_bind(&doc.resource_did)
                .push_bind(doc.cursor)
                .push_bind(&doc.package_version)
                .push_bind(&doc.did_document_hash)
                .push_bind(&doc.metadata_hash)
                .push_bind(&doc.package_hash)
                .push_bind(&doc.resource_type)
                .push_bind(&doc.lifecycle_state)
                .push_bind(&doc.capability_tags)
                .push_bind(&doc.protocols)
                .push_bind(&doc.service_endpoints)
                .push_bind(&doc.name)
                .push_bind(&doc.description)
                .push_bind(serde_json::to_value(&doc.examples).unwrap_or_else(|_| json!([])))
                .push_bind(serde_json::to_value(&doc.use_cases).unwrap_or_else(|_| json!([])))
                .push_bind(&doc.tag_text)
                .push_bind(&doc.search_text)
                .push_bind(&doc.semantic_source_hash)
                .push(format!("{}::vector", pgvector_literal(&embedding)))
                .push_bind(&state.semantic.embedding_model)
                .push_bind(&state.semantic.embedding_version)
                .push_bind(updated_at);
        });
        builder.push(
            r#"
            ON CONFLICT(resource_did)
            DO UPDATE SET
                cursor = excluded.cursor,
                package_version = excluded.package_version,
                did_document_hash = excluded.did_document_hash,
                metadata_hash = excluded.metadata_hash,
                package_hash = excluded.package_hash,
                resource_type = excluded.resource_type,
                lifecycle_state = excluded.lifecycle_state,
                capability_tags = excluded.capability_tags,
                protocols = excluded.protocols,
                service_endpoints = excluded.service_endpoints,
                name = excluded.name,
                description = excluded.description,
                examples = excluded.examples,
                use_cases = excluded.use_cases,
                tag_text = excluded.tag_text,
                search_text = excluded.search_text,
                semantic_source_hash = excluded.semantic_source_hash,
                embedding = excluded.embedding,
                embedding_model = excluded.embedding_model,
                embedding_version = excluded.embedding_version,
                updated_at = excluded.updated_at
            "#,
        );
        builder.build().execute(postgres.pool()).await?;
    }
    if stage.includes_intent() {
        upsert_pgvector_intent_index_batch(state, &docs).await?;
    }
    Ok(())
}

async fn upsert_pgvector_intent_index_batch(
    state: &AppState,
    docs: &[SearchDocument],
) -> Result<()> {
    let Some(postgres) = &state.postgres else {
        return Ok(());
    };
    if docs.is_empty() {
        return Ok(());
    }
    let updated_at = Utc::now();
    for chunk in docs.chunks(50) {
        let resource_dids = chunk
            .iter()
            .map(|doc| doc.resource_did.clone())
            .collect::<Vec<_>>();
        sqlx::query(&format!(
            "DELETE FROM {DISCOVERY_INTENT_INDEX_TABLE} WHERE resource_did = ANY($1) AND embedding_model = $2 AND embedding_version = $3"
        ))
        .bind(&resource_dids)
        .bind(&state.semantic.embedding_model)
        .bind(&state.semantic.embedding_version)
        .execute(postgres.pool())
        .await?;

        let mut embedded = Vec::new();
        for doc in chunk {
            for intent in semantic_intent_documents(doc) {
                let embedding = embed_semantic_text(
                    &state.config.semantic_search,
                    &state.client,
                    &intent.intent_text,
                )
                .await?;
                embedded.push((intent, embedding));
            }
        }
        if embedded.is_empty() {
            continue;
        }
        let mut builder = QueryBuilder::<Postgres>::new(format!(
            r#"
            INSERT INTO {DISCOVERY_INTENT_INDEX_TABLE}(
                resource_did, intent_id, intent_kind, intent_text, resource_type,
                lifecycle_state, semantic_source_hash, embedding, embedding_model,
                embedding_version, updated_at
            )
            "#
        ));
        builder.push_values(embedded, |mut row, (intent, embedding)| {
            row.push_bind(intent.resource_did)
                .push_bind(intent.intent_id)
                .push_bind(intent.intent_kind)
                .push_bind(intent.intent_text)
                .push_bind(intent.resource_type)
                .push_bind(intent.lifecycle_state)
                .push_bind(intent.semantic_source_hash)
                .push(format!("{}::vector", pgvector_literal(&embedding)))
                .push_bind(&state.semantic.embedding_model)
                .push_bind(&state.semantic.embedding_version)
                .push_bind(updated_at);
        });
        builder.push(
            r#"
            ON CONFLICT(resource_did, intent_id, embedding_model, embedding_version)
            DO UPDATE SET
                intent_kind = excluded.intent_kind,
                intent_text = excluded.intent_text,
                resource_type = excluded.resource_type,
                lifecycle_state = excluded.lifecycle_state,
                semantic_source_hash = excluded.semantic_source_hash,
                embedding = excluded.embedding,
                updated_at = excluded.updated_at
            "#,
        );
        builder.build().execute(postgres.pool()).await?;
    }
    Ok(())
}

async fn read_semantic_source_hashes(
    state: &AppState,
    docs: &[SearchDocument],
) -> Result<BTreeMap<String, String>> {
    let Some(postgres) = &state.postgres else {
        return Ok(BTreeMap::new());
    };
    if docs.is_empty() {
        return Ok(BTreeMap::new());
    }
    let dids = docs
        .iter()
        .map(|doc| doc.resource_did.clone())
        .collect::<Vec<_>>();
    let rows = sqlx::query(&format!(
        "SELECT resource_did, semantic_source_hash FROM {DISCOVERY_SEMANTIC_INDEX_TABLE} WHERE resource_did = ANY($1) AND embedding_model = $2 AND embedding_version = $3"
    ))
    .bind(&dids)
    .bind(&state.semantic.embedding_model)
    .bind(&state.semantic.embedding_version)
    .fetch_all(postgres.pool())
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| (row.get::<String, _>(0), row.get::<String, _>(1)))
        .collect())
}

async fn count_semantic_indexed_resources(state: &AppState) -> Result<Option<i64>> {
    let Some(postgres) = &state.postgres else {
        return Ok(None);
    };
    if !state.semantic.enabled {
        return Ok(None);
    }
    let row = sqlx::query(&format!(
        "SELECT COUNT(*) FROM {DISCOVERY_SEMANTIC_INDEX_TABLE} WHERE embedding_model = $1 AND embedding_version = $2"
    ))
    .bind(&state.semantic.embedding_model)
    .bind(&state.semantic.embedding_version)
    .fetch_one(postgres.pool())
    .await?;
    Ok(Some(row.get::<i64, _>(0)))
}

async fn count_intent_indexed_rows(state: &AppState) -> Result<Option<i64>> {
    let Some(postgres) = &state.postgres else {
        return Ok(None);
    };
    if !state.semantic.enabled {
        return Ok(None);
    }
    let row = sqlx::query(&format!(
        "SELECT COUNT(*) FROM {DISCOVERY_INTENT_INDEX_TABLE} WHERE embedding_model = $1 AND embedding_version = $2"
    ))
    .bind(&state.semantic.embedding_model)
    .bind(&state.semantic.embedding_version)
    .fetch_one(postgres.pool())
    .await?;
    Ok(Some(row.get::<i64, _>(0)))
}

async fn clear_semantic_indexes_for_current_model(
    state: &AppState,
    stage: SemanticRebuildStage,
) -> Result<()> {
    let Some(postgres) = &state.postgres else {
        return Ok(());
    };
    if stage.includes_intent() {
        sqlx::query(&format!(
            "DELETE FROM {DISCOVERY_INTENT_INDEX_TABLE} WHERE embedding_model = $1 AND embedding_version = $2"
        ))
        .bind(&state.semantic.embedding_model)
        .bind(&state.semantic.embedding_version)
        .execute(postgres.pool())
        .await?;
    }
    if stage.includes_context() {
        sqlx::query(&format!(
            "DELETE FROM {DISCOVERY_SEMANTIC_INDEX_TABLE} WHERE embedding_model = $1 AND embedding_version = $2"
        ))
        .bind(&state.semantic.embedding_model)
        .bind(&state.semantic.embedding_version)
        .execute(postgres.pool())
        .await?;
    }
    Ok(())
}

async fn rebuild_semantic_indexes(
    state: &AppState,
    reset: bool,
    stage: SemanticRebuildStage,
) -> Result<SemanticRebuildReport> {
    if !semantic_search_available(state) {
        return Ok(SemanticRebuildReport {
            stage: stage.as_str().to_owned(),
            phase: "skipped".to_owned(),
            backend: discovery_backend_name(state),
            semantic_enabled: false,
            package_count: 0,
            context_indexed_count: 0,
            intent_indexed_count: 0,
            skipped_packages: 0,
            recovered_packages: 0,
            retries: 0,
            last_cursor: None,
            safe_to_delete_old_indexes: false,
            skipped_reason: state.semantic.fallback_reason.clone(),
        });
    }
    let packages = read_indexed_resource_packages(state).await?;
    let visible = packages
        .iter()
        .enumerate()
        .map(|(index, package)| (index as i64 + 1, package))
        .filter(|(_, package)| {
            package.metadata.lifecycle_state == "active"
                && is_user_consumable_resource_type(&package.resource_type)
        })
        .collect::<Vec<_>>();
    let progress = if reset {
        None
    } else {
        load_semantic_rebuild_progress(state, stage).await?
    };
    let mut skipped_packages = 0usize;
    let mut retries = 0usize;
    let mut last_cursor = None;
    let mut index = progress
        .as_ref()
        .and_then(|record| {
            visible
                .iter()
                .position(|(cursor, _)| Some(*cursor) == record.last_cursor)
                .map(|pos| pos + 1)
        })
        .unwrap_or(0usize);
    let mut batch_size = state.config.semantic_search.embedding.batch_size.max(1);
    if index > 0 {
        skipped_packages = 0;
        retries = 0;
    } else {
        clear_semantic_indexes_for_current_model(state, stage).await?;
        clear_semantic_rebuild_progress(state, stage).await?;
        clear_semantic_rebuild_skip_records(state, Some(stage)).await?;
    }
    while index < visible.len() {
        let end = (index + batch_size).min(visible.len());
        let projected = visible[index..end]
            .iter()
            .map(|(cursor, package)| DiscoveryProjectedPackage {
                cursor: *cursor,
                package,
                package_json: serde_json::to_value(package).unwrap_or_else(|_| json!({})),
                projection: discovery_package_projection(package),
            })
            .collect::<Vec<_>>();
        match upsert_semantic_index_batch(state, &projected, stage).await {
            Ok(()) => {
                last_cursor = projected.last().map(|item| item.cursor);
                index = end;
                store_semantic_rebuild_progress(
                    state,
                    stage,
                    "running",
                    last_cursor,
                    index,
                    visible.len(),
                    skipped_packages,
                    retries,
                    batch_size,
                )
                .await?;
            }
            Err(err) => {
                if is_embedding_timeout_error(&err) && batch_size > 1 {
                    retries += 1;
                    batch_size = (batch_size / 2).max(1);
                    store_semantic_rebuild_progress(
                        state,
                        stage,
                        "throttled",
                        last_cursor,
                        index,
                        visible.len(),
                        skipped_packages,
                        retries,
                        batch_size,
                    )
                    .await?;
                    continue;
                }
                if let Some(failed) = projected.first() {
                    skipped_packages += 1;
                    index = end;
                    last_cursor = Some(failed.cursor);
                    store_semantic_rebuild_skip(
                        state,
                        stage,
                        failed.cursor,
                        failed.package.resource_did.clone(),
                        err.to_string(),
                    )
                    .await?;
                    store_semantic_rebuild_progress(
                        state,
                        stage,
                        "skip",
                        last_cursor,
                        index,
                        visible.len(),
                        skipped_packages,
                        retries,
                        batch_size,
                    )
                    .await?;
                    continue;
                }
                return Err(err);
            }
        }
    }
    let final_phase = if skipped_packages == 0 {
        "completed"
    } else {
        "completed-with-skips"
    };
    store_semantic_rebuild_progress(
        state,
        stage,
        final_phase,
        last_cursor,
        index,
        visible.len(),
        skipped_packages,
        retries,
        batch_size,
    )
    .await?;
    Ok(SemanticRebuildReport {
        phase: final_phase.to_owned(),
        stage: stage.as_str().to_owned(),
        backend: discovery_backend_name(state),
        semantic_enabled: true,
        package_count: visible.len(),
        context_indexed_count: count_semantic_indexed_resources(state)
            .await?
            .unwrap_or_default() as usize,
        intent_indexed_count: count_intent_indexed_rows(state).await?.unwrap_or_default() as usize,
        skipped_packages,
        recovered_packages: 0,
        retries,
        last_cursor,
        safe_to_delete_old_indexes: skipped_packages == 0 && matches!(stage, SemanticRebuildStage::Both),
        skipped_reason: None,
    })
}

async fn backfill_skipped_semantic_indexes(
    state: &AppState,
    stage: SemanticRebuildStage,
) -> Result<SemanticRebuildReport> {
    if !semantic_search_available(state) {
        return Ok(SemanticRebuildReport {
            stage: stage.as_str().to_owned(),
            phase: "skipped".to_owned(),
            backend: discovery_backend_name(state),
            semantic_enabled: false,
            package_count: 0,
            context_indexed_count: 0,
            intent_indexed_count: 0,
            skipped_packages: 0,
            recovered_packages: 0,
            retries: 0,
            last_cursor: None,
            safe_to_delete_old_indexes: false,
            skipped_reason: state.semantic.fallback_reason.clone(),
        });
    }

    let skipped = load_semantic_rebuild_skip_records(state, Some(stage)).await?;
    if skipped.is_empty() {
        return Ok(SemanticRebuildReport {
            stage: stage.as_str().to_owned(),
            phase: "completed".to_owned(),
            backend: discovery_backend_name(state),
            semantic_enabled: true,
            package_count: 0,
            context_indexed_count: count_semantic_indexed_resources(state)
                .await?
                .unwrap_or_default() as usize,
            intent_indexed_count: count_intent_indexed_rows(state).await?.unwrap_or_default() as usize,
            skipped_packages: 0,
            recovered_packages: 0,
            retries: 0,
            last_cursor: None,
        safe_to_delete_old_indexes: matches!(stage, SemanticRebuildStage::Both),
        skipped_reason: None,
        });
    }

    let indexed = read_indexed_resource_packages(state).await?;
    let by_did = indexed
        .into_iter()
        .map(|package| (package.resource_did.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let mut recovered = 0usize;
    let mut skipped_packages = 0usize;
    let mut retries = 0usize;
    let mut last_cursor = None;

    for record in skipped {
        if let Some(package) = by_did.get(&record.resource_did) {
            let cursor = record.cursor.max(1);
            let projected = DiscoveryProjectedPackage {
                cursor,
                package,
                package_json: serde_json::to_value(package).unwrap_or_else(|_| json!({})),
                projection: discovery_package_projection(package),
            };
            match upsert_semantic_index_batch(state, &[projected], stage).await {
                Ok(()) => {
                    recovered += 1;
                    last_cursor = Some(cursor);
                    clear_semantic_rebuild_skip_record(state, stage, &record.resource_did).await?;
                }
                Err(err) => {
                    skipped_packages += 1;
                    retries += 1;
                    store_semantic_rebuild_skip(
                        state,
                        stage,
                        cursor,
                        record.resource_did.clone(),
                        err.to_string(),
                    )
                    .await?;
                }
            }
        }
    }

    Ok(SemanticRebuildReport {
        stage: stage.as_str().to_owned(),
        phase: "backfilled".to_owned(),
        backend: discovery_backend_name(state),
        semantic_enabled: true,
        package_count: recovered,
        context_indexed_count: count_semantic_indexed_resources(state)
            .await?
            .unwrap_or_default() as usize,
        intent_indexed_count: count_intent_indexed_rows(state).await?.unwrap_or_default() as usize,
        skipped_packages,
        recovered_packages: recovered,
        retries,
        last_cursor,
        safe_to_delete_old_indexes: skipped_packages == 0 && matches!(stage, SemanticRebuildStage::Both),
        skipped_reason: None,
    })
}

async fn clear_semantic_rebuild_progress(
    state: &AppState,
    stage: SemanticRebuildStage,
) -> Result<()> {
    clear_discovery_sync_state_like(state, &format!("semantic_rebuild_progress:{}%", stage.as_str())).await
}

async fn clear_semantic_rebuild_skip_records(
    state: &AppState,
    stage: Option<SemanticRebuildStage>,
) -> Result<()> {
    clear_discovery_sync_state_like(state, &format!("{}%", semantic_rebuild_skip_prefix(stage))).await
}

async fn store_semantic_rebuild_progress(
    state: &AppState,
    stage: SemanticRebuildStage,
    phase: &str,
    last_cursor: Option<i64>,
    processed: usize,
    total: usize,
    skipped_packages: usize,
    retries: usize,
    batch_size: usize,
) -> Result<()> {
    let record = SemanticRebuildProgressRecord {
        stage: stage.as_str().to_owned(),
        phase: phase.to_owned(),
        last_cursor,
        processed,
        total,
        skipped_packages,
        retries,
        batch_size,
        updated_at: Utc::now().to_rfc3339(),
    };
    upsert_discovery_sync_state(state, &semantic_rebuild_progress_key(stage), &record).await
}

async fn store_semantic_rebuild_skip(
    state: &AppState,
    stage: SemanticRebuildStage,
    cursor: i64,
    resource_did: String,
    reason: String,
) -> Result<()> {
    let record = SemanticRebuildSkipRecord {
        stage: stage.as_str().to_owned(),
        resource_did,
        cursor,
        reason,
        updated_at: Utc::now().to_rfc3339(),
    };
    upsert_discovery_sync_state(
        state,
        &format!("semantic_rebuild_skip:{}:{cursor}", stage.as_str()),
        &record,
    )
    .await
}

async fn clear_semantic_rebuild_skip_record(
    state: &AppState,
    stage: SemanticRebuildStage,
    resource_did: &str,
) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!(
            "DELETE FROM {DISCOVERY_SYNC_STATE_TABLE} WHERE sync_key LIKE ? AND json_extract(sync_value, '$.resourceDid') = ?"
        ))
        .bind(format!("semantic_rebuild_skip:{}:%", stage.as_str()))
        .bind(resource_did)
        .execute(sqlite.pool())
        .await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        sqlx::query(&format!(
            "DELETE FROM {DISCOVERY_SYNC_STATE_TABLE} WHERE sync_key LIKE $1 AND sync_value->>'resourceDid' = $2"
        ))
        .bind(format!("semantic_rebuild_skip:{}:%", stage.as_str()))
        .bind(resource_did)
        .execute(postgres.pool())
        .await?;
    }
    Ok(())
}

async fn load_semantic_rebuild_skip_records(
    state: &AppState,
    stage: Option<SemanticRebuildStage>,
) -> Result<Vec<SemanticRebuildSkipRecord>> {
    let prefix = semantic_rebuild_skip_prefix(stage);
    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            "SELECT sync_value FROM {DISCOVERY_SYNC_STATE_TABLE} WHERE sync_key LIKE ? ORDER BY sync_key"
        ))
        .bind(format!("{prefix}%"))
        .fetch_all(sqlite.pool())
        .await?;
        return Ok(rows
            .into_iter()
            .filter_map(|row| {
                serde_json::from_str::<SemanticRebuildSkipRecord>(&row.get::<String, _>(0)).ok()
            })
            .collect());
    }
    if let Some(postgres) = &state.postgres {
        let rows = sqlx::query(&format!(
            "SELECT sync_value::text FROM {DISCOVERY_SYNC_STATE_TABLE} WHERE sync_key LIKE $1 ORDER BY sync_key"
        ))
        .bind(format!("{prefix}%"))
        .fetch_all(postgres.pool())
        .await?;
        return Ok(rows
            .into_iter()
            .filter_map(|row| {
                serde_json::from_str::<SemanticRebuildSkipRecord>(&row.get::<String, _>(0)).ok()
            })
            .collect());
    }
    Ok(vec![])
}

async fn clear_discovery_sync_state_like(state: &AppState, pattern: &str) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!(
            "DELETE FROM {DISCOVERY_SYNC_STATE_TABLE} WHERE sync_key LIKE ?"
        ))
        .bind(pattern)
        .execute(sqlite.pool())
        .await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        sqlx::query(&format!(
            "DELETE FROM {DISCOVERY_SYNC_STATE_TABLE} WHERE sync_key LIKE $1"
        ))
        .bind(pattern)
        .execute(postgres.pool())
        .await?;
        return Ok(());
    }
    Ok(())
}

async fn load_semantic_rebuild_progress(
    state: &AppState,
    stage: SemanticRebuildStage,
) -> Result<Option<SemanticRebuildProgressRecord>> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            "SELECT sync_value FROM {DISCOVERY_SYNC_STATE_TABLE} WHERE sync_key = ?"
        ))
        .bind(semantic_rebuild_progress_key(stage))
        .fetch_optional(sqlite.pool())
        .await?;
        if let Some(row) = row {
            let value = row.get::<String, _>(0);
            return Ok(serde_json::from_str::<SemanticRebuildProgressRecord>(&value).ok());
        }
        return Ok(None);
    }
    if let Some(postgres) = &state.postgres {
        let row = sqlx::query(&format!(
            "SELECT sync_value::text FROM {DISCOVERY_SYNC_STATE_TABLE} WHERE sync_key = $1"
        ))
        .bind(semantic_rebuild_progress_key(stage))
        .fetch_optional(postgres.pool())
        .await?;
        if let Some(row) = row {
            let value = row.get::<String, _>(0);
            return Ok(serde_json::from_str::<SemanticRebuildProgressRecord>(&value).ok());
        }
        return Ok(None);
    }
    Ok(None)
}

async fn upsert_discovery_sync_state<T: Serialize>(
    state: &AppState,
    key: &str,
    value: &T,
) -> Result<()> {
    let payload = serde_json::to_value(value)?;
    let updated_at = Utc::now();
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!(
            r#"
            INSERT INTO {DISCOVERY_SYNC_STATE_TABLE}(state_key, state_value, sync_key, sync_value, updated_at)
            VALUES (?1, ?2, ?1, ?2, ?3)
            ON CONFLICT(state_key)
            DO UPDATE SET
                state_value = excluded.state_value,
                sync_key = excluded.sync_key,
                sync_value = excluded.sync_value,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(key)
        .bind(payload.to_string())
        .bind(updated_at)
        .execute(sqlite.pool())
        .await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        sqlx::query(&format!(
            r#"
            INSERT INTO {DISCOVERY_SYNC_STATE_TABLE}(state_key, state_value, sync_key, sync_value, updated_at)
            VALUES ($1, $2::jsonb, $1, $2::jsonb, $3)
            ON CONFLICT(state_key)
            DO UPDATE SET
                state_value = excluded.state_value,
                sync_key = excluded.sync_key,
                sync_value = excluded.sync_value,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(key)
        .bind(payload.to_string())
        .bind(updated_at)
        .execute(postgres.pool())
        .await?;
        return Ok(());
    }
    Ok(())
}

fn is_embedding_timeout_error(err: &anyhow::Error) -> bool {
    let text = err.to_string().to_ascii_lowercase();
    text.contains("timed out") || text.contains("timeout")
}

fn discovery_package_projection(package: &ResourcePackage) -> DiscoveryPackageProjection {
    let mut protocols = package
        .metadata
        .protocol_bindings
        .iter()
        .filter_map(|binding| binding["protocol"].as_str())
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    protocols.extend(
        package
            .metadata
            .services
            .iter()
            .filter_map(|service| service.protocol.as_ref())
            .map(|value| value.to_ascii_lowercase()),
    );
    protocols.sort();
    protocols.dedup();

    let mut service_endpoints = package
        .metadata
        .services
        .iter()
        .map(|service| service.service_endpoint.clone())
        .collect::<Vec<_>>();
    service_endpoints.sort();
    service_endpoints.dedup();

    let search_text = semantic_search_text(&[
        package.resource_did.clone(),
        package.resource_type.as_str().to_owned(),
        package.metadata.name.clone(),
        package.metadata.description.clone(),
        package.metadata.capability_tags.join(" "),
        protocols.join(" "),
        service_endpoints.join(" "),
    ]);
    let tag_text = semantic_search_text(&[
        package.resource_did.clone(),
        package.resource_type.as_str().to_owned(),
        package.metadata.capability_tags.join(" "),
        protocols.join(" "),
        service_endpoints.join(" "),
    ]);

    DiscoveryPackageProjection {
        resource_type: package.resource_type.as_str().to_owned(),
        lifecycle_state: package.metadata.lifecycle_state.clone(),
        capability_tags: package.metadata.capability_tags.clone(),
        protocols,
        service_endpoints,
        tag_text,
        search_text,
    }
}

async fn count_indexed_resource_packages(state: &AppState) -> Result<usize> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!("SELECT COUNT(*) FROM {DISCOVERY_PACKAGE_TABLE}"))
            .fetch_one(sqlite.pool())
            .await?;
        return Ok(row.get::<i64, _>(0) as usize);
    }
    if let Some(postgres) = &state.postgres {
        let row = sqlx::query(&format!("SELECT COUNT(*) FROM {DISCOVERY_PACKAGE_TABLE}"))
            .fetch_one(postgres.pool())
            .await?;
        return Ok(row.get::<i64, _>(0) as usize);
    }
    Ok(state
        .index
        .read::<Vec<ResourcePackage>>("resource-capabilities.json")
        .unwrap_or_default()
        .len())
}

async fn read_indexed_resource_package(
    state: &AppState,
    did: &str,
) -> Result<Option<ResourcePackage>> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            "SELECT package_json FROM {DISCOVERY_PACKAGE_TABLE} WHERE resource_did = ?"
        ))
        .bind(did)
        .fetch_optional(sqlite.pool())
        .await?;
        return row
            .map(|row| {
                serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0))
                    .map_err(anyhow::Error::from)
            })
            .transpose();
    }
    if let Some(postgres) = &state.postgres {
        let row = sqlx::query(&format!(
            "SELECT package_json::text FROM {DISCOVERY_PACKAGE_TABLE} WHERE resource_did = $1"
        ))
        .bind(did)
        .fetch_optional(postgres.pool())
        .await?;
        return row
            .map(|row| {
                serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0))
                    .map_err(anyhow::Error::from)
            })
            .transpose();
    }
    Ok(state
        .index
        .read::<Vec<ResourcePackage>>("resource-capabilities.json")
        .unwrap_or_default()
        .into_iter()
        .find(|package| package.resource_did == did))
}

async fn indexed_resource_visibility(state: &AppState, dids: &[String]) -> Result<Vec<String>> {
    if dids.is_empty() {
        return Ok(Vec::new());
    }
    if let Some(sqlite) = &state.sqlite {
        let mut visible = Vec::new();
        for chunk in dids.chunks(500) {
            let mut builder = QueryBuilder::<Sqlite>::new(format!(
                "SELECT resource_did FROM {DISCOVERY_PACKAGE_TABLE} WHERE resource_did IN ("
            ));
            let mut separated = builder.separated(", ");
            for did in chunk {
                separated.push_bind(did);
            }
            separated.push_unseparated(")");
            let rows = builder.build().fetch_all(sqlite.pool()).await?;
            visible.extend(rows.into_iter().map(|row| row.get::<String, _>(0)));
        }
        return Ok(visible);
    }
    if let Some(postgres) = &state.postgres {
        let rows = sqlx::query(&format!(
            "SELECT resource_did FROM {DISCOVERY_PACKAGE_TABLE} WHERE resource_did = ANY($1)"
        ))
        .bind(dids)
        .fetch_all(postgres.pool())
        .await?;
        return Ok(rows
            .into_iter()
            .map(|row| row.get::<String, _>(0))
            .collect());
    }
    let visible = state
        .index
        .read::<Vec<ResourcePackage>>("resource-capabilities.json")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|package| {
            dids.iter()
                .any(|did| did == &package.resource_did)
                .then_some(package.resource_did)
        })
        .collect();
    Ok(visible)
}

async fn query_indexed_resource_packages(
    state: &AppState,
    query: &ResourceDiscoveryQuery,
) -> Result<(Vec<ResourcePackage>, bool)> {
    if let Some(postgres) = &state.postgres {
        let mut builder: QueryBuilder<Postgres> = QueryBuilder::new(format!(
            "SELECT package_json::text FROM {DISCOVERY_PACKAGE_TABLE} WHERE lifecycle_state = "
        ));
        builder.push_bind("active");
        if let Some(resource_type) = &query.resource_type {
            builder.push(" AND resource_type = ");
            builder.push_bind(resource_type.as_str());
        } else {
            builder.push(" AND resource_type = ANY(");
            builder.push_bind(default_discoverable_resource_type_names());
            builder.push(")");
        }
        if let Some(version) = &query.version {
            builder.push(" AND version = ");
            builder.push_bind(version);
        }
        if !query.capability_tags.is_empty() {
            builder.push(" AND capability_tags @> ");
            builder.push_bind(query.capability_tags.clone());
        }
        if let Some(protocol) = &query.protocol {
            builder.push(" AND protocols && ");
            builder.push_bind(vec![protocol.to_ascii_lowercase()]);
        }
        let tag_tokens = semantic_query_tag_tokens(query);
        let query_text = query.query.as_ref().map(|value| value.trim()).filter(|value| !value.is_empty());
        if query_text.is_some() {
            let text = query_text.expect("checked query text");
            builder.push(" AND (");
            builder.push("to_tsvector('simple', tag_text) @@ plainto_tsquery('simple', ");
            builder.push_bind(text.to_ascii_lowercase());
            builder.push(") OR to_tsvector('simple', search_text) @@ plainto_tsquery('simple', ");
            builder.push_bind(text.to_ascii_lowercase());
            builder.push("))");
        }
        if !tag_tokens.is_empty() {
            builder.push(" ORDER BY ");
            builder.push(
                "ts_rank_cd(to_tsvector('simple', tag_text), plainto_tsquery('simple', ",
            );
            if let Some(text) = query_text {
                builder.push_bind(text.to_ascii_lowercase());
            } else {
                builder.push_bind(tag_tokens.join(" "));
            }
            builder.push(")) DESC, ");
            builder.push(
                "ts_rank_cd(to_tsvector('simple', search_text), plainto_tsquery('simple', ",
            );
            if let Some(text) = query_text {
                builder.push_bind(text.to_ascii_lowercase());
            } else {
                builder.push_bind(tag_tokens.join(" "));
            }
            builder.push(")) DESC, updated_at DESC, resource_did LIMIT ");
        } else if should_use_sql_text_prefilter(query) {
            let text = query.query.as_ref().expect("checked query text");
            builder.push(
                " ORDER BY ts_rank_cd(to_tsvector('simple', search_text), plainto_tsquery('simple', ",
            );
            builder.push_bind(text.to_ascii_lowercase());
            builder.push(")) DESC, updated_at DESC, resource_did LIMIT ");
        } else {
            builder.push(" ORDER BY updated_at DESC, resource_did LIMIT ");
        }
        builder.push_bind(discovery_sql_candidate_limit_for_query(query));
        let rows = builder.build().fetch_all(postgres.pool()).await?;
        let packages = rows
            .into_iter()
            .map(|row| serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0)))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        return Ok((filter_packages_for_local_discovery(state, packages)?, true));
    }
    read_indexed_resource_packages(state)
        .await
        .and_then(|packages| {
            let packages = packages
                .into_iter()
                .filter(|package| should_search_resource_type(package, query))
                .collect::<Vec<_>>();
            Ok((filter_packages_for_local_discovery(state, packages)?, false))
        })
}

async fn query_semantic_index(
    state: &AppState,
    query: &ResourceDiscoveryQuery,
) -> Result<Option<Vec<SemanticQueryHit>>> {
    if !semantic_search_available(state) {
        return Ok(None);
    }
    let engine = DiscoverySearchEngine::from_config(&state.config.semantic_search)?;
    engine.query(state, query).await
}

async fn query_pgvector_semantic_index(
    state: &AppState,
    query: &ResourceDiscoveryQuery,
) -> Result<Option<Vec<SemanticQueryHit>>> {
    if !semantic_search_available(state) {
        return Ok(None);
    }
    let Some(text) = query
        .query
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let Some(postgres) = &state.postgres else {
        return Ok(None);
    };

    let query_embedding =
        embed_semantic_text(&state.config.semantic_search, &state.client, text).await?;
    let candidate_limit = semantic_candidate_limit(query.limit, &state.config.semantic_search);
    let mut builder = QueryBuilder::<Postgres>::new(format!(
        r#"
        SELECT
            p.package_json::text,
            (1 - (s.embedding <=> {}::vector))::float4 AS semantic_score
        FROM {DISCOVERY_SEMANTIC_INDEX_TABLE} s
        JOIN {DISCOVERY_PACKAGE_TABLE} p ON p.resource_did = s.resource_did
        WHERE p.lifecycle_state = 
        "#,
        pgvector_literal(&query_embedding),
    ));
    builder.push_bind("active");
    builder.push(" AND s.lifecycle_state = ");
    builder.push_bind("active");
    builder.push(" AND s.embedding_model = ");
    builder.push_bind(&state.semantic.embedding_model);
    builder.push(" AND s.embedding_version = ");
    builder.push_bind(&state.semantic.embedding_version);

    if let Some(resource_type) = &query.resource_type {
        builder.push(" AND p.resource_type = ");
        builder.push_bind(resource_type.as_str());
    } else {
        builder.push(" AND p.resource_type = ANY(");
        builder.push_bind(default_discoverable_resource_type_names());
        builder.push(")");
    }
    if let Some(version) = &query.version {
        builder.push(" AND p.version = ");
        builder.push_bind(version);
    }
    if !query.capability_tags.is_empty()
        && state
            .config
            .semantic_search
            .filters
            .capability_tags
            .eq_ignore_ascii_case("hard")
    {
        builder.push(" AND p.capability_tags @> ");
        builder.push_bind(query.capability_tags.clone());
    }
    if let Some(protocol) = &query.protocol {
        if state
            .config
            .semantic_search
            .filters
            .protocol
            .eq_ignore_ascii_case("hard")
        {
            builder.push(" AND p.protocols && ");
            builder.push_bind(vec![protocol.to_ascii_lowercase()]);
        }
    }
    builder.push(format!(
        " ORDER BY s.embedding <=> {}::vector LIMIT ",
        pgvector_literal(&query_embedding)
    ));
    builder.push_bind(candidate_limit);

    let rows = builder.build().fetch_all(postgres.pool()).await?;
    let vector_hits = rows
        .into_iter()
        .map(|row| {
            let package = serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0))?;
            let vector_score = row.get::<f32, _>(1).clamp(0.0, 1.0);
            Ok::<_, anyhow::Error>((package, vector_score))
        })
        .collect::<Result<Vec<_>>>()?;
    let (lexical_packages, _) = query_indexed_resource_packages(state, query).await?;
    let mut hits = hybrid_semantic_hits(vector_hits, lexical_packages, query);
    if let Err(err) = apply_pgvector_intent_maxsim(state, &query_embedding, &mut hits).await {
        eprintln!("intent maxsim rerank skipped: {err}");
    }
    let allowed_domains = local_discovery_authorized_domains(state)?;
    hits.retain(|hit| {
        authorized_domains_cover(&allowed_domains, &hit.package.metadata.authorized_domains)
    });
    hits.sort_by(|a, b| b.final_score.total_cmp(&a.final_score));
    hits.truncate(query.limit as usize);
    Ok(Some(hits))
}

async fn apply_pgvector_intent_maxsim(
    state: &AppState,
    query_embedding: &[f32],
    hits: &mut [SemanticQueryHit],
) -> Result<()> {
    let Some(postgres) = &state.postgres else {
        return Ok(());
    };
    if hits.is_empty() {
        return Ok(());
    }
    let dids = hits
        .iter()
        .map(|hit| hit.package.resource_did.clone())
        .collect::<Vec<_>>();
    let rows = sqlx::query(&format!(
        r#"
        SELECT resource_did, intent_text, intent_score
        FROM (
            SELECT
                resource_did,
                intent_text,
                (1 - (embedding <=> {}::vector))::float4 AS intent_score,
                ROW_NUMBER() OVER (
                    PARTITION BY resource_did
                    ORDER BY embedding <=> {}::vector
                ) AS rank
            FROM {DISCOVERY_INTENT_INDEX_TABLE}
            WHERE resource_did = ANY($1)
              AND lifecycle_state = 'active'
              AND embedding_model = $2
              AND embedding_version = $3
        ) ranked
        WHERE rank = 1
        "#,
        pgvector_literal(query_embedding),
        pgvector_literal(query_embedding),
    ))
    .bind(&dids)
    .bind(&state.semantic.embedding_model)
    .bind(&state.semantic.embedding_version)
    .fetch_all(postgres.pool())
    .await?;

    let maxsim_by_did = rows
        .into_iter()
        .map(|row| {
            (
                row.get::<String, _>("resource_did"),
                (
                    row.get::<f32, _>("intent_score").clamp(0.0, 1.0),
                    row.get::<String, _>("intent_text"),
                ),
            )
        })
        .collect::<HashMap<_, _>>();

    for hit in hits {
        if let Some((intent_score, intent_text)) = maxsim_by_did.get(&hit.package.resource_did) {
            if *intent_score > hit.intent_score {
                hit.intent_score = *intent_score;
                hit.matched_intent = Some(intent_text.clone());
                hit.semantic_score =
                    (0.80 * hit.semantic_score + 0.20 * intent_score).clamp(0.0, 1.0);
                hit.final_score =
                    (hit.semantic_score + hit.structured_score + 0.03).clamp(0.0, 1.0);
            }
        }
    }
    Ok(())
}

fn hybrid_semantic_hits(
    vector_hits: Vec<(ResourcePackage, f32)>,
    lexical_packages: Vec<ResourcePackage>,
    query: &ResourceDiscoveryQuery,
) -> Vec<SemanticQueryHit> {
    let query_projection = semantic_query_projection(query);
    let mut vector_scores = HashMap::new();
    let mut packages = Vec::new();
    let mut seen = HashSet::new();
    for (package, vector_score) in vector_hits {
        vector_scores.insert(package.resource_did.clone(), vector_score.clamp(0.0, 1.0));
        if seen.insert(package.resource_did.clone()) {
            packages.push(package);
        }
    }
    for package in lexical_packages {
        if seen.insert(package.resource_did.clone()) {
            packages.push(package);
        }
    }
    let doc_tokens = packages
        .iter()
        .map(|package| {
            let projection = discovery_package_projection(package);
            let doc = search_document_from_package(0, package, &projection);
            semantic_tokens(&semantic_context_text(&doc))
        })
        .collect::<Vec<_>>();
    let mut hits = packages
        .into_iter()
        .enumerate()
        .map(|(index, package)| {
            let vector_score = vector_scores
                .get(&package.resource_did)
                .copied()
                .unwrap_or(0.0);
            let bm25_score = bm25_like_score(&query_projection.expanded_tokens, &doc_tokens, index);
            let mut hit = semantic_resource_scores(&package, query, &query_projection, bm25_score);
            hit.semantic_score = (0.45 * vector_score) + (0.55 * hit.semantic_score);
            hit.final_score = (hit.semantic_score + hit.structured_score + 0.03).clamp(0.0, 1.0);
            hit
        })
        .filter(|hit| resource_matches_explicit_constraints(&hit.package, query))
        .collect::<Vec<_>>();
    hits.sort_by(|a, b| b.final_score.total_cmp(&a.final_score));
    hits.truncate(query.limit as usize);
    hits
}

fn filter_packages_for_local_discovery(
    state: &AppState,
    packages: Vec<ResourcePackage>,
) -> Result<Vec<ResourcePackage>> {
    let allowed_domains = local_discovery_authorized_domains(state)?;
    Ok(packages
        .into_iter()
        .filter(|package| {
            authorized_domains_cover(&allowed_domains, &package.metadata.authorized_domains)
        })
        .collect())
}

fn local_discovery_authorized_domains(state: &AppState) -> Result<Vec<String>> {
    let document: DidDocument = state.data.read("did-document.json")?;
    let domains = document
        .oan_metadata
        .as_ref()
        .map(|metadata| metadata.authorized_domains.clone())
        .unwrap_or_default();
    validate_authorized_domain_list(&domains).map_err(anyhow::Error::msg)?;
    Ok(domains)
}

fn validate_authorized_domain_list(domains: &[String]) -> std::result::Result<(), String> {
    if domains.iter().any(|domain| domain == "*") {
        return if domains.len() == 1 {
            Ok(())
        } else {
            Err("invalid_authorized_domains".to_owned())
        };
    }
    for domain in domains {
        if domain.trim().is_empty()
            || domain != domain.trim()
            || domain.contains("..")
            || domain.starts_with('.')
            || domain.ends_with('.')
        {
            return Err("invalid_authorized_domains".to_owned());
        }
    }
    if domains.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("invalid_authorized_domains".to_owned());
    }
    Ok(())
}

fn authorized_domain_covers(granted: &str, requested: &str) -> bool {
    granted == requested
        || requested
            .strip_prefix(granted)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn authorized_domains_cover(granted: &[String], requested: &[String]) -> bool {
    if requested.is_empty() {
        return false;
    }
    if granted.iter().any(|domain| domain == "*") {
        return true;
    }
    if granted.is_empty() {
        return false;
    }
    requested.iter().all(|requested_domain| {
        granted
            .iter()
            .any(|granted_domain| authorized_domain_covers(granted_domain, requested_domain))
    })
}

fn semantic_candidate_limit(query_limit: u32, config: &SemanticSearchConfig) -> i64 {
    let requested = query_limit.max(1);
    let expanded = requested.saturating_mul(config.candidate_multiplier.max(1));
    expanded
        .max(25)
        .min(config.max_candidates.max(requested))
        .max(requested) as i64
}

fn discovery_sql_candidate_limit(query_limit: u32) -> i64 {
    let requested = query_limit.max(1) as i64;
    (requested * 3).clamp(25, 5_000).max(requested)
}

fn discovery_sql_candidate_limit_for_query(query: &ResourceDiscoveryQuery) -> i64 {
    if should_use_sql_text_prefilter(query) {
        return discovery_sql_candidate_limit(query.limit);
    }
    let requested = query.limit.max(1) as i64;
    (requested * 50).clamp(200, 5_000).max(requested)
}

async fn read_indexed_resource_packages(state: &AppState) -> Result<Vec<ResourcePackage>> {
    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            "SELECT package_json FROM {DISCOVERY_PACKAGE_TABLE} ORDER BY updated_at, resource_did"
        ))
        .fetch_all(sqlite.pool())
        .await?;
        if !rows.is_empty() {
            let packages = rows
                .into_iter()
                .map(|row| serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0)))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            return Ok(packages);
        }
    }
    if let Some(postgres) = &state.postgres {
        let rows = sqlx::query(&format!(
            "SELECT package_json::text FROM {DISCOVERY_PACKAGE_TABLE} ORDER BY updated_at, resource_did"
        ))
        .fetch_all(postgres.pool())
        .await?;
        if !rows.is_empty() {
            let packages = rows
                .into_iter()
                .map(|row| serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0)))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            return Ok(packages);
        }
    }
    Ok(state
        .index
        .read("resource-capabilities.json")
        .unwrap_or_default())
}

async fn write_indexed_resource_packages(
    state: &AppState,
    packages: &[ResourcePackage],
) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!("DELETE FROM {DISCOVERY_PACKAGE_TABLE}"))
            .execute(sqlite.pool())
            .await?;
        let items = packages
            .iter()
            .enumerate()
            .map(|(cursor, package)| (cursor as i64 + 1, package.clone()))
            .collect::<Vec<_>>();
        upsert_indexed_resource_packages_batch(state, &items).await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        sqlx::query(&format!("DELETE FROM {DISCOVERY_PACKAGE_TABLE}"))
            .execute(postgres.pool())
            .await?;
        let items = packages
            .iter()
            .enumerate()
            .map(|(cursor, package)| (cursor as i64 + 1, package.clone()))
            .collect::<Vec<_>>();
        upsert_indexed_resource_packages_batch(state, &items).await?;
        return Ok(());
    }
    state
        .index
        .write("resource-capabilities.json", &packages.to_vec())?;
    Ok(())
}

async fn seed_semantic_evaluation_packages(state: &AppState, suite_path: &Path) -> Result<usize> {
    let suite: SemanticEvaluationSuite =
        serde_json::from_str(&read_utf8_text_allowing_bom(suite_path)?)?;
    let mut packages = suite.seed_packages;
    packages.extend(
        suite
            .seed_resources
            .iter()
            .map(seed_resource_package)
            .collect::<Result<Vec<_>>>()?,
    );
    if packages.is_empty() {
        return Ok(0);
    }
    for package in &packages {
        validate_resource_package_for_index(package)
            .map_err(|reason| anyhow!("invalid_seed_package:{}:{reason}", package.resource_did))?;
    }
    let count = packages.len();
    write_indexed_resource_packages(state, &packages).await?;
    Ok(count)
}

fn seed_resource_package(seed: &SemanticEvaluationSeedResource) -> Result<ResourcePackage> {
    let did = seed.resource_did.clone();
    let service_endpoint = seed.service_endpoint.clone().unwrap_or_else(|| {
        format!(
            "https://example.org/oan/resources/{}",
            did.replace(':', "/")
        )
    });
    let protocol = seed
        .protocols
        .first()
        .cloned()
        .unwrap_or_else(|| "https".to_owned());
    let service = ServiceEndpoint {
        id: format!("{did}#service-1"),
        service_type: format!("{}Service", seed.resource_type.as_str()),
        service_endpoint: service_endpoint.clone(),
        version: Some(seed.package_version.clone()),
        protocol: Some(protocol.clone()),
        server_type: None,
        port: None,
    };
    let binding = ProtocolBinding {
        id: format!("{did}#binding-{protocol}"),
        protocol: protocol.clone(),
        version: None,
        transport: Some(if protocol.eq_ignore_ascii_case("https") {
            "http".to_owned()
        } else {
            protocol.clone()
        }),
        service_ref: Some(service.id.clone()),
        schema_ref: None,
        extra: Default::default(),
    };
    let authorized_domains = if seed.authorized_domains.is_empty() {
        vec!["examples".to_owned()]
    } else {
        seed.authorized_domains.clone()
    };
    let description = ResourceDescription {
        name: Some(seed.name.clone()),
        description: Some(seed.description.clone()),
        capability_description: Some(seed.capability_description.clone()),
        capability_tags: seed.capability_tags.clone(),
        use_case_examples: seed.use_case_examples.clone(),
        examples: seed.examples.clone(),
        version: Some(seed.package_version.clone()),
        ..Default::default()
    };
    let did_document = DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
        id: did.clone(),
        verification_method: vec![VerificationMethod {
            id: format!("{did}#key-1"),
            method_type: "Ed25519VerificationKey2020".to_owned(),
            controller: did.clone(),
            crypto_suite: Some(CryptoSuite::Ed25519Sha256),
            public_key_format: None,
            public_key_multibase: Some("zExample".to_owned()),
            public_key_jwk: None,
        }],
        authentication: vec![format!("{did}#key-1")],
        assertion_method: vec![format!("{did}#key-1")],
        service: vec![service.clone()],
        oan_metadata: Some(OanMetadata {
            subject_type: seed.resource_type.clone(),
            resource_type: seed.resource_type.clone(),
            node_role: None,
            identity_type: None,
            controller_did: None,
            publisher_did: Some("did:oan:AGUS:semantic-evaluation-publisher".to_owned()),
            issuer_did: None,
            ttl: None,
            resource_description: Some(description),
            agent_description: None,
            capability_tags: seed.capability_tags.clone(),
            authorized_domains: authorized_domains.clone(),
            protocol_bindings: vec![binding],
            implementation_links: vec![ImplementationLink {
                relation: "service".to_owned(),
                target_did: did.clone(),
                target_type: Some(seed.resource_type.clone()),
                target_service: Some(service.id.clone()),
                version_constraint: Some(seed.package_version.clone()),
            }],
            credential_requirements: vec![],
            package_info: None,
            service_policy: None,
            network_scope: Some("oan-evaluation".to_owned()),
            lifecycle_state: Some("active".to_owned()),
            extra: Default::default(),
        }),
    };
    let mut package = ResourcePackage {
        package_version: seed.package_version.clone(),
        resource_did: did.clone(),
        resource_type: seed.resource_type.clone(),
        did_document,
        did_document_hash: String::new(),
        metadata_hash: String::new(),
        package_hash: String::new(),
        hash_algorithm: "sha256".to_owned(),
        metadata: ResourceMetadata {
            resource_did: did.clone(),
            resource_type: seed.resource_type.clone(),
            subject_type: seed.resource_type.clone(),
            publisher_did: Some("did:oan:AGUS:semantic-evaluation-publisher".to_owned()),
            subject_did: Some(did.clone()),
            name: seed.name.clone(),
            description: seed.description.clone(),
            capability_tags: seed.capability_tags.clone(),
            authorized_domains,
            protocol_bindings: vec![json!({"protocol": protocol, "role": "service"})],
            services: vec![service],
            lifecycle_state: "active".to_owned(),
            package_version: seed.package_version.clone(),
            package_hash: String::new(),
            metadata_hash: String::new(),
            hash_algorithm: "sha256".to_owned(),
            updated_at: Utc::now(),
        },
        root_proof: RootProof {
            root_did: "did:oan:AGRT:semantic-evaluation-root".to_owned(),
            bulletin_event_hash: None,
            signature: None,
            package_claims: None,
            proof: None,
            crypto_suite: Some(CryptoSuite::Ed25519Sha256),
            hash_algorithm: Some("sha256".to_owned()),
        },
        created_at: Utc::now(),
    };
    refresh_resource_package_hashes(&mut package)?;
    Ok(package)
}

fn refresh_resource_package_hashes(package: &mut ResourcePackage) -> Result<()> {
    package.did_document_hash =
        hash_json_with_suite(CryptoSuite::Ed25519Sha256, &package.did_document)
            .map(|hash| format!("sha256:{hash}"))?;
    package.metadata.metadata_hash.clear();
    package.metadata.package_hash.clear();
    package.metadata_hash =
        hash_resource_metadata_with_suite(CryptoSuite::Ed25519Sha256, &package.metadata)
            .map(|hash| format!("sha256:{hash}"))?;
    package.metadata.metadata_hash = package.metadata_hash.clone();
    package.package_hash = hash_json_with_suite(
        CryptoSuite::Ed25519Sha256,
        &json!({
            "packageVersion": package.package_version,
            "resourceDid": package.resource_did,
            "resourceType": package.resource_type,
            "didDocumentHash": package.did_document_hash,
            "metadataHash": package.metadata_hash,
            "hashAlgorithm": package.hash_algorithm,
        }),
    )
    .map(|hash| format!("sha256:{hash}"))?;
    package.metadata.package_hash = package.package_hash.clone();
    package.root_proof.package_claims = Some(serde_json::to_value(ResourcePackageClaims {
        resource_did: package.resource_did.clone(),
        resource_type: package.resource_type.clone(),
        version: package.package_version.clone(),
        did_document_hash: package.did_document_hash.clone(),
        metadata_hash: package.metadata_hash.clone(),
        package_hash: package.package_hash.clone(),
        hash_algorithm: package.hash_algorithm.clone(),
        lifecycle_state: package.metadata.lifecycle_state.clone(),
        authorized_domains: package.metadata.authorized_domains.clone(),
        bulletin_ref: None,
    })?);
    Ok(())
}

fn read_utf8_text_allowing_bom(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path)?;
    Ok(text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned())
}

async fn write_sync_history_store(state: &AppState, item: Value) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlite
            .upsert_json(
                "discovery.sync_history",
                &format!("{}", Utc::now().timestamp_nanos_opt().unwrap_or_default()),
                &item,
            )
            .await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        postgres
            .upsert_json(
                "discovery.sync_history",
                &format!("{}", Utc::now().timestamp_nanos_opt().unwrap_or_default()),
                &item,
            )
            .await?;
    }
    Ok(())
}

async fn read_sync_cursor(state: &AppState) -> Result<i64> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            "SELECT COALESCE(state_value, sync_value) FROM {DISCOVERY_SYNC_STATE_TABLE} WHERE state_key = ? OR sync_key = ?"
        ))
        .bind(DISCOVERY_CDN_CURSOR_KEY)
        .bind(DISCOVERY_CDN_CURSOR_KEY)
        .fetch_optional(sqlite.pool())
        .await?;
        return Ok(row
            .and_then(|row| row.get::<String, _>(0).parse::<i64>().ok())
            .unwrap_or(0));
    }
    if let Some(postgres) = &state.postgres {
        let row = sqlx::query(&format!(
            "SELECT COALESCE(state_value, sync_value::text) FROM {DISCOVERY_SYNC_STATE_TABLE} WHERE state_key = $1 OR sync_key = $1"
        ))
        .bind(DISCOVERY_CDN_CURSOR_KEY)
        .fetch_optional(postgres.pool())
        .await?;
        return Ok(row
            .and_then(|row| row.get::<String, _>(0).parse::<i64>().ok())
            .unwrap_or(0));
    }
    Ok(state
        .index
        .read::<Value>("sync-state.json")
        .ok()
        .and_then(|value| value[DISCOVERY_CDN_CURSOR_KEY].as_i64())
        .unwrap_or(0))
}

async fn write_sync_cursor(state: &AppState, cursor: i64) -> Result<()> {
    let updated_at = Utc::now();
    let updated_at_text = updated_at.to_rfc3339();
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!(
            r#"
            INSERT INTO {DISCOVERY_SYNC_STATE_TABLE}(state_key, state_value, sync_key, sync_value, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(state_key)
            DO UPDATE SET
                state_value = excluded.state_value,
                sync_key = excluded.sync_key,
                sync_value = excluded.sync_value,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(DISCOVERY_CDN_CURSOR_KEY)
        .bind(cursor.to_string())
        .bind(DISCOVERY_CDN_CURSOR_KEY)
        .bind(cursor.to_string())
        .bind(&updated_at_text)
        .execute(sqlite.pool())
        .await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        sqlx::query(&format!(
            r#"
            INSERT INTO {DISCOVERY_SYNC_STATE_TABLE}(state_key, state_value, sync_key, sync_value, updated_at)
            VALUES ($1, $2, $1, $2::jsonb, $3::timestamptz)
            ON CONFLICT(state_key)
            DO UPDATE SET
                state_value = excluded.state_value,
                sync_key = excluded.sync_key,
                sync_value = excluded.sync_value,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(DISCOVERY_CDN_CURSOR_KEY)
        .bind(cursor.to_string())
        .bind(updated_at)
        .execute(postgres.pool())
        .await?;
        return Ok(());
    }
    state.index.write(
        "sync-state.json",
        &json!({ DISCOVERY_CDN_CURSOR_KEY: cursor }),
    )?;
    Ok(())
}

async fn write_rejected_packages(state: &AppState, rejected: &[Value]) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        let now = Utc::now().to_rfc3339();
        let mut tx = sqlite.pool().begin().await?;
        for item in rejected {
            let reject_key = rejected_package_key(item);
            sqlx::query(&format!(
                r#"
                INSERT INTO {DISCOVERY_REJECTED_TABLE}(reject_key, item_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(reject_key)
                DO UPDATE SET item_json = excluded.item_json, updated_at = excluded.updated_at
                "#
            ))
            .bind(reject_key)
            .bind(serde_json::to_string(item)?)
            .bind(now.clone())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        let now = Utc::now();
        let mut tx = postgres.pool().begin().await?;
        for item in rejected {
            let reject_key = rejected_package_key(item);
            sqlx::query(&format!(
                r#"
                INSERT INTO {DISCOVERY_REJECTED_TABLE}(reject_key, item_json, updated_at)
                VALUES ($1, $2::jsonb, $3::timestamptz)
                ON CONFLICT(reject_key)
                DO UPDATE SET item_json = excluded.item_json, updated_at = excluded.updated_at
                "#
            ))
            .bind(reject_key)
            .bind(serde_json::to_string(item)?)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        return Ok(());
    }
    state.index.write("rejected-packages.json", &rejected)?;
    Ok(())
}

fn rejected_package_key(item: &Value) -> String {
    format!(
        "{}:{}",
        rejected_package_resource_did(item),
        item["cursor"].as_i64().unwrap_or_default()
    )
}

fn rejected_package_resource_did(item: &Value) -> &str {
    item["resourceDid"]
        .as_str()
        .or_else(|| item["did"].as_str())
        .unwrap_or("unknown")
}

async fn delete_rejected_packages_by_did(state: &AppState, resource_dids: &[String]) -> Result<()> {
    if resource_dids.is_empty() {
        return Ok(());
    }
    if let Some(sqlite) = &state.sqlite {
        let mut tx = sqlite.pool().begin().await?;
        for resource_did in resource_dids {
            sqlx::query(&format!(
                "DELETE FROM {DISCOVERY_REJECTED_TABLE} WHERE json_extract(item_json, '$.resourceDid') = ? OR json_extract(item_json, '$.did') = ?"
            ))
            .bind(resource_did)
            .bind(resource_did)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        let mut tx = postgres.pool().begin().await?;
        for resource_did in resource_dids {
            sqlx::query(&format!(
                "DELETE FROM {DISCOVERY_REJECTED_TABLE} WHERE item_json->>'resourceDid' = $1 OR item_json->>'did' = $1"
            ))
            .bind(resource_did)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        return Ok(());
    }
    let dids = resource_dids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let rejected = read_rejected_packages(state)
        .await?
        .into_iter()
        .filter(|item| !dids.contains(rejected_package_resource_did(item)))
        .collect::<Vec<_>>();
    state.index.write("rejected-packages.json", &rejected)?;
    Ok(())
}

async fn delete_rejected_packages(state: &AppState, reject_keys: &[String]) -> Result<()> {
    if reject_keys.is_empty() {
        return Ok(());
    }
    if let Some(sqlite) = &state.sqlite {
        let mut tx = sqlite.pool().begin().await?;
        for reject_key in reject_keys {
            sqlx::query(&format!(
                "DELETE FROM {DISCOVERY_REJECTED_TABLE} WHERE reject_key = ?"
            ))
            .bind(reject_key)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        let mut tx = postgres.pool().begin().await?;
        for reject_key in reject_keys {
            sqlx::query(&format!(
                "DELETE FROM {DISCOVERY_REJECTED_TABLE} WHERE reject_key = $1"
            ))
            .bind(reject_key)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        return Ok(());
    }
    let reject_key_set = reject_keys.iter().collect::<HashSet<_>>();
    let rejected = read_rejected_packages(state)
        .await?
        .into_iter()
        .filter(|item| !reject_key_set.contains(&rejected_package_key(item)))
        .collect::<Vec<_>>();
    state.index.write("rejected-packages.json", &rejected)?;
    Ok(())
}

async fn read_sync_history(state: &AppState) -> Result<Vec<Value>> {
    if let Some(sqlite) = &state.sqlite {
        return sqlite
            .read_namespace("discovery.sync_history")
            .await
            .map_err(Into::into);
    }
    if let Some(postgres) = &state.postgres {
        return postgres
            .read_namespace("discovery.sync_history")
            .await
            .map_err(Into::into);
    }
    Ok(state.index.read("sync-history.json").unwrap_or_default())
}

async fn export_discovery_debug_snapshot(state: &AppState) -> Result<()> {
    if state.sqlite.is_none() && state.postgres.is_none() {
        return Ok(());
    }
    let packages = read_indexed_resource_packages(state).await?;
    state.index.write("resource-capabilities.json", &packages)?;
    let rejected = read_rejected_packages(state).await?;
    state.index.write("rejected-packages.json", &rejected)?;
    let history = read_sync_history(state).await?;
    state.index.write("sync-history.json", &history)?;
    Ok(())
}

async fn read_rejected_packages(state: &AppState) -> Result<Vec<Value>> {
    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            "SELECT item_json FROM {DISCOVERY_REJECTED_TABLE} ORDER BY updated_at, reject_key"
        ))
        .fetch_all(sqlite.pool())
        .await?;
        return rows
            .into_iter()
            .map(|row| {
                serde_json::from_str::<Value>(&row.get::<String, _>(0)).map_err(anyhow::Error::from)
            })
            .collect();
    }
    if let Some(postgres) = &state.postgres {
        let rows = sqlx::query(&format!(
            "SELECT item_json::text FROM {DISCOVERY_REJECTED_TABLE} ORDER BY updated_at, reject_key"
        ))
        .fetch_all(postgres.pool())
        .await?;
        return rows
            .into_iter()
            .map(|row| {
                serde_json::from_str::<Value>(&row.get::<String, _>(0)).map_err(anyhow::Error::from)
            })
            .collect();
    }
    Ok(state
        .index
        .read("rejected-packages.json")
        .unwrap_or_default())
}

fn validate_resource_package_for_index(
    package: &ResourcePackage,
) -> std::result::Result<(), String> {
    package
        .did_document
        .validate_oan_resource()
        .map_err(|err| err.to_string())?;
    package
        .verify_did_document_hash()
        .and_then(|_| package.verify_metadata_hash())
        .and_then(|_| package.verify_package_hash())
        .and_then(|_| package.verify_resource_type_consistency())
        .and_then(|_| package.verify_metadata_consistency())
        .and_then(|_| package.verify_root_claim_binding())
        .map_err(|err| err.to_string())?;
    if package.metadata.lifecycle_state != "active" {
        return Err("resource_not_active".to_owned());
    }
    if package.metadata.authorized_domains.is_empty() {
        return Err("resource_domains_required".to_owned());
    }
    validate_authorized_domain_list(&package.metadata.authorized_domains)?;
    Ok(())
}

fn resource_matches_explicit_constraints(
    package: &ResourcePackage,
    query: &ResourceDiscoveryQuery,
) -> bool {
    if query
        .resource_type
        .as_ref()
        .is_some_and(|resource_type| resource_type != &package.resource_type)
    {
        return false;
    }
    if query
        .version
        .as_ref()
        .is_some_and(|version| version != &package.package_version)
    {
        return false;
    }
    if !query.capability_tags.is_empty()
        && !query
            .capability_tags
            .iter()
            .all(|tag| package.metadata.capability_tags.contains(tag))
    {
        return false;
    }
    if query.protocol.as_ref().is_some_and(|protocol| {
        let expected = protocol.to_ascii_lowercase();
        !package.metadata.protocol_bindings.iter().any(|binding| {
            binding["protocol"]
                .as_str()
                .map(|value| value.eq_ignore_ascii_case(&expected))
                .unwrap_or(false)
        }) && !package.metadata.services.iter().any(|service| {
            service
                .protocol
                .as_ref()
                .map(|value| value.eq_ignore_ascii_case(&expected))
                .unwrap_or(false)
        })
    }) {
        return false;
    }
    true
}

fn resource_matches_exact_did_query(
    package: &ResourcePackage,
    query: &ResourceDiscoveryQuery,
) -> bool {
    let mut constraint_query = query.clone();
    constraint_query.query = None;
    resource_matches_explicit_constraints(package, &constraint_query)
}

fn discovery_authorized_domains(bulletin: &Value, discovery_did: &str) -> Vec<String> {
    bulletin["events"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .rev()
                .find(|event| {
                    event["subjectDid"] == discovery_did
                        && event["eventType"] == "DISCOVERY_NODE_DOMAINS_UPDATED"
                })
                .map(|event| event["payload"].clone())
        })
        .and_then(|payload| payload["authorizedDomains"].as_array().cloned())
        .map(|values| {
            values
                .into_iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use chrono::Utc;
    use oan_core::{
        CryptoSuite, OanMetadata, ProtocolBinding, ResourceDescription, ServiceEndpoint,
        VerificationMethod,
    };
    use oan_crypto::{public_key_jwk, public_key_multibase, VerifyingKey};
    use oan_package::RootProof;
    use serde_json::json;
    use tempfile::tempdir;

    fn resource_did() -> String {
        "did:oan:SKLG:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned()
    }

    fn discovery_did() -> String {
        "did:oan:AGDS:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned()
    }

    fn sample_resource_package() -> ResourcePackage {
        let did = resource_did();
        let did_document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.clone(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#key-1"),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.clone(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: None,
                public_key_multibase: Some("zExample".to_owned()),
                public_key_jwk: None,
            }],
            authentication: vec![format!("{did}#key-1")],
            assertion_method: vec![format!("{did}#key-1")],
            service: vec![ServiceEndpoint {
                id: format!("{did}#download"),
                service_type: "SkillPackageDownload".to_owned(),
                service_endpoint: "https://example.org/skills/contract-review.json".to_owned(),
                version: Some("1.0.0".to_owned()),
                protocol: Some("https".to_owned()),
                server_type: None,
                port: None,
            }],
            oan_metadata: Some(OanMetadata {
                subject_type: ResourceType::Skill,
                resource_type: ResourceType::Skill,
                node_role: None,
                identity_type: None,
                controller_did: None,
                publisher_did: Some("did:oan:AGUS:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned()),
                issuer_did: None,
                ttl: None,
                resource_description: Some(ResourceDescription {
                    name: Some("Contract Review Skill".to_owned()),
                    description: Some("Review contracts and highlight risky clauses".to_owned()),
                    capability_description: Some(
                        "Detect payment, termination, liability, and compliance risks.".to_owned(),
                    ),
                    capability_tags: vec!["legal.contract.review".to_owned()],
                    use_case_examples: vec!["Find payment and termination risks".to_owned()],
                    examples: vec![json!({
                        "task": "Review a commercial contract",
                        "output": "Risk checklist"
                    })],
                    ..Default::default()
                }),
                agent_description: None,
                capability_tags: vec!["legal.contract.review".to_owned()],
                authorized_domains: vec!["legal".to_owned()],
                protocol_bindings: vec![ProtocolBinding {
                    id: format!("{did}#binding-https"),
                    protocol: "https".to_owned(),
                    version: None,
                    transport: Some("http".to_owned()),
                    service_ref: Some(format!("{did}#download")),
                    schema_ref: None,
                    extra: Default::default(),
                }],
                implementation_links: vec![ImplementationLink {
                    relation: "download".to_owned(),
                    target_did: did.clone(),
                    target_type: Some(ResourceType::Skill),
                    target_service: Some(format!("{did}#download")),
                    version_constraint: Some("1".to_owned()),
                }],
                credential_requirements: vec![],
                package_info: None,
                service_policy: None,
                network_scope: None,
                lifecycle_state: Some("active".to_owned()),
                extra: Default::default(),
            }),
        };
        let mut package = ResourcePackage {
            package_version: "1".to_owned(),
            resource_did: did.clone(),
            resource_type: ResourceType::Skill,
            did_document,
            did_document_hash: String::new(),
            metadata_hash: String::new(),
            package_hash: String::new(),
            hash_algorithm: "sha256".to_owned(),
            metadata: ResourceMetadata {
                resource_did: did.clone(),
                resource_type: ResourceType::Skill,
                subject_type: ResourceType::Skill,
                publisher_did: Some("did:oan:AGUS:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned()),
                subject_did: Some(did),
                name: "Contract Review Skill".to_owned(),
                description: "Review contracts and highlight risky clauses".to_owned(),
                capability_tags: vec!["legal.contract.review".to_owned()],
                authorized_domains: vec!["legal".to_owned()],
                protocol_bindings: vec![json!({"protocol": "https", "role": "download"})],
                services: vec![ServiceEndpoint {
                    id: format!("{}#download", resource_did()),
                    service_type: "SkillPackageDownload".to_owned(),
                    service_endpoint: "https://example.org/skills/contract-review.json".to_owned(),
                    version: Some("1.0.0".to_owned()),
                    protocol: Some("https".to_owned()),
                    server_type: None,
                    port: None,
                }],
                lifecycle_state: "active".to_owned(),
                package_version: "1".to_owned(),
                package_hash: String::new(),
                metadata_hash: String::new(),
                hash_algorithm: "sha256".to_owned(),
                updated_at: Utc::now(),
            },
            root_proof: RootProof {
                root_did: "did:oan:AGRT:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: None,
                proof: None,
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                hash_algorithm: Some("sha256".to_owned()),
            },
            created_at: Utc::now(),
        };
        refresh_hashes(&mut package);
        package
    }

    fn refresh_hashes(package: &mut ResourcePackage) {
        refresh_resource_package_hashes(package).unwrap();
    }

    fn sample_resource_package_with_did(resource_did: &str) -> ResourcePackage {
        let mut package = sample_resource_package();
        package.resource_did = resource_did.to_owned();
        package.did_document.id = resource_did.to_owned();
        package.did_document.verification_method[0].id = format!("{resource_did}#key-1");
        package.did_document.verification_method[0].controller = resource_did.to_owned();
        package.did_document.authentication = vec![format!("{resource_did}#key-1")];
        package.did_document.assertion_method = vec![format!("{resource_did}#key-1")];
        package.metadata.resource_did = resource_did.to_owned();
        package.metadata.subject_did = Some(resource_did.to_owned());
        refresh_hashes(&mut package);
        package
    }

    fn app_state(dir: &std::path::Path) -> AppState {
        let state = AppState {
            data: JsonStore::new(dir.join("data")),
            index: JsonStore::new(dir.join("index")),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8004,
                },
                cors: CorsConfig::default(),
                debug: DebugConfig::default(),
                semantic_search: SemanticSearchConfig::default(),
                upstream: UpstreamConfig {
                    root_endpoint: "http://127.0.0.1:8001".to_owned(),
                    cdn_endpoint: Some("http://127.0.0.1:8003".to_owned()),
                },
                paths: PathConfig {
                    data_dir: dir.join("data"),
                    index_dir: dir.join("index"),
                    keys_dir: dir.join("keys"),
                    database_url: None,
                },
            },
            did: discovery_did(),
            sqlite: None,
            postgres: None,
            semantic: SemanticRuntimeState::disabled(
                "semantic_disabled",
                &SemanticSearchConfig::default(),
            ),
            recommender: Arc::new(SemanticRecommender::new().unwrap()),
            client: reqwest::Client::new(),
            resource_sync_lock: Arc::new(Mutex::new(())),
            index_stats_cache: Arc::new(Mutex::new(None)),
        };
        write_discovery_document(&state, vec!["*".to_owned()]);
        state
    }

    fn write_discovery_document(state: &AppState, domains: Vec<String>) {
        let did = discovery_did();
        let document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.clone(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            service: vec![],
            oan_metadata: Some(OanMetadata {
                subject_type: ResourceType::InfrastructureNode,
                resource_type: ResourceType::InfrastructureNode,
                node_role: Some("discovery".to_owned()),
                identity_type: Some("discovery".to_owned()),
                controller_did: None,
                publisher_did: None,
                issuer_did: None,
                ttl: None,
                resource_description: None,
                agent_description: None,
                capability_tags: vec![],
                authorized_domains: domains,
                protocol_bindings: vec![],
                implementation_links: vec![],
                credential_requirements: vec![],
                package_info: None,
                service_policy: None,
                network_scope: Some("oan-local".to_owned()),
                lifecycle_state: Some("active".to_owned()),
                extra: Default::default(),
            }),
        };
        state.data.write("did-document.json", &document).unwrap();
    }

    fn set_package_authorized_domains(package: &mut ResourcePackage, domains: Vec<String>) {
        package.metadata.authorized_domains = domains.clone();
        package
            .did_document
            .oan_metadata
            .as_mut()
            .unwrap()
            .authorized_domains = domains;
        refresh_hashes(package);
    }

    fn set_package_type(package: &mut ResourcePackage, resource_type: ResourceType) {
        package.resource_type = resource_type.clone();
        package.metadata.resource_type = resource_type.clone();
        package.metadata.subject_type = resource_type.clone();
        let metadata = package.did_document.oan_metadata.as_mut().unwrap();
        metadata.resource_type = resource_type.clone();
        metadata.subject_type = resource_type;
        refresh_hashes(package);
    }

    fn set_package_tags(package: &mut ResourcePackage, tags: Vec<String>) {
        package.metadata.capability_tags = tags.clone();
        package
            .did_document
            .oan_metadata
            .as_mut()
            .unwrap()
            .capability_tags = tags;
        refresh_hashes(package);
    }

    fn set_package_description(package: &mut ResourcePackage, name: &str, description: &str) {
        package.metadata.name = name.to_owned();
        package.metadata.description = description.to_owned();
        if let Some(metadata) = package.did_document.oan_metadata.as_mut() {
            if let Some(resource_description) = metadata.resource_description.as_mut() {
                resource_description.name = Some(name.to_owned());
                resource_description.description = Some(description.to_owned());
            }
        }
        refresh_hashes(package);
    }

    fn set_package_capability_details(
        package: &mut ResourcePackage,
        capability_description: &str,
        use_cases: Vec<String>,
    ) {
        if let Some(metadata) = package.did_document.oan_metadata.as_mut() {
            if let Some(resource_description) = metadata.resource_description.as_mut() {
                resource_description.capability_description =
                    Some(capability_description.to_owned());
                resource_description.use_case_examples = use_cases;
            }
        }
        refresh_hashes(package);
    }

    async fn app_state_with_sqlite(dir: &std::path::Path) -> AppState {
        let sqlite =
            SqliteJsonStore::connect(&format!("sqlite:{}", dir.join("discovery.db").display()))
                .await
                .unwrap();
        initialize_discovery_sqlite(&sqlite).await.unwrap();
        let mut state = app_state(dir);
        state.sqlite = Some(sqlite);
        state
    }

    async fn app_state_with_semantic_postgres(dir: &std::path::Path) -> Option<AppState> {
        let url = env::var("OAN_DISCOVERY_SEMANTIC_TEST_DATABASE_URL").ok()?;
        let postgres = PostgresJsonStore::connect(&url).await.ok()?;
        if initialize_discovery_postgres(&postgres).await.is_err() {
            return None;
        }
        let mut state = app_state(dir);
        state.config.semantic_search.enabled = true;
        state.config.semantic_search.embedding.dimension = 16;
        if initialize_semantic_postgres(&postgres, &state.config.semantic_search)
            .await
            .is_err()
        {
            return None;
        }
        sqlx::query(&format!("DELETE FROM {DISCOVERY_SEMANTIC_INDEX_TABLE}"))
            .execute(postgres.pool())
            .await
            .ok()?;
        sqlx::query(&format!("DELETE FROM {DISCOVERY_INTENT_INDEX_TABLE}"))
            .execute(postgres.pool())
            .await
            .ok()?;
        sqlx::query(&format!("DELETE FROM {DISCOVERY_PACKAGE_TABLE}"))
            .execute(postgres.pool())
            .await
            .ok()?;
        state.semantic = SemanticRuntimeState {
            enabled: true,
            healthy: true,
            backend: "pgvector".to_owned(),
            fallback_reason: None,
            embedding_model: state.config.semantic_search.embedding.model_name.clone(),
            embedding_version: semantic_embedding_version(&state.config.semantic_search),
            embedding_dtype: state.config.semantic_search.embedding.dtype.clone(),
            dimension: state.config.semantic_search.embedding.dimension,
        };
        state.postgres = Some(postgres);
        Some(state)
    }

    fn root_document_with_key(did: &str, signing_key: &ed25519_dalek::SigningKey) -> DidDocument {
        let key_id = format!("{did}#key-1");
        let verifying_key = VerifyingKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256,
            key: signing_key.verifying_key(),
        };
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: key_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: Some("multibase".to_owned()),
                public_key_multibase: Some(public_key_multibase(&verifying_key)),
                public_key_jwk: Some(public_key_jwk(&verifying_key)),
            }],
            authentication: vec![key_id.clone()],
            assertion_method: vec![key_id],
            service: vec![],
            oan_metadata: Some(OanMetadata {
                subject_type: ResourceType::InfrastructureNode,
                resource_type: ResourceType::InfrastructureNode,
                node_role: Some("root".to_owned()),
                identity_type: Some("root".to_owned()),
                controller_did: None,
                publisher_did: None,
                issuer_did: None,
                ttl: None,
                resource_description: None,
                agent_description: None,
                capability_tags: vec![],
                authorized_domains: vec!["*".to_owned()],
                protocol_bindings: vec![],
                implementation_links: vec![],
                credential_requirements: vec![],
                package_info: None,
                service_policy: None,
                network_scope: Some("oan-local".to_owned()),
                lifecycle_state: Some("active".to_owned()),
                extra: Default::default(),
            }),
        }
    }

    #[test]
    fn resource_package_validation_accepts_complete_oan_resource() {
        let package = sample_resource_package();
        assert!(validate_resource_package_for_index(&package).is_ok());
    }

    #[test]
    fn resource_package_validation_rejects_tampered_hash() {
        let mut package = sample_resource_package();
        package.metadata.description.push_str(" tampered");
        assert_eq!(
            validate_resource_package_for_index(&package).unwrap_err(),
            "metadata hash mismatch"
        );
    }

    #[test]
    fn resource_package_validation_rejects_missing_authorized_domains() {
        let mut package = sample_resource_package();
        set_package_authorized_domains(&mut package, vec![]);

        assert_eq!(
            validate_resource_package_for_index(&package).unwrap_err(),
            "resource_domains_required"
        );
    }

    #[test]
    fn resource_query_matches_semantic_description_tags_type_version_and_protocol() {
        let package = sample_resource_package();
        let query = ResourceDiscoveryQuery {
            query: Some("risky clauses".to_owned()),
            resource_type: Some(ResourceType::Skill),
            capability_tags: vec!["legal.contract.review".to_owned()],
            protocol: Some("https".to_owned()),
            version: Some("1".to_owned()),
            version_mode: "exact".to_owned(),
            limit: 10,
        };
        let hits = rank_resource_packages_semantically(vec![package.clone()], &query);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].final_score > 0.0);

        let wrong_type = ResourceDiscoveryQuery {
            resource_type: Some(ResourceType::McpServer),
            ..query.clone()
        };
        assert!(rank_resource_packages_semantically(vec![package.clone()], &wrong_type).is_empty());

        let wrong_protocol = ResourceDiscoveryQuery {
            protocol: Some("a2a".to_owned()),
            ..query
        };
        assert!(rank_resource_packages_semantically(vec![package], &wrong_protocol).is_empty());
    }

    #[test]
    fn resource_query_requires_all_explicit_capability_tags() {
        let package = sample_resource_package();
        let query = ResourceDiscoveryQuery {
            query: None,
            resource_type: Some(ResourceType::Skill),
            capability_tags: vec![
                "legal.contract.review".to_owned(),
                "missing.required.tag".to_owned(),
            ],
            protocol: None,
            version: None,
            version_mode: "latest".to_owned(),
            limit: 10,
        };

        assert!(rank_resource_packages_semantically(vec![package], &query).is_empty());
    }

    #[test]
    fn semantic_alias_catalog_supports_chinese_and_english_query_terms() {
        let tokens = semantic_tokens("我想审查合同风险并输出风险清单");
        assert!(tokens.iter().any(|token| token == "document.analysis"));
        assert!(tokens.iter().any(|token| token == "security.risk"));

        let english_tokens = semantic_tokens("find a model context protocol server");
        assert!(english_tokens.iter().any(|token| token == "mcp.protocol"));
    }

    #[test]
    fn local_semantic_ranking_matches_chinese_query_to_english_metadata() {
        let contract = sample_resource_package();
        let mut weather =
            sample_resource_package_with_did("did:oan:SKLG:44444444444444444444444444444444");
        set_package_description(
            &mut weather,
            "Weather Forecast Skill",
            "Forecast rainfall and temperature for travel planning.",
        );
        set_package_tags(&mut weather, vec!["weather.forecast".to_owned()]);

        let query = ResourceDiscoveryQuery {
            query: Some("我想审查合同里的付款和终止风险".to_owned()),
            resource_type: None,
            capability_tags: vec![],
            protocol: None,
            version: None,
            version_mode: "latest".to_owned(),
            limit: 5,
        };
        let hits = rank_resource_packages_semantically(vec![weather, contract.clone()], &query);
        assert_eq!(hits[0].package.resource_did, contract.resource_did);
        assert!(hits[0].intent_score > 0.0 || hits[0].context_score > 0.0);
    }

    #[test]
    fn semantic_intent_documents_split_use_cases_examples_and_pseudo_queries() {
        let package = sample_resource_package();
        let projection = discovery_package_projection(&package);
        let document = search_document_from_package(1, &package, &projection);
        let intents = semantic_intent_documents(&document);

        assert!(intents.iter().any(|intent| intent.intent_kind == "use_case"
            && intent.intent_text.contains("payment and termination risks")));
        assert!(intents.iter().any(|intent| intent.intent_kind == "example"
            && intent.intent_text.contains("Review a commercial contract")));
        assert!(intents
            .iter()
            .any(|intent| intent.intent_kind == "pseudo_query"));
        assert!(intents
            .windows(2)
            .all(|window| window[0].intent_id < window[1].intent_id));
    }

    #[test]
    fn local_semantic_ranking_keeps_explicit_type_and_protocol_hard() {
        let mut mcp =
            sample_resource_package_with_did("did:oan:MCDM:55555555555555555555555555555555");
        set_package_type(&mut mcp, ResourceType::McpServer);
        set_package_description(
            &mut mcp,
            "Repository MCP Server",
            "Search GitHub issues, pull requests, and source repositories through MCP.",
        );
        set_package_tags(&mut mcp, vec!["github.repository".to_owned()]);

        let skill = sample_resource_package();
        let query = ResourceDiscoveryQuery {
            query: Some("search github pull requests".to_owned()),
            resource_type: Some(ResourceType::McpServer),
            capability_tags: vec!["github.repository".to_owned()],
            protocol: Some("https".to_owned()),
            version: None,
            version_mode: "latest".to_owned(),
            limit: 5,
        };
        let hits = rank_resource_packages_semantically(vec![skill, mcp.clone()], &query);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].package.resource_did, mcp.resource_did);
    }

    #[test]
    fn hybrid_semantic_hits_merges_vector_and_lexical_candidates() {
        let vector_only = sample_resource_package();
        let mut lexical_only =
            sample_resource_package_with_did("did:oan:MCDM:88888888888888888888888888888888");
        set_package_type(&mut lexical_only, ResourceType::McpServer);
        set_package_description(
            &mut lexical_only,
            "Repository MCP Server",
            "Search GitHub issues and pull requests through Model Context Protocol.",
        );
        set_package_tags(&mut lexical_only, vec!["github.repository".to_owned()]);

        let query = ResourceDiscoveryQuery {
            query: Some("github pull request mcp".to_owned()),
            resource_type: None,
            capability_tags: vec![],
            protocol: None,
            version: None,
            version_mode: "latest".to_owned(),
            limit: 10,
        };

        let hits = hybrid_semantic_hits(
            vec![(vector_only.clone(), 0.92)],
            vec![lexical_only.clone()],
            &query,
        );
        let dids = hits
            .iter()
            .map(|hit| hit.package.resource_did.as_str())
            .collect::<Vec<_>>();

        assert!(dids.contains(&vector_only.resource_did.as_str()));
        assert!(dids.contains(&lexical_only.resource_did.as_str()));
    }

    #[test]
    fn discovery_package_projection_separates_tag_text_from_context_text() {
        let mut package = sample_resource_package();
        set_package_description(
            &mut package,
            "合同审查助手",
            "审查合同付款、终止、责任和合规风险，并生成风险清单。",
        );
        let projection = discovery_package_projection(&package);

        assert!(projection.tag_text.contains("legal.contract.review"));
        assert!(projection.tag_text.contains("https"));
        assert!(!projection.tag_text.contains("审查合同付款"));
        assert!(projection.search_text.contains("审查合同付款"));
    }

    #[test]
    fn tag_layer_is_scored_separately_from_context_layer() {
        let mut package = sample_resource_package();
        set_package_description(
            &mut package,
            "合同审查助手",
            "审查合同付款、终止、责任和合规风险，并生成风险清单。",
        );
        let query = ResourceDiscoveryQuery {
            query: Some("legal contract review".to_owned()),
            resource_type: Some(ResourceType::Skill),
            capability_tags: vec!["legal.contract.review".to_owned()],
            protocol: Some("https".to_owned()),
            version: None,
            version_mode: "latest".to_owned(),
            limit: 5,
        };
        let query_projection = semantic_query_projection(&query);
        let projection = discovery_package_projection(&package);
        let doc = search_document_from_package(1, &package, &projection);
        let hit = semantic_resource_scores(&package, &query, &query_projection, 0.0);

        assert!(hit.tag_score > 0.0);
        assert!(hit.context_score > 0.0);
        assert!(hit.semantic_score > 0.0);
        assert!(hit.final_score > 0.0);
        assert!(doc.tag_text.contains("legal.contract.review"));
    }

    #[test]
    fn no_resource_type_query_prefers_tag_aligned_result() {
        let contract = sample_resource_package();
        let mut weather =
            sample_resource_package_with_did("did:oan:SKLG:77777777777777777777777777777777");
        set_package_description(
            &mut weather,
            "Weather Forecast Skill",
            "Forecast rainfall and temperature for travel planning.",
        );
        set_package_tags(&mut weather, vec!["weather.forecast".to_owned()]);

        let query = ResourceDiscoveryQuery {
            query: Some("我要审查合同风险并生成风险清单".to_owned()),
            resource_type: None,
            capability_tags: vec![],
            protocol: None,
            version: None,
            version_mode: "latest".to_owned(),
            limit: 5,
        };
        let hits = rank_resource_packages_semantically(vec![weather, contract.clone()], &query);

        assert_eq!(
            hits.first().map(|hit| &hit.package.resource_did),
            Some(&contract.resource_did)
        );
        assert!(hits.first().map(|hit| hit.tag_score).unwrap_or(0.0) > 0.0);
    }

    #[tokio::test]
    async fn resource_query_returns_resource_candidates_without_agent_fields() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        write_indexed_resource_packages(&state, &[sample_resource_package()])
            .await
            .unwrap();

        let response = resource_query(
            State(state),
            Json(ResourceDiscoveryQuery {
                query: Some("contract".to_owned()),
                resource_type: Some(ResourceType::Skill),
                capability_tags: vec![],
                protocol: None,
                version: None,
                version_mode: "latest".to_owned(),
                limit: 5,
            }),
        )
        .await
        .unwrap();
        let value = serde_json::to_value(&response.0).unwrap();
        assert_eq!(value["candidates"].as_array().unwrap().len(), 1);
        assert_eq!(value["candidates"][0]["resourceDid"], resource_did());
    }

    #[tokio::test]
    async fn resource_query_supports_chinese_natural_language_without_type() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let contract = sample_resource_package();
        let mut weather =
            sample_resource_package_with_did("did:oan:SKLG:66666666666666666666666666666666");
        set_package_description(
            &mut weather,
            "Weather Forecast Skill",
            "Forecast rainfall and temperature for travel planning.",
        );
        set_package_tags(&mut weather, vec!["weather.forecast".to_owned()]);
        write_indexed_resource_packages(&state, &[weather, contract.clone()])
            .await
            .unwrap();

        let response = resource_query(
            State(state),
            Json(ResourceDiscoveryQuery {
                query: Some("我需要审查合同风险并生成风险清单".to_owned()),
                resource_type: None,
                capability_tags: vec![],
                protocol: None,
                version: None,
                version_mode: "latest".to_owned(),
                limit: 5,
            }),
        )
        .await
        .unwrap();
        assert!(!response.0.candidates.is_empty());
        assert_eq!(response.0.candidates[0].resource_did, contract.resource_did);
    }

    #[tokio::test]
    async fn semantic_evaluation_suite_runs_real_resource_query_path() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let suite_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("evaluation")
            .join("real-resource-regression.v1.json");
        let seed_count = seed_semantic_evaluation_packages(&state, &suite_path)
            .await
            .unwrap();
        let report = evaluate_semantic_discovery(&state, &suite_path)
            .await
            .unwrap();
        assert!(seed_count >= 10);
        assert!(report.case_count >= 20);
        assert!(report.recall_at_5 >= 0.9);
        assert!(report.recall_at_10 >= 0.95);
        assert!(report.mrr_at_10 >= 0.9);
        assert!(report.cases.iter().all(|case| case.passed));
    }

    #[tokio::test]
    async fn semantic_rebuild_reports_disabled_when_pgvector_is_unavailable() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        state.config.semantic_search.enabled = true;
        write_indexed_resource_packages(&state, &[sample_resource_package()])
            .await
            .unwrap();

        let report = rebuild_semantic_indexes(&state, true, SemanticRebuildStage::Both)
            .await
            .unwrap();
        assert!(!report.semantic_enabled);
        assert_eq!(report.package_count, 0);
        assert_eq!(report.context_indexed_count, 0);
        assert_eq!(report.intent_indexed_count, 0);
        assert!(report.skipped_reason.is_some());
    }

    #[tokio::test]
    async fn semantic_rebuild_progress_is_isolated_by_stage() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        store_semantic_rebuild_progress(
            &state,
            SemanticRebuildStage::Context,
            "running",
            Some(3),
            10,
            1,
            0,
            4,
            4,
        )
        .await
        .unwrap();
        store_semantic_rebuild_progress(
            &state,
            SemanticRebuildStage::Intent,
            "running",
            Some(8),
            10,
            2,
            1,
            2,
            2,
        )
        .await
        .unwrap();

        let context = load_semantic_rebuild_progress(&state, SemanticRebuildStage::Context)
            .await
            .unwrap()
            .unwrap();
        let intent = load_semantic_rebuild_progress(&state, SemanticRebuildStage::Intent)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(context.stage, "context");
        assert_eq!(context.last_cursor, Some(3));
        assert_eq!(intent.stage, "intent");
        assert_eq!(intent.last_cursor, Some(8));
    }

    #[tokio::test]
    async fn semantic_rebuild_skip_records_are_isolated_by_stage() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        store_semantic_rebuild_skip(
            &state,
            SemanticRebuildStage::Context,
            11,
            "did:oan:SKLG:context".to_owned(),
            "context failure".to_owned(),
        )
        .await
        .unwrap();
        store_semantic_rebuild_skip(
            &state,
            SemanticRebuildStage::Intent,
            22,
            "did:oan:SKLG:intent".to_owned(),
            "intent failure".to_owned(),
        )
        .await
        .unwrap();

        let context =
            load_semantic_rebuild_skip_records(&state, Some(SemanticRebuildStage::Context))
                .await
                .unwrap();
        let intent = load_semantic_rebuild_skip_records(&state, Some(SemanticRebuildStage::Intent))
            .await
            .unwrap();

        assert_eq!(context.len(), 1);
        assert_eq!(context[0].stage, "context");
        assert_eq!(context[0].resource_did, "did:oan:SKLG:context");
        assert_eq!(intent.len(), 1);
        assert_eq!(intent[0].stage, "intent");
        assert_eq!(intent[0].resource_did, "did:oan:SKLG:intent");

        clear_semantic_rebuild_skip_record(
            &state,
            SemanticRebuildStage::Context,
            "did:oan:SKLG:context",
        )
        .await
        .unwrap();

        let context_after =
            load_semantic_rebuild_skip_records(&state, Some(SemanticRebuildStage::Context))
                .await
                .unwrap();
        let intent_after =
            load_semantic_rebuild_skip_records(&state, Some(SemanticRebuildStage::Intent))
                .await
                .unwrap();

        assert!(context_after.is_empty());
        assert_eq!(intent_after.len(), 1);
        assert_eq!(intent_after[0].resource_did, "did:oan:SKLG:intent");
    }

    #[tokio::test]
    async fn semantic_rebuild_report_is_not_safe_to_delete_old_indexes_for_stage_runs() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        state.config.semantic_search.enabled = true;
        write_indexed_resource_packages(&state, &[sample_resource_package()])
            .await
            .unwrap();

        let report = rebuild_semantic_indexes(&state, true, SemanticRebuildStage::Context)
            .await
            .unwrap();
        assert_eq!(report.stage, "context");
        assert!(!report.safe_to_delete_old_indexes);
    }

    #[tokio::test]
    async fn resource_query_treats_complete_did_as_exact_lookup() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let target = sample_resource_package();
        let mut other =
            sample_resource_package_with_did("did:oan:MCDM:33333333333333333333333333333333");
        other.resource_type = ResourceType::McpServer;
        write_indexed_resource_packages(&state, &[target.clone(), other])
            .await
            .unwrap();

        let response = resource_query(
            State(state.clone()),
            Json(ResourceDiscoveryQuery {
                query: Some(target.resource_did.clone()),
                resource_type: Some(ResourceType::Skill),
                capability_tags: vec![],
                protocol: None,
                version: None,
                version_mode: "latest".to_owned(),
                limit: 5,
            }),
        )
        .await
        .unwrap();
        let candidates = response.0.candidates;
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].resource_did, target.resource_did);
        assert_eq!(candidates[0].score, 1.0);

        write_discovery_document(&state, vec!["legal".to_owned()]);
        let response = resource_query(
            State(state.clone()),
            Json(ResourceDiscoveryQuery {
                query: Some("did:oan:MCDM:33333333333333333333333333333333".to_owned()),
                resource_type: Some(ResourceType::Skill),
                capability_tags: vec![],
                protocol: None,
                version: None,
                version_mode: "latest".to_owned(),
                limit: 5,
            }),
        )
        .await
        .unwrap();
        let candidates = response.0.candidates;
        assert!(candidates.is_empty());

        let mut out_of_scope =
            sample_resource_package_with_did("did:oan:SKLG:77777777777777777777777777777777");
        set_package_authorized_domains(&mut out_of_scope, vec!["finance".to_owned()]);
        write_indexed_resource_packages(&state, &[out_of_scope.clone()])
            .await
            .unwrap();

        let response = resource_query(
            State(state),
            Json(ResourceDiscoveryQuery {
                query: Some(out_of_scope.resource_did.clone()),
                resource_type: None,
                capability_tags: vec![],
                protocol: None,
                version: None,
                version_mode: "latest".to_owned(),
                limit: 5,
            }),
        )
        .await
        .unwrap();
        assert!(response.0.candidates.is_empty());
    }

    #[tokio::test]
    async fn resource_query_without_type_searches_only_user_consumable_resources_by_default() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let skill = sample_resource_package();
        let mut node =
            sample_resource_package_with_did("did:oan:AGDS:33333333333333333333333333333333");
        set_package_type(&mut node, ResourceType::InfrastructureNode);
        write_indexed_resource_packages(&state, &[skill.clone(), node])
            .await
            .unwrap();

        let response = resource_query(
            State(state),
            Json(ResourceDiscoveryQuery {
                query: None,
                resource_type: None,
                capability_tags: vec![],
                protocol: None,
                version: None,
                version_mode: "latest".to_owned(),
                limit: 10,
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0.candidates.len(), 1);
        assert_eq!(response.0.candidates[0].resource_did, skill.resource_did);
    }

    #[tokio::test]
    async fn route_lookup_and_index_stats_are_resource_based() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let package = sample_resource_package();
        write_indexed_resource_packages(&state, std::slice::from_ref(&package))
            .await
            .unwrap();

        let route = route_lookup(State(state.clone()), AxumPath(package.resource_did.clone()))
            .await
            .unwrap();
        assert_eq!(route.0["resourceDid"], package.resource_did);
        assert_eq!(route.0["resourceType"], "skill");

        let stats = api_index_stats(State(state)).await.unwrap();
        assert_eq!(stats.0["indexedResourceCount"], 1);
        assert_eq!(stats.0["resourceTypeCounts"]["skill"], 1);
        assert_eq!(stats.0["syncCursor"], 0);
    }

    #[tokio::test]
    async fn api_index_stats_reuses_short_lived_cache() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let first = sample_resource_package_with_did("did:oan:resource:first");
        write_indexed_resource_packages(&state, std::slice::from_ref(&first))
            .await
            .unwrap();

        let initial = api_index_stats(State(state.clone())).await.unwrap();
        assert_eq!(initial.0["indexedResourceCount"], 1);

        let second = sample_resource_package_with_did("did:oan:resource:second");
        write_indexed_resource_packages(&state, &[first, second])
            .await
            .unwrap();

        let cached = api_index_stats(State(state.clone())).await.unwrap();
        assert_eq!(cached.0["indexedResourceCount"], 1);

        sleep(TokioDuration::from_millis(
            DISCOVERY_INDEX_STATS_CACHE_TTL_MS + 50,
        ))
        .await;

        let refreshed = api_index_stats(State(state)).await.unwrap();
        assert_eq!(refreshed.0["indexedResourceCount"], 2);
    }

    #[tokio::test]
    async fn api_query_explain_uses_resource_query_contract() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        write_indexed_resource_packages(&state, &[sample_resource_package()])
            .await
            .unwrap();

        let response = api_query_explain(
            State(state),
            Json(ResourceDiscoveryQuery {
                query: Some("contract".to_owned()),
                resource_type: Some(ResourceType::Skill),
                capability_tags: vec!["legal.contract.review".to_owned()],
                protocol: Some("https".to_owned()),
                version: None,
                version_mode: "latest".to_owned(),
                limit: 10,
            }),
        )
        .await
        .unwrap();
        assert_eq!(response.0["items"][0]["resourceDid"], resource_did());
        assert_eq!(response.0["items"][0]["matched"], true);
    }

    #[tokio::test]
    async fn sqlite_resource_index_upsert_replaces_existing_package() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let mut first = sample_resource_package();
        first.package_version = "1.0.0".to_owned();
        first.metadata.package_version = first.package_version.clone();
        first.metadata.description = "first".to_owned();
        refresh_hashes(&mut first);
        let mut second = first.clone();
        second.metadata.description = "second".to_owned();
        refresh_hashes(&mut second);

        upsert_indexed_resource_package(&state, 1, &first)
            .await
            .unwrap();
        upsert_indexed_resource_package(&state, 2, &second)
            .await
            .unwrap();

        let packages = read_indexed_resource_packages(&state).await.unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].package_version, "1.0.0");
        assert_eq!(packages[0].metadata.description, "second");
    }

    #[tokio::test]
    async fn sqlite_resource_index_batch_upsert_indexes_multiple_packages() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let first = sample_resource_package();
        let mut second = sample_resource_package();
        let second_did = "did:oan:SKLG:6HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned();
        second.resource_did = second_did.clone();
        second.did_document.id = second_did.clone();
        second.metadata.resource_did = second_did.clone();
        second.metadata.name = "Invoice Review Skill".to_owned();
        second.metadata.capability_tags = vec!["finance.invoice.review".to_owned()];
        if let Some(metadata) = second.did_document.oan_metadata.as_mut() {
            metadata.capability_tags = second.metadata.capability_tags.clone();
            if let Some(description) = metadata.resource_description.as_mut() {
                description.name = Some(second.metadata.name.clone());
                description.capability_tags = second.metadata.capability_tags.clone();
            }
        }
        refresh_hashes(&mut second);

        upsert_indexed_resource_packages_batch(&state, &[(1, first.clone()), (2, second.clone())])
            .await
            .unwrap();

        assert_eq!(count_indexed_resource_packages(&state).await.unwrap(), 2);
        let found_second = read_indexed_resource_package(&state, &second_did)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found_second.metadata.name, "Invoice Review Skill");
    }

    #[tokio::test]
    async fn sqlite_resource_index_batch_upsert_keeps_latest_duplicate_did() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let mut first = sample_resource_package();
        first.package_version = "1.0.0".to_owned();
        first.metadata.package_version = first.package_version.clone();
        first.metadata.description = "older package".to_owned();
        refresh_hashes(&mut first);
        let mut second = first.clone();
        second.package_version = "1.1.0".to_owned();
        second.metadata.package_version = second.package_version.clone();
        second.metadata.description = "newer package".to_owned();
        refresh_hashes(&mut second);

        upsert_indexed_resource_packages_batch(&state, &[(10, first), (11, second)])
            .await
            .unwrap();

        let packages = read_indexed_resource_packages(&state).await.unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].package_version, "1.1.0");
        assert_eq!(packages[0].metadata.description, "newer package");
    }

    #[tokio::test]
    async fn accepted_package_upsert_clears_old_rejections_for_same_did() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let package = sample_resource_package();
        write_rejected_packages(
            &state,
            &[
                json!({
                    "resourceDid": package.resource_did,
                    "cursor": 7,
                    "reason": "package_version_mismatch"
                }),
                json!({
                    "resourceDid": "did:oan:SKLG:other",
                    "cursor": 8,
                    "reason": "package_hash_mismatch"
                }),
            ],
        )
        .await
        .unwrap();

        upsert_indexed_resource_package(&state, 9, &package)
            .await
            .unwrap();

        let rejected = read_rejected_packages(&state).await.unwrap();
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0]["resourceDid"], "did:oan:SKLG:other");
    }

    #[tokio::test]
    async fn resolved_historical_rejection_audit_is_dry_run_by_default() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let package = sample_resource_package();
        upsert_indexed_resource_package(&state, 9, &package)
            .await
            .unwrap();
        write_rejected_packages(
            &state,
            &[json!({
                "resourceDid": package.resource_did,
                "cursor": 7,
                "reason": "package_hash_mismatch"
            })],
        )
        .await
        .unwrap();

        let report = audit_resolved_rejected_packages(
            &state,
            ResolvedRejectedPackageCleanupRequest::default(),
        )
        .await
        .unwrap();

        assert_eq!(report["status"], "audited");
        assert_eq!(report["resolvedRejectedCount"], 1);
        assert_eq!(report["deletedCount"], 0);
        assert_eq!(read_rejected_packages(&state).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn resolved_historical_rejection_cleanup_deletes_only_visible_mismatches() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let package = sample_resource_package();
        upsert_indexed_resource_package(&state, 9, &package)
            .await
            .unwrap();
        write_rejected_packages(
            &state,
            &[
                json!({
                    "resourceDid": package.resource_did,
                    "cursor": 7,
                    "reason": "capability_tags_mismatch"
                }),
                json!({
                    "resourceDid": package.resource_did,
                    "cursor": 8,
                    "reason": "unauthorized_domains"
                }),
                json!({
                    "resourceDid": "did:oan:SKLG:not-visible",
                    "cursor": 9,
                    "reason": "package_version_mismatch"
                }),
            ],
        )
        .await
        .unwrap();

        let report = audit_resolved_rejected_packages(
            &state,
            ResolvedRejectedPackageCleanupRequest {
                dry_run: false,
                max_items: None,
                resource_dids: vec![],
            },
        )
        .await
        .unwrap();

        assert_eq!(report["status"], "cleaned");
        assert_eq!(report["deletedCount"], 1);
        let rejected = read_rejected_packages(&state).await.unwrap();
        assert_eq!(rejected.len(), 2);
        assert!(rejected
            .iter()
            .any(|item| item["reason"] == "unauthorized_domains"));
        assert!(rejected
            .iter()
            .any(|item| item["resourceDid"] == "did:oan:SKLG:not-visible"));
    }

    #[tokio::test]
    async fn postgres_semantic_rebuild_persists_completed_phase_when_available() {
        let dir = tempdir().unwrap();
        let Some(state) = app_state_with_semantic_postgres(dir.path()).await else {
            eprintln!(
                "skipping pgvector semantic rebuild progress test; set OAN_DISCOVERY_SEMANTIC_TEST_DATABASE_URL"
            );
            return;
        };
        upsert_indexed_resource_package(&state, 1, &sample_resource_package())
            .await
            .unwrap();

        let report = rebuild_semantic_indexes(&state, true, SemanticRebuildStage::Both)
            .await
            .unwrap();
        let progress = load_semantic_rebuild_progress(&state, SemanticRebuildStage::Both)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(report.phase, "completed");
        assert_eq!(progress.phase, "completed");
        assert_eq!(progress.processed, report.package_count);
        assert_eq!(progress.total, report.package_count);
    }

    #[tokio::test]
    async fn postgres_pgvector_semantic_query_ranks_verified_packages_when_available() {
        let dir = tempdir().unwrap();
        let Some(state) = app_state_with_semantic_postgres(dir.path()).await else {
            eprintln!(
                "skipping pgvector semantic integration test; set OAN_DISCOVERY_SEMANTIC_TEST_DATABASE_URL"
            );
            return;
        };
        let first = sample_resource_package();
        let mut second = sample_resource_package_with_did("did:oan:resource:weather");
        second.metadata.name = "Weather Forecast Skill".to_owned();
        second.metadata.description =
            "Forecast rainfall and temperature for travel planning".to_owned();
        second.metadata.capability_tags = vec!["weather.forecast".to_owned()];
        if let Some(metadata) = second.did_document.oan_metadata.as_mut() {
            metadata.capability_tags = second.metadata.capability_tags.clone();
            if let Some(description) = metadata.resource_description.as_mut() {
                description.name = Some(second.metadata.name.clone());
                description.description = Some(second.metadata.description.clone());
                description.capability_description =
                    Some("Predict local weather conditions".to_owned());
                description.capability_tags = second.metadata.capability_tags.clone();
                description.use_case_examples =
                    vec!["Plan a trip around rain probability".to_owned()];
                description.examples = vec![json!("Will it rain tomorrow?")];
            }
        }
        refresh_hashes(&mut second);

        upsert_indexed_resource_packages_batch(&state, &[(1, first.clone()), (2, second)])
            .await
            .unwrap();
        assert_eq!(
            count_semantic_indexed_resources(&state).await.unwrap(),
            Some(2)
        );
        assert!(
            count_intent_indexed_rows(&state)
                .await
                .unwrap()
                .unwrap_or_default()
                >= 2,
            "expected per-intent embeddings to be indexed"
        );

        let hits = query_semantic_index(
            &state,
            &ResourceDiscoveryQuery {
                query: Some("commercial contract risk review".to_owned()),
                resource_type: None,
                capability_tags: vec![],
                protocol: None,
                version: None,
                version_mode: "latest".to_owned(),
                limit: 2,
            },
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(hits[0].package.resource_did, first.resource_did);
        assert!(hits[0].semantic_score >= hits[1].semantic_score);

        let explain = api_query_explain(
            State(state),
            Json(ResourceDiscoveryQuery {
                query: Some("commercial contract risk review".to_owned()),
                resource_type: None,
                capability_tags: vec![],
                protocol: None,
                version: None,
                version_mode: "latest".to_owned(),
                limit: 2,
            }),
        )
        .await
        .unwrap();
        assert_eq!(explain.0["semanticSearch"]["fallbackUsed"], false);
        assert!(explain.0["items"][0]["semanticScore"].as_f64().is_some());
    }

    #[tokio::test]
    async fn sqlite_query_prefilter_falls_back_to_api_equivalent_filtering() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let package = sample_resource_package();
        upsert_indexed_resource_package(&state, 1, &package)
            .await
            .unwrap();

        let query = ResourceDiscoveryQuery {
            query: Some("contract".to_owned()),
            resource_type: Some(ResourceType::Skill),
            capability_tags: vec!["legal.contract.review".to_owned()],
            protocol: Some("https".to_owned()),
            version: Some("1".to_owned()),
            version_mode: "exact".to_owned(),
            limit: 10,
        };
        let (packages, prefiltered) = query_indexed_resource_packages(&state, &query)
            .await
            .unwrap();
        assert!(!prefiltered);
        assert_eq!(packages.len(), 1);
        assert_eq!(
            rank_resource_packages_semantically(packages, &query).len(),
            1
        );
    }

    #[tokio::test]
    async fn resource_query_filters_indexed_packages_outside_discovery_grant() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        write_discovery_document(&state, vec!["legal".to_owned()]);
        let legal = sample_resource_package();
        let mut finance =
            sample_resource_package_with_did("did:oan:SKLG:33333333333333333333333333333333");
        set_package_authorized_domains(&mut finance, vec!["finance".to_owned()]);
        upsert_indexed_resource_package(&state, 1, &legal)
            .await
            .unwrap();
        upsert_indexed_resource_package(&state, 2, &finance)
            .await
            .unwrap();

        let response = resource_query(
            State(state),
            Json(ResourceDiscoveryQuery {
                query: None,
                resource_type: Some(ResourceType::Skill),
                capability_tags: vec![],
                protocol: None,
                version: None,
                version_mode: "latest".to_owned(),
                limit: 10,
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0.candidates.len(), 1);
        assert_eq!(response.0.candidates[0].resource_did, legal.resource_did);
        assert_eq!(
            response.0.candidates[0].authorized_domains,
            vec!["legal".to_owned()]
        );
    }

    #[tokio::test]
    async fn resource_query_accepts_empty_query_with_structured_filters() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let mut legal = sample_resource_package();
        set_package_tags(
            &mut legal,
            vec![
                "legal.contract.review".to_owned(),
                "risk.analysis".to_owned(),
            ],
        );
        let mut finance =
            sample_resource_package_with_did("did:oan:SKLG:44444444444444444444444444444444");
        set_package_tags(&mut finance, vec!["finance.invoice.audit".to_owned()]);
        upsert_indexed_resource_package(&state, 1, &legal)
            .await
            .unwrap();
        upsert_indexed_resource_package(&state, 2, &finance)
            .await
            .unwrap();

        let response = resource_query(
            State(state),
            Json(ResourceDiscoveryQuery {
                query: None,
                resource_type: Some(ResourceType::Skill),
                capability_tags: vec![
                    "legal.contract.review".to_owned(),
                    "risk.analysis".to_owned(),
                ],
                protocol: Some("https".to_owned()),
                version: None,
                version_mode: "latest".to_owned(),
                limit: 10,
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0.candidates.len(), 1);
        assert_eq!(response.0.candidates[0].resource_did, legal.resource_did);
    }

    #[tokio::test]
    async fn database_index_count_and_point_lookup_do_not_require_full_scan() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let package = sample_resource_package();

        upsert_indexed_resource_package(&state, 9, &package)
            .await
            .unwrap();

        assert_eq!(count_indexed_resource_packages(&state).await.unwrap(), 1);
        let found = read_indexed_resource_package(&state, &package.resource_did)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.resource_did, package.resource_did);
        assert!(
            read_indexed_resource_package(&state, "did:oan:SKLG:not-found")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn api_index_resource_visibility_returns_only_indexed_dids() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let package = sample_resource_package();
        upsert_indexed_resource_package(&state, 9, &package)
            .await
            .unwrap();

        let response = api_index_resource_visibility(
            State(state),
            Json(IndexedResourceVisibilityRequest {
                resource_dids: vec![
                    package.resource_did.clone(),
                    "did:oan:SKLG:not-found".to_owned(),
                ],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["visibleCount"], 1);
        assert_eq!(response.0["visible"][0], package.resource_did);
    }

    #[tokio::test]
    async fn resource_query_reports_no_candidates_for_indexed_mismatch() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        upsert_indexed_resource_package(&state, 1, &sample_resource_package())
            .await
            .unwrap();

        let response = resource_query(
            State(state),
            Json(ResourceDiscoveryQuery {
                query: Some("contract".to_owned()),
                resource_type: Some(ResourceType::McpServer),
                capability_tags: vec!["legal.contract.review".to_owned()],
                protocol: Some("https".to_owned()),
                version: None,
                version_mode: "latest".to_owned(),
                limit: 10,
            }),
        )
        .await
        .unwrap();

        assert!(response.0.candidates.is_empty());
    }

    #[test]
    fn discovery_package_projection_extracts_indexable_hot_fields() {
        let package = sample_resource_package();
        let projection = discovery_package_projection(&package);

        assert_eq!(projection.resource_type, "skill");
        assert_eq!(projection.lifecycle_state, "active");
        assert!(projection
            .capability_tags
            .contains(&"legal.contract.review".to_owned()));
        assert!(projection.protocols.contains(&"https".to_owned()));
        assert!(projection.search_text.contains("contract review skill"));
        assert!(projection.search_text.contains("legal.contract.review"));
    }

    #[test]
    fn discovery_package_projection_adds_chinese_tokens_and_aliases_to_search_text() {
        let mut package = sample_resource_package();
        set_package_description(
            &mut package,
            "合同审查助手",
            "审查合同付款、终止、责任和合规风险，并生成风险清单。",
        );
        let projection = discovery_package_projection(&package);

        assert!(projection.search_text.contains("合同"));
        assert!(projection.search_text.contains("风险"));
        assert!(projection.search_text.contains("document.analysis"));
        assert!(projection.search_text.contains("security.risk"));
    }

    #[test]
    fn semantic_search_document_extracts_did_metadata_without_package_examples() {
        let package = sample_resource_package();
        let projection = discovery_package_projection(&package);
        let doc = search_document_from_package(42, &package, &projection);

        assert_eq!(doc.resource_did, package.resource_did);
        assert_eq!(doc.cursor, 42);
        assert_eq!(doc.resource_type, "skill");
        assert!(doc
            .description
            .contains("Detect payment, termination, liability"));
        assert!(doc
            .capability_tags
            .contains(&"legal.contract.review".to_owned()));
        assert!(doc.protocols.contains(&"https".to_owned()));
        assert!(doc
            .use_cases
            .contains(&"Find payment and termination risks".to_owned()));
        assert!(doc
            .examples
            .iter()
            .any(|example| example.contains("commercial contract")));
        let semantic_text = semantic_document_text(&doc);
        assert!(semantic_text.contains("Tag view:"));
        assert!(semantic_text.contains("Context view:"));
        assert!(semantic_text.contains("Intent view:"));
        assert!(semantic_text.contains("User wants to Find payment and termination risks"));
        assert!(doc.semantic_source_hash.starts_with("sha256:"));
    }

    #[test]
    fn semantic_filter_defaults_keep_explicit_metadata_as_hard_constraints() {
        let config = SemanticSearchConfig::default();

        assert_eq!(config.filters.resource_type, "hard");
        assert_eq!(config.filters.capability_tags, "hard");
        assert_eq!(config.filters.protocol, "hard");
    }

    #[test]
    fn deterministic_embedding_is_stable_and_normalized() {
        let first = deterministic_embedding("contract risk review", 16);
        let second = deterministic_embedding("contract risk review", 16);
        let unrelated = deterministic_embedding("weather forecast", 16);

        assert_eq!(first, second);
        assert_ne!(first, unrelated);
        let norm = first.iter().map(|value| value * value).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.0001);
        assert_eq!(pgvector_literal(&first).matches(',').count(), 15);
        assert!(pgvector_literal(&first).starts_with("'["));
        assert!(pgvector_literal(&first).ends_with("]'"));
    }

    #[tokio::test]
    async fn semantic_engine_and_embedding_provider_have_explicit_extension_points() {
        let mut config = SemanticSearchConfig {
            enabled: true,
            ..SemanticSearchConfig::default()
        };
        assert_eq!(
            DiscoverySearchEngine::from_config(&config).unwrap(),
            DiscoverySearchEngine::PgVector
        );
        assert_eq!(
            EmbeddingProviderKind::from_config(&config.embedding).unwrap(),
            EmbeddingProviderKind::DeterministicLocal
        );
        assert!(
            embed_semantic_text(&config, &reqwest::Client::new(), "contract risk")
                .await
                .unwrap()
                .iter()
                .any(|value| *value > 0.0)
        );

        config.engine = "grail".to_owned();
        assert!(DiscoverySearchEngine::from_config(&config)
            .unwrap_err()
            .to_string()
            .contains("grail_engine_not_implemented"));
    }

    #[tokio::test]
    async fn http_embedding_provider_validates_health_and_embeds_query_text() {
        let app = Router::new()
            .route(
                "/health",
                get(|| async {
                    Json(json!({
                        "model": "gte-multilingual-base",
                        "embeddingVersion": "test-revision",
                        "dtype": "q8",
                        "dimension": 4,
                        "ready": true
                    }))
                }),
            )
            .route(
                "/embed",
                post(|Json(body): Json<Value>| async move {
                    assert_eq!(body["model"], "gte-multilingual-base");
                    assert_eq!(body["input"].as_array().unwrap().len(), 1);
                    Json(json!({
                        "model": "gte-multilingual-base",
                        "embeddingVersion": "test-revision",
                        "dtype": "q8",
                        "dimension": 4,
                        "vectors": [[1.0, 0.0, 0.0, 0.0]]
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let config = SemanticSearchConfig {
            embedding: SemanticEmbeddingConfig {
                provider: "http-embedding".to_owned(),
                endpoint: Some(format!("http://{addr}/embed")),
                health_endpoint: Some(format!("http://{addr}/health")),
                model_name: "gte-multilingual-base".to_owned(),
                model_version: Some("test-revision".to_owned()),
                strict_model_version: true,
                dtype: Some("q8".to_owned()),
                dimension: 4,
                ..SemanticEmbeddingConfig::default()
            },
            ..SemanticSearchConfig::default()
        };
        let client = reqwest::Client::new();

        validate_embedding_provider(&config, &client).await.unwrap();
        let vector = embed_semantic_text(&config, &client, "我需要搜索代码仓库")
            .await
            .unwrap();
        assert_eq!(vector.len(), 4);
        assert!((vector[0] - 1.0).abs() < 0.0001);
    }

    #[tokio::test]
    async fn http_embedding_provider_rejects_dtype_mismatch() {
        let app = Router::new().route(
            "/health",
            get(|| async {
                Json(json!({
                    "model": "gte-multilingual-base",
                    "embeddingVersion": "test-revision",
                    "dtype": "fp32",
                    "dimension": 4,
                    "ready": true
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let config = SemanticSearchConfig {
            embedding: SemanticEmbeddingConfig {
                provider: "http-embedding".to_owned(),
                endpoint: Some(format!("http://{addr}/embed")),
                health_endpoint: Some(format!("http://{addr}/health")),
                model_name: "gte-multilingual-base".to_owned(),
                model_version: Some("test-revision".to_owned()),
                strict_model_version: true,
                dtype: Some("q8".to_owned()),
                dimension: 4,
                ..SemanticEmbeddingConfig::default()
            },
            ..SemanticSearchConfig::default()
        };

        let error = validate_embedding_provider(&config, &reqwest::Client::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("http_embedding_dtype_mismatch:fp32"));
    }

    #[tokio::test]
    async fn unavailable_http_embedding_provider_disables_semantic_runtime() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        state.config.semantic_search = SemanticSearchConfig {
            enabled: true,
            embedding: SemanticEmbeddingConfig {
                provider: "http-embedding".to_owned(),
                endpoint: Some("http://127.0.0.1:9/embed".to_owned()),
                health_endpoint: Some("http://127.0.0.1:9/health".to_owned()),
                model_name: "gte-multilingual-base".to_owned(),
                model_version: Some("gte-multilingual-base".to_owned()),
                strict_model_version: true,
                dimension: 768,
                timeout_ms: 50,
                ..SemanticEmbeddingConfig::default()
            },
            ..SemanticSearchConfig::default()
        };

        state.semantic = initialize_semantic_runtime(&state.config, state.postgres.as_ref()).await;
        assert!(!semantic_search_available(&state));

        let status = semantic_status_json(&state, true, Some("keyword_fallback".to_owned()));
        assert_eq!(status["enabled"], false);
        assert_eq!(status["healthy"], false);
        assert_eq!(status["embeddingProvider"], "http-embedding");
        assert_eq!(status["embeddingModel"], "gte-multilingual-base");
        assert_eq!(status["fallbackUsed"], true);
        assert!(status["fallbackReason"].as_str().unwrap().len() > 0);
    }

    #[test]
    fn semantic_candidate_limit_respects_headroom_and_caps() {
        let config = SemanticSearchConfig {
            candidate_multiplier: 8,
            max_candidates: 500,
            ..SemanticSearchConfig::default()
        };
        assert_eq!(semantic_candidate_limit(0, &config), 25);
        assert_eq!(semantic_candidate_limit(1, &config), 25);
        assert_eq!(semantic_candidate_limit(10, &config), 80);
        assert_eq!(semantic_candidate_limit(100, &config), 500);
    }

    #[test]
    fn semantic_status_is_disabled_by_default_for_json_storage() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let status = semantic_status_json(&state, true, Some("test_fallback".to_owned()));

        assert_eq!(status["enabled"], false);
        assert_eq!(status["healthy"], false);
        assert_eq!(status["fallbackReason"], "test_fallback");
        assert_eq!(status["filters"]["resourceType"], "hard");
    }

    #[test]
    fn discovery_sql_candidate_limit_is_bounded_for_query_pushdown() {
        assert_eq!(discovery_sql_candidate_limit(0), 25);
        assert_eq!(discovery_sql_candidate_limit(1), 25);
        assert_eq!(discovery_sql_candidate_limit(10), 30);
        assert_eq!(discovery_sql_candidate_limit(100), 300);
        assert_eq!(discovery_sql_candidate_limit(1_000), 3_000);
        assert_eq!(discovery_sql_candidate_limit(10_000), 10_000);
    }

    #[test]
    fn discovery_sql_candidate_limit_expands_when_text_prefilter_is_unavailable() {
        let mut query = ResourceDiscoveryQuery {
            query: Some("合同风险审查".to_owned()),
            resource_type: None,
            capability_tags: Vec::new(),
            protocol: None,
            version: None,
            version_mode: "latest".to_owned(),
            limit: 10,
        };

        assert!(!should_use_sql_text_prefilter(&query));
        assert_eq!(discovery_sql_candidate_limit_for_query(&query), 500);

        query.query = Some("contract risk review".to_owned());
        assert!(should_use_sql_text_prefilter(&query));
        assert_eq!(discovery_sql_candidate_limit_for_query(&query), 30);
    }

    #[tokio::test]
    async fn sync_resources_from_authorized_summary_fetches_only_notified_items() {
        let dir = tempdir().unwrap();
        let package = sample_resource_package();
        let app = Router::new()
            .route(
                "/cdn/resources/index",
                get(|| async {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "index_should_not_be_called"})),
                    )
                }),
            )
            .route(
                "/cdn/resources/batch-get",
                post({
                    let package = package.clone();
                    move || {
                        let package = package.clone();
                        async move {
                            Json(json!({
                                "requestedCount": 1,
                                "foundCount": 1,
                                "items": [{
                                    "resourceDid": package.resource_did,
                                    "package": package
                                }]
                            }))
                        }
                    }
                }),
            )
            .route(
                "/cdn/resources/{*did}",
                get(|| async {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "single_resource_get_should_not_be_called"})),
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.upstream.cdn_endpoint = Some(format!("http://{addr}"));
        let response = sync_resources_from_authorized_summary(
            State(state.clone()),
            Json(DiscoverySyncRequest {
                max_publications: Some(10),
                cursor_hint: Some(7),
                items: vec![DiscoveryNotificationItem {
                    resource_did: package.resource_did.clone(),
                    package_version: package.package_version.clone(),
                    publication_cursor: 7,
                    package_hash: package.package_hash.clone(),
                    metadata_hash: package.metadata_hash.clone(),
                    did_document_hash: package.did_document_hash.clone(),
                    resource_type: Some("skill".to_owned()),
                    capability_tags: package.metadata.capability_tags.clone(),
                    authorized_domains: package.metadata.authorized_domains.clone(),
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["syncMode"], "authorized-summary");
        assert_eq!(response.0["syncedResourceCount"], 1);
        assert_eq!(response.0["rejectedCount"], 0);
        assert_eq!(response.0["pagesFetched"], 0);
        assert_eq!(response.0["itemsFetched"], 1);
        assert_eq!(read_sync_cursor(&state).await.unwrap(), 7);
        let indexed = read_indexed_resource_packages(&state).await.unwrap();
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0].resource_did, package.resource_did);
    }

    #[tokio::test]
    async fn sync_resources_from_authorized_summary_indexes_current_package_for_stale_hash_notice()
    {
        let dir = tempdir().unwrap();
        let package = sample_resource_package();
        let app = Router::new().route(
            "/cdn/resources/{*did}",
            get({
                let package = package.clone();
                move || {
                    let package = package.clone();
                    async move { Json(package) }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.upstream.cdn_endpoint = Some(format!("http://{addr}"));
        let response = sync_resources_from_authorized_summary(
            State(state.clone()),
            Json(DiscoverySyncRequest {
                max_publications: Some(10),
                cursor_hint: Some(9),
                items: vec![DiscoveryNotificationItem {
                    resource_did: package.resource_did.clone(),
                    package_version: package.package_version.clone(),
                    publication_cursor: 9,
                    package_hash: "sha256:bad".to_owned(),
                    metadata_hash: "sha256:bad".to_owned(),
                    did_document_hash: "sha256:bad".to_owned(),
                    resource_type: Some("skill".to_owned()),
                    capability_tags: package.metadata.capability_tags.clone(),
                    authorized_domains: package.metadata.authorized_domains.clone(),
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["syncMode"], "authorized-summary");
        assert_eq!(response.0["syncedResourceCount"], 1);
        assert_eq!(response.0["rejectedCount"], 0);
        let indexed = read_indexed_resource_packages(&state).await.unwrap();
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0].resource_did, package.resource_did);
    }

    #[tokio::test]
    async fn sync_resources_from_authorized_summary_indexes_current_cdn_package_for_stale_notice() {
        let dir = tempdir().unwrap();
        let package = sample_resource_package();
        let app = Router::new().route(
            "/cdn/resources/{*did}",
            get({
                let package = package.clone();
                move || {
                    let package = package.clone();
                    async move { Json(package) }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.upstream.cdn_endpoint = Some(format!("http://{addr}"));
        let response = sync_resources_from_authorized_summary(
            State(state.clone()),
            Json(DiscoverySyncRequest {
                max_publications: Some(10),
                cursor_hint: Some(9),
                items: vec![DiscoveryNotificationItem {
                    resource_did: package.resource_did.clone(),
                    package_version: "1.0.0".to_owned(),
                    publication_cursor: 9,
                    package_hash: "sha256:older".to_owned(),
                    metadata_hash: "sha256:older".to_owned(),
                    did_document_hash: "sha256:older".to_owned(),
                    resource_type: Some("skill".to_owned()),
                    capability_tags: package.metadata.capability_tags.clone(),
                    authorized_domains: package.metadata.authorized_domains.clone(),
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["syncMode"], "authorized-summary");
        assert_eq!(response.0["syncedResourceCount"], 1);
        assert_eq!(response.0["rejectedCount"], 0);
        let indexed = read_indexed_resource_packages(&state).await.unwrap();
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0].resource_did, package.resource_did);
        assert_eq!(indexed[0].package_version, package.package_version);
    }

    #[tokio::test]
    async fn sync_resources_from_authorized_summary_drops_same_batch_rejection_for_accepted_did() {
        let dir = tempdir().unwrap();
        let package = sample_resource_package();
        let app = Router::new().route(
            "/cdn/resources/{*did}",
            get({
                let package = package.clone();
                move || {
                    let package = package.clone();
                    async move { Json(package) }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.upstream.cdn_endpoint = Some(format!("http://{addr}"));
        let response = sync_resources_from_authorized_summary(
            State(state.clone()),
            Json(DiscoverySyncRequest {
                max_publications: Some(10),
                cursor_hint: Some(9),
                items: vec![
                    DiscoveryNotificationItem {
                        resource_did: package.resource_did.clone(),
                        package_version: package.package_version.clone(),
                        publication_cursor: 8,
                        package_hash: package.package_hash.clone(),
                        metadata_hash: package.metadata_hash.clone(),
                        did_document_hash: package.did_document_hash.clone(),
                        resource_type: Some("skill".to_owned()),
                        capability_tags: vec!["stale-tag".to_owned()],
                        authorized_domains: package.metadata.authorized_domains.clone(),
                    },
                    DiscoveryNotificationItem {
                        resource_did: package.resource_did.clone(),
                        package_version: package.package_version.clone(),
                        publication_cursor: 9,
                        package_hash: package.package_hash.clone(),
                        metadata_hash: package.metadata_hash.clone(),
                        did_document_hash: package.did_document_hash.clone(),
                        resource_type: Some("skill".to_owned()),
                        capability_tags: package.metadata.capability_tags.clone(),
                        authorized_domains: package.metadata.authorized_domains.clone(),
                    },
                ],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["syncedResourceCount"], 1);
        assert_eq!(response.0["rejectedCount"], 0);
        assert!(read_rejected_packages(&state).await.unwrap().is_empty());
        let indexed = read_indexed_resource_packages(&state).await.unwrap();
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0].resource_did, package.resource_did);
    }

    #[tokio::test]
    async fn sync_resources_from_authorized_summary_rejects_authorized_domains_mismatch() {
        let dir = tempdir().unwrap();
        let package = sample_resource_package();
        let app = Router::new().route(
            "/cdn/resources/{*did}",
            get({
                let package = package.clone();
                move || {
                    let package = package.clone();
                    async move { Json(package) }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.upstream.cdn_endpoint = Some(format!("http://{addr}"));
        let response = sync_resources_from_authorized_summary(
            State(state.clone()),
            Json(DiscoverySyncRequest {
                max_publications: Some(10),
                cursor_hint: Some(9),
                items: vec![DiscoveryNotificationItem {
                    resource_did: package.resource_did.clone(),
                    package_version: package.package_version.clone(),
                    publication_cursor: 9,
                    package_hash: package.package_hash.clone(),
                    metadata_hash: package.metadata_hash.clone(),
                    did_document_hash: package.did_document_hash.clone(),
                    resource_type: Some("skill".to_owned()),
                    capability_tags: package.metadata.capability_tags.clone(),
                    authorized_domains: vec!["finance".to_owned()],
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["syncMode"], "authorized-summary");
        assert_eq!(response.0["syncedResourceCount"], 0);
        assert_eq!(response.0["rejectedCount"], 1);
        assert_eq!(
            response.0["rejected"][0]["reason"],
            "authorized_domains_mismatch"
        );
        assert_eq!(
            read_indexed_resource_packages(&state).await.unwrap().len(),
            0
        );
    }

    #[tokio::test]
    async fn sync_resources_from_authorized_summary_rejects_missing_authorized_domains_item() {
        let dir = tempdir().unwrap();
        let package = sample_resource_package();
        let app = Router::new().route(
            "/cdn/resources/{*did}",
            get({
                let package = package.clone();
                move || {
                    let package = package.clone();
                    async move { Json(package) }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.upstream.cdn_endpoint = Some(format!("http://{addr}"));
        let response = sync_resources_from_authorized_summary(
            State(state.clone()),
            Json(DiscoverySyncRequest {
                max_publications: Some(10),
                cursor_hint: Some(9),
                items: vec![DiscoveryNotificationItem {
                    resource_did: package.resource_did.clone(),
                    package_version: package.package_version.clone(),
                    publication_cursor: 9,
                    package_hash: package.package_hash.clone(),
                    metadata_hash: package.metadata_hash.clone(),
                    did_document_hash: package.did_document_hash.clone(),
                    resource_type: Some("skill".to_owned()),
                    capability_tags: package.metadata.capability_tags.clone(),
                    authorized_domains: vec![],
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["syncedResourceCount"], 0);
        assert_eq!(response.0["rejectedCount"], 1);
        assert_eq!(
            response.0["rejected"][0]["reason"],
            "resource_domains_required"
        );
        assert_eq!(
            read_indexed_resource_packages(&state).await.unwrap().len(),
            0
        );
    }

    #[tokio::test]
    async fn sync_resources_from_authorized_summary_rejects_domains_outside_discovery_grant() {
        let dir = tempdir().unwrap();
        let mut package = sample_resource_package();
        set_package_authorized_domains(&mut package, vec!["finance".to_owned()]);
        let app = Router::new().route(
            "/cdn/resources/{*did}",
            get({
                let package = package.clone();
                move || {
                    let package = package.clone();
                    async move { Json(package) }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut state = app_state_with_sqlite(dir.path()).await;
        write_discovery_document(&state, vec!["legal".to_owned()]);
        state.config.upstream.cdn_endpoint = Some(format!("http://{addr}"));
        let response = sync_resources_from_authorized_summary(
            State(state.clone()),
            Json(DiscoverySyncRequest {
                max_publications: Some(10),
                cursor_hint: Some(9),
                items: vec![DiscoveryNotificationItem {
                    resource_did: package.resource_did.clone(),
                    package_version: package.package_version.clone(),
                    publication_cursor: 9,
                    package_hash: package.package_hash.clone(),
                    metadata_hash: package.metadata_hash.clone(),
                    did_document_hash: package.did_document_hash.clone(),
                    resource_type: Some("skill".to_owned()),
                    capability_tags: package.metadata.capability_tags.clone(),
                    authorized_domains: package.metadata.authorized_domains.clone(),
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["syncedResourceCount"], 0);
        assert_eq!(response.0["rejectedCount"], 1);
        assert_eq!(response.0["rejected"][0]["reason"], "unauthorized_domains");
        assert_eq!(
            read_indexed_resource_packages(&state).await.unwrap().len(),
            0
        );
    }

    #[tokio::test]
    async fn sync_resources_from_authorized_summary_skips_unavailable_package_without_blocking() {
        let dir = tempdir().unwrap();
        let first =
            sample_resource_package_with_did("did:oan:SKLG:11111111111111111111111111111111");
        let third =
            sample_resource_package_with_did("did:oan:SKLG:33333333333333333333333333333333");
        let missing_did = "did:oan:SKLG:22222222222222222222222222222222".to_owned();
        let app = Router::new().route(
            "/cdn/resources/{*did}",
            get({
                let first = first.clone();
                let third = third.clone();
                move |AxumPath(did): AxumPath<String>| {
                    let first = first.clone();
                    let third = third.clone();
                    async move {
                        let did = did.trim_start_matches('/');
                        if did == first.resource_did {
                            Json(first).into_response()
                        } else if did == third.resource_did {
                            Json(third).into_response()
                        } else {
                            (StatusCode::NOT_FOUND, Json(json!({"error": "missing"})))
                                .into_response()
                        }
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.upstream.cdn_endpoint = Some(format!("http://{addr}"));
        let response = sync_resources_from_authorized_summary(
            State(state.clone()),
            Json(DiscoverySyncRequest {
                max_publications: Some(10),
                cursor_hint: Some(3),
                items: vec![
                    DiscoveryNotificationItem {
                        resource_did: first.resource_did.clone(),
                        package_version: first.package_version.clone(),
                        publication_cursor: 1,
                        package_hash: first.package_hash.clone(),
                        metadata_hash: first.metadata_hash.clone(),
                        did_document_hash: first.did_document_hash.clone(),
                        resource_type: Some("skill".to_owned()),
                        capability_tags: first.metadata.capability_tags.clone(),
                        authorized_domains: first.metadata.authorized_domains.clone(),
                    },
                    DiscoveryNotificationItem {
                        resource_did: missing_did,
                        package_version: "1".to_owned(),
                        publication_cursor: 2,
                        package_hash: "sha256:missing".to_owned(),
                        metadata_hash: "sha256:missing".to_owned(),
                        did_document_hash: "sha256:missing".to_owned(),
                        resource_type: Some("skill".to_owned()),
                        capability_tags: vec![],
                        authorized_domains: vec![],
                    },
                    DiscoveryNotificationItem {
                        resource_did: third.resource_did.clone(),
                        package_version: third.package_version.clone(),
                        publication_cursor: 3,
                        package_hash: third.package_hash.clone(),
                        metadata_hash: third.metadata_hash.clone(),
                        did_document_hash: third.did_document_hash.clone(),
                        resource_type: Some("skill".to_owned()),
                        capability_tags: third.metadata.capability_tags.clone(),
                        authorized_domains: third.metadata.authorized_domains.clone(),
                    },
                ],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["syncMode"], "authorized-summary");
        assert_eq!(response.0["syncedResourceCount"], 2);
        assert_eq!(response.0["rejectedCount"], 1);
        assert_eq!(
            response.0["rejected"][0]["reason"],
            "resource_package_unavailable"
        );
        assert_eq!(response.0["toCursor"], 3);
        assert_eq!(response.0["blockedCursor"], 2);
        assert_eq!(read_sync_cursor(&state).await.unwrap(), 3);
        let indexed = read_indexed_resource_packages(&state).await.unwrap();
        assert_eq!(indexed.len(), 2);
        assert!(indexed
            .iter()
            .any(|package| package.resource_did == first.resource_did));
        assert!(indexed
            .iter()
            .any(|package| package.resource_did == third.resource_did));
    }

    #[tokio::test]
    async fn backfill_rejected_packages_indexes_transiently_unavailable_package() {
        let dir = tempdir().unwrap();
        let missing =
            sample_resource_package_with_did("did:oan:SKLG:22222222222222222222222222222222");
        let available = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let app = Router::new().route(
            "/cdn/resources/{*did}",
            get({
                let missing = missing.clone();
                let available = available.clone();
                move |AxumPath(did): AxumPath<String>| {
                    let missing = missing.clone();
                    let available = available.clone();
                    async move {
                        let did = did.trim_start_matches('/');
                        if did == missing.resource_did
                            && available.load(std::sync::atomic::Ordering::SeqCst)
                        {
                            Json(missing).into_response()
                        } else {
                            (StatusCode::NOT_FOUND, Json(json!({"error": "missing"})))
                                .into_response()
                        }
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut state = app_state_with_sqlite(dir.path()).await;
        let cdn_base = format!("http://{addr}");
        state.config.upstream.cdn_endpoint = Some(cdn_base.clone());
        let response = sync_resources_from_authorized_summary(
            State(state.clone()),
            Json(DiscoverySyncRequest {
                max_publications: Some(10),
                cursor_hint: Some(2),
                items: vec![DiscoveryNotificationItem {
                    resource_did: missing.resource_did.clone(),
                    package_version: "1".to_owned(),
                    publication_cursor: 2,
                    package_hash: missing.package_hash.clone(),
                    metadata_hash: missing.metadata_hash.clone(),
                    did_document_hash: missing.did_document_hash.clone(),
                    resource_type: Some("skill".to_owned()),
                    capability_tags: missing.metadata.capability_tags.clone(),
                    authorized_domains: missing.metadata.authorized_domains.clone(),
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["syncedResourceCount"], 0);
        assert_eq!(
            response.0["rejected"][0]["reason"],
            "resource_package_unavailable"
        );
        assert_eq!(
            read_indexed_resource_packages(&state).await.unwrap().len(),
            0
        );
        assert_eq!(read_rejected_packages(&state).await.unwrap().len(), 1);

        available.store(true, std::sync::atomic::Ordering::SeqCst);
        let report = backfill_rejected_resource_packages(
            &state,
            &cdn_base,
            RejectedPackageBackfillRequest {
                max_items: Some(10),
                resource_dids: vec![],
            },
        )
        .await
        .unwrap();

        assert_eq!(report["attemptedCount"], 1);
        assert_eq!(report["recoveredCount"], 1);
        assert_eq!(report["remainingRejectedCount"], 0);
        let indexed = read_indexed_resource_packages(&state).await.unwrap();
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0].resource_did, missing.resource_did);
        assert!(read_rejected_packages(&state).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn backfill_rejected_packages_leaves_non_transient_rejections_untouched() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        write_rejected_packages(
            &state,
            &[json!({
                "resourceDid": "did:oan:SKLG:not-transient",
                "cursor": 7,
                "reason": "unauthorized_domains"
            })],
        )
        .await
        .unwrap();

        let report = backfill_rejected_resource_packages(
            &state,
            "http://127.0.0.1:9",
            RejectedPackageBackfillRequest {
                max_items: Some(10),
                resource_dids: vec![],
            },
        )
        .await
        .unwrap();

        assert_eq!(report["attemptedCount"], 0);
        assert_eq!(report["recoveredCount"], 0);
        assert_eq!(report["remainingRejectedCount"], 1);
        let rejected = read_rejected_packages(&state).await.unwrap();
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0]["reason"], "unauthorized_domains");
    }

    #[tokio::test]
    async fn backfill_rejected_packages_replaces_transient_reason_with_validation_reason() {
        let dir = tempdir().unwrap();
        let mut package =
            sample_resource_package_with_did("did:oan:SKLG:22222222222222222222222222222222");
        set_package_authorized_domains(&mut package, vec!["blocked".to_owned()]);
        let app = Router::new().route(
            "/cdn/resources/{*did}",
            get({
                let package = package.clone();
                move |AxumPath(did): AxumPath<String>| {
                    let package = package.clone();
                    async move {
                        let did = did.trim_start_matches('/');
                        if did == package.resource_did {
                            Json(package).into_response()
                        } else {
                            (StatusCode::NOT_FOUND, Json(json!({"error": "missing"})))
                                .into_response()
                        }
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let state = app_state_with_sqlite(dir.path()).await;
        write_discovery_document(&state, vec!["legal".to_owned()]);
        write_rejected_packages(
            &state,
            &[json!({
                "resourceDid": package.resource_did,
                "cursor": 2,
                "reason": "resource_package_unavailable"
            })],
        )
        .await
        .unwrap();

        let report = backfill_rejected_resource_packages(
            &state,
            &format!("http://{addr}"),
            RejectedPackageBackfillRequest {
                max_items: Some(10),
                resource_dids: vec![],
            },
        )
        .await
        .unwrap();

        assert_eq!(report["attemptedCount"], 1);
        assert_eq!(report["recoveredCount"], 0);
        assert_eq!(report["failedCount"], 1);
        assert_eq!(report["remainingRejectedCount"], 1);
        let rejected = read_rejected_packages(&state).await.unwrap();
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0]["reason"], "unauthorized_domains");
        assert_eq!(
            read_indexed_resource_packages(&state).await.unwrap().len(),
            0
        );
    }

    #[tokio::test]
    async fn export_snapshot_writes_resource_index_for_database_backend() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        upsert_indexed_resource_package(&state, 1, &sample_resource_package())
            .await
            .unwrap();
        write_rejected_packages(
            &state,
            &[json!({"resourceDid": "did:oan:SKLG:reject", "reason": "invalid"})],
        )
        .await
        .unwrap();

        export_discovery_debug_snapshot(&state).await.unwrap();

        let resources: Vec<ResourcePackage> =
            state.index.read("resource-capabilities.json").unwrap();
        assert_eq!(resources.len(), 1);
        assert!(!dir.path().join("index").join("capabilities.json").exists());
        let rejected: Vec<Value> = state.index.read("rejected-packages.json").unwrap();
        assert_eq!(rejected.len(), 1);
    }

    #[test]
    fn discovery_authorization_status_reports_revoked_or_active() {
        let did = discovery_did();
        let bulletin = json!({
            "events": [{
                "subjectDid": did,
                "eventType": "DISCOVERY_NODE_REVOKED"
            }]
        });
        assert_eq!(
            discovery_authorization_status(&bulletin, &discovery_did()),
            "revoked"
        );
        assert_eq!(
            discovery_authorization_status(&json!({"events": []}), &discovery_did()),
            "active"
        );
    }

    #[test]
    fn discovery_authorized_domains_defaults_to_empty_and_uses_latest_update() {
        let did = discovery_did();
        assert_eq!(
            discovery_authorized_domains(&json!({"events": []}), &did),
            Vec::<String>::new()
        );
        let bulletin = json!({
            "events": [
                {"subjectDid": did, "eventType": "DISCOVERY_NODE_DOMAINS_UPDATED", "payload": {"authorizedDomains": ["finance"]}},
                {"subjectDid": did, "eventType": "DISCOVERY_NODE_DOMAINS_UPDATED", "payload": {"authorizedDomains": ["legal"]}}
            ]
        });
        assert_eq!(
            discovery_authorized_domains(&bulletin, &discovery_did()),
            vec!["legal".to_owned()]
        );
    }

    #[test]
    fn root_document_fixture_is_did_oan_only() {
        let key = oan_crypto::generate_ed25519_keypair();
        let document =
            root_document_with_key("did:oan:AGRT:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu", &key);
        assert!(document.id.starts_with("did:oan:"));
        assert_eq!(
            document
                .oan_metadata
                .as_ref()
                .map(|metadata| metadata.resource_type.clone()),
            Some(ResourceType::InfrastructureNode)
        );
    }
}
