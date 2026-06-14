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
use oan_core::{CryptoSuite, DidDocument};
use oan_crypto::signing_key_from_bytes;
use oan_package::ResourcePackage;
use oan_protocol::{
    HealthResponse, ResourceDiscoveryCandidate, ResourceDiscoveryQuery, ResourceDiscoveryResponse,
};
use oan_storage::{DatabaseBackend, DatabaseConfig, JsonStore, PostgresJsonStore, SqliteJsonStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Postgres, QueryBuilder, Row, Sqlite};
use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration as StdDuration, Instant},
};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration as TokioDuration};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

const DISCOVERY_SYNC_STATE_TABLE: &str = "discovery_sync_state";
const DISCOVERY_PACKAGE_TABLE: &str = "discovery_packages";
const DISCOVERY_REJECTED_TABLE: &str = "discovery_rejected_packages";
const DISCOVERY_INDEX_STATS_CACHE_TTL_MS: u64 = 500;
const DISCOVERY_CDN_CURSOR_KEY: &str = "cdn_publication_cursor";

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
    #[serde(rename = "packageVersion")]
    package_version: String,
    #[serde(rename = "publicationCursor")]
    publication_cursor: i64,
    #[serde(rename = "packageHash")]
    package_hash: String,
    #[serde(rename = "metadataHash")]
    metadata_hash: String,
    #[serde(rename = "didDocumentHash")]
    did_document_hash: String,
    #[serde(rename = "resourceType", default)]
    resource_type: Option<String>,
    #[serde(rename = "capabilityTags", default)]
    capability_tags: Vec<String>,
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
    client: reqwest::Client,
    resource_sync_lock: Arc<Mutex<()>>,
    index_stats_cache: Arc<Mutex<Option<CachedIndexStats>>>,
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
    search_text: String,
}

struct DiscoveryProjectedPackage<'a> {
    cursor: i64,
    package: &'a ResourcePackage,
    package_json: Value,
    projection: DiscoveryPackageProjection,
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

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "services/discovery-node/config.example.toml".to_owned());
    let config = load_config(config_path)?;
    let did_doc: DidDocument = JsonStore::new(&config.paths.data_dir).read("did-document.json")?;
    let key: DevKeyFile = JsonStore::new(".").read(config.paths.keys_dir.join("keypair.json"))?;
    let crypto_suite = crypto_suite_from_algorithm(&key.algorithm)?;
    let _signing_key = signing_key_from_bytes(
        crypto_suite,
        &URL_SAFE_NO_PAD.decode(key.private_key_jwk.d)?,
    )?;
    let (sqlite, postgres) = match config.paths.database_url.as_deref() {
        Some(url) if !url.is_empty() => {
            let database = DatabaseConfig::parse(url)?;
            match database.backend() {
                DatabaseBackend::Sqlite => {
                    let sqlite = SqliteJsonStore::connect(url).await?;
                    initialize_discovery_sqlite(&sqlite).await?;
                    (Some(sqlite), None)
                }
                DatabaseBackend::Postgres => {
                    let postgres = PostgresJsonStore::connect(url).await?;
                    initialize_discovery_postgres(&postgres).await?;
                    (None, Some(postgres))
                }
            }
        }
        _ => (None, None),
    };
    let state = AppState {
        data: JsonStore::new(&config.paths.data_dir),
        index: JsonStore::new(&config.paths.index_dir),
        config: config.clone(),
        did: did_doc.id,
        sqlite,
        postgres,
        client: reqwest::Client::new(),
        resource_sync_lock: Arc::new(Mutex::new(())),
        index_stats_cache: Arc::new(Mutex::new(None)),
    };
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
        .route("/discovery/query/explain", post(api_query_explain))
        .route("/discovery/rejected-packages", get(api_rejected_packages))
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
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {DISCOVERY_PACKAGE_TABLE} (
                resource_did TEXT PRIMARY KEY,
                cursor INTEGER NOT NULL,
                version TEXT NOT NULL,
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
                state_value TEXT NOT NULL,
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
            CREATE INDEX IF NOT EXISTS idx_discovery_packages_search_text
            ON {DISCOVERY_PACKAGE_TABLE} USING GIN(to_tsvector('simple', search_text));
            CREATE INDEX IF NOT EXISTS idx_discovery_rejected_updated
            ON {DISCOVERY_REJECTED_TABLE}(updated_at, reject_key);
            "#
        ))
        .await?;
    Ok(())
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
        if blocked_cursor.is_some() {
            break;
        }
        fetched_count += 1;
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
                    blocked_cursor = Some(item.publication_cursor);
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
            blocked_cursor = Some(item.publication_cursor);
            continue;
        }
        if let Err(reason) = validate_notified_resource_package(&item, &package) {
            rejected.push(json!({
                "resourceDid": item.resource_did,
                "cursor": item.publication_cursor,
                "reason": reason
            }));
            blocked_cursor = Some(item.publication_cursor);
            continue;
        }
        if let Err(reason) = validate_resource_package_for_index(&package) {
            rejected.push(json!({
                "resourceDid": package.resource_did,
                "cursor": item.publication_cursor,
                "reason": reason
            }));
            blocked_cursor = Some(item.publication_cursor);
            continue;
        }
        cursor = cursor.max(item.publication_cursor);
        accepted.push((item.publication_cursor, package));
    }

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
    if package.package_version != item.package_version {
        return Err("package_version_mismatch".to_owned());
    }
    if package.package_hash != item.package_hash {
        return Err("package_hash_mismatch".to_owned());
    }
    if package.metadata_hash != item.metadata_hash {
        return Err("metadata_hash_mismatch".to_owned());
    }
    if package.did_document_hash != item.did_document_hash {
        return Err("did_document_hash_mismatch".to_owned());
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
    Ok(())
}

async fn resource_query(
    State(state): State<AppState>,
    Json(query): Json<ResourceDiscoveryQuery>,
) -> ApiResult<ResourceDiscoveryResponse> {
    let started = Instant::now();
    let (packages, prefiltered) = query_indexed_resource_packages(&state, &query)
        .await
        .map_err(ApiError::internal)?;
    let candidate_count = packages.len();
    let mut candidates = packages
        .into_iter()
        .filter(|package| prefiltered || resource_matches_query(package, &query))
        .map(|package| ResourceDiscoveryCandidate {
            resource_did: package.resource_did.clone(),
            resource_type: package.resource_type.clone(),
            score: resource_score(&package, &query),
            version: Some(package.package_version.clone()),
            lifecycle_state: Some(package.metadata.lifecycle_state.clone()),
            capability_tags: package.metadata.capability_tags.clone(),
            services: package.metadata.services.clone(),
            protocol_bindings: package.metadata.protocol_bindings.clone(),
            package_info: package
                .did_document
                .oan_metadata
                .as_ref()
                .and_then(|metadata| metadata.package_info.as_ref())
                .and_then(|info| serde_json::to_value(info).ok()),
            root_proof: serde_json::to_value(&package.root_proof).ok(),
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| b.score.total_cmp(&a.score));
    candidates.truncate(query.limit as usize);
    let metrics = DiscoveryQueryMetrics {
        backend: if state.postgres.is_some() {
            "postgres".to_owned()
        } else if state.sqlite.is_some() {
            "sqlite".to_owned()
        } else {
            "json".to_owned()
        },
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
        "rootAuthorizationStatus": bulletin.as_ref().map(|b| discovery_authorization_status(b, &state.did)).unwrap_or_else(|| "unknown".to_owned())
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
    let body = if let Some(postgres) = &state.postgres {
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

async fn api_query_explain(
    State(state): State<AppState>,
    Json(query): Json<ResourceDiscoveryQuery>,
) -> ApiResult<Value> {
    let (packages, prefiltered) = query_indexed_resource_packages(&state, &query)
        .await
        .map_err(ApiError::internal)?;
    let explanations = packages
        .iter()
        .map(|package| {
            let matched = resource_matches_query(package, &query);
            json!({
                "resourceDid": package.resource_did,
                "resourceType": package.resource_type,
                "matched": matched,
                "score": if matched { resource_score(package, &query) } else { 0.0 },
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
                })
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "query": query,
        "items": explanations,
        "candidateCount": packages.len(),
        "usedIndexedPrefilter": prefiltered
    })))
}

async fn api_rejected_packages(State(state): State<AppState>) -> ApiResult<Value> {
    let items = read_rejected_packages(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": items, "count": items.len() })))
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
                    capability_tags, protocols, service_endpoints, search_text,
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
                    search_text = excluded.search_text,
                    package_json = excluded.package_json,
                    updated_at = excluded.updated_at
                "#,
            );
            builder.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        return Ok(());
    }
    let mut indexed = read_indexed_resource_packages(state).await?;
    for (_, package) in packages {
        indexed.retain(|candidate| candidate.resource_did != package.resource_did);
        indexed.push(package.clone());
    }
    state.index.write("resource-capabilities.json", &indexed)?;
    Ok(())
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

    let search_text = format!(
        "{} {} {} {} {} {}",
        package.resource_did,
        package.resource_type.as_str(),
        package.metadata.name,
        package.metadata.description,
        package.metadata.capability_tags.join(" "),
        service_endpoints.join(" ")
    )
    .to_ascii_lowercase();

    DiscoveryPackageProjection {
        resource_type: package.resource_type.as_str().to_owned(),
        lifecycle_state: package.metadata.lifecycle_state.clone(),
        capability_tags: package.metadata.capability_tags.clone(),
        protocols,
        service_endpoints,
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
        if let Some(text) = &query.query {
            builder.push(" AND to_tsvector('simple', search_text) @@ plainto_tsquery('simple', ");
            builder.push_bind(text.to_ascii_lowercase());
            builder.push(")");
        }
        if let Some(text) = &query.query {
            builder.push(
                " ORDER BY ts_rank_cd(to_tsvector('simple', search_text), plainto_tsquery('simple', ",
            );
            builder.push_bind(text.to_ascii_lowercase());
            builder.push(")) DESC, updated_at DESC, resource_did LIMIT ");
        } else {
            builder.push(" ORDER BY updated_at DESC, resource_did LIMIT ");
        }
        builder.push_bind(discovery_sql_candidate_limit(query.limit));
        let rows = builder.build().fetch_all(postgres.pool()).await?;
        let packages = rows
            .into_iter()
            .map(|row| serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0)))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        return Ok((packages, true));
    }
    read_indexed_resource_packages(state)
        .await
        .map(|packages| (packages, false))
}

fn discovery_sql_candidate_limit(query_limit: u32) -> i64 {
    let requested = query_limit.max(1) as i64;
    (requested * 3).clamp(25, 5_000).max(requested)
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

#[cfg(test)]
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
            "SELECT state_value FROM {DISCOVERY_SYNC_STATE_TABLE} WHERE state_key = ?"
        ))
        .bind(DISCOVERY_CDN_CURSOR_KEY)
        .fetch_optional(sqlite.pool())
        .await?;
        return Ok(row
            .and_then(|row| row.get::<String, _>(0).parse::<i64>().ok())
            .unwrap_or(0));
    }
    if let Some(postgres) = &state.postgres {
        let row = sqlx::query(&format!(
            "SELECT state_value FROM {DISCOVERY_SYNC_STATE_TABLE} WHERE state_key = $1"
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
            INSERT INTO {DISCOVERY_SYNC_STATE_TABLE}(state_key, state_value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(state_key)
            DO UPDATE SET state_value = excluded.state_value, updated_at = excluded.updated_at
            "#
        ))
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
            INSERT INTO {DISCOVERY_SYNC_STATE_TABLE}(state_key, state_value, updated_at)
            VALUES ($1, $2, $3::timestamptz)
            ON CONFLICT(state_key)
            DO UPDATE SET state_value = excluded.state_value, updated_at = excluded.updated_at
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
            let reject_key = format!(
                "{}:{}",
                item["resourceDid"]
                    .as_str()
                    .or_else(|| item["did"].as_str())
                    .unwrap_or("unknown"),
                item["cursor"].as_i64().unwrap_or_default()
            );
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
            let reject_key = format!(
                "{}:{}",
                item["resourceDid"]
                    .as_str()
                    .or_else(|| item["did"].as_str())
                    .unwrap_or("unknown"),
                item["cursor"].as_i64().unwrap_or_default()
            );
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
    Ok(())
}

fn resource_matches_query(package: &ResourcePackage, query: &ResourceDiscoveryQuery) -> bool {
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
            .any(|tag| package.metadata.capability_tags.contains(tag))
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
    if let Some(text) = &query.query {
        let needle = text.to_ascii_lowercase();
        let haystack = format!(
            "{} {} {} {} {:?}",
            package.resource_did,
            package.resource_type.as_str(),
            package.metadata.name,
            package.metadata.description,
            package.metadata.capability_tags
        )
        .to_ascii_lowercase();
        return haystack.contains(&needle);
    }
    true
}

fn resource_score(package: &ResourcePackage, query: &ResourceDiscoveryQuery) -> f32 {
    let mut score = 0.5;
    if query
        .resource_type
        .as_ref()
        .is_some_and(|resource_type| resource_type == &package.resource_type)
    {
        score += 0.2;
    }
    score += query
        .capability_tags
        .iter()
        .filter(|tag| package.metadata.capability_tags.contains(tag))
        .count() as f32
        * 0.1;
    if query.query.as_ref().is_some_and(|text| {
        package
            .metadata
            .description
            .to_ascii_lowercase()
            .contains(&text.to_ascii_lowercase())
    }) {
        score += 0.2;
    }
    score
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
        .unwrap_or_else(|| vec!["*".to_owned()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use chrono::Utc;
    use oan_core::{
        CryptoSuite, ImplementationLink, OanMetadata, ProtocolBinding, ResourceDescription,
        ResourceType, ServiceEndpoint, VerificationMethod,
    };
    use oan_crypto::{hash_json_with_suite, public_key_jwk, public_key_multibase, VerifyingKey};
    use oan_package::{
        hash_resource_metadata_with_suite, ResourceMetadata, ResourcePackageClaims, RootProof,
    };
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
                    capability_tags: vec!["legal.contract.review".to_owned()],
                    use_case_examples: vec!["Find payment and termination risks".to_owned()],
                    ..Default::default()
                }),
                agent_description: None,
                capability_tags: vec!["legal.contract.review".to_owned()],
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
        package.did_document_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256, &package.did_document)
                .map(|hash| format!("sha256:{hash}"))
                .unwrap();
        package.metadata.metadata_hash.clear();
        package.metadata.package_hash.clear();
        package.metadata_hash =
            hash_resource_metadata_with_suite(CryptoSuite::Ed25519Sha256, &package.metadata)
                .map(|hash| format!("sha256:{hash}"))
                .unwrap();
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
        .map(|hash| format!("sha256:{hash}"))
        .unwrap();
        package.metadata.package_hash = package.package_hash.clone();
        package.root_proof.package_claims = Some(
            serde_json::to_value(ResourcePackageClaims {
                resource_did: package.resource_did.clone(),
                resource_type: package.resource_type.clone(),
                version: package.package_version.clone(),
                did_document_hash: package.did_document_hash.clone(),
                metadata_hash: package.metadata_hash.clone(),
                package_hash: package.package_hash.clone(),
                hash_algorithm: package.hash_algorithm.clone(),
                lifecycle_state: package.metadata.lifecycle_state.clone(),
                bulletin_ref: None,
            })
            .unwrap(),
        );
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
        AppState {
            data: JsonStore::new(dir.join("data")),
            index: JsonStore::new(dir.join("index")),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8004,
                },
                cors: CorsConfig::default(),
                debug: DebugConfig::default(),
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
            client: reqwest::Client::new(),
            resource_sync_lock: Arc::new(Mutex::new(())),
            index_stats_cache: Arc::new(Mutex::new(None)),
        }
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
        assert!(resource_matches_query(&package, &query));
        assert!(resource_score(&package, &query) > 0.9);

        let wrong_type = ResourceDiscoveryQuery {
            resource_type: Some(ResourceType::McpServer),
            ..query.clone()
        };
        assert!(!resource_matches_query(&package, &wrong_type));

        let wrong_protocol = ResourceDiscoveryQuery {
            protocol: Some("a2a".to_owned()),
            ..query
        };
        assert!(!resource_matches_query(&package, &wrong_protocol));
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
        assert!(resource_matches_query(&packages[0], &query));
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
    fn discovery_sql_candidate_limit_is_bounded_for_query_pushdown() {
        assert_eq!(discovery_sql_candidate_limit(0), 25);
        assert_eq!(discovery_sql_candidate_limit(1), 25);
        assert_eq!(discovery_sql_candidate_limit(10), 30);
        assert_eq!(discovery_sql_candidate_limit(100), 300);
        assert_eq!(discovery_sql_candidate_limit(1_000), 3_000);
        assert_eq!(discovery_sql_candidate_limit(10_000), 10_000);
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
    async fn sync_resources_from_authorized_summary_rejects_hash_mismatch() {
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
                    metadata_hash: package.metadata_hash.clone(),
                    did_document_hash: package.did_document_hash.clone(),
                    resource_type: Some("skill".to_owned()),
                    capability_tags: package.metadata.capability_tags.clone(),
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["syncMode"], "authorized-summary");
        assert_eq!(response.0["syncedResourceCount"], 0);
        assert_eq!(response.0["rejectedCount"], 1);
        assert_eq!(response.0["rejected"][0]["reason"], "package_hash_mismatch");
        assert_eq!(
            read_indexed_resource_packages(&state).await.unwrap().len(),
            0
        );
    }

    #[tokio::test]
    async fn sync_resources_from_authorized_summary_keeps_cursor_before_unavailable_package() {
        let dir = tempdir().unwrap();
        let first =
            sample_resource_package_with_did("did:oan:SKLG:11111111111111111111111111111111");
        let missing_did = "did:oan:SKLG:22222222222222222222222222222222".to_owned();
        let app = Router::new().route(
            "/cdn/resources/{*did}",
            get({
                let first = first.clone();
                move |AxumPath(did): AxumPath<String>| {
                    let first = first.clone();
                    async move {
                        if did.trim_start_matches('/') == first.resource_did {
                            Json(first).into_response()
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
                cursor_hint: Some(2),
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
                    },
                ],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["syncMode"], "authorized-summary");
        assert_eq!(response.0["syncedResourceCount"], 1);
        assert_eq!(response.0["rejectedCount"], 1);
        assert_eq!(
            response.0["rejected"][0]["reason"],
            "resource_package_unavailable"
        );
        assert_eq!(response.0["toCursor"], 1);
        assert_eq!(response.0["blockedCursor"], 2);
        assert_eq!(read_sync_cursor(&state).await.unwrap(), 1);
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
    fn discovery_authorized_domains_defaults_to_wildcard_and_uses_latest_update() {
        let did = discovery_did();
        assert_eq!(
            discovery_authorized_domains(&json!({"events": []}), &did),
            vec!["*".to_owned()]
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
