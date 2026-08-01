<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# Discovery Node

Builds a verified local resource index from CDN packages and serves signed
discovery responses.

## Role

Discovery Node syncs Root-verified resource packages from CDN, verifies
bulletin and package proof material, filters packages by authorized domains,
builds a local semantic index, and returns signed discovery responses.

Discovery indexes `did:oan` DID Documents and Root-verified package metadata
for Agent Service, Skill, MCP Server, and Tool/API resources. It does not host
or guarantee product-native artifacts outside the verified package, such as
external Skill files, API descriptions, or MCP server descriptors referenced by
URI in a DID Document.

## Governance and VC Boundary

Discovery is an authorized infrastructure participant only when its governance
state is active and it holds a valid Root-issued infrastructure authorization
VC. It uses that VC in service-to-service interaction with Root and other
authorized infrastructure services.

The latest governance state bounds whether Discovery should continue receiving
Root notifications or serving as an authorized discovery endpoint. If its state
is inactive, revoked, or stale, it should fail closed and stop presenting itself
as an authorized Discovery node.

## Local Run

```powershell
cargo run -p discovery-node
```

The default local API listens on port `8002` when using the sample
configuration and demo scripts.

## Multilingual Semantic Search

Discovery Node can use a local HTTP embedding service for Chinese and English
semantic discovery. The reference service is in
`services/embedding-service` and exposes `GET /health` plus `POST /embed`.

The Discovery Node process does not load embedding model weights directly. In
production, run the embedding service with `gte-multilingual-base`, configure
`[semanticSearch.embedding]` with `provider = "http-embedding"`, and keep
`modelVersion` pinned until the semantic index is rebuilt.

The intended deployment shape is:

- code built in: this repository contains the Discovery integration and the
  optional HTTP embedding service implementation;
- model externalized: model weights are loaded from a runtime cache or an
  operator-managed local model directory, not from Git or a submodule;
- configuration bound: Discovery pins `modelName`, `modelVersion`, `dimension`,
  endpoint, health endpoint, timeout, and strict version checking in
  `config.example.toml` or an environment-specific config;
- graceful fallback: if semantic search is disabled, PostgreSQL/pgvector is not
  available, or the embedding service is not healthy, Discovery continues with
  the local lexical and structured semantic ranking path.

Semantic discovery uses two pgvector-backed indexes:

- `discovery_semantic_index`: one resource-level context embedding per resource.
- `discovery_intent_index`: one embedding per use case, example, and generated
  pseudo query. Query-time ranking applies example-level MaxSim over this table
  for the current candidate set.

When `modelName`, `modelVersion`, or `dimension` changes, rebuild both semantic
indexes before relying on production semantic ranking:

```powershell
cargo run -p discovery-node -- semantic-rebuild services/discovery-node/config.example.toml
```

The command reads the current verified resource package index, projects active
user-consumable resources, rebuilds the resource-level and intent-level
embeddings for the configured model version, and prints a JSON report with the
indexed resource and intent counts. If semantic search is unavailable, it exits
successfully with `semantic_enabled: false` and a `skipped_reason`.

Use `--stage context` or `--stage intent` when you need to rebuild only one
side of the semantic index. The default `--stage both` rebuilds both indexes and
is the only mode that can report `safe_to_delete_old_indexes: true` when the run
finishes without unresolved skips.

The rebuild command is intended to support a safe cutover after old semantic
index data is deleted. Its JSON report includes:

- `phase`: `completed`, `completed-with-skips`, `backfilled`, or `skipped`;
- `safe_to_delete_old_indexes`: `true` only when the rebuild/backfill run has
  finished without unresolved skipped items;
- `skipped_packages`: packages that still need attention;
- `recovered_packages`: skipped items successfully backfilled in the current
  run.

If the main rebuild run records skipped items, run:

```powershell
cargo run -p discovery-node -- semantic-backfill-skipped services/discovery-node/config.example.toml
```

This command retries the recorded skipped semantic items without touching the
already rebuilt main index batch. It is meant for final cleanup after the full
rebuild has completed.

The repository also includes a smoke evaluation suite for real OAN-style
resource queries:

```powershell
cargo run -p discovery-node -- semantic-evaluate services/discovery-node/config.example.toml services/discovery-node/evaluation/real-resource-smoke.v1.json
```

Each evaluation case uses the same `ResourceDiscoveryQuery` shape as
`POST /discovery/resources/query`, so the evaluation exercises the production
query path. The seed suite covers Chinese, English, mixed Chinese-English, and
exact DID lookup. Larger exported suites can reuse the same JSON schema.
