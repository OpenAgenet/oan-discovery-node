# OAN Discovery Node

Discovery service workspace for OpenAgenet (OAN), an open infrastructure
project for the Internet of Agents (IoA). A Discovery node indexes Root-approved
resource packages and serves trust-aware discovery results for Agent Service,
Skill, MCP Server, and Tool/API resources before users or applications invoke
them.

This repository owns:

- `discovery-node`
- `embedding-service`, an optional HTTP embedding service for multilingual
  semantic discovery

Shared protocol, bulletin, package, storage, and crypto crates live in the
sibling `oan-protocol-common` repository.

## Service Role

Discovery nodes pull authorized resource summaries from Root/CDN, enforce their
own authorized-domain scope, index current resource packages, and answer
resource queries. The Rust node supports exact DID lookup, structured filters,
semantic discovery, query explanations, rejected-package inspection, and index
statistics. PostgreSQL plus pgvector enables the semantic index; SQLite remains
useful for local validation and lightweight runs.

Key routes implemented by `services/discovery-node` include:

- `GET /health`
- `GET /discovery/did`
- `GET /discovery/status`
- `GET /discovery/root-authorization`
- `GET /discovery/authorized-domains`
- `POST /discovery/resources/sync-authorized`
- `GET /discovery/index/stats`
- `GET /discovery/query/stats`
- `GET /discovery/index/resources`
- `GET /discovery/index/resources/visibility`
- `GET /discovery/index/resources/{did}`
- `POST /discovery/resources/query`
- `POST /discovery/query/suggestions`
- `POST /discovery/query/explain`
- `GET /discovery/rejected-packages`
- `GET /discovery/capability-tree`

For public browser workflows, the official website gateway exposes the current
query route at `https://www.openagenet.xyz/discovery/resources/query`.

The optional `services/embedding-service` provides an HTTP embedding provider
for multilingual semantic discovery experiments and production configurations
that use an external embedding model behind a small local API.

## Local Checks

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace -j 1
```

Embedding service checks:

```powershell
cd services/embedding-service
npm install
npm test
npm run build
```

Full-network integration tests, deployment gates, and benchmarks are maintained
separately by official operators. Service-node identity material should be
provided by the operator for each deployment; this repository does not own
private node identity material.

## License

This core service repository is licensed under `Apache-2.0`. Brand and
official-node identity rights are reserved separately.
