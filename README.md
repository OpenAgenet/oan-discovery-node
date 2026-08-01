# OAN Discovery Node

Discovery service workspace for OpenAgenet.

This repository owns:

- `discovery-node`
- `embedding-service`, an optional HTTP embedding service for multilingual
  semantic discovery

Shared protocol, bulletin, package, storage, and crypto crates live in the
sibling `oan-protocol-common` repository.

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

Official integration tests and benchmarks are run through
`oan-official-skill/skills/oan-system-test-ops/fixtures/oan-ops-harness`.
Service-node identity material is copied from `oan-design-docs/genesis/nodes`
into per-run work directories; this repository does not own genesis private
material.

## License

This core service repository is licensed under `Apache-2.0`. Brand and
official-node identity rights are reserved separately.
