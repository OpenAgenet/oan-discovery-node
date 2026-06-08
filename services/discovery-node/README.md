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
