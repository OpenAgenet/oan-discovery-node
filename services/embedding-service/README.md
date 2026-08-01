# OAN Discovery Embedding Service

This service provides multilingual sentence embeddings for Discovery Node
semantic search through a small HTTP API. It lives in this repository so the
Discovery Node deployment has a reference embedding implementation, but the
Discovery Node process remains decoupled and only talks to it over HTTP.

The service supports two providers:

- `deterministic`: lightweight deterministic vectors for unit tests and offline
  checks. It is not intended for production relevance.
- `transformers`: `gte-multilingual-base` through Transformers.js. Model files
  are downloaded to a runtime cache or loaded from a local model path; model
  weights are not committed to this repository.

## HTTP Contract

```http
GET /health
```

```json
{
  "model": "gte-multilingual-base",
  "embeddingVersion": "gte-multilingual-base-q8-local",
  "dtype": "q8",
  "dimension": 768,
  "ready": true
}
```

```http
POST /embed
content-type: application/json

{
  "model": "gte-multilingual-base",
  "input": ["Find a resource for code search", "查找代码仓库检索工具"]
}
```

```json
{
  "model": "gte-multilingual-base",
  "embeddingVersion": "gte-multilingual-base-q8-local",
  "dtype": "q8",
  "dimension": 768,
  "vectors": [[0.01, 0.02]]
}
```

## Local Checks

```powershell
npm install --omit=optional
npm test
npm run build
```

The default test path uses the deterministic provider and does not download a
model. Tests use Node.js built-in `node:test`; no test framework runtime is
required.

## Run With gte-multilingual-base

```powershell
npm install --include=optional
Copy-Item .env.example .env
$env:OAN_EMBEDDING_PROVIDER="transformers"
$env:OAN_EMBEDDING_MODEL="gte-multilingual-base"
$env:OAN_EMBEDDING_MODEL_ID="D:\Works\VscodeProject\OAN\models\onnx-community\gte-multilingual-base"
$env:OAN_EMBEDDING_LOCAL_MODEL_PATH="D:\Works\VscodeProject\OAN\models\onnx-community"
$env:OAN_EMBEDDING_VERSION="gte-multilingual-base-q8-local"
$env:OAN_EMBEDDING_DIMENSION="768"
$env:OAN_EMBEDDING_DTYPE="q8"
npm run dev
```

For controlled deployments, set `OAN_EMBEDDING_LOCAL_MODEL_PATH` to a prepared
Transformers.js-compatible local model directory and keep
`OAN_EMBEDDING_VERSION` pinned to the exact model snapshot or release label used
to build the Discovery semantic index.

`OAN_EMBEDDING_MODEL` is the model name exposed to Discovery Node. It should
match `semanticSearch.embedding.modelName`. `OAN_EMBEDDING_MODEL_ID` is the
Transformers.js model identifier or local model selector used by this service.

The real model smoke test is opt-in:

```powershell
$env:OAN_EMBEDDING_PROVIDER="transformers"
$env:OAN_EMBEDDING_MODEL="gte-multilingual-base"
$env:OAN_EMBEDDING_MODEL_ID="D:\Works\VscodeProject\OAN\models\onnx-community\gte-multilingual-base"
$env:OAN_EMBEDDING_LOCAL_MODEL_PATH="D:\Works\VscodeProject\OAN\models\onnx-community"
$env:OAN_EMBEDDING_VERSION="gte-multilingual-base-q8-local"
$env:OAN_EMBEDDING_DIMENSION="768"
$env:OAN_EMBEDDING_DTYPE="q8"
npm run smoke:real
```
