export type EmbeddingProviderName = "deterministic" | "transformers";

export interface EmbeddingServiceConfig {
  host: string;
  port: number;
  provider: EmbeddingProviderName;
  model: string;
  modelId: string;
  embeddingVersion: string;
  dimension: number;
  maxInputChars: number;
  batchSize: number;
  dtype: string;
  cacheDir?: string;
  localModelPath?: string;
}

function intFromEnv(name: string, fallback: number): number {
  const value = process.env[name];
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`invalid_integer_env:${name}`);
  }
  return parsed;
}

function providerFromEnv(): EmbeddingProviderName {
  const value = process.env.OAN_EMBEDDING_PROVIDER ?? "deterministic";
  if (value === "deterministic" || value === "transformers") {
    return value;
  }
  throw new Error(`unsupported_embedding_provider:${value}`);
}

export function loadConfig(): EmbeddingServiceConfig {
  const provider = providerFromEnv();
  const model =
    process.env.OAN_EMBEDDING_MODEL ??
    (provider === "transformers"
      ? "gte-multilingual-base"
      : "oan-deterministic-local-v1");
  const modelId =
    process.env.OAN_EMBEDDING_MODEL_ID ??
    (provider === "transformers" ? "Alibaba-NLP/gte-multilingual-base" : model);

  return {
    host: process.env.OAN_EMBEDDING_HOST ?? "127.0.0.1",
    port: intFromEnv("OAN_EMBEDDING_PORT", 18080),
    provider,
    model,
    modelId,
    embeddingVersion:
      process.env.OAN_EMBEDDING_VERSION ??
      (provider === "transformers" ? "gte-multilingual-base" : "deterministic-v1"),
    dimension: intFromEnv(
      "OAN_EMBEDDING_DIMENSION",
      provider === "transformers" ? 768 : 64,
    ),
    maxInputChars: intFromEnv("OAN_EMBEDDING_MAX_INPUT_CHARS", 6000),
    batchSize: intFromEnv("OAN_EMBEDDING_BATCH_SIZE", 16),
    dtype: process.env.OAN_EMBEDDING_DTYPE ?? "q8",
    cacheDir: process.env.OAN_EMBEDDING_CACHE_DIR,
    localModelPath: process.env.OAN_EMBEDDING_LOCAL_MODEL_PATH,
  };
}
