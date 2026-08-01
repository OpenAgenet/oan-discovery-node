import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { TransformersEmbeddingProvider } from "../src/embedding.js";
import type { EmbeddingServiceConfig } from "../src/config.js";

const runRealModel = process.env.OAN_EMBEDDING_PROVIDER === "transformers";

describe("gte-multilingual-base smoke test", { skip: !runRealModel }, () => {
  it("embeds English and Chinese text with the configured model", async () => {
    const config: EmbeddingServiceConfig = {
      host: "127.0.0.1",
      port: 18080,
      provider: "transformers",
      model: process.env.OAN_EMBEDDING_MODEL ?? "gte-multilingual-base",
      modelId: process.env.OAN_EMBEDDING_MODEL_ID ?? "Alibaba-NLP/gte-multilingual-base",
      embeddingVersion: process.env.OAN_EMBEDDING_VERSION ?? "gte-multilingual-base",
      dimension: Number.parseInt(process.env.OAN_EMBEDDING_DIMENSION ?? "768", 10),
      maxInputChars: 6000,
      batchSize: 2,
      dtype: process.env.OAN_EMBEDDING_DTYPE ?? "q8",
      cacheDir: process.env.OAN_EMBEDDING_CACHE_DIR,
      localModelPath: process.env.OAN_EMBEDDING_LOCAL_MODEL_PATH,
    };
    const provider = new TransformersEmbeddingProvider(config);
    const vectors = await provider.embed([
      "Find a resource for repository search and code understanding.",
      "查找一个用于代码仓库检索和项目理解的资源。",
    ]);

    assert.equal(vectors.length, 2);
    assert.equal(vectors[0].length, config.dimension);
    assert.equal(vectors[1].length, config.dimension);
  });
});
