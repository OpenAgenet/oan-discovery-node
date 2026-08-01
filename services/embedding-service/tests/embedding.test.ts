import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DeterministicEmbeddingProvider } from "../src/embedding.js";
import type { EmbeddingServiceConfig } from "../src/config.js";

function testConfig(): EmbeddingServiceConfig {
  return {
    host: "127.0.0.1",
    port: 18080,
    provider: "deterministic",
    model: "oan-deterministic-local-v1",
    modelId: "oan-deterministic-local-v1",
    embeddingVersion: "deterministic-v1",
    dimension: 16,
    maxInputChars: 6000,
    batchSize: 8,
    dtype: "q8",
  };
}

describe("deterministic embedding provider", () => {
  it("returns stable normalized vectors", async () => {
    const provider = new DeterministicEmbeddingProvider(testConfig());
    const first = await provider.embed(["search MCP servers for repository management"]);
    const second = await provider.embed(["search MCP servers for repository management"]);

    assert.deepEqual(first, second);
    assert.equal(first[0].length, 16);
    const norm = Math.sqrt(first[0].reduce((sum, value) => sum + value * value, 0));
    assert.ok(Math.abs(norm - 1) < 0.00001);
  });

  it("accepts Chinese text as embedding input", async () => {
    const provider = new DeterministicEmbeddingProvider(testConfig());
    const [vector] = await provider.embed(["我需要一个可以检索代码仓库并总结项目结构的工具。"]);

    assert.equal(vector.length, 16);
    assert.equal(vector.some((value) => value > 0), true);
  });
});
