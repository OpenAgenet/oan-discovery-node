import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import type { Server } from "node:http";
import { createEmbeddingServer } from "../src/server.js";
import type { EmbeddingServiceConfig } from "../src/config.js";

let server: Server | undefined;

function testConfig(batchSize = 2): EmbeddingServiceConfig {
  return {
    host: "127.0.0.1",
    port: 0,
    provider: "deterministic",
    model: "oan-deterministic-local-v1",
    modelId: "oan-deterministic-local-v1",
    embeddingVersion: "deterministic-v1",
    dimension: 16,
    maxInputChars: 20,
    batchSize,
    dtype: "q8",
  };
}

async function startServer(config = testConfig()): Promise<string> {
  server = createEmbeddingServer(config);
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("test_server_address_unavailable");
  }
  return `http://127.0.0.1:${address.port}`;
}

afterEach(async () => {
  if (server) {
    await new Promise<void>((resolve, reject) =>
      server!.close((error) => (error ? reject(error) : resolve())),
    );
    server = undefined;
  }
});

describe("embedding HTTP service", () => {
  it("serves Discovery Node compatible health responses", async () => {
    const baseUrl = await startServer();
    const response = await fetch(`${baseUrl}/health`);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.deepEqual(body, {
      model: "oan-deterministic-local-v1",
      embeddingVersion: "deterministic-v1",
      dtype: "q8",
      dimension: 16,
      ready: true,
    });
  });

  it("serves Discovery Node compatible embedding responses", async () => {
    const baseUrl = await startServer();
    const response = await fetch(`${baseUrl}/embed`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "oan-deterministic-local-v1",
        input: ["find a bilingual scheduling skill"],
      }),
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.model, "oan-deterministic-local-v1");
    assert.equal(body.embeddingVersion, "deterministic-v1");
    assert.equal(body.dtype, "q8");
    assert.equal(body.dimension, 16);
    assert.equal(body.vectors.length, 1);
    assert.equal(body.vectors[0].length, 16);
  });

  it("keeps batched embedding output count and order for batch sizes 8 and 16", async () => {
    for (const batchSize of [8, 16]) {
      const baseUrl = await startServer(testConfig(batchSize));
      const input = Array.from({ length: batchSize }, (_, index) => `query-${index}`);
      const response = await fetch(`${baseUrl}/embed`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: "oan-deterministic-local-v1",
          input,
        }),
      });
      const body = await response.json();

      assert.equal(response.status, 200);
      assert.equal(body.vectors.length, batchSize);
      assert.notDeepEqual(body.vectors[0], body.vectors[1]);
      const reversed = await fetch(`${baseUrl}/embed`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: "oan-deterministic-local-v1",
          input: [...input].reverse(),
        }),
      });
      const reversedBody = await reversed.json();
      assert.equal(reversed.status, 200);
      assert.deepEqual(reversedBody.vectors[batchSize - 1], body.vectors[0]);
      assert.deepEqual(reversedBody.vectors[0], body.vectors[batchSize - 1]);

      await new Promise<void>((resolve, reject) =>
        server!.close((error) => (error ? reject(error) : resolve())),
      );
      server = undefined;
    }
  });

  it("rejects model mismatches and oversized batches", async () => {
    const baseUrl = await startServer();
    const mismatch = await fetch(`${baseUrl}/embed`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "wrong-model", input: ["query"] }),
    });
    assert.equal(mismatch.status, 400);

    const oversized = await fetch(`${baseUrl}/embed`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "oan-deterministic-local-v1",
        input: ["one", "two", "three"],
      }),
    });
    assert.equal(oversized.status, 500);
    assert.deepEqual(await oversized.json(), {
      error: "embedding_batch_too_large:3:2",
    });
  });
});
