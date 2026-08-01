import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig, type EmbeddingServiceConfig } from "./config.js";
import { createEmbeddingProvider, type EmbeddingProvider } from "./embedding.js";

interface EmbedRequest {
  model?: string;
  input?: string[] | string;
}

export function createEmbeddingServer(config: EmbeddingServiceConfig) {
  let providerPromise: Promise<EmbeddingProvider> | undefined;

  function getProvider(): Promise<EmbeddingProvider> {
    if (!providerPromise) {
      providerPromise = Promise.resolve(createEmbeddingProvider(config));
    }
    return providerPromise;
  }

  return http.createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/health") {
        const provider = await getProvider();
        writeJson(response, 200, {
          model: provider.model,
          embeddingVersion: provider.embeddingVersion,
          dtype: provider.dtype,
          dimension: provider.dimension,
          ready: true,
        });
        return;
      }
      if (request.method === "POST" && request.url === "/embed") {
        const provider = await getProvider();
        const body = await readJson<EmbedRequest>(request);
        if (body.model && body.model !== provider.model) {
          writeJson(response, 400, { error: `model_mismatch:${body.model}` });
          return;
        }
        const input = normalizeInput(body.input, config);
        const vectors = await provider.embed(input);
        writeJson(response, 200, {
          model: provider.model,
          embeddingVersion: provider.embeddingVersion,
          dtype: provider.dtype,
          dimension: provider.dimension,
          vectors,
        });
        return;
      }
      writeJson(response, 404, { error: "not_found" });
    } catch (error) {
      writeJson(response, 500, { error: error instanceof Error ? error.message : "internal_error" });
    }
  });
}

function normalizeInput(input: EmbedRequest["input"], config: EmbeddingServiceConfig): string[] {
  const values = typeof input === "string" ? [input] : input;
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error("embedding_input_required");
  }
  if (values.length > config.batchSize) {
    throw new Error(`embedding_batch_too_large:${values.length}:${config.batchSize}`);
  }
  return values.map((value) => {
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new Error("embedding_input_must_be_non_empty_string");
    }
    return Array.from(value).slice(0, config.maxInputChars).join("");
  });
}

async function readJson<T>(request: IncomingMessage): Promise<T> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return JSON.parse(raw) as T;
}

function writeJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const config = loadConfig();
  const server = createEmbeddingServer(config);
  server.listen(config.port, config.host, () => {
    console.log(
      `OAN embedding service listening on http://${config.host}:${config.port} (${config.provider}, ${config.model})`,
    );
  });
}
