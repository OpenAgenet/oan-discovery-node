import type { EmbeddingServiceConfig } from "./config.js";
import { deterministicEmbedding, normalizeVector, validateVector } from "./vector.js";

export interface EmbeddingProvider {
  readonly model: string;
  readonly embeddingVersion: string;
  readonly dtype: string;
  readonly dimension: number;
  embed(input: string[]): Promise<number[][]>;
}

export class DeterministicEmbeddingProvider implements EmbeddingProvider {
  readonly model: string;
  readonly embeddingVersion: string;
  readonly dtype: string;
  readonly dimension: number;

  constructor(config: EmbeddingServiceConfig) {
    this.model = config.model;
    this.embeddingVersion = config.embeddingVersion;
    this.dtype = config.dtype;
    this.dimension = config.dimension;
  }

  async embed(input: string[]): Promise<number[][]> {
    return input.map((text) => deterministicEmbedding(text, this.dimension));
  }
}

export class TransformersEmbeddingProvider implements EmbeddingProvider {
  readonly model: string;
  readonly embeddingVersion: string;
  readonly dtype: string;
  readonly dimension: number;
  private extractorPromise?: Promise<(text: string, options: Record<string, unknown>) => Promise<unknown>>;

  constructor(private readonly config: EmbeddingServiceConfig) {
    this.model = config.model;
    this.embeddingVersion = config.embeddingVersion;
    this.dtype = config.dtype;
    this.dimension = config.dimension;
  }

  async embed(input: string[]): Promise<number[][]> {
    const extractor = await this.loadExtractor();
    const vectors: number[][] = [];
    for (const text of input) {
      const output = await extractor(text, { pooling: "mean", normalize: true });
      const vector = tensorToVector(output);
      validateVector(vector, this.dimension);
      vectors.push(normalizeVector(vector));
    }
    return vectors;
  }

  private loadExtractor(): Promise<(text: string, options: Record<string, unknown>) => Promise<unknown>> {
    if (!this.extractorPromise) {
      this.extractorPromise = loadTransformersExtractor(this.config);
    }
    return this.extractorPromise;
  }
}

async function loadTransformersExtractor(
  config: EmbeddingServiceConfig,
): Promise<(text: string, options: Record<string, unknown>) => Promise<unknown>> {
  const moduleName = "@huggingface/transformers";
  const transformers = (await import(moduleName)) as {
    env?: {
      cacheDir?: string;
      localModelPath?: string;
      allowLocalModels?: boolean;
    };
    pipeline: (
      task: string,
      model: string,
      options?: Record<string, unknown>,
    ) => Promise<(text: string, options: Record<string, unknown>) => Promise<unknown>>;
  };

  if (config.cacheDir && transformers.env) {
    transformers.env.cacheDir = config.cacheDir;
  }
  if (config.localModelPath && transformers.env) {
    transformers.env.localModelPath = config.localModelPath;
    transformers.env.allowLocalModels = true;
  }

  return transformers.pipeline("feature-extraction", config.modelId, {
    dtype: config.dtype,
  });
}

function tensorToVector(output: unknown): number[] {
  if (Array.isArray(output)) {
    return flattenNumericArray(output);
  }
  if (output && typeof output === "object") {
    const candidate = output as {
      data?: Iterable<number>;
      dims?: number[];
      tolist?: () => unknown;
    };
    if (typeof candidate.tolist === "function") {
      return flattenNumericArray(candidate.tolist());
    }
    if (candidate.data) {
      return Array.from(candidate.data, Number);
    }
  }
  throw new Error("unsupported_transformers_embedding_output");
}

function flattenNumericArray(value: unknown): number[] {
  if (!Array.isArray(value)) {
    if (typeof value === "number") {
      return [value];
    }
    throw new Error("unsupported_transformers_embedding_output");
  }
  const flattened: number[] = [];
  for (const item of value) {
    if (Array.isArray(item)) {
      flattened.push(...flattenNumericArray(item));
    } else if (typeof item === "number") {
      flattened.push(item);
    } else {
      throw new Error("unsupported_transformers_embedding_output");
    }
  }
  return flattened;
}

export function createEmbeddingProvider(config: EmbeddingServiceConfig): EmbeddingProvider {
  if (config.provider === "deterministic") {
    return new DeterministicEmbeddingProvider(config);
  }
  return new TransformersEmbeddingProvider(config);
}
