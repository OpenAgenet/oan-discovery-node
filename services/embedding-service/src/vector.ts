import { createHash } from "node:crypto";

export function normalizeVector(vector: number[]): number[] {
  const norm = Math.sqrt(vector.reduce((sum, value) => sum + value * value, 0));
  if (norm === 0) {
    return vector;
  }
  return vector.map((value) => value / norm);
}

export function validateVector(vector: number[], dimension: number): void {
  if (vector.length !== dimension) {
    throw new Error(`embedding_dimension_mismatch:${vector.length}:${dimension}`);
  }
  if (vector.some((value) => !Number.isFinite(value))) {
    throw new Error("embedding_vector_contains_non_finite_value");
  }
}

export function deterministicEmbedding(text: string, dimension: number): number[] {
  const vector = new Array<number>(dimension).fill(0);
  const tokens = text
    .toLowerCase()
    .normalize("NFKC")
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean);
  const units = tokens.length > 0 ? tokens : Array.from(text.normalize("NFKC"));
  for (const unit of units) {
    const digest = createHash("sha256").update(unit).digest();
    const index = digest.readUInt32BE(0) % dimension;
    vector[index] += 1;
  }
  return normalizeVector(vector);
}
