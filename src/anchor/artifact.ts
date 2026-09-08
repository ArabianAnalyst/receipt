import { createHash } from "node:crypto";

export const ARTIFACT_PREFIX = "deadlatch-anchor-v1";

/**
 * The bytes the witness signs and the log records. Binding the stream and the
 * position in means an anchor cannot be replayed for another stream or seq.
 */
export function artifactOf(stream: string, seq: number, head: string): Uint8Array {
  if (typeof stream !== "string" || stream.length === 0 || stream.includes("\n")) {
    throw new Error("anchor: stream must be a non-empty string without newlines");
  }
  if (!Number.isInteger(seq) || seq < 0) throw new Error("anchor: seq must be a non-negative integer");
  if (!/^[0-9a-f]{64}$/.test(head)) throw new Error("anchor: head must be 64 lowercase hex characters");
  return new TextEncoder().encode(`${ARTIFACT_PREFIX}\n${stream}\n${seq}\n${head}\n`);
}

export function digestOf(artifact: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(artifact).digest());
}
