// The Deadlatch receipt. One immutable, hash-chained envelope shared by
// Purse (kind "decision"), blackbox (kind "action"), and anything else that
// needs a record a third party can verify without trusting the writer.

/** prevHash of the first record in every chain: 64 zeros. */
export const GENESIS = "0".repeat(64);

/** A committed receipt. `hash` covers id, ts, kind, payload, prevHash. */
export interface Receipt<P = unknown> {
  id: string;
  /** ISO-8601 */
  ts: string;
  /** What kind of payload this is, e.g. "decision" | "action". */
  kind: string;
  payload: P;
  /** Hash of the previous receipt, or GENESIS for the first. */
  prevHash: string;
  /** SHA-256 hex over the canonical form of this receipt (see canonicalize). */
  hash: string;
}

/** The caller-owned part of a receipt. The engine assigns id, ts, prevHash, hash. */
export interface ReceiptInput<P = unknown> {
  kind: string;
  payload: P;
}

/** A pluggable append-only store. */
export interface Store<P = unknown> {
  lastHash(): string;
  append(rec: Receipt<P>): void;
  all(): Receipt<P>[];
}

export interface VerifyResult {
  ok: boolean;
  /** Index of the first broken receipt. */
  brokenAt?: number;
  /** Id of the first broken receipt. */
  id?: string;
  reason?: string;
}

/** Injectable clock and id source (tests pass fixed values). */
export interface MakeOptions {
  now?: () => string;
  newId?: () => string;
}
