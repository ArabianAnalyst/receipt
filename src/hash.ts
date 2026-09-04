import { createHash } from "node:crypto";
import { GENESIS } from "./types.js";
import type { Receipt, VerifyResult } from "./types.js";

/**
 * The exact bytes the hash covers. Key order is the spec:
 * id, ts, kind, payload, prevHash. JSON.stringify omits undefined fields,
 * so optional payload fields that were never set do not shift the hash.
 */
export function canonicalize(rec: Omit<Receipt, "hash">): string {
  return JSON.stringify({
    id: rec.id,
    ts: rec.ts,
    kind: rec.kind,
    payload: rec.payload,
    prevHash: rec.prevHash,
  });
}

/** SHA-256 hex over the canonical form. */
export function hashRecord(rec: Omit<Receipt, "hash">): string {
  return createHash("sha256").update(canonicalize(rec)).digest("hex");
}

/**
 * Walk the chain. Each prevHash must equal the previous receipt's hash, and
 * each hash must recompute from the receipt's own contents. Any alteration,
 * insertion, removal, or reorder breaks one of those and is reported with
 * the index and id of the first broken receipt.
 */
export function verifyChain(records: ReadonlyArray<Receipt>): VerifyResult {
  let prev = GENESIS;
  for (let i = 0; i < records.length; i++) {
    const r = records[i]!;
    if (r.prevHash !== prev) {
      return { ok: false, brokenAt: i, id: r.id, reason: "prevHash mismatch (a record was inserted, removed, or reordered)" };
    }
    const { hash, ...rest } = r;
    if (hashRecord(rest) !== hash) {
      return { ok: false, brokenAt: i, id: r.id, reason: "hash mismatch (a record was altered)" };
    }
    prev = hash;
  }
  return { ok: true };
}
