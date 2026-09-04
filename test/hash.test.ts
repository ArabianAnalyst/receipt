import { test } from "node:test";
import assert from "node:assert/strict";
import { GENESIS } from "../src/types.js";
import { canonicalize, hashRecord, verifyChain } from "../src/hash.js";
import type { Receipt } from "../src/types.js";

const base = {
  id: "id-1",
  ts: "2026-09-04T00:00:00.000Z",
  kind: "action",
  payload: { action: "charge", outcome: "ok" },
  prevHash: GENESIS,
};

test("canonicalize fixes the key order id, ts, kind, payload, prevHash", () => {
  assert.equal(
    canonicalize(base),
    `{"id":"id-1","ts":"2026-09-04T00:00:00.000Z","kind":"action","payload":{"action":"charge","outcome":"ok"},"prevHash":"${GENESIS}"}`,
  );
});

test("hashRecord is sha256 hex and deterministic", () => {
  const h = hashRecord(base);
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.equal(h, hashRecord(base));
});

test("every covered field changes the hash", () => {
  const h = hashRecord(base);
  assert.notEqual(h, hashRecord({ ...base, id: "id-2" }));
  assert.notEqual(h, hashRecord({ ...base, ts: "2027-01-01T00:00:00.000Z" }));
  assert.notEqual(h, hashRecord({ ...base, kind: "decision" }));
  assert.notEqual(h, hashRecord({ ...base, payload: { action: "refund", outcome: "ok" } }));
  assert.notEqual(h, hashRecord({ ...base, prevHash: "1".repeat(64) }));
});

test("undefined payload fields do not change the hash", () => {
  const a = hashRecord({ ...base, payload: { action: "charge", outcome: "ok" } });
  const b = hashRecord({ ...base, payload: { action: "charge", outcome: "ok", cost: undefined } });
  assert.equal(a, b);
});

function chain(n: number): Receipt[] {
  const out: Receipt[] = [];
  let prev = GENESIS;
  for (let i = 1; i <= n; i++) {
    const rest = { id: `id-${i}`, ts: "2026-09-04T00:00:00.000Z", kind: "action", payload: { i }, prevHash: prev };
    const rec: Receipt = { ...rest, hash: hashRecord(rest) };
    out.push(rec);
    prev = rec.hash;
  }
  return out;
}

test("verifyChain accepts an empty chain and a valid chain", () => {
  assert.deepEqual(verifyChain([]), { ok: true });
  assert.deepEqual(verifyChain(chain(3)), { ok: true });
});

test("verifyChain reports an altered receipt by index and id", () => {
  const c = chain(3);
  (c[1]!.payload as { i: number }).i = 999;
  const r = verifyChain(c);
  assert.equal(r.ok, false);
  assert.equal(r.brokenAt, 1);
  assert.equal(r.id, "id-2");
  assert.match(r.reason ?? "", /altered/);
});

test("verifyChain reports a removed receipt", () => {
  const c = chain(3);
  const r = verifyChain([c[0]!, c[2]!]);
  assert.equal(r.ok, false);
  assert.equal(r.brokenAt, 1);
  assert.match(r.reason ?? "", /inserted, removed, or reordered/);
});

test("verifyChain reports a reordered chain at index 0", () => {
  const c = chain(3);
  const r = verifyChain([c[1]!, c[0]!, c[2]!]);
  assert.equal(r.ok, false);
  assert.equal(r.brokenAt, 0);
});

test("verifyChain reports an inserted receipt", () => {
  const c = chain(3);
  const extraRest = {
    id: "id-extra",
    ts: "2026-09-04T00:00:00.000Z",
    kind: "action",
    payload: { i: 99 },
    prevHash: c[1]!.hash,
  };
  const extra: Receipt = { ...extraRest, hash: hashRecord(extraRest) };
  const spliced = [c[0]!, c[1]!, extra, c[2]!];
  const r = verifyChain(spliced);
  assert.equal(r.ok, false);
  assert.equal(r.brokenAt, 3);
  assert.equal(r.id, "id-3");
});
