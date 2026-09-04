import { test } from "node:test";
import assert from "node:assert/strict";
import { GENESIS } from "../src/types.js";
import { MemoryStore } from "../src/store.js";
import { makeReceipt } from "../src/chain.js";
import { hashRecord, verifyChain } from "../src/hash.js";

const fixed = () => {
  let seq = 0;
  return { now: () => "2026-09-04T00:00:00.000Z", newId: () => `id-${++seq}` };
};

test("makeReceipt assigns id, ts, prevHash and a matching hash", () => {
  const store = new MemoryStore<{ n: number }>();
  const r1 = makeReceipt(store, { kind: "decision", payload: { n: 1 } }, fixed());
  assert.equal(r1.id, "id-1");
  assert.equal(r1.ts, "2026-09-04T00:00:00.000Z");
  assert.equal(r1.kind, "decision");
  assert.deepEqual(r1.payload, { n: 1 });
  assert.equal(r1.prevHash, GENESIS);
  const { hash, ...rest } = r1;
  assert.equal(hash, hashRecord(rest));
});

test("makeReceipt chains prevHash to the previous hash and appends", () => {
  const store = new MemoryStore<{ n: number }>();
  const opts = fixed();
  const r1 = makeReceipt(store, { kind: "decision", payload: { n: 1 } }, opts);
  const r2 = makeReceipt(store, { kind: "decision", payload: { n: 2 } }, opts);
  assert.equal(r2.prevHash, r1.hash);
  assert.equal(store.all().length, 2);
  assert.deepEqual(verifyChain(store.all()), { ok: true });
});

test("makeReceipt defaults to a real clock and a uuid", () => {
  const store = new MemoryStore();
  const r = makeReceipt(store, { kind: "action", payload: null });
  assert.match(r.id, /^[0-9a-f-]{36}$/);
  assert.ok(!Number.isNaN(Date.parse(r.ts)));
});

test("a tampered payload is detected after the fact", () => {
  const store = new MemoryStore<{ n: number }>();
  const opts = fixed();
  makeReceipt(store, { kind: "decision", payload: { n: 1 } }, opts);
  makeReceipt(store, { kind: "decision", payload: { n: 2 } }, opts);
  store.all()[0]!.payload.n = 99; // all() copies the array, not the receipts
  const r = verifyChain(store.all());
  assert.equal(r.ok, false);
  assert.equal(r.brokenAt, 0);
  assert.equal(r.id, "id-1");
});
