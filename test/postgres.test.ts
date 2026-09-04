import { test } from "node:test";
import assert from "node:assert/strict";
import { PGlite } from "@electric-sql/pglite";
import { PostgresStore, GENESIS, makeReceipt, verifyChain } from "../src/index.js";
import type { SqlClient } from "../src/index.js";

function fixed() {
  let n = 0;
  return { now: () => new Date(1700000000000 + n * 1000).toISOString(), newId: () => `id-${++n}` };
}

test("open migrates an empty database and starts at GENESIS", async () => {
  const db = new PGlite();
  const store = await PostgresStore.open(db, { stream: "t" });
  assert.equal(store.lastHash(), GENESIS);
  assert.deepEqual(store.all(), []);
  assert.equal(store.pending(), 0);
});

test("append then reopen continues the chain and verifies", async () => {
  const db = new PGlite();
  const opts = fixed();
  const s1 = await PostgresStore.open<{ n: number }>(db, { stream: "t" });
  makeReceipt(s1, { kind: "x", payload: { n: 1 } }, opts);
  makeReceipt(s1, { kind: "x", payload: { n: 2 } }, opts);
  assert.equal(s1.pending(), 2);
  await s1.flush();
  assert.equal(s1.pending(), 0);
  const s2 = await PostgresStore.open<{ n: number }>(db, { stream: "t" });
  assert.equal(s2.all().length, 2);
  assert.equal(s2.lastHash(), s1.lastHash());
  makeReceipt(s2, { kind: "x", payload: { n: 3 } }, opts);
  await s2.flush();
  const s3 = await PostgresStore.open(db, { stream: "t" });
  assert.equal(verifyChain(s3.all()).ok, true);
  assert.equal(s3.all().length, 3);
});

test("streams are isolated", async () => {
  const db = new PGlite();
  const a = await PostgresStore.open(db, { stream: "a" });
  const b = await PostgresStore.open(db, { stream: "b" });
  makeReceipt(a, { kind: "x", payload: 1 }, fixed());
  await a.flush();
  assert.equal(b.all().length, 0);
  assert.equal((await PostgresStore.open(db, { stream: "b" })).lastHash(), GENESIS);
});

test("payload with integer-like and non-ASCII keys survives a round trip", async () => {
  const db = new PGlite();
  const s1 = await PostgresStore.open(db, { stream: "t" });
  const rec = makeReceipt(s1, { kind: "x", payload: { z: 1, a: { "10": true, "9": false }, ü: "ñ" } }, fixed());
  await s1.flush();
  const s2 = await PostgresStore.open(db, { stream: "t" });
  assert.deepEqual(s2.all()[0], rec);
  assert.equal(JSON.stringify(s2.all()[0]?.payload), JSON.stringify(rec.payload));
  assert.equal(verifyChain(s2.all()).ok, true);
});

test("a burst of appends lands in order", async () => {
  const db = new PGlite();
  const s = await PostgresStore.open<number>(db, { stream: "t" });
  const opts = fixed();
  for (let i = 0; i < 25; i++) makeReceipt(s, { kind: "x", payload: i }, opts);
  await s.flush();
  const { rows } = await db.query<{ id: string }>(`SELECT id FROM receipts WHERE stream = $1 ORDER BY seq`, ["t"]);
  assert.deepEqual(rows.map((r) => r.id), Array.from({ length: 25 }, (_, i) => `id-${i + 1}`));
});

test("a second writer on the same head is rejected and latches", async () => {
  const db = new PGlite();
  const s1 = await PostgresStore.open(db, { stream: "t" });
  makeReceipt(s1, { kind: "x", payload: 1 }, fixed());
  await s1.flush();
  const s2 = await PostgresStore.open(db, { stream: "t" });
  makeReceipt(s1, { kind: "x", payload: 2 }, { now: () => "2026-01-01T00:00:00.000Z", newId: () => "one" });
  await s1.flush();
  makeReceipt(s2, { kind: "x", payload: 3 }, { now: () => "2026-01-01T00:00:00.000Z", newId: () => "two" });
  await assert.rejects(s2.flush(), /degraded/);
  assert.equal(s2.pending(), 1);
  assert.throws(() => s2.append({ id: "z", ts: "t", kind: "x", payload: 0, prevHash: s2.lastHash(), hash: "h" }), /degraded/);
  const s3 = await PostgresStore.open(db, { stream: "t" });
  assert.equal(s3.all().length, 2);
  assert.equal(verifyChain(s3.all()).ok, true);
});

test("open refuses a stream that fails verification", async () => {
  const db = new PGlite();
  const s1 = await PostgresStore.open(db, { stream: "t" });
  makeReceipt(s1, { kind: "x", payload: 1 }, fixed());
  await s1.flush();
  await db.query(`UPDATE receipts SET record = replace(record, '"payload":1', '"payload":2') WHERE stream = $1`, ["t"]);
  await assert.rejects(PostgresStore.open(db, { stream: "t" }), /fails verification at index 0/);
});

test("transient failures are retried, then a hard failure latches", async () => {
  const db = new PGlite();
  let failures = 0;
  const flaky: SqlClient = {
    query: async (text, params) => {
      if (text.startsWith("INSERT") && failures > 0) { failures--; throw new Error("connection reset"); }
      return db.query(text, params as unknown[]);
    },
  };
  const s = await PostgresStore.open(flaky, { stream: "t", retries: 3, backoffMs: [0, 0, 0] });
  failures = 2;
  makeReceipt(s, { kind: "x", payload: 1 }, fixed());
  await s.flush();
  assert.equal(s.pending(), 0);
  failures = 10;
  makeReceipt(s, { kind: "x", payload: 2 }, { now: () => "2026-01-01T00:00:00.000Z", newId: () => "two" });
  await assert.rejects(s.flush(), /degraded.*connection reset/);
  assert.equal(s.pending(), 1);
});

test("flush resolves only after the last insert", async () => {
  const db = new PGlite();
  let inFlight = 0, maxInFlight = 0;
  const counting: SqlClient = {
    query: async (text, params) => {
      inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
      try { return await db.query(text, params as unknown[]); } finally { inFlight--; }
    },
  };
  const s = await PostgresStore.open(counting, { stream: "t" });
  const opts = fixed();
  for (let i = 0; i < 5; i++) makeReceipt(s, { kind: "x", payload: i }, opts);
  await s.flush();
  assert.equal(maxInFlight, 1);
  const { rows } = await db.query(`SELECT count(*)::int AS c FROM receipts`);
  assert.equal((rows[0] as { c: number }).c, 5);
});
