# Postgres Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a write-through `PostgresStore` to `@olurabian/receipt` so Purse and blackbox run against Postgres with their synchronous APIs unchanged, and make Purse's broker flush receipts before money moves.

**Architecture:** `PostgresStore<P>` implements the existing sync `Store<P>` by holding the stream in memory and queueing ordered INSERTs to a caller-supplied `SqlClient` (one `query` method, so the package stays zero-dependency). `open()` migrates, loads, and verifies. A hard insert error latches the store. Purse's `Broker.execute()` awaits `flush()` before calling the executor and before returning. Tests run real SQL through embedded PGlite.

**Tech Stack:** TypeScript strict, NodeNext ESM, `node:test` via `tsx --test` (receipt), Purse's own `check()` harness, `@electric-sql/pglite` as a devDependency of receipt only.

**Spec:** `docs/superpowers/specs/2026-09-04-postgres-store-design.md`

## Global Constraints

- `@olurabian/receipt` keeps **zero runtime dependencies**. PGlite is a devDependency only. No database driver is imported anywhere in `src/`.
- `SqlClient = { query(text: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[] }> }`.
- Reload reads the `record` text column, never `payload` jsonb.
- The schema has `UNIQUE (stream, id)`, `UNIQUE (stream, hash)`, `UNIQUE (stream, prev_hash)`.
- A unique-constraint violation is never retried. After the first hard error the store is latched: `append()` throws, `flush()` rejects, `pending()` still counts.
- `open()` verifies the loaded chain and throws on a broken one.
- Purse: `execute()` awaits `flush()` before the executor runs and before it returns; `authorize()` stays synchronous.
- All TypeScript import specifiers end in `.js` (NodeNext).
- Versions: receipt `0.1.0 → 0.2.0`, purse `0.3.0 → 0.3.1`. Purse's dependency range moves to `^0.2.0` only in the release task, after receipt 0.2.0 is on the registry, using `npm install @olurabian/receipt@^0.2.0` explicitly (a plain `npm install` keeps a satisfying local link).
- Before every `npm publish`: `npm run build && npm test && npm pack --dry-run` and confirm `dist/index.js` and `dist/index.d.ts` are in the tarball (`ignore-scripts=true` disables `prepublishOnly`).
- Every repo touched ends every task with `npm run build && npm test` green. Every commit message ends with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- No push and no publish before the release task, and that task runs only after ARABA confirms.
- Public copy (READMEs, CHANGELOGs) has no colons and no em dashes inside prose sentences; code, headings, and tables are exempt. No counterparty names anywhere.
- Never stage `purse/docs/launch-x402.md`.

## File structure

**receipt** (branch `postgres-store`):
- Create `src/postgres.ts` (SqlClient, options, schema, PostgresStore)
- Modify `src/index.ts` (export the new names)
- Create `test/postgres.test.ts`
- Modify `package.json` (pglite devDependency, version 0.2.0), `README.md` (Postgres section), `CHANGELOG.md`

**purse** (branch `postgres-store`):
- Modify `src/broker.ts` (flush points, `flush()`), `src/policy.ts` (`flush()`), `package.json` (version 0.3.1, test script), `README.md` (Production store section)
- Create `test/broker-flush.test.ts`, `CHANGELOG.md`

**blackbox** (branch `postgres-store`):
- Modify `README.md` (Postgres example). No version change, no publish.

---

### Task 1: PostgresStore with real-SQL tests

**Files:**
- Create: `src/postgres.ts`, `test/postgres.test.ts`
- Modify: `src/index.ts`, `package.json` (devDependency only)

**Interfaces:**
- Consumes: `Store<P>`, `Receipt<P>`, `GENESIS` from `src/types.ts`; `verifyChain` from `src/hash.ts`.
- Produces: `SqlClient`, `PostgresStoreOptions`, `schema(table)`, `PostgresStore<P>` with `static open()`, `flush()`, `pending()`.

- [ ] **Step 1: Add PGlite as a devDependency**

Run from `/c/Users/ARABA/Workspace/SaaS/receipt`:

```bash
npm install --save-dev @electric-sql/pglite@^0.5.8 --no-audit --no-fund
npx allow-scripts
node -e "console.log(require('./package.json').devDependencies['@electric-sql/pglite'])"
```

Expected: the version prints; `allow-scripts` lists only `tsx>esbuild` (PGlite has no install script). Do not add anything to `lavamoat.allowScripts`.

- [ ] **Step 2: Write the failing tests**

Create `test/postgres.test.ts`:

```ts
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
```

- [ ] **Step 3: Run the tests to see them fail**

Run: `npx tsx --test test/postgres.test.ts`
Expected: every test fails at import time with `PostgresStore` not exported (or `Cannot find module '../src/postgres.js'` once the export line exists but the file does not).

- [ ] **Step 4: Implement the store**

Create `src/postgres.ts`:

```ts
import { GENESIS } from "./types.js";
import type { Receipt, Store } from "./types.js";
import { verifyChain } from "./hash.js";

/** The one thing a database driver must provide. pg, Neon serverless, and PGlite satisfy it as-is. */
export interface SqlClient {
  query(text: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

export interface PostgresStoreOptions {
  /** One table serves many products; each product writes one stream. Default "default". */
  stream?: string;
  /** Table name. Default "receipts". Letters, digits, underscores only. */
  table?: string;
  /** Run CREATE TABLE IF NOT EXISTS and the index on open. Default true. */
  migrate?: boolean;
  /** Retries for transient insert failures before the store latches. Default 3. */
  retries?: number;
  /** Backoff per retry in milliseconds. Default [100, 400, 1600]. Tests pass zeros. */
  backoffMs?: number[];
}

const IDENT = /^[a-z_][a-z0-9_]*$/;

/** The schema, as executed by open(). Exposed so operators can run it themselves. */
export function schema(table = "receipts"): string[] {
  if (!IDENT.test(table)) throw new Error(`PostgresStore: invalid table name "${table}"`);
  return [
    `CREATE TABLE IF NOT EXISTS ${table} (
  seq BIGSERIAL PRIMARY KEY,
  stream TEXT NOT NULL,
  id TEXT NOT NULL,
  ts TIMESTAMPTZ NOT NULL,
  kind TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  payload JSONB NOT NULL,
  record TEXT NOT NULL,
  UNIQUE (stream, id),
  UNIQUE (stream, hash),
  UNIQUE (stream, prev_hash)
)`,
    `CREATE INDEX IF NOT EXISTS ${table}_stream_seq ON ${table} (stream, seq)`,
  ];
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Write-through Postgres store. Synchronous Store<P> for callers; every append is queued
 * as one ordered INSERT. Reload reads the canonical `record` text, never `payload` jsonb,
 * because jsonb reorders keys and would break the hash. The UNIQUE (stream, prev_hash)
 * constraint makes the database reject a fork. The first hard error latches the store.
 */
export class PostgresStore<P = unknown> implements Store<P> {
  private records: Receipt<P>[] = [];
  private queue: Receipt<P>[] = [];
  private chain: Promise<void> = Promise.resolve();
  private latched: Error | null = null;
  private readonly stream: string;
  private readonly table: string;
  private readonly retries: number;
  private readonly backoffMs: number[];

  private constructor(private readonly client: SqlClient, opts: PostgresStoreOptions) {
    this.stream = opts.stream ?? "default";
    this.table = opts.table ?? "receipts";
    if (!IDENT.test(this.table)) throw new Error(`PostgresStore: invalid table name "${this.table}"`);
    this.retries = opts.retries ?? 3;
    this.backoffMs = opts.backoffMs ?? [100, 400, 1600];
  }

  /** Migrate (optional), load the stream in order, verify it, and return a synchronous store. */
  static async open<P = unknown>(client: SqlClient, opts: PostgresStoreOptions = {}): Promise<PostgresStore<P>> {
    const store = new PostgresStore<P>(client, opts);
    if (opts.migrate ?? true) {
      for (const stmt of schema(store.table)) await client.query(stmt);
    }
    const { rows } = await client.query(`SELECT record FROM ${store.table} WHERE stream = $1 ORDER BY seq`, [store.stream]);
    store.records = rows.map((r) => JSON.parse(String(r.record)) as Receipt<P>);
    const v = verifyChain(store.records);
    if (!v.ok) {
      throw new Error(`PostgresStore: stream "${store.stream}" fails verification at index ${v.brokenAt} (${v.reason})`);
    }
    return store;
  }

  lastHash(): string {
    const last = this.records[this.records.length - 1];
    return last ? last.hash : GENESIS;
  }

  append(rec: Receipt<P>): void {
    if (this.latched) throw new Error(`PostgresStore: degraded, ${this.latched.message}`);
    this.records.push(rec);
    this.queue.push(rec);
    this.chain = this.chain.then(() => this.insert(rec));
  }

  all(): Receipt<P>[] {
    return [...this.records];
  }

  /** Appends queued but not yet durable. */
  pending(): number {
    return this.queue.length;
  }

  /** Resolves when every queued append is durable. Rejects with the latched error. */
  async flush(): Promise<void> {
    await this.chain;
    if (this.latched) throw new Error(`PostgresStore: degraded, ${this.latched.message}`);
  }

  private async insert(rec: Receipt<P>): Promise<void> {
    if (this.latched) return;
    const sql = `INSERT INTO ${this.table} (stream, id, ts, kind, prev_hash, hash, payload, record) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`;
    const params = [this.stream, rec.id, rec.ts, rec.kind, rec.prevHash, rec.hash, JSON.stringify(rec.payload), JSON.stringify(rec)];
    for (let attempt = 0; ; attempt++) {
      try {
        await this.client.query(sql, params);
        this.queue.shift();
        return;
      } catch (e) {
        const err = e as Error & { code?: string };
        const unique = err.code === "23505" || /unique constraint/i.test(err.message);
        if (unique || attempt >= this.retries) {
          this.latched = new Error(`insert of receipt ${rec.id} failed after ${attempt + 1} attempt(s): ${err.message}`);
          return;
        }
        await sleep(this.backoffMs[Math.min(attempt, this.backoffMs.length - 1)] ?? 0);
      }
    }
  }
}
```

- [ ] **Step 5: Export from the index**

Replace `src/index.ts` with:

```ts
export { GENESIS } from "./types.js";
export type { Receipt, ReceiptInput, Store, VerifyResult, MakeOptions } from "./types.js";
export { canonicalize, hashRecord, verifyChain } from "./hash.js";
export { makeReceipt } from "./chain.js";
export { MemoryStore, JsonlStore } from "./store.js";
export { PostgresStore, schema } from "./postgres.js";
export type { SqlClient, PostgresStoreOptions } from "./postgres.js";
```

- [ ] **Step 6: Run the tests to see them pass**

Run: `npx tsx --test test/postgres.test.ts`
Expected: 9 tests pass, 0 fail, no warnings. If PGlite prints a one-time WASM notice, report it; it is not a failure.

Then: `npm run build && npm test`
Expected: build clean, 29 tests pass (20 existing + 9 new).

- [ ] **Step 7: Commit**

```bash
git add src/postgres.ts src/index.ts test/postgres.test.ts package.json package-lock.json
git commit -q -m "feat: PostgresStore, a write-through store over any SQL client

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: receipt docs, changelog, version 0.2.0

**Files:**
- Modify: `README.md`, `CHANGELOG.md`, `package.json`

- [ ] **Step 1: README Postgres section**

Insert the following section in `README.md` immediately before the `## The receipt` heading:

```markdown
## Postgres

For real deployments, `PostgresStore` keeps the same synchronous `Store` interface and writes every receipt through to Postgres in order. It takes any client with a `query(text, params)` method, so the package stays dependency free. `pg`, Neon's serverless driver, and PGlite work as they are.

```js
import pg from "pg";
import { PostgresStore, makeReceipt } from "@olurabian/receipt";

const client = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const store = await PostgresStore.open(client, { stream: "purse" });

makeReceipt(store, { kind: "decision", payload: { status: "allowed" } });
await store.flush(); // resolves once the receipt is durable
```

With Neon, replace the pool with `new Pool({ connectionString })` from `@neondatabase/serverless`. With postgres.js, wrap it once:

```js
const client = { query: (text, params = []) => sql.unsafe(text, params).then((rows) => ({ rows })) };
```

What `open` does. It creates the table if it is missing, loads the stream in order, verifies the chain, and refuses to start on a broken one. One table holds many streams, one per product.

One writer per stream. The table has a unique constraint on the previous hash, so a second process appending on the same head is rejected by the database rather than corrupting the chain. Run one writer per stream.

Degraded means stopped. A transient insert failure is retried three times. A hard failure, including a rejected fork, latches the store. After that `append()` throws, `flush()` rejects, and `pending()` reports the backlog. Fix the database and restart the process, and `open` reloads and re-verifies.

Reload reads the canonical text. Postgres reorders keys inside `jsonb`, which would break the hash on reload, so the store keeps the exact receipt text in a `record` column and uses `payload` only for SQL queries.
```

Note the nested fence: the section contains code fences inside the markdown fence above. Write it into the README as plain markdown (the outer fence here is only for this plan).

- [ ] **Step 2: Changelog and version**

Prepend to `CHANGELOG.md`, above the 0.1.0 entry:

```markdown
## 0.2.0 (2026-09-04)

Adds `PostgresStore`, a write-through store over any SQL client with a `query(text, params)` method. Same synchronous interface as the other stores, ordered inserts, `flush()` and `pending()`, fork rejection at the database, and a fail-closed reload that verifies the chain. Adds `schema()` and the `SqlClient` and `PostgresStoreOptions` types. No breaking changes.

```

Set `"version": "0.2.0"` in `package.json`.

- [ ] **Step 3: Verify and commit**

Run: `npm run build && npm test`
Expected: green, 29 tests.

```bash
git add README.md CHANGELOG.md package.json package-lock.json
git commit -q -m "docs: Postgres section and changelog; version 0.2.0

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Purse flushes before money moves

**Working directory:** `/c/Users/ARABA/Workspace/SaaS/purse`, branch `postgres-store`.

**Files:**
- Modify: `src/broker.ts`, `src/policy.ts`, `package.json`, `README.md`
- Create: `test/broker-flush.test.ts`, `CHANGELOG.md`

**Interfaces:**
- Consumes: `AuditStore` (any `Store<DecisionPayload>`); a store MAY have `flush(): Promise<void>`.
- Produces: `Broker.flush()`, `Purse.flush()`.

- [ ] **Step 1: Write the failing test**

Create `test/broker-flush.test.ts` (Purse's own harness, same shape as `test/broker.test.ts`):

```ts
import { Broker } from "../src/broker";
import { MockExecutor } from "../src/executor";
import { JsonlAuditStore } from "../src/audit";

let passed = 0, failed = 0;
function check(name: string, cond: boolean) {
  if (cond) { passed++; console.log(`  ok   ${name}`); }
  else { failed++; console.error(`  FAIL ${name}`); }
}

class FlushingStore extends JsonlAuditStore {
  constructor(private readonly log: string[], private readonly fail = false) { super(); }
  async flush(): Promise<void> {
    this.log.push("flush");
    if (this.fail) throw new Error("db down");
  }
}

class LoggingExecutor extends MockExecutor {
  constructor(private readonly log: string[]) { super(); }
  override async execute(p: Parameters<MockExecutor["execute"]>[0]) {
    this.log.push("execute");
    return super.execute(p);
  }
}

// Scene 1: execute flushes before the executor runs and before it returns
{
  const log: string[] = [];
  const b = new Broker({ maxPerAction: "$5", allow: ["api.stripe.com"], executor: new LoggingExecutor(log), store: new FlushingStore(log) });
  const r = b.request({ amount: "$3", payee: "api.stripe.com", intent: "credits" });
  const x = await b.execute(r.grantId!);
  check("spend is paid", x.status === "paid");
  check("flush runs before the executor and again before returning", JSON.stringify(log) === JSON.stringify(["flush", "execute", "flush"]));
}

// Scene 2: a rejecting flush stops the executor from running and rejects execute
{
  const log: string[] = [];
  const b = new Broker({ maxPerAction: "$5", allow: ["api.stripe.com"], executor: new LoggingExecutor(log), store: new FlushingStore(log, true) });
  const r = b.request({ amount: "$3", payee: "api.stripe.com", intent: "credits" });
  let threw = "";
  try { await b.execute(r.grantId!); } catch (e) { threw = (e as Error).message; }
  check("execute rejects when the receipt cannot be made durable", /db down/.test(threw));
  check("the executor never ran", !log.includes("execute"));
}

// Scene 3: stores without flush are fine, and Broker.flush()/Purse.flush() are no-ops on them
{
  const b = new Broker({ maxPerAction: "$5", allow: ["api.stripe.com"], executor: new MockExecutor() });
  const r = b.request({ amount: "$3", payee: "api.stripe.com", intent: "credits" });
  const x = await b.execute(r.grantId!);
  check("plain store still pays", x.status === "paid");
  await b.flush();
  check("Broker.flush() resolves on a store without flush", true);
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
```

Add `&& tsx test/broker-flush.test.ts` to the end of the `test` script in `package.json`.

- [ ] **Step 2: Run it to see it fail**

Run: `npx tsx test/broker-flush.test.ts`
Expected: Scene 1's order check FAILs (log is `["execute"]`), Scene 2 FAILs (execute did not reject), and Scene 3's `b.flush()` throws `b.flush is not a function`.

- [ ] **Step 3: Implement**

In `src/broker.ts`:

(a) Add this method after `verify()`:

```ts
  /** Wait until the audit store has made every receipt durable. No-op on stores without flush(). */
  async flush(): Promise<void> {
    const s = this.store as unknown as { flush?: () => Promise<void> };
    if (typeof s.flush === "function") await s.flush();
  }
```

(b) Rename the existing `async execute(grantId: string): Promise<ExecuteResult>` to `private async executeInner(grantId: string): Promise<ExecuteResult>` and add, directly above it, the public wrapper:

```ts
  /** Redeem a grant. The decision is flushed before money moves, and the outcome before this resolves. */
  async execute(grantId: string): Promise<ExecuteResult> {
    const result = await this.executeInner(grantId);
    await this.flush();
    return result;
  }
```

(c) Inside `executeInner`, immediately after the line `const req: NormalizedRequest = { amount: g.amount, payee: g.payee, intent: g.intent, category: g.category };` and before `let receipt;`, insert:

```ts
    await this.flush(); // the claim is recorded above; make it durable before the executor runs
```

Grep-verify all three landed: `grep -n "executeInner\|await this.flush()" src/broker.ts` shows the wrapper, the rename, the pre-executor flush, and the method.

In `src/policy.ts`, add after `verify()`:

```ts
  /** Wait until the audit store has made every receipt durable. No-op on stores without flush(). */
  async flush(): Promise<void> {
    const s = this.store as unknown as { flush?: () => Promise<void> };
    if (typeof s.flush === "function") await s.flush();
  }
```

- [ ] **Step 4: Run to see it pass**

Run: `npx tsx test/broker-flush.test.ts`
Expected: `5 passed, 0 failed`.

Run: `npm run build && npm test`
Expected: every suite `0 failed`.

- [ ] **Step 5: README, changelog, version**

In `README.md`, insert immediately before `## Upgrading from 0.2`:

```markdown
## Production store

Pass any store that implements the receipt `Store` interface. For Postgres use `PostgresStore` from `@olurabian/receipt`, which keeps the synchronous API and writes every decision through in order.

```js
import pg from "pg";
import { PostgresStore } from "@olurabian/receipt";
import { Broker, MockExecutor } from "@olurabian/purse";

const store = await PostgresStore.open(new pg.Pool({ connectionString: process.env.DATABASE_URL }), { stream: "purse" });
const broker = new Broker({ maxPerAction: "$50", allow: ["api.stripe.com"], executor: new MockExecutor(), store });
```

`execute()` waits for the store to make the decision durable before it calls the executor, and for the outcome before it resolves, so money never moves ahead of its receipt. `authorize()` stays synchronous, and its receipt is durable on the next turn of the event loop. Call `broker.flush()` or `purse.flush()` before shutting down.
```

Create `CHANGELOG.md`:

```markdown
# Changelog

## 0.3.1 (2026-09-04)

`Broker.execute()` now waits for the audit store to make the decision durable before the executor runs, and for the outcome before it resolves. Adds `Broker.flush()` and `Purse.flush()`. Works with `PostgresStore` from `@olurabian/receipt` 0.2. No breaking changes.

## 0.3.0 (2026-09-04)

Audit records are `@olurabian/receipt` envelopes. Decision fields moved under `payload`. Audit files written by 0.2 are refused with a migration hint.
```

Set `"version": "0.3.1"` in `package.json`. Leave the `@olurabian/receipt` range at `^0.1.0` for now (the release task bumps it after 0.2.0 is on the registry).

- [ ] **Step 6: Commit**

```bash
git add src/broker.ts src/policy.ts test/broker-flush.test.ts package.json README.md CHANGELOG.md
git commit -q -m "feat(broker): flush the audit store before money moves and before execute resolves

Adds Broker.flush() and Purse.flush(). Version 0.3.1.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: blackbox README example

**Working directory:** `/c/Users/ARABA/Workspace/SaaS/blackbox`, branch `postgres-store`.

- [ ] **Step 1: Add the example**

In `README.md`, insert immediately before `## The receipt`:

```markdown
## Postgres

The recorder takes any receipt store. For Postgres, open a `PostgresStore` from `@olurabian/receipt` and pass it in. Call `store.flush()` before the process exits.

```js
import pg from "pg";
import { PostgresStore } from "@olurabian/receipt";
import { createRecorder } from "@olurabian/blackbox";

const store = await PostgresStore.open(new pg.Pool({ connectionString: process.env.DATABASE_URL }), { stream: "blackbox" });
const rec = createRecorder({ store });
rec.record({ action: "ping", outcome: "ok" });
await store.flush();
```
```

- [ ] **Step 2: Verify and commit**

Run: `npm run build && npm test` (unchanged, must stay green).

```bash
git add README.md
git commit -q -m "docs: Postgres store example

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: Gate and final review

**Files:** none modified.

- [ ] **Step 1: Clean-install gate**

```bash
for r in receipt purse blackbox; do
  cd /c/Users/ARABA/Workspace/SaaS/$r && rm -rf node_modules && npm ci --no-audit --no-fund && npx allow-scripts && npm run build && npm test || { echo "FAILED: $r"; exit 1; }
done
echo ALL GREEN
```

- [ ] **Step 2: Confirm nothing was pushed or published**

`npm view @olurabian/receipt version` prints `0.1.0`; each repo's `postgres-store` branch is ahead of its mainline and has no upstream.

- [ ] **Step 3: Final whole-change review** on the most capable model, over the three branch diffs, with this plan's Global Constraints as the lens. Fix Critical and Important findings before the release task.

---

### Task 6: Release (only after ARABA confirms)

- [ ] **Step 1: receipt 0.2.0**

```bash
cd /c/Users/ARABA/Workspace/SaaS/receipt && git checkout main && git merge --ff-only postgres-store && git push origin main
npm run build && npm test && npm pack --dry-run 2>&1 | grep -E "dist/index\.js|dist/index\.d\.ts" && npm publish --access public && npm view @olurabian/receipt version
```

Expected: `0.2.0`.

- [ ] **Step 2: purse 0.3.1 against the registry**

```bash
cd /c/Users/ARABA/Workspace/SaaS/purse && git checkout main && git merge --ff-only postgres-store
npm install @olurabian/receipt@^0.2.0 --no-audit --no-fund && npx allow-scripts
node -p "JSON.parse(require('fs').readFileSync('package-lock.json','utf8')).packages['node_modules/@olurabian/receipt'].resolved"
npm run build && npm test
git add package.json package-lock.json && git commit -q -m "chore: depend on @olurabian/receipt ^0.2.0

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" && git push origin main
npm pack --dry-run 2>&1 | grep -E "dist/index\.js|dist/index\.d\.ts" && npm publish --access public && npm view @olurabian/purse version
```

Expected: the resolved line is a registry URL, not `../receipt`; version `0.3.1`.

- [ ] **Step 3: blackbox docs**

```bash
cd /c/Users/ARABA/Workspace/SaaS/blackbox && git checkout main && git merge --ff-only postgres-store && git push origin main
```

- [ ] **Step 4: Smoke from a clean directory** (session scratchpad, not /tmp)

```bash
mkdir -p "$SCRATCH/pg-smoke" && cd "$SCRATCH/pg-smoke" && rm -rf * && npm init -y >/dev/null && npm i @olurabian/receipt @olurabian/purse @electric-sql/pglite --no-audit --no-fund --ignore-scripts
node --input-type=module -e "
import { PGlite } from '@electric-sql/pglite';
import { PostgresStore, verifyChain } from '@olurabian/receipt';
import { Broker, MockExecutor } from '@olurabian/purse';
const db = new PGlite();
const store = await PostgresStore.open(db, { stream: 'purse' });
const b = new Broker({ maxPerAction: '\$5', allow: ['api.stripe.com'], executor: new MockExecutor(), store });
const r = b.request({ amount: '\$3', payee: 'api.stripe.com', intent: 'credits' });
const x = await b.execute(r.grantId);
const again = await PostgresStore.open(db, { stream: 'purse' });
console.log('paid', x.status, '| durable receipts', again.all().length, '| verify', JSON.stringify(verifyChain(again.all())));
"
```

Expected: `paid paid | durable receipts 3 | verify {"ok":true}` (request, claim, executed).

---

## Self-review

**Spec coverage.** Shape, options, SqlClient (Task 1). Schema with the three unique constraints and `record` text (Task 1). Open, load, verify, refuse (Task 1 test "open refuses"). Write-through, ordering, flush, pending, retries, latch (Task 1 tests). Consumers: broker flush points and passthroughs (Task 3), blackbox docs (Task 4). Docs and changelogs (Tasks 2, 3). Versions (Tasks 2, 3, 6). Non-goals untouched.

**Placeholder scan.** No TBD. Every code step carries its code. The one conditional is the ARABA confirmation before Task 6.

**Type consistency.** `SqlClient.query` returns `{ rows: Record<string, unknown>[] }`; tests read `rows[0].c` and `r.id` through casts. `PostgresStore.open<P>` returns `Promise<PostgresStore<P>>`, and `PostgresStore<P> implements Store<P>`, which is what `BrokerOptions.store` and `RecorderOptions.store` accept. `flush(): Promise<void>` and `pending(): number` match the spec. `FlushingStore extends JsonlAuditStore` with no path is in-memory (the base allows an optional path).
