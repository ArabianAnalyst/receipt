# Receipt Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the hash-chain engine shared by Purse and blackbox into a zero-dependency package, `@olurabian/receipt`, wire both to consume it (envelope receipts, one verifier), adapt Tripwire and deadlatch-otel, regenerate the integration handover for spec v1, and roll LavaMoat allow-scripts to every repo touched.

**Architecture:** One new package (`SaaS/receipt`) owns the envelope type, canonicalization, hashing, chain verification, and two stores. Purse and blackbox become thin typed adapters over it (`kind: "decision"` and `kind: "action"`), keeping their public names (`JsonlAuditStore`, `makeRecord`, `MemoryStore`, `JsonlStore`, `createRecorder`, `verifyChain`). Record fields move under `payload`, a deliberate pre-1.0 breaking change. Tripwire's `fromBlackbox` unwraps envelopes; deadlatch-otel reads both shapes.

**Tech Stack:** TypeScript 5 strict, ESM `NodeNext`, Node ≥ 18 (dev machine: Node 22, npm 10). `node:test` + `node:assert/strict` via `tsx --test` for the new package; Purse and blackbox keep their existing zero-dep `check()` runners. LavaMoat `@lavamoat/allow-scripts` on every repo. GitHub Actions CI.

**Spec:** `docs/superpowers/specs/2026-09-04-receipt-engine-design.md` (in `SaaS/receipt`).

## Global Constraints

- `@olurabian/receipt` has **zero runtime dependencies**. Purse and blackbox may depend on `@olurabian/receipt` and nothing else at runtime.
- Canonicalization is exactly `sha256(JSON.stringify({ id, ts, kind, payload, prevHash }))` in that key order. `GENESIS = "0".repeat(64)`.
- `VerifyResult = { ok: boolean; brokenAt?: number; id?: string; reason?: string }`, `brokenAt` is an index.
- All TypeScript import specifiers end in `.js` (NodeNext), except tests in tripwire which follow that repo's existing `.ts` convention.
- Every repo touched ends every task with `npm run build && npm test` green.
- Versions: receipt `0.1.0`, purse `0.2.2 → 0.3.0`, blackbox `0.1.1 → 0.2.0`, tripwire `0.1.0 → 0.1.1`, deadlatch-otel `0.1.0 → 0.1.1`.
- Until Task 9, Purse and blackbox depend on `"@olurabian/receipt": "file:../receipt"`. **No `git push` and no `npm publish` before Task 9.** Task 9 flips the dependency to `^0.1.0` and releases in order: receipt → purse, blackbox → tripwire, deadlatch-otel.
- Every repo gets `.npmrc` with `ignore-scripts=true`, a `lavamoat.allowScripts` allowlist in `package.json`, and `npx allow-scripts` after install in CI.
- Every commit message ends with the trailer: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Working directory for each task is stated at the top of the task. Paths below are relative to `C:/Users/ARABA/Workspace/SaaS/` unless absolute. Use Git Bash syntax (`/c/Users/...`).
- Do not touch `purse/docs/launch-x402.md` (untracked, local-only by design).

---

## File map

**Create (`receipt/`):** `package.json`, `tsconfig.json`, `.npmrc`, `.gitignore`, `LICENSE`, `README.md`, `src/types.ts`, `src/hash.ts`, `src/store.ts`, `src/chain.ts`, `src/index.ts`, `test/hash.test.ts`, `test/store.test.ts`, `test/chain.test.ts`, `.github/workflows/ci.yml`, `.github/workflows/security.yml`.

**Modify (`purse/`):** `src/types.ts` (AuditRecord → DecisionPayload + alias), `src/audit.ts` (full rewrite as adapter), `src/policy.ts:70-74`, `src/index.ts:5-16`, `test/audit-explain.test.ts`, `test/policy.test.ts:66`, `test/broker.test.ts:58`, `examples/x402/broker-host.ts:31`, `examples/x402/broker-host-llm.ts:22`, `package.json`, `README.md`, `docs/integration/receipt-handover.md`. **Create:** `scripts/sample-receipts.mjs`, `docs/integration/samples/purse-sample-receipts.json`.

**Modify (`blackbox/`):** `src/types.ts`, `src/hash.ts`, `src/store.ts`, `src/recorder.ts` (all full rewrites), `test/hash.test.ts` (rewrite), `test/store.test.ts:12-14`, `test/recorder.test.ts:32,33,42,43`, `test/verify.test.ts:25,27,28`, `examples/demo.ts:20,26`, `README.md:47,58`, `package.json`, `.github/workflows/ci.yml`. **Create:** `.npmrc`.

**Modify (`tripwire/`):** `src/capture.ts:42-47`, `package.json`, `.github/workflows/ci.yml`. **Create:** `test/from-blackbox.test.ts`, `.npmrc`.

**Modify (`deadlatch-otel/`):** `src/blackbox.ts:20-29`, `package.json`, `.github/workflows/ci.yml`. **Create:** `.npmrc`.

---

### Task 1: Scaffold `@olurabian/receipt` with its types

**Working directory:** `receipt/` (create it).

**Files:**
- Create: `receipt/package.json`, `receipt/tsconfig.json`, `receipt/.npmrc`, `receipt/.gitignore`, `receipt/LICENSE`, `receipt/src/types.ts`, `receipt/test/types.test.ts`

**Interfaces:**
- Produces: `GENESIS: string`, `Receipt<P>`, `ReceiptInput<P>`, `Store<P>`, `VerifyResult`, `MakeOptions` from `src/types.ts` (exact shapes in Step 4). Later tasks import these.

- [ ] **Step 1: Create the package skeleton**

```bash
mkdir -p /c/Users/ARABA/Workspace/SaaS/receipt/src /c/Users/ARABA/Workspace/SaaS/receipt/test
cd /c/Users/ARABA/Workspace/SaaS/receipt && git init -q && git branch -M main
```

Write `receipt/package.json`:

```json
{
  "name": "@olurabian/receipt",
  "version": "0.1.0",
  "description": "The Deadlatch receipt. A zero-dependency, hash-chained, independently verifiable record envelope shared by Purse, blackbox and Tripwire.",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "types": "./dist/index.d.ts"
    }
  },
  "files": [
    "dist",
    "README.md",
    "LICENSE"
  ],
  "scripts": {
    "build": "tsc",
    "typecheck": "tsc --noEmit",
    "test": "tsx --test test/*.test.ts",
    "prepublishOnly": "npm run build"
  },
  "keywords": [
    "ai",
    "agents",
    "audit",
    "tamper-evident",
    "hash-chain",
    "receipt",
    "governance",
    "deadlatch"
  ],
  "license": "MIT",
  "publishConfig": {
    "access": "public"
  },
  "author": "Oluwasegun Araba (ARABA)",
  "repository": {
    "type": "git",
    "url": "https://github.com/ArabianAnalyst/receipt"
  },
  "engines": {
    "node": ">=18"
  },
  "devDependencies": {
    "@lavamoat/allow-scripts": "^5.1.0",
    "@types/node": "^22.10.0",
    "tsx": "^4.19.0",
    "typescript": "^5.7.0"
  }
}
```

Write `receipt/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022"],
    "outDir": "dist",
    "rootDir": "src",
    "declaration": true,
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": ["src"],
  "exclude": ["node_modules", "dist", "test"]
}
```

Write `receipt/.npmrc`:

```
# Supply-chain hardening: npm runs NO dependency install scripts by default.
# Only packages allowlisted in package.json "lavamoat.allowScripts" run, via:
#   npx allow-scripts
ignore-scripts=true
```

Write `receipt/.gitignore`:

```
node_modules
dist
```

Write `receipt/LICENSE` (MIT, same as Purse):

```
MIT License

Copyright (c) 2026 Oluwasegun Araba

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 2: Install with scripts disabled, then allowlist esbuild**

```bash
cd /c/Users/ARABA/Workspace/SaaS/receipt
npm install --no-audit --no-fund
npx allow-scripts auto
sed -i 's/\("tsx>esbuild#[^"]*": \)false/\1true/' package.json
npx allow-scripts
```

Expected: `allow-scripts auto` prints `Adding lifecycle tsx>esbuild#<version>`; after the sed the `lavamoat.allowScripts` entry is `true`; `npx allow-scripts` runs the esbuild install script and nothing else.

- [ ] **Step 3: Write the failing test**

Write `receipt/test/types.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { GENESIS } from "../src/types.js";
import type { Receipt, Store } from "../src/types.js";

test("GENESIS is 64 zeros", () => {
  assert.equal(GENESIS, "0".repeat(64));
  assert.match(GENESIS, /^0{64}$/);
});

test("Receipt and Store types compile against a hand-built receipt", () => {
  const r: Receipt<{ n: number }> = {
    id: "id-1",
    ts: "2026-09-04T00:00:00.000Z",
    kind: "test",
    payload: { n: 1 },
    prevHash: GENESIS,
    hash: "0".repeat(64),
  };
  const store: Store<{ n: number }> = {
    lastHash: () => GENESIS,
    append: () => {},
    all: () => [r],
  };
  assert.equal(store.all()[0]?.payload.n, 1);
});
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cd /c/Users/ARABA/Workspace/SaaS/receipt && npm test`
Expected: FAIL, `Cannot find module '../src/types.js'` (or equivalent resolution error).

- [ ] **Step 5: Write the types**

Write `receipt/src/types.ts`:

```ts
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
```

- [ ] **Step 6: Run test to verify it passes, and the package builds**

Run: `cd /c/Users/ARABA/Workspace/SaaS/receipt && npm run build && npm test`
Expected: `tsc` exits 0 and produces `dist/types.js`; `npm test` reports 2 passing tests, 0 failing.

- [ ] **Step 7: Commit**

```bash
cd /c/Users/ARABA/Workspace/SaaS/receipt
git add package.json package-lock.json tsconfig.json .npmrc .gitignore LICENSE src/types.ts test/types.test.ts docs
git commit -q -m "feat: scaffold @olurabian/receipt with the envelope types

Zero-dependency package for the Deadlatch receipt. Types only; the
hashing, chain, and stores follow in the next commits.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Canonicalization, hashing, and chain verification

**Working directory:** `receipt/`.

**Files:**
- Create: `receipt/src/hash.ts`, `receipt/test/hash.test.ts`

**Interfaces:**
- Consumes: `GENESIS`, `Receipt`, `VerifyResult` from `src/types.ts`.
- Produces: `canonicalize(rec: Omit<Receipt, "hash">): string`, `hashRecord(rec: Omit<Receipt, "hash">): string`, `verifyChain(records: ReadonlyArray<Receipt>): VerifyResult`.

- [ ] **Step 1: Write the failing tests**

Write `receipt/test/hash.test.ts`:

```ts
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /c/Users/ARABA/Workspace/SaaS/receipt && npm test`
Expected: FAIL, `Cannot find module '../src/hash.js'`.

- [ ] **Step 3: Write the implementation**

Write `receipt/src/hash.ts`:

```ts
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /c/Users/ARABA/Workspace/SaaS/receipt && npm run build && npm test`
Expected: build exits 0; 10 tests pass (2 from Task 1 + 8 here), 0 fail.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ARABA/Workspace/SaaS/receipt
git add src/hash.ts test/hash.test.ts
git commit -q -m "feat: canonicalization, hashRecord, verifyChain

sha256 over JSON.stringify({id, ts, kind, payload, prevHash}) in that
order. verifyChain reports the index and id of the first broken receipt.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Stores, makeReceipt, public index, README, CI

**Working directory:** `receipt/`.

**Files:**
- Create: `receipt/src/store.ts`, `receipt/src/chain.ts`, `receipt/src/index.ts`, `receipt/test/store.test.ts`, `receipt/test/chain.test.ts`, `receipt/README.md`, `receipt/.github/workflows/ci.yml`, `receipt/.github/workflows/security.yml`

**Interfaces:**
- Consumes: everything from Tasks 1–2.
- Produces: `MemoryStore<P>`, `JsonlStore<P>(path?: string)`, `makeReceipt<P>(store: Store<P>, input: ReceiptInput<P>, opts?: MakeOptions): Receipt<P>`, and the package root `src/index.ts` re-exporting `GENESIS, canonicalize, hashRecord, verifyChain, makeReceipt, MemoryStore, JsonlStore` plus the types. Purse and blackbox import only from the package root.

- [ ] **Step 1: Write the failing store tests**

Write `receipt/test/store.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { rmSync, existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GENESIS } from "../src/types.js";
import { MemoryStore, JsonlStore } from "../src/store.js";
import type { Receipt } from "../src/types.js";

const rec = (id: string, prevHash: string): Receipt<{ a: number }> => ({
  id, ts: "2026-09-04T00:00:00.000Z", kind: "test", payload: { a: 1 }, prevHash, hash: "h" + id,
});

test("MemoryStore starts at GENESIS and tracks the tip", () => {
  const m = new MemoryStore<{ a: number }>();
  assert.equal(m.lastHash(), GENESIS);
  m.append(rec("1", GENESIS));
  m.append(rec("2", "h1"));
  assert.equal(m.lastHash(), "h2");
  assert.equal(m.all().length, 2);
  assert.notEqual(m.all(), m.all(), "all() returns a fresh array");
});

test("JsonlStore without a path is in-memory", () => {
  const j = new JsonlStore<{ a: number }>();
  j.append(rec("1", GENESIS));
  assert.equal(j.lastHash(), "h1");
});

test("JsonlStore persists one line per receipt and reloads", () => {
  const dir = mkdtempSync(join(tmpdir(), "receipt-"));
  const path = join(dir, "chain.jsonl");
  const j1 = new JsonlStore<{ a: number }>(path);
  j1.append(rec("1", GENESIS));
  j1.append(rec("2", "h1"));
  const j2 = new JsonlStore<{ a: number }>(path);
  assert.equal(j2.all().length, 2);
  assert.equal(j2.lastHash(), "h2");
  assert.equal(j2.all()[0]!.id, "1");
  rmSync(dir, { recursive: true, force: true });
  assert.equal(existsSync(path), false);
});
```

- [ ] **Step 2: Write the failing chain tests**

Write `receipt/test/chain.test.ts`:

```ts
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /c/Users/ARABA/Workspace/SaaS/receipt && npm test`
Expected: FAIL, cannot find `../src/store.js` / `../src/chain.js`.

- [ ] **Step 4: Write the stores**

Write `receipt/src/store.ts`:

```ts
import { appendFileSync, readFileSync, existsSync } from "node:fs";
import { GENESIS } from "./types.js";
import type { Receipt, Store } from "./types.js";

/** In-memory append-only store. lastHash() returns the tip of the chain. */
export class MemoryStore<P = unknown> implements Store<P> {
  protected records: Receipt<P>[] = [];

  lastHash(): string {
    const last = this.records[this.records.length - 1];
    return last ? last.hash : GENESIS;
  }

  append(rec: Receipt<P>): void {
    this.records.push(rec);
  }

  all(): Receipt<P>[] {
    return [...this.records];
  }
}

/**
 * Append-only JSONL store, one receipt per line. Pass a path to persist and
 * reload across restarts; omit it for an in-memory store.
 */
export class JsonlStore<P = unknown> extends MemoryStore<P> {
  constructor(private readonly path?: string) {
    super();
    if (path && existsSync(path)) {
      this.records = readFileSync(path, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l) as Receipt<P>);
    }
  }

  append(rec: Receipt<P>): void {
    super.append(rec);
    if (this.path) appendFileSync(this.path, JSON.stringify(rec) + "\n");
  }
}
```

- [ ] **Step 5: Write makeReceipt and the index**

Write `receipt/src/chain.ts`:

```ts
import { randomUUID } from "node:crypto";
import { hashRecord } from "./hash.js";
import type { MakeOptions, Receipt, ReceiptInput, Store } from "./types.js";

/** Build, hash, and append a receipt. Returns the finished receipt. */
export function makeReceipt<P>(store: Store<P>, input: ReceiptInput<P>, opts: MakeOptions = {}): Receipt<P> {
  const now = opts.now ?? (() => new Date().toISOString());
  const newId = opts.newId ?? (() => randomUUID());
  const base: Omit<Receipt<P>, "hash"> = {
    id: newId(),
    ts: now(),
    kind: input.kind,
    payload: input.payload,
    prevHash: store.lastHash(),
  };
  const rec: Receipt<P> = { ...base, hash: hashRecord(base) };
  store.append(rec);
  return rec;
}
```

Write `receipt/src/index.ts`:

```ts
export { GENESIS } from "./types.js";
export type { Receipt, ReceiptInput, Store, VerifyResult, MakeOptions } from "./types.js";
export { canonicalize, hashRecord, verifyChain } from "./hash.js";
export { makeReceipt } from "./chain.js";
export { MemoryStore, JsonlStore } from "./store.js";
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /c/Users/ARABA/Workspace/SaaS/receipt && npm run build && npm test`
Expected: build exits 0 and `dist/index.js` exists; 17 tests pass, 0 fail.

- [ ] **Step 7: README and CI**

Write `receipt/README.md`:

````markdown
# @olurabian/receipt

The Deadlatch receipt. A zero-dependency, hash-chained record envelope that a third party can verify without trusting the writer. It is the engine under [Purse](https://github.com/ArabianAnalyst/purse) (`kind: "decision"`) and [blackbox](https://github.com/ArabianAnalyst/blackbox) (`kind: "action"`), published on its own so anyone can verify a chain with one install.

```bash
npm i @olurabian/receipt
```

```ts
import { makeReceipt, verifyChain, JsonlStore } from "@olurabian/receipt";

const store = new JsonlStore("receipts.jsonl");
makeReceipt(store, { kind: "decision", payload: { payee: "api.stripe.com", amount: 1200, status: "allowed" } });

verifyChain(store.all()); // { ok: true }
// after any edit, insert, removal, or reorder:
// { ok: false, brokenAt: 0, id: "…", reason: "hash mismatch (a record was altered)" }
```

## The receipt

```ts
{ id, ts, kind, payload, prevHash, hash }
```

`hash = sha256( JSON.stringify({ id, ts, kind, payload, prevHash }) )` in exactly that key order. `prevHash` of the first receipt is 64 zeros. That is the whole spec. Match it byte for byte in any language and you can verify a Deadlatch chain with nothing from us.

`verifyChain` walks the chain and reports the index and id of the first receipt that fails, and why.

Part of [Deadlatch](https://deadlatch.dev), enforce, prove, watch. MIT.
````

Write `receipt/.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main, master]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm install --no-audit --no-fund
      - run: npx allow-scripts # install scripts are off by default (.npmrc); run only allowlisted ones
      - run: npm run build
      - run: npm test
```

Copy the security workflow from Purse (identical content):

```bash
mkdir -p /c/Users/ARABA/Workspace/SaaS/receipt/.github/workflows
cp /c/Users/ARABA/Workspace/SaaS/purse/.github/workflows/security.yml /c/Users/ARABA/Workspace/SaaS/receipt/.github/workflows/security.yml
```

- [ ] **Step 8: Prove a clean install works with scripts off**

```bash
cd /c/Users/ARABA/Workspace/SaaS/receipt && rm -rf node_modules && npm ci && npx allow-scripts && npm run build && npm test
```

Expected: `npm ci` runs no dependency scripts; `allow-scripts` runs only `tsx>esbuild`; build and 17 tests green.

- [ ] **Step 9: Commit**

```bash
cd /c/Users/ARABA/Workspace/SaaS/receipt
git add src/store.ts src/chain.ts src/index.ts test/store.test.ts test/chain.test.ts README.md .github
git commit -q -m "feat: stores, makeReceipt, public index, README, CI

MemoryStore and JsonlStore (path optional). makeReceipt assigns id, ts,
prevHash, hash and appends. CI runs allow-scripts after install; the
security workflow (gitleaks + osv-scanner) matches the other packages.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Wire Purse to `@olurabian/receipt`

**Working directory:** `purse/`.

**Files:**
- Modify: `purse/src/types.ts` (import at top; replace the `AuditRecord` interface block), `purse/src/audit.ts` (full rewrite), `purse/src/policy.ts:70-74`, `purse/src/index.ts:5-16`, `purse/test/audit-explain.test.ts:19,20,24,27-31`, `purse/test/policy.test.ts:66`, `purse/test/broker.test.ts:58`, `purse/examples/x402/broker-host.ts:31`, `purse/examples/x402/broker-host-llm.ts:22`, `purse/package.json`, `purse/README.md`

**Interfaces:**
- Consumes: `@olurabian/receipt` root exports (Task 3), linked via `file:../receipt`.
- Produces: `DecisionPayload` (new type), `AuditRecord = Receipt<DecisionPayload>`, and unchanged signatures for `JsonlAuditStore`, `makeRecord(store, input)`, `verifyChain`, `AuditStore`, `VerifyResult`. `broker.ts` is untouched and must keep compiling.

- [ ] **Step 1: Add the dependency and bump the version**

```bash
cd /c/Users/ARABA/Workspace/SaaS/purse
node -e "const fs=require('fs');const p=JSON.parse(fs.readFileSync('package.json','utf8'));p.version='0.3.0';p.dependencies={'@olurabian/receipt':'file:../receipt'};p.description=p.description.replace('Zero dependencies.','Zero third-party dependencies.');fs.writeFileSync('package.json',JSON.stringify(p,null,2)+'\n');"
npm install --no-audit --no-fund
npx allow-scripts
ls -la node_modules/@olurabian/receipt/dist/index.js
```

Expected: `package.json` now has `"version": "0.3.0"` and `"dependencies": { "@olurabian/receipt": "file:../receipt" }`; `node_modules/@olurabian/receipt` is a symlink to `../receipt` and `dist/index.js` exists (built in Task 3).

- [ ] **Step 2: Make the tests fail by updating them to the envelope**

Edit `purse/test/audit-explain.test.ts`. Apply these exact replacements:

```bash
cd /c/Users/ARABA/Workspace/SaaS/purse
sed -i 's/store.all()\[0\]!.explain?.rule/store.all()[0]!.payload.explain?.rule/' test/audit-explain.test.ts
sed -i 's/store.all()\[1\]!.event/store.all()[1]!.payload.event/' test/audit-explain.test.ts
sed -i 's/tampered\[0\]!.explain!.rule/tampered[0]!.payload.explain!.rule/' test/audit-explain.test.ts
```

Then replace lines 27–31 of `test/audit-explain.test.ts`, which currently read:

```ts
// a v0.1-shaped record (no event/explain) still hashes stably
const legacy = { id: "a", ts: "2026-01-01T00:00:00.000Z", request: req, status: "allowed" as const, reason: "ok", policyVersion: "v1", prevHash: "0".repeat(64) };
const h1 = hashRecord(legacy);
const h2 = hashRecord({ ...legacy, event: undefined, explain: undefined });
check("undefined new fields do not change legacy hash", h1 === h2);
```

with:

```ts
// optional payload fields that were never set (no event/explain) do not change the hash
const minimal = { id: "a", ts: "2026-01-01T00:00:00.000Z", kind: "decision", payload: { request: req, status: "allowed" as const, reason: "ok", policyVersion: "v1" }, prevHash: "0".repeat(64) };
const h1 = hashRecord(minimal);
const h2 = hashRecord({ ...minimal, payload: { ...minimal.payload, event: undefined, explain: undefined } });
check("undefined optional fields do not change the hash", h1 === h2);
```

Edit the other three call sites:

```bash
cd /c/Users/ARABA/Workspace/SaaS/purse
sed -i 's/tampered\[0\]!.request.amount.amount = 999_999/tampered[0]!.payload.request.amount.amount = 999_999/' test/policy.test.ts
sed -i 's/b.audit()\[0\]!.explain?.rule/b.audit()[0]!.payload.explain?.rule/' test/broker.test.ts
sed -i 's/r.event === "executed"/r.payload.event === "executed"/' examples/x402/broker-host.ts examples/x402/broker-host-llm.ts
grep -n "payload" test/audit-explain.test.ts test/policy.test.ts test/broker.test.ts examples/x402/broker-host.ts examples/x402/broker-host-llm.ts
```

Expected: the grep shows 7 lines containing `payload` (4 in audit-explain, 1 in policy, 1 in broker, 1 in each example = 8 total lines; audit-explain contributes lines 19, 20, 24, and the new minimal block).

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /c/Users/ARABA/Workspace/SaaS/purse && npm test`
Expected: FAIL. `tsx test/policy.test.ts` throws a TypeScript/runtime error because `payload` does not exist on the current flat `AuditRecord` (the first failing file stops the `&&` chain).

- [ ] **Step 4: Rewrite `src/audit.ts` as the adapter**

Replace the entire contents of `purse/src/audit.ts` with:

```ts
// audit.ts
// Purse's audit log is a chain of Deadlatch receipts. The engine (hashing,
// chain verification, stores) lives in @olurabian/receipt. This module types
// it for payment decisions and keeps Purse's public names stable:
// JsonlAuditStore, makeRecord, verifyChain, hashRecord, GENESIS.

import { JsonlStore, makeReceipt } from "@olurabian/receipt";
import type { Receipt, Store } from "@olurabian/receipt";
import type { DecisionPayload } from "./types.js";

export { GENESIS, hashRecord, verifyChain } from "@olurabian/receipt";
export type { VerifyResult } from "@olurabian/receipt";

/** A store of decision receipts. */
export type AuditStore = Store<DecisionPayload>;

/** The caller-owned fields of a decision receipt. The engine assigns id, ts, prevHash, hash. */
export type RecordInput = DecisionPayload;

/**
 * Append-only JSONL store of decision receipts. Zero third-party dependencies.
 * Pass a path to persist; omit it for an in-memory store.
 */
export class JsonlAuditStore extends JsonlStore<DecisionPayload> implements AuditStore {}

/** Build, hash, and append a decision receipt (kind "decision"). Returns the finished record. */
export function makeRecord(store: AuditStore, input: RecordInput): Receipt<DecisionPayload> {
  return makeReceipt(store, { kind: "decision", payload: input });
}
```

- [ ] **Step 5: Retype `AuditRecord` in `src/types.ts`**

At the top of `purse/src/types.ts`, directly after the line `import type { Money } from "./money.js";`, add:

```ts
import type { Receipt } from "@olurabian/receipt";
```

Then replace this exact block (the current `AuditRecord` interface):

```ts
/** One immutable, hash-chained entry in the audit log. */
export interface AuditRecord {
  id: string;
  ts: string; // ISO-8601
  request: NormalizedRequest;
  status: DecisionStatus;
  reason: string;
  /** Short hash of the policy that produced this decision. */
  policyVersion: string;
  event?: AuditEvent;
  explain?: Explain;
  grantId?: string;
  receipt?: ScrubbedReceipt;
  /** Hash of the previous record (or 64 zeros for the first record). */
  prevHash: string;
  /** SHA-256 over this record's fields plus prevHash. */
  hash: string;
}
```

with:

```ts
/** The payload of a Purse decision receipt, the `payload` of an @olurabian/receipt envelope. */
export interface DecisionPayload {
  request: NormalizedRequest;
  status: DecisionStatus;
  reason: string;
  /** Short hash of the policy that produced this decision. */
  policyVersion: string;
  event?: AuditEvent;
  explain?: Explain;
  grantId?: string;
  receipt?: ScrubbedReceipt;
}

/**
 * One immutable, hash-chained entry in the audit log: a Deadlatch receipt of
 * kind "decision". The decision fields live under `payload`; `prevHash` and
 * `hash` are on the envelope.
 */
export type AuditRecord = Receipt<DecisionPayload>;
```

- [ ] **Step 6: Update the ledger read in `src/policy.ts`**

Replace this exact block in `purse/src/policy.ts` (currently lines 70–74):

```ts
    for (const r of this.store.all()) {
      if (r.status !== "allowed") continue;
      if (r.request.amount.currency !== currency) continue;
      if (new Date(r.ts).getTime() < sinceMs) continue;
      total += r.request.amount.amount;
    }
```

with:

```ts
    for (const r of this.store.all()) {
      const d = r.payload;
      if (d.status !== "allowed") continue;
      if (d.request.amount.currency !== currency) continue;
      if (new Date(r.ts).getTime() < sinceMs) continue;
      total += d.request.amount.amount;
    }
```

- [ ] **Step 7: Export the new names from `src/index.ts`**

Replace this exact block in `purse/src/index.ts` (currently lines 5–16):

```ts
export type {
  PolicyConfig,
  AuthorizeRequest,
  NormalizedRequest,
  Decision,
  DecisionStatus,
  AuditRecord,
} from "./types.js";

export { parseMoney, format, decimalsFor, type Money } from "./money.js";

export { verifyChain, JsonlAuditStore, type AuditStore, type VerifyResult } from "./audit.js";
```

with:

```ts
export type {
  PolicyConfig,
  AuthorizeRequest,
  NormalizedRequest,
  Decision,
  DecisionStatus,
  AuditRecord,
  DecisionPayload,
} from "./types.js";

export { parseMoney, format, decimalsFor, type Money } from "./money.js";

export { verifyChain, hashRecord, GENESIS, JsonlAuditStore, makeRecord, type AuditStore, type VerifyResult } from "./audit.js";
export type { Receipt } from "@olurabian/receipt";
```

- [ ] **Step 8: Build and run the full suite**

Run: `cd /c/Users/ARABA/Workspace/SaaS/purse && npm run build && npm test`
Expected: `tsc` exits 0 with **no edits to `src/broker.ts`** (its `makeRecord` calls and `AuditStore` import are unchanged). All 12 test files print `N passed, 0 failed`. In particular `policy.test.ts` prints `ok   tampered chain is detected` and `audit-explain.test.ts` prints `ok   undefined optional fields do not change the hash`.

- [ ] **Step 9: Update the README wording**

```bash
cd /c/Users/ARABA/Workspace/SaaS/purse
sed -i 's|dependencies-zero-37D07E?style=for-the-badge" alt="zero dependencies"|third--party%20deps-zero-37D07E?style=for-the-badge" alt="zero third-party dependencies"|' README.md
sed -i 's/three lines of code, zero dependencies\./three lines of code, zero third-party dependencies (the only dependency is @olurabian\/receipt, the shared chain engine)./' README.md
grep -n "third-party" README.md
```

Expected: two matching lines (the badge and the intro sentence).

- [ ] **Step 10: Commit**

```bash
cd /c/Users/ARABA/Workspace/SaaS/purse
git add package.json package-lock.json src/types.ts src/audit.ts src/policy.ts src/index.ts test/audit-explain.test.ts test/policy.test.ts test/broker.test.ts examples/x402/broker-host.ts examples/x402/broker-host-llm.ts README.md
git commit -q -m "feat!: audit log is now a chain of @olurabian/receipt envelopes

AuditRecord becomes Receipt<DecisionPayload> (kind \"decision\"); the
decision fields live under payload. audit.ts is a thin adapter that keeps
JsonlAuditStore, makeRecord, verifyChain stable. broker.ts unchanged.
Bumps to 0.3.0 (breaking pre-1.0). Dependency is a local file link until
the receipt package is published.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: Wire blackbox to `@olurabian/receipt` and add allow-scripts

**Working directory:** `blackbox/`.

**Files:**
- Modify: `blackbox/src/types.ts`, `blackbox/src/hash.ts`, `blackbox/src/store.ts`, `blackbox/src/recorder.ts` (all full rewrites), `blackbox/test/hash.test.ts` (full rewrite), `blackbox/test/store.test.ts:12-14`, `blackbox/test/recorder.test.ts:32,33,42,43`, `blackbox/test/verify.test.ts:25,27,28`, `blackbox/examples/demo.ts:20,26`, `blackbox/README.md:47,58`, `blackbox/package.json`, `blackbox/.github/workflows/ci.yml`
- Create: `blackbox/.npmrc`

**Interfaces:**
- Consumes: `@olurabian/receipt` root exports via `file:../receipt`.
- Produces: `ActionPayload`, `ActionRecord = Receipt<ActionPayload>`, unchanged names `createRecorder`, `MemoryStore`, `JsonlStore(path)`, `GENESIS`, `hashRecord`, `verifyChain`, `Query`, `RecordInput`, `Store`, `VerifyResult`. `deadlatch-otel` (Task 6) relies on `record()` returning an object with `payload.action`, `payload.outcome`, and top-level `hash`.

- [ ] **Step 1: Dependency, version, and supply-chain gate**

```bash
cd /c/Users/ARABA/Workspace/SaaS/blackbox
node -e "const fs=require('fs');const p=JSON.parse(fs.readFileSync('package.json','utf8'));p.version='0.2.0';p.dependencies={'@olurabian/receipt':'file:../receipt'};p.devDependencies['@lavamoat/allow-scripts']='^5.1.0';p.description=p.description.replace('Zero dependencies.','Zero third-party dependencies.');fs.writeFileSync('package.json',JSON.stringify(p,null,2)+'\n');"
cp /c/Users/ARABA/Workspace/SaaS/purse/.npmrc .npmrc
npm install --no-audit --no-fund
npx allow-scripts auto
sed -i 's/\("tsx>esbuild#[^"]*": \)false/\1true/' package.json
npx allow-scripts
```

Expected: `.npmrc` present with `ignore-scripts=true`; `package.json` has `version 0.2.0`, the receipt dependency, and `lavamoat.allowScripts` with `tsx>esbuild#…: true`; `node_modules/@olurabian/receipt/dist/index.js` exists.

- [ ] **Step 2: Update the tests to the envelope (they will fail first)**

Replace the entire contents of `blackbox/test/hash.test.ts` with:

```ts
import { GENESIS, hashRecord } from "../src/hash";

let passed = 0, failed = 0;
function check(name: string, cond: boolean) {
  if (cond) { passed++; console.log(`  ok   ${name}`); }
  else { failed++; console.error(`  FAIL ${name}`); }
}

const base = {
  id: "id-1", ts: "2026-07-28T00:00:00.000Z", kind: "action",
  payload: { action: "charge-card", outcome: "ok" as const },
  prevHash: GENESIS,
};

check("GENESIS is 64 zeros", GENESIS === "0".repeat(64));
check("hash is 64 hex chars", /^[0-9a-f]{64}$/.test(hashRecord(base)));
check("hash is deterministic", hashRecord(base) === hashRecord(base));
check("changing action changes hash", hashRecord(base) !== hashRecord({ ...base, payload: { ...base.payload, action: "refund" } }));
check("changing prevHash changes hash", hashRecord(base) !== hashRecord({ ...base, prevHash: "1".repeat(64) }));
check("changing cost changes hash", hashRecord(base) !== hashRecord({ ...base, payload: { ...base.payload, cost: 5 } }));

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
```

In `blackbox/test/store.test.ts`, replace the `rec` helper (lines 12–14):

```ts
const rec = (id: string, prevHash: string): ActionRecord => ({
  id, ts: "2026-07-28T00:00:00.000Z", action: "a", outcome: "ok", prevHash, hash: "h" + id,
});
```

with:

```ts
const rec = (id: string, prevHash: string): ActionRecord => ({
  id, ts: "2026-07-28T00:00:00.000Z", kind: "action", payload: { action: "a", outcome: "ok" }, prevHash, hash: "h" + id,
});
```

Apply the single-line edits:

```bash
cd /c/Users/ARABA/Workspace/SaaS/blackbox
sed -i 's/recW.all()\[0\]!.outcome/recW.all()[0]!.payload.outcome/; s/recW.all()\[0\]!.latencyMs/recW.all()[0]!.payload.latencyMs/' test/recorder.test.ts
sed -i 's/recE.all()\[0\]!.outcome/recE.all()[0]!.payload.outcome/; s/recE.all()\[0\]!.error/recE.all()[0]!.payload.error/' test/recorder.test.ts
sed -i 's/recs\[1\]!.cost = 999/recs[1]!.payload.cost = 999/; s/recs\[1\]!.cost = 3/recs[1]!.payload.cost = 3/' test/verify.test.ts
sed -i 's/check("edited field reports the record id", rec.verify().brokenAt === "id-2")/check("edited field reports the index and id", rec.verify().brokenAt === 1 \&\& rec.verify().id === "id-2")/' test/verify.test.ts
grep -n "payload\|brokenAt === 1" test/recorder.test.ts test/verify.test.ts test/store.test.ts
```

Expected: grep shows `payload` on recorder lines 32, 33, 42, 43, verify lines 25 and 28, store line 13, and the new `brokenAt === 1` check on verify line 27.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /c/Users/ARABA/Workspace/SaaS/blackbox && npm test`
Expected: FAIL. `hash.test.ts` errors because the current `hashRecord` expects the flat `ActionRecord` shape (`action` missing on the envelope object).

- [ ] **Step 4: Rewrite the four source files**

Replace `blackbox/src/types.ts` with:

```ts
import type { Receipt, Store as ReceiptStore, VerifyResult as ReceiptVerifyResult } from "@olurabian/receipt";

// The unit of spend/outcome for a single agent action.
export type Outcome = "ok" | "error" | "blocked";

/** The payload of a blackbox action receipt, the `payload` of an @olurabian/receipt envelope. */
export interface ActionPayload {
  action: string;
  input?: unknown;
  outcome: Outcome;
  error?: string;
  latencyMs?: number;
  cost?: number;
  meta?: Record<string, unknown>;
}

/**
 * A committed record: a Deadlatch receipt of kind "action". The action fields
 * live under `payload`; `prevHash` and `hash` are on the envelope and together
 * form a tamper-evident chain.
 */
export type ActionRecord = Receipt<ActionPayload>;

// The caller-owned fields for record(). The recorder assigns id/ts/prevHash/hash.
export type RecordInput = ActionPayload;

// A pluggable append-only store.
export type Store = ReceiptStore<ActionPayload>;

export type VerifyResult = ReceiptVerifyResult;

export interface Query {
  action?: string;
  outcome?: Outcome;
}
```

Replace `blackbox/src/hash.ts` with:

```ts
// The chain engine lives in @olurabian/receipt. Re-exported here so existing
// imports (and the interactive demo's reading of this file) keep working.
export { GENESIS, canonicalize, hashRecord, verifyChain } from "@olurabian/receipt";
```

Replace `blackbox/src/store.ts` with:

```ts
import { MemoryStore as BaseMemoryStore, JsonlStore as BaseJsonlStore } from "@olurabian/receipt";
import type { ActionPayload } from "./types.js";

// In-memory append-only store. lastHash() returns the tip of the chain.
export class MemoryStore extends BaseMemoryStore<ActionPayload> {}

// Persists to an append-only JSONL file, one record per line. Reloads any
// existing file on construction so the chain survives process restarts.
export class JsonlStore extends BaseJsonlStore<ActionPayload> {
  constructor(path: string) {
    super(path);
  }
}
```

Replace `blackbox/src/recorder.ts` with:

```ts
import { makeReceipt, verifyChain } from "@olurabian/receipt";
import type { ActionRecord, RecordInput, Store, Query, VerifyResult } from "./types.js";

export interface RecorderOptions {
  store: Store;
  now?: () => string;   // injectable clock (tests inject a fixed value)
  newId?: () => string; // injectable id (tests inject a fixed sequence)
}

export interface Recorder {
  record(entry: RecordInput): ActionRecord;
  wrap<T>(action: string, input: unknown, fn: () => T | Promise<T>): Promise<T>;
  query(q: Query): ActionRecord[];
  all(): ActionRecord[];
  verify(): VerifyResult;
}

export function createRecorder(opts: RecorderOptions): Recorder {
  const { store, now, newId } = opts;

  function record(entry: RecordInput): ActionRecord {
    return makeReceipt(store, { kind: "action", payload: entry }, { now, newId });
  }

  async function wrap<T>(action: string, input: unknown, fn: () => T | Promise<T>): Promise<T> {
    const start = Date.now();
    try {
      const result = await fn();
      record({ action, input, outcome: "ok", latencyMs: Date.now() - start });
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      record({ action, input, outcome: "error", error: message, latencyMs: Date.now() - start });
      throw err;
    }
  }

  function query(q: Query): ActionRecord[] {
    return store.all().filter((r) =>
      (q.action === undefined || r.payload.action === q.action) &&
      (q.outcome === undefined || r.payload.outcome === q.outcome)
    );
  }

  function all(): ActionRecord[] {
    return store.all();
  }

  function verify(): VerifyResult {
    return verifyChain(store.all());
  }

  return { record, wrap, query, all, verify };
}
```

`blackbox/src/index.ts` needs no change (it re-exports from `./hash.js`, `./store.js`, `./recorder.js`, `./types.js`, all of which still export the same names; `ActionPayload` is additionally exported by adding it in the next step).

Add `ActionPayload` to the type export line in `blackbox/src/index.ts`:

```bash
cd /c/Users/ARABA/Workspace/SaaS/blackbox
sed -i 's/export type { ActionRecord, RecordInput, Outcome, Store, VerifyResult, Query } from ".\/types.js";/export type { ActionRecord, ActionPayload, RecordInput, Outcome, Store, VerifyResult, Query } from ".\/types.js";/' src/index.ts
grep -n "ActionPayload" src/index.ts
```

Expected: one line.

- [ ] **Step 5: Build and run the suite**

Run: `cd /c/Users/ARABA/Workspace/SaaS/blackbox && npm run build && npm test`
Expected: build exits 0; all four test files print `N passed, 0 failed`, including `ok   edited field reports the index and id` and `ok   reordering records breaks the chain`.

- [ ] **Step 6: Update the demo and README to the envelope**

```bash
cd /c/Users/ARABA/Workspace/SaaS/blackbox
sed -i 's/console.log(`  ${r.action}  ${r.outcome}${r.error ? " (" + r.error + ")" : ""}  ${r.latencyMs}ms`);/console.log(`  ${r.payload.action}  ${r.payload.outcome}${r.payload.error ? " (" + r.payload.error + ")" : ""}  ${r.payload.latencyMs}ms`);/' examples/demo.ts
sed -i 's/rec.all()\[0\]!.action = "refund-card";/rec.all()[0]!.payload.action = "refund-card";/' examples/demo.ts
sed -i "s/rec.verify();   \/\/ { ok: true }  or  { ok: false, brokenAt, reason }/rec.verify();   \/\/ { ok: true }  or  { ok: false, brokenAt, id, reason }/" README.md
sed -i "s/verify() after editing a record: { ok: false, brokenAt: 'id-1', reason: 'record hash does not match its contents' }/verify() after editing a record: { ok: false, brokenAt: 0, id: 'id-1', reason: 'hash mismatch (a record was altered)' }/" README.md
npm run demo
```

Expected: the demo prints two recorded actions from `payload`, `verify() on the untouched log: { ok: true }`, then `{ ok: false, brokenAt: 0, id: '…', reason: 'hash mismatch (a record was altered)' }`.

Then append this section to `blackbox/README.md` immediately after the "## Tamper detection" section's last paragraph (the line beginning `Two ways to see it.`):

```markdown

## The receipt

Every record is a [Deadlatch receipt](https://github.com/ArabianAnalyst/receipt), `{ id, ts, kind: "action", payload, prevHash, hash }`. The action fields (`action`, `outcome`, `latencyMs`, `cost`, `error`, `meta`) live under `payload`. `hash` is SHA-256 over `JSON.stringify({ id, ts, kind, payload, prevHash })`, so anyone can verify a blackbox log with `npm i @olurabian/receipt` and nothing from you.
```

- [ ] **Step 7: CI runs allow-scripts**

Replace this exact block in `blackbox/.github/workflows/ci.yml`:

```yaml
      - run: npm install --no-audit --no-fund
      - run: npm run build
      - run: npm test
```

with:

```yaml
      - run: npm install --no-audit --no-fund
      - run: npx allow-scripts # install scripts are off by default (.npmrc); run only allowlisted ones
      - run: npm run build
      - run: npm test
```

- [ ] **Step 8: Prove a clean install with scripts off, then commit**

```bash
cd /c/Users/ARABA/Workspace/SaaS/blackbox && rm -rf node_modules && npm ci && npx allow-scripts && npm run build && npm test
git add package.json package-lock.json .npmrc src test examples/demo.ts README.md .github/workflows/ci.yml
git commit -q -m "feat!: records are @olurabian/receipt envelopes; gate install scripts

ActionRecord becomes Receipt<ActionPayload> (kind \"action\"); action
fields live under payload. hash/store/recorder are thin adapters over the
shared engine; public names unchanged. verify() now reports brokenAt as an
index plus the record id. LavaMoat allow-scripts gates dependency install
scripts. Bumps to 0.2.0 (breaking pre-1.0).

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

Expected: `npm ci` runs no dependency scripts; all tests green; commit succeeds (the global gitleaks pre-commit hook prints `no leaks found`).

---

### Task 6: Adapt Tripwire and deadlatch-otel, roll allow-scripts to both

**Working directory:** `tripwire/`, then `deadlatch-otel/`.

**Files:**
- Modify: `tripwire/src/capture.ts:42-47`, `tripwire/package.json`, `tripwire/.github/workflows/ci.yml`, `deadlatch-otel/src/blackbox.ts:20-29`, `deadlatch-otel/package.json`, `deadlatch-otel/.github/workflows/ci.yml`, `deadlatch-otel/test/instrument.test.ts` (append one test)
- Create: `tripwire/test/from-blackbox.test.ts`, `tripwire/.npmrc`, `deadlatch-otel/.npmrc`

**Interfaces:**
- Consumes: the envelope shape from Task 5 (`{ payload: { action, outcome, … }, hash }`). Neither package imports `@olurabian/receipt` or blackbox at runtime; both stay structural.
- Produces: `fromBlackbox(records: ReadonlyArray<ActionRecord | { payload: ActionRecord }>): Trace` in tripwire; `instrumentRecorder` in deadlatch-otel reads `payload.action`/`payload.outcome` when present.

- [ ] **Step 1: Tripwire, write the failing test**

Write `tripwire/test/from-blackbox.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { fromBlackbox } from "../src/capture.ts";

test("fromBlackbox unwraps receipt envelopes and still accepts bare records", () => {
  const trace = fromBlackbox([
    { payload: { action: "charge", outcome: "ok" } },
    { action: "email", outcome: "error", error: "x" },
  ]);
  assert.equal(trace.records.length, 2);
  assert.equal(trace.records[0]?.action, "charge");
  assert.equal(trace.records[1]?.outcome, "error");
  assert.equal(trace.count({ outcome: "ok" }), 1);
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /c/Users/ARABA/Workspace/SaaS/tripwire && npx tsx --test test/from-blackbox.test.ts`
Expected: FAIL, a type error on the `{ payload: … }` element (not assignable to `ActionRecord`) or `trace.records[0].action` being `undefined`.

- [ ] **Step 3: Implement the adapter**

Replace this exact block in `tripwire/src/capture.ts` (currently lines 42–47):

```ts
// blackbox records already match ActionRecord shape; this is an explicit adapter
// so callers using blackbox can feed its record array straight into the checker.
export function fromBlackbox(records: ActionRecord[]): Trace {
  return new Trace(records);
}
```

with:

```ts
/** A blackbox record: a receipt envelope whose payload is the action record. */
export interface BlackboxReceiptLike {
  payload: ActionRecord;
}

// blackbox records are @olurabian/receipt envelopes whose payload matches
// ActionRecord. This adapter unwraps them (and still accepts bare records) so
// a blackbox log can be fed straight into the checker.
export function fromBlackbox(records: ReadonlyArray<ActionRecord | BlackboxReceiptLike>): Trace {
  return new Trace(records.map((r) => ("payload" in r ? r.payload : r)));
}
```

- [ ] **Step 4: Tripwire tests, version, supply-chain gate**

```bash
cd /c/Users/ARABA/Workspace/SaaS/tripwire
node -e "const fs=require('fs');const p=JSON.parse(fs.readFileSync('package.json','utf8'));p.version='0.1.1';p.devDependencies['@lavamoat/allow-scripts']='^5.1.0';fs.writeFileSync('package.json',JSON.stringify(p,null,2)+'\n');"
cp /c/Users/ARABA/Workspace/SaaS/purse/.npmrc .npmrc
npm install --no-audit --no-fund
npx allow-scripts auto
sed -i 's/\("tsx>esbuild#[^"]*": \)false/\1true/' package.json
npx allow-scripts
sed -i 's/      - run: npm install --no-audit --no-fund/      - run: npm install --no-audit --no-fund\n      - run: npx allow-scripts # install scripts are off by default (.npmrc); run only allowlisted ones/' .github/workflows/ci.yml
npm run build && npm test
```

Expected: the full tripwire suite passes including the new test; `ci.yml` has the `allow-scripts` step after install.

- [ ] **Step 5: Commit tripwire**

```bash
cd /c/Users/ARABA/Workspace/SaaS/tripwire
git add package.json package-lock.json .npmrc src/capture.ts test/from-blackbox.test.ts .github/workflows/ci.yml
git commit -q -m "feat: fromBlackbox accepts receipt envelopes; gate install scripts

blackbox 0.2 records are @olurabian/receipt envelopes with the action
under payload. The adapter unwraps them and still accepts bare records.
LavaMoat allow-scripts added. 0.1.1.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

- [ ] **Step 6: deadlatch-otel, write the failing test**

Append to `deadlatch-otel/test/instrument.test.ts` (after the existing blackbox test, before the tripwire test):

```ts
test("blackbox: a receipt envelope (blackbox >= 0.2) is read from payload", () => {
  exporter.reset();
  const recorder = instrumentRecorder({
    record: (e) => ({ id: "id-1", ts: "2026-09-04T00:00:00.000Z", kind: "action", payload: e as object, prevHash: "0".repeat(64), hash: "abc123" }),
    verify: () => ({ ok: true }),
  });
  recorder.record({ action: "pay", outcome: "error", error: "declined" });
  const rec = exporter.getFinishedSpans().find((s) => s.name === "deadlatch.prove");
  assert.ok(rec, "record span emitted");
  assert.equal(rec!.attributes["blackbox.action"], "pay");
  assert.equal(rec!.attributes["blackbox.outcome"], "error");
  assert.equal(rec!.attributes["blackbox.hash"], "abc123");
  assert.equal(rec!.status.code, 2); // ERROR, from payload.outcome
});
```

- [ ] **Step 7: Run it to verify it fails**

Run: `cd /c/Users/ARABA/Workspace/SaaS/deadlatch-otel && npm test`
Expected: FAIL, `blackbox.action` attribute is `undefined` (the instrumentation reads the flat shape only).

- [ ] **Step 8: Read both shapes**

Replace this exact block in `deadlatch-otel/src/blackbox.ts` (currently lines 20–29):

```ts
      const rec = origRecord(entry) as Record<string, unknown>;
      span.setAttribute("deadlatch.leg", "prove");
      span.setAttribute("deadlatch.package", "blackbox");
      if (rec?.action != null) span.setAttribute("blackbox.action", String(rec.action));
      if (rec?.outcome != null) span.setAttribute("blackbox.outcome", String(rec.outcome));
      if (rec?.seq != null) span.setAttribute("blackbox.seq", Number(rec.seq));
      if (rec?.hash != null) span.setAttribute("blackbox.hash", String(rec.hash));
      if (rec?.outcome === "error") {
        span.setStatus({ code: SpanStatusCode.ERROR, message: String(rec.error ?? "error") });
      }
```

with:

```ts
      const rec = origRecord(entry) as Record<string, unknown>;
      // blackbox >= 0.2 returns a receipt envelope with the action fields under
      // payload; older versions return them flat. Read whichever is present.
      const p = (rec?.payload ?? rec) as Record<string, unknown>;
      span.setAttribute("deadlatch.leg", "prove");
      span.setAttribute("deadlatch.package", "blackbox");
      if (p?.action != null) span.setAttribute("blackbox.action", String(p.action));
      if (p?.outcome != null) span.setAttribute("blackbox.outcome", String(p.outcome));
      if (rec?.seq != null) span.setAttribute("blackbox.seq", Number(rec.seq));
      if (rec?.hash != null) span.setAttribute("blackbox.hash", String(rec.hash));
      if (p?.outcome === "error") {
        span.setStatus({ code: SpanStatusCode.ERROR, message: String(p.error ?? "error") });
      }
```

- [ ] **Step 9: deadlatch-otel version, supply-chain gate, run**

```bash
cd /c/Users/ARABA/Workspace/SaaS/deadlatch-otel
node -e "const fs=require('fs');const p=JSON.parse(fs.readFileSync('package.json','utf8'));p.version='0.1.1';p.devDependencies['@lavamoat/allow-scripts']='^5.1.0';fs.writeFileSync('package.json',JSON.stringify(p,null,2)+'\n');"
cp /c/Users/ARABA/Workspace/SaaS/purse/.npmrc .npmrc
npm install --no-audit --no-fund
npx allow-scripts auto
sed -i 's/\("[^"]*esbuild#[^"]*": \)false/\1true/' package.json
npx allow-scripts
sed -i 's/      - run: npm install --no-audit --no-fund/      - run: npm install --no-audit --no-fund\n      - run: npx allow-scripts # install scripts are off by default (.npmrc); run only allowlisted ones/' .github/workflows/ci.yml
npm run build && npm test
```

Expected: `allow-scripts auto` lists `tsx>esbuild#…` (and nothing from `@opentelemetry/*`, which have no install scripts); after the sed only esbuild is `true`; the suite passes including both blackbox tests (flat and envelope).

- [ ] **Step 10: Commit deadlatch-otel**

```bash
cd /c/Users/ARABA/Workspace/SaaS/deadlatch-otel
git add package.json package-lock.json .npmrc src/blackbox.ts test/instrument.test.ts .github/workflows/ci.yml
git commit -q -m "feat: instrument blackbox receipt envelopes; gate install scripts

Reads action/outcome from payload when present (blackbox >= 0.2) and
falls back to the flat shape. LavaMoat allow-scripts added. 0.1.1.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Regenerate the integration handover as receipt spec v1

**Working directory:** `purse/`.

**Files:**
- Create: `purse/scripts/sample-receipts.mjs`, `purse/docs/integration/samples/purse-sample-receipts.json`
- Modify: `purse/docs/integration/receipt-handover.md` (full rewrite), `purse/package.json` (add the `samples` script)

**Interfaces:**
- Consumes: the built `purse/dist` from Task 4 (`Purse`, `verifyChain`).
- Produces: a committed, reproducible sample file and a handover doc that describes the envelope. The integrator builds against these.

- [ ] **Step 1: Add the generator**

Write `purse/scripts/sample-receipts.mjs`:

```js
// Generates docs/integration/samples/purse-sample-receipts.json by running the
// real Purse policy engine. Run:  npm run samples   (after npm run build)
import { pathToFileURL } from "node:url";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

const here = dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const mod = await import(pathToFileURL(resolve(here, "../dist/index.js")).href);
const { Purse, verifyChain } = mod;

const purse = new Purse({
  currency: "USD",
  maxPerAction: "$100.00",
  maxPerDay: "$500.00",
  allow: ["api.stripe.com", "*.aws.amazon.com", "acme-supplies.example"],
  deny: ["*.unknown-vendor.example"],
  requireApprovalOver: "$50.00",
});

purse.authorize({ amount: "$12.00",  payee: "api.stripe.com",                 intent: "top up API credits", agentId: "agent-7" }); // allowed
purse.authorize({ amount: "$4.20",   payee: "s3.aws.amazon.com",              intent: "object storage",     agentId: "agent-7" }); // allowed
purse.authorize({ amount: "$80.00",  payee: "acme-supplies.example",          intent: "reorder toner",      agentId: "agent-7" }); // needs_approval
purse.authorize({ amount: "$9.99",   payee: "sketchy.unknown-vendor.example", intent: "unknown",            agentId: "agent-7" }); // denied (deny-list)
purse.authorize({ amount: "$250.00", payee: "api.stripe.com",                 intent: "large charge",       agentId: "agent-7" }); // denied (per-action cap)

const records = purse.audit();
const verdict = verifyChain(records);
if (!verdict.ok) throw new Error("generated chain does not verify: " + JSON.stringify(verdict));

const out = resolve(here, "../docs/integration/samples/purse-sample-receipts.json");
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(records, null, 2) + "\n");
console.log(`wrote ${records.length} receipts (${records.map((r) => r.payload.status).join(", ")}), verify: ${JSON.stringify(verdict)}`);
```

Add the script to `package.json`:

```bash
cd /c/Users/ARABA/Workspace/SaaS/purse
node -e "const fs=require('fs');const p=JSON.parse(fs.readFileSync('package.json','utf8'));p.scripts.samples='node scripts/sample-receipts.mjs';fs.writeFileSync('package.json',JSON.stringify(p,null,2)+'\n');"
npm run build && npm run samples
node -e "const r=require('./docs/integration/samples/purse-sample-receipts.json');console.log(r.length, r[0].kind, Object.keys(r[0]).join(','), Object.keys(r[0].payload).join(','))"
```

Expected: `wrote 5 receipts (allowed, allowed, needs_approval, denied, denied), verify: {"ok":true}`; the check prints `5 decision id,ts,kind,payload,prevHash,hash request,status,reason,policyVersion,event,explain`.

- [ ] **Step 2: Rewrite the handover doc for spec v1**

Replace the entire contents of `purse/docs/integration/receipt-handover.md` with:

````markdown
# Purse to an external hub, receipt handover (spec v1)

The integration in one line. **Purse produces a hash-chained receipt for every decision. The hub takes it as-is, verifies it independently, and binds it into the wider trail.** Purse's receipt is the source of truth. The hub is the witness and aggregator above it, not the root of trust.

A receipt verifies on its own, with nothing from Purse and nothing from the hub. That property is the whole point, so keep it.

Ships with `samples/purse-sample-receipts.json`, five real receipts from a live Purse run (2 allowed, 1 needs_approval, 2 denied), regenerated with `npm run samples`. The chain verifies, and editing any field breaks it.

> **What changed from the previous draft.** Purse now emits the shared Deadlatch receipt envelope from [`@olurabian/receipt`](https://github.com/ArabianAnalyst/receipt). The decision fields moved under `payload`, and the hash covers the envelope. Build against this shape; the earlier flat shape is retired.

---

## The receipt

Every `authorize()` call writes one immutable receipt. Shape:

```jsonc
{
  "id": "190f084b-…",                 // uuid, unique per decision
  "ts": "2026-09-04T11:31:36.514Z",   // ISO-8601
  "kind": "decision",                 // Purse receipts are always "decision"
  "payload": {
    "request": {
      "amount": { "amount": 8000, "currency": "USD" },  // integer MINOR units: 8000 = $80.00
      "payee": "acme-supplies.example",
      "intent": "reorder toner",      // optional
      "category": "…",                // optional
      "agentId": "agent-7"            // optional
    },
    "status": "needs_approval",       // "allowed" | "denied" | "needs_approval"
    "reason": "needs approval: 80.00 USD is above the auto-approve threshold of 50.00 USD",
    "policyVersion": "4c94d6cb4f21",  // 12-char sha256 prefix of the policy that decided
    "event": "decision",              // "decision" | "grant_minted" | "executed" | "execution_failed" | "grant_expired"
    "explain": { "rule": "require-approval", "policyVersion": "4c94d6cb4f21", "evaluated": { … } },
    "grantId": "…",                   // present once a grant is minted
    "receipt": { "ok": true, "ref": "…", "paidAmount": { … } }  // present after settlement; scrubbed
  },
  "prevHash": "1f2fb9…",              // hash of the previous receipt, or 64 zeros for the first
  "hash": "2ed45a…"                   // sha256 over the envelope, see below
}
```

Two notes that bite if missed:

- **Amounts are integer minor units plus a currency code.** `{ "amount": 8000, "currency": "USD" }` is $80.00. Use the currency's minor-unit exponent, do not divide by 100 blindly.
- **Undefined fields are omitted.** Optional payload fields only appear when set. The hash is computed over what is present.

---

## Verifying a receipt (independently)

The `hash` is SHA-256 over the envelope's fields in **this exact order**, with `hash` itself excluded:

```js
sha256(JSON.stringify({ id, ts, kind, payload, prevHash }))
```

`payload` is serialized exactly as the producer wrote it (the parsed object's key order). The chain: `prevHash` of the first receipt is 64 zeros. Each subsequent `prevHash` equals the previous receipt's `hash`. Alter a field and that receipt's `hash` no longer matches. Insert, drop, or reorder a receipt and the `prevHash` linkage breaks.

**You do not need to reimplement this.** The verifier is a zero-dependency package:

```js
import { verifyChain } from "@olurabian/receipt"; // npm i @olurabian/receipt

const records = JSON.parse(fs.readFileSync("purse-sample-receipts.json", "utf8"));
verifyChain(records);
// { ok: true }
// on tamper: { ok: false, brokenAt: 0, id: "190f084b-…", reason: "hash mismatch (a record was altered)" }
```

`@olurabian/purse` re-exports the same `verifyChain`. If the hub prefers no dependency, reimplement the two checks above in any language; the only thing that must match byte for byte is the `JSON.stringify` key order.

---

## Division of labour

- **Purse (enforcer)** decides and writes the receipt. The receipt is verifiable on its own.
- **The hub** ingests the receipt, verifies it independently, and anchors its `hash` into the wider KMS-signed trail so a set of receipts across tools becomes one cross-system record.
- The hub does **not** re-mint or replace the receipt. The enforcer that made the decision owns the proof.

The trail should verify even if the hub is offline. The hub is the outside witness that makes a receipt evidence rather than one tool's word, it is not the thing you have to trust to believe the record.

---

## Two decisions to close

1. **Signing.** Receipts are hash-chained, which is tamper-evident. If we want per-receipt provenance on top, Purse adds an `ed25519` signature over `hash` and hands the hub the public key. Otherwise the hub's KMS signature provides provenance at the trail level. Proposed for v1: no per-receipt signing, KMS at the trail.
2. **Transport.** v1 simplest, Purse exports a JSON or JSONL bundle (exactly like the sample) and the hub ingests it. Or Purse POSTs each receipt to a hub endpoint as it is written. Agree the easy one first; the receipt shape is the same either way.

---

## Files

- `samples/purse-sample-receipts.json` — five real receipts, `verifyChain` returns `{ ok: true }`. Regenerate with `npm run samples`.
- The envelope, canonicalization, and verifier: `@olurabian/receipt`, `src/hash.ts` and `src/chain.ts`.
- Purse's decision payload type: `@olurabian/purse`, `src/types.ts` (`DecisionPayload`).
````

- [ ] **Step 3: Verify the committed samples with the public verifier, then commit**

```bash
cd /c/Users/ARABA/Workspace/SaaS/purse
node -e "import('@olurabian/receipt').then(({verifyChain})=>{const r=require('./docs/integration/samples/purse-sample-receipts.json');console.log(JSON.stringify(verifyChain(r)));r[0].payload.reason='edited';console.log(JSON.stringify(verifyChain(r)));})"
git add scripts/sample-receipts.mjs docs/integration/samples/purse-sample-receipts.json docs/integration/receipt-handover.md package.json
git commit -q -m "docs: integration handover regenerated for receipt spec v1

Envelope shape, canonicalization, and the verifyChain pointer at
@olurabian/receipt. Samples are generated by npm run samples from the
real policy engine and committed.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

Expected: the check prints `{"ok":true}` then `{"ok":false,"brokenAt":0,"id":"…","reason":"hash mismatch (a record was altered)"}`.

---

### Task 8: Final whole-change review gate

**Working directory:** all five repos.

**Files:** none modified. This task is the pre-release verification.

- [ ] **Step 1: Clean-install every repo with scripts off and run everything**

```bash
for r in receipt purse blackbox tripwire deadlatch-otel; do
  echo "=== $r ==="
  cd /c/Users/ARABA/Workspace/SaaS/$r && rm -rf node_modules && npm ci && npx allow-scripts && npm run build && npm test || { echo "FAILED: $r"; exit 1; }
done
echo ALL GREEN
```

Expected: `ALL GREEN`. (`npm ci` for purse and blackbox resolves the `file:../receipt` link from the lockfile.)

- [ ] **Step 2: Confirm no repo was pushed and no package was published**

```bash
for r in receipt purse blackbox tripwire deadlatch-otel; do cd /c/Users/ARABA/Workspace/SaaS/$r; echo "$r: $(git log --oneline origin/$(git branch --show-current)..HEAD 2>/dev/null | wc -l) unpushed commits"; done
npm view @olurabian/receipt version 2>&1 | head -1
```

Expected: purse, blackbox, tripwire, deadlatch-otel each report ≥ 1 unpushed commit; receipt reports an error (no `origin` yet) which is correct; `npm view` reports `404` / not found for `@olurabian/receipt`.

- [ ] **Step 3: Dispatch the final code review** (per superpowers:requesting-code-review) over the combined diffs of all five repos, with this plan's Global Constraints as the attention lens. Fix any Critical or Important findings before Task 9.

---

### Task 9: Release

**Working directory:** each repo in the order below. **This task pushes to GitHub and publishes to npm.** npm is authenticated as `olurabian`; gh as `ArabianAnalyst`. If `npm publish` asks for a one-time password, stop and hand that command to ARABA to run, then continue.

**Files:**
- Modify: `purse/package.json`, `purse/package-lock.json`, `blackbox/package.json`, `blackbox/package-lock.json`, `deadlatch-otel/package.json`, `deadlatch-otel/package-lock.json`

**Interfaces:**
- Produces: `@olurabian/receipt@0.1.0`, `@olurabian/purse@0.3.0`, `@olurabian/blackbox@0.2.0`, `@olurabian/tripwire@0.1.1`, `@olurabian/deadlatch-otel@0.1.1` on npm; all five repos pushed with green CI.

- [ ] **Step 1: Publish the receipt package first**

```bash
cd /c/Users/ARABA/Workspace/SaaS/receipt
gh repo create ArabianAnalyst/receipt --public --description "The Deadlatch receipt. Zero-dependency, hash-chained, independently verifiable record envelope." --source=. --remote=origin --push
npm publish --access public
npm view @olurabian/receipt version
```

Expected: the repo exists at github.com/ArabianAnalyst/receipt with `main` pushed; `npm view` prints `0.1.0`. Then check CI: `gh run list --repo ArabianAnalyst/receipt --limit 2` shows `CI` and `security` both `success`.

- [ ] **Step 2: Flip Purse and blackbox to the registry version, verify, commit, push, publish**

```bash
for r in purse blackbox; do
  cd /c/Users/ARABA/Workspace/SaaS/$r
  node -e "const fs=require('fs');const p=JSON.parse(fs.readFileSync('package.json','utf8'));p.dependencies['@olurabian/receipt']='^0.1.0';fs.writeFileSync('package.json',JSON.stringify(p,null,2)+'\n');"
  rm -rf node_modules && npm install --no-audit --no-fund && npx allow-scripts && npm run build && npm test || exit 1
  git add package.json package-lock.json
  git commit -q -m "chore: depend on @olurabian/receipt ^0.1.0 from the registry

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
  git push -q origin $(git branch --show-current)
  npm publish --access public
done
npm view @olurabian/purse version; npm view @olurabian/blackbox version
```

Expected: `0.3.0` and `0.2.0`. `node_modules/@olurabian/receipt` is now a real directory (not a symlink). CI green on both repos.

- [ ] **Step 3: Bump deadlatch-otel's dev deps to the new majors, push tripwire and deadlatch-otel, publish both**

```bash
cd /c/Users/ARABA/Workspace/SaaS/deadlatch-otel
node -e "const fs=require('fs');const p=JSON.parse(fs.readFileSync('package.json','utf8'));p.devDependencies['@olurabian/blackbox']='^0.2.0';p.devDependencies['@olurabian/purse']='^0.3.0';fs.writeFileSync('package.json',JSON.stringify(p,null,2)+'\n');"
rm -rf node_modules && npm install --no-audit --no-fund && npx allow-scripts && npm run build && npm test
git add package.json package-lock.json
git commit -q -m "chore: test against blackbox 0.2 and purse 0.3

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
git push -q origin main && npm publish --access public
cd /c/Users/ARABA/Workspace/SaaS/tripwire && git push -q origin master && npm publish --access public
npm view @olurabian/tripwire version; npm view @olurabian/deadlatch-otel version
```

Expected: `0.1.1` and `0.1.1`; CI green on both.

- [ ] **Step 4: Prove the published set works from a clean directory**

```bash
mkdir -p /tmp/receipt-smoke && cd /tmp/receipt-smoke && rm -rf * && npm init -y >/dev/null && npm i @olurabian/receipt @olurabian/purse @olurabian/blackbox --no-audit --no-fund --ignore-scripts
node --input-type=module -e "
import { Purse, verifyChain } from '@olurabian/purse';
import { createRecorder, MemoryStore } from '@olurabian/blackbox';
const p = new Purse({ maxPerAction: '\$5.00' });
p.authorize({ amount: '\$1.00', payee: 'x' });
const rec = createRecorder({ store: new MemoryStore() });
rec.record({ action: 'ping', outcome: 'ok' });
console.log('purse', p.audit()[0].kind, JSON.stringify(p.verify()));
console.log('blackbox', rec.all()[0].kind, JSON.stringify(rec.verify()));
console.log('shared verifier', JSON.stringify(verifyChain(rec.all())));
"
```

Expected:
```
purse decision {"ok":true}
blackbox action {"ok":true}
shared verifier {"ok":true}
```
That last line is the whole point of the change: one verifier, both products.

---

## Self-review

**Spec coverage.** Envelope, canonicalization, chain rules, VerifyResult (Task 2). API surface incl. stores and makeReceipt (Task 3). Purse consumer with names kept and `broker.ts` untouched (Task 4). blackbox consumer with names kept, `brokenAt` index + `id` (Task 5). Tripwire `fromBlackbox` and deadlatch-otel dual-shape (Task 6). Breaking-change handling via the regenerated integration handover (Task 7). Supply chain on every repo (Tasks 1, 5, 6; Purse already had it). Non-goals untouched. Versions per Global Constraints (Tasks 4, 5, 6, 9).

**Placeholder scan.** No TBD/TODO. Every code step has its code. The one intentionally conditional step is the npm OTP hand-off in Task 9, stated explicitly.

**Type consistency.** `VerifyResult.brokenAt: number` and `id?: string` are used identically in receipt tests, blackbox `verify.test.ts` (`brokenAt === 1 && id === "id-2"`), the blackbox README output line, and deadlatch-otel (`Number(res.brokenAt)`). `makeReceipt(store, { kind, payload }, { now, newId })` matches its use in Purse `makeRecord` and blackbox `record`. `JsonlStore<P>(path?)` matches `JsonlAuditStore` (path optional) and blackbox `JsonlStore(path)` (required, narrowed by the subclass). `fromBlackbox` accepts `{ payload: ActionRecord }` which is exactly what blackbox 0.2 `all()` returns.
