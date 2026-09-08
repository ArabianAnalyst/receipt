# Anchor subpath (receipt 0.3.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `@olurabian/receipt/anchor`, the zero-dependency module that submits a chain head to Rekor v2, verifies the returned proof, stores anchors, and lets anyone verify a chain against its anchors, plus the `receipt-verify` CLI.

**Architecture:** Small pure modules under `src/anchor/` (artifact, bytes, merkle, checkpoint, signer, body, verify, rekor, store) composed by `verifyAnchored` and `RekorV2`. Everything cryptographic is `node:crypto`. Tests run against a captured real Rekor v2 entry (fixture) and a `FakeLog` test helper that builds real RFC 6962 trees and signs real C2SP checkpoints with a test Ed25519 key, so every property can be exercised offline.

**Tech Stack:** TypeScript strict, ESM (NodeNext), `node:test` via `tsx`, `node:crypto`, global `fetch`, PGlite for the Postgres store tests. No runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-09-08-anchoring-witness-design.md` (this repository). Plan 1 of two. The witness process is Plan 2 in the purse repository and consumes the API this plan produces.

## Global Constraints

- Zero runtime dependencies. `package.json` has no `dependencies` key at the end of this plan.
- ESM, `"type": "module"`, Node `>=18`, TypeScript `strict` with `noUncheckedIndexedAccess`, `moduleResolution: NodeNext`. Every relative import specifier ends in `.js`.
- Tests are `test/*.test.ts` run by `tsx --test`; helpers live in `test/helpers/` and are not matched by the glob. The CLI test runs the built `dist/cli.js`, so `npm run build` precedes `npm test` (CI already does this).
- The package ships no log key and no witness key. A verifier handed an untrusted key gets `ok: false` with `reason: "untrusted log key"` or `"untrusted witness key"`, never a silent pass.
- `RekorV2.submit` verifies the reply with `verifyAnchorProof` before returning an `Anchor`; a reply that does not verify is an error.
- The anchored artifact is exactly `deadlatch-anchor-v1\n<stream>\n<seq>\n<head>\n` in UTF-8, `seq` decimal, `head` 64 lowercase hex.
- Only Ed25519 log keys are supported for checkpoints in this version; any other key type fails with `"checkpoint: only Ed25519 log keys are supported"`.
- README prose contains no colons and no em dashes outside code, inline code, tables, and URLs. No counterparty or partner names anywhere.
- Version becomes `0.3.0`. Nothing is published and nothing is pushed to `main` before the release task, which runs only after ARABA confirms. `main` is protected: push to a branch, wait for the `test` and `gitleaks (secrets)` checks, then fast-forward `main`.
- Commit trailer on every commit: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Fixtures under `test/fixtures/rekor-v2/` are public data only. Never commit a private key.

---

### Task 1: Types, bytes, artifact, Merkle, and the package wiring

**Files:**
- Create: `src/anchor/types.ts`, `src/anchor/bytes.ts`, `src/anchor/artifact.ts`, `src/anchor/merkle.ts`, `src/anchor/index.ts`
- Modify: `package.json` (version, exports, bin), `tsconfig.test.json` only if it does not already include `test/**`
- Test: `test/helpers/fixture.ts`, `test/anchor-artifact.test.ts`, `test/anchor-merkle.test.ts`

**Interfaces:**
- Produces: `Anchor`, `InclusionProof`, `LogKey`, `AnchorTrust`, `AnchorCheck`, `AnchoredVerifyResult`, `AnchorStore` (types); `toBase64(bytes): string`, `fromBase64(s): Uint8Array`, `bytesEqual(a, b): boolean`, `concat(...parts): Uint8Array`; `ARTIFACT_PREFIX`, `artifactOf(stream, seq, head): Uint8Array`, `digestOf(artifact): Uint8Array`; `leafHashOf(data): Uint8Array`, `nodeHashOf(left, right): Uint8Array`, `verifyInclusionPath(leafHash, index: bigint, size: bigint, path: Uint8Array[], root): boolean`, `verifyInclusion(leafHash, proof: InclusionProof): boolean`; test helper `fixtureEntry()`, `fixtureAnchor(): Anchor`, `fixtureTrust: AnchorTrust`.

- [ ] **Step 1: Types**

`src/anchor/types.ts`:

```ts
import type { VerifyResult } from "../types.js";

/** A Rekor v2 inclusion proof as returned, strings kept as strings. */
export interface InclusionProof {
  logIndex: string;
  treeSize: string;
  rootHash: string;      // base64
  hashes: string[];      // base64, leaf to root
  checkpoint: string;    // the C2SP signed note envelope
}

/** One anchoring event. Nothing in it is secret. */
export interface Anchor {
  v: 1;
  stream: string;
  /** 0-based position of the anchored receipt in the stream. Not the receipts table's seq column. */
  seq: number;
  /** That receipt's hash, 64 lowercase hex. */
  head: string;
  /** Witness clock, ISO-8601, informational. */
  at: string;
  witness: { alg: "ecdsa-p256"; publicKey: string };   // base64 SPKI DER
  /** base64 DER ECDSA signature over the artifact bytes. */
  signature: string;
  log: { url: string; keyId: string };                 // keyId base64, 32 bytes
  entry: { logIndex: string; canonicalizedBody: string };
  proof: InclusionProof;
}

export interface LogKey { origin: string; publicKey: string }   // publicKey base64 SPKI DER

export interface AnchorTrust {
  logKeys: ReadonlyArray<LogKey>;
  witnessKeys: ReadonlyArray<string>;                   // base64 SPKI DER
}

export interface AnchorCheck {
  seq: number;
  ok: boolean;
  reason?: string;
  logIndex: string;
  cosigned: string[];
}

export interface AnchoredVerifyResult {
  ok: boolean;
  coveredUpTo: number | null;
  anchors: AnchorCheck[];
  chain: VerifyResult;
}

/** Append-only by contract. Nothing in this package updates or deletes an anchor. */
export interface AnchorStore {
  append(a: Anchor): Promise<void>;
  list(stream: string, sinceSeq?: number): Promise<Anchor[]>;
  last(stream: string): Promise<Anchor | null>;
}
```

- [ ] **Step 2: Bytes and the artifact**

`src/anchor/bytes.ts`:

```ts
export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function fromBase64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

/** Constant-time equality for equal-length inputs; false on length mismatch. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
```

`src/anchor/artifact.ts`:

```ts
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
```

- [ ] **Step 3: Merkle**

`src/anchor/merkle.ts`:

```ts
import { createHash } from "node:crypto";
import { bytesEqual, fromBase64 } from "./bytes.js";
import type { InclusionProof } from "./types.js";

function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

/** RFC 6962 leaf hash, sha256(0x00 || data). */
export function leafHashOf(data: Uint8Array): Uint8Array {
  return sha256(new Uint8Array([0]), data);
}

/** RFC 6962 interior node, sha256(0x01 || left || right). */
export function nodeHashOf(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(new Uint8Array([1]), left, right);
}

/**
 * RFC 9162 section 2.1.3.2. True when the path from the leaf at `index` in a
 * tree of `size` leaves reaches `root`.
 */
export function verifyInclusionPath(
  leafHash: Uint8Array,
  index: bigint,
  size: bigint,
  path: ReadonlyArray<Uint8Array>,
  root: Uint8Array,
): boolean {
  if (index < 0n || size <= 0n || index >= size) return false;
  let fn = index;
  let sn = size - 1n;
  let r = leafHash;
  for (const p of path) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      r = nodeHashOf(p, r);
      if ((fn & 1n) === 0n) {
        while (fn !== 0n && (fn & 1n) === 0n) { fn >>= 1n; sn >>= 1n; }
      }
    } else {
      r = nodeHashOf(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && bytesEqual(r, root);
}

/** Verify a Rekor-shaped proof for a leaf hash. False on any malformed number. */
export function verifyInclusion(leafHash: Uint8Array, proof: InclusionProof): boolean {
  let index: bigint;
  let size: bigint;
  try { index = BigInt(proof.logIndex); size = BigInt(proof.treeSize); } catch { return false; }
  return verifyInclusionPath(leafHash, index, size, proof.hashes.map(fromBase64), fromBase64(proof.rootHash));
}
```

- [ ] **Step 4: Subpath index and package wiring**

`src/anchor/index.ts` (grows in later tasks; this is its Task 1 content):

```ts
export type { Anchor, InclusionProof, LogKey, AnchorTrust, AnchorCheck, AnchoredVerifyResult, AnchorStore } from "./types.js";
export { toBase64, fromBase64, bytesEqual, concat } from "./bytes.js";
export { ARTIFACT_PREFIX, artifactOf, digestOf } from "./artifact.js";
export { leafHashOf, nodeHashOf, verifyInclusionPath, verifyInclusion } from "./merkle.js";
```

In `package.json` set `"version": "0.3.0"`, and replace the `exports` block with:

```json
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js"
    },
    "./anchor": {
      "types": "./dist/anchor/index.d.ts",
      "import": "./dist/anchor/index.js"
    }
  },
  "bin": {
    "receipt-verify": "dist/cli.js"
  },
```

The `bin` target is created in Task 7; until then `npm pack --dry-run` warns about a missing bin file and that is expected. Check `tsconfig.test.json` includes `test` (it does today; leave it if so).

- [ ] **Step 5: The fixture helper**

`test/helpers/fixture.ts`:

```ts
import { readFileSync } from "node:fs";
import type { Anchor, AnchorTrust } from "../../src/anchor/types.js";

interface FixtureFile {
  captured: string;
  log: string;
  artifact: { stream: string; seq: number; head: string; text: string };
  request: { hashedRekordRequestV002: { digest: string; signature: { content: string; verifier: { keyDetails: string; publicKey: { rawBytes: string } } } } };
  response: {
    logIndex: string;
    logId: { keyId: string };
    canonicalizedBody: string;
    inclusionProof: { logIndex: string; treeSize: string; rootHash: string; hashes: string[]; checkpoint: { envelope: string } };
  };
}

const read = <T>(name: string): T => JSON.parse(readFileSync(new URL(`../fixtures/rekor-v2/${name}`, import.meta.url), "utf8")) as T;

export const fixtureEntry = (): FixtureFile => read<FixtureFile>("fixture-entry.json");
const logKeyFile = read<{ baseUrl: string; publicKey: { rawBytes: string }; logId: { keyId: string } }>("log2025-1-key.json");

export const FIXTURE_ORIGIN = "log2025-1.rekor.sigstore.dev";

export function fixtureAnchor(): Anchor {
  const f = fixtureEntry();
  const r = f.response;
  return {
    v: 1,
    stream: f.artifact.stream,
    seq: f.artifact.seq,
    head: f.artifact.head,
    at: f.captured,
    witness: { alg: "ecdsa-p256", publicKey: f.request.hashedRekordRequestV002.signature.verifier.publicKey.rawBytes },
    signature: f.request.hashedRekordRequestV002.signature.content,
    log: { url: f.log, keyId: r.logId.keyId },
    entry: { logIndex: r.logIndex, canonicalizedBody: r.canonicalizedBody },
    proof: { logIndex: r.inclusionProof.logIndex, treeSize: r.inclusionProof.treeSize, rootHash: r.inclusionProof.rootHash, hashes: r.inclusionProof.hashes, checkpoint: r.inclusionProof.checkpoint.envelope },
  };
}

export const fixtureLogKey = { origin: FIXTURE_ORIGIN, publicKey: logKeyFile.publicKey.rawBytes };
export const fixtureLogId = logKeyFile.logId.keyId;
export const fixtureTrust: AnchorTrust = { logKeys: [fixtureLogKey], witnessKeys: [fixtureAnchor().witness.publicKey] };
```

- [ ] **Step 6: Tests**

`test/anchor-artifact.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { artifactOf, digestOf, ARTIFACT_PREFIX } from "../src/anchor/artifact.js";
import { toBase64, fromBase64, bytesEqual, concat } from "../src/anchor/bytes.js";
import { fixtureEntry } from "./helpers/fixture.js";

const HEAD = "a".repeat(64);

test("artifactOf is the four-line text, newline terminated", () => {
  const text = new TextDecoder().decode(artifactOf("purse", 6, HEAD));
  assert.equal(text, `${ARTIFACT_PREFIX}\npurse\n6\n${HEAD}\n`);
});

test("artifactOf rejects a bad stream, seq, or head", () => {
  assert.throws(() => artifactOf("", 0, HEAD), /stream/);
  assert.throws(() => artifactOf("a\nb", 0, HEAD), /stream/);
  assert.throws(() => artifactOf("purse", -1, HEAD), /seq/);
  assert.throws(() => artifactOf("purse", 1.5, HEAD), /seq/);
  assert.throws(() => artifactOf("purse", 0, HEAD.toUpperCase()), /head/);
  assert.throws(() => artifactOf("purse", 0, "abc"), /head/);
});

test("digestOf matches the digest the real log recorded for the fixture artifact", () => {
  const f = fixtureEntry();
  const artifact = artifactOf(f.artifact.stream, f.artifact.seq, f.artifact.head);
  assert.equal(new TextDecoder().decode(artifact), f.artifact.text);
  assert.equal(toBase64(digestOf(artifact)), f.request.hashedRekordRequestV002.digest);
  assert.equal(toBase64(digestOf(artifact)), createHash("sha256").update(f.artifact.text).digest("base64"));
});

test("bytes helpers round-trip and compare", () => {
  const a = new Uint8Array([1, 2, 3]);
  assert.deepEqual(fromBase64(toBase64(a)), a);
  assert.ok(bytesEqual(a, new Uint8Array([1, 2, 3])));
  assert.ok(!bytesEqual(a, new Uint8Array([1, 2, 4])));
  assert.ok(!bytesEqual(a, new Uint8Array([1, 2])));
  assert.deepEqual(concat(new Uint8Array([1]), new Uint8Array([2, 3])), a);
});
```

`test/anchor-merkle.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { leafHashOf, nodeHashOf, verifyInclusionPath, verifyInclusion } from "../src/anchor/merkle.js";
import { fromBase64, toBase64 } from "../src/anchor/bytes.js";
import { fixtureEntry } from "./helpers/fixture.js";

const leaf = (n: number) => leafHashOf(new Uint8Array([n]));

test("a two-leaf tree proves both leaves", () => {
  const l0 = leaf(0), l1 = leaf(1);
  const root = nodeHashOf(l0, l1);
  assert.ok(verifyInclusionPath(l0, 0n, 2n, [l1], root));
  assert.ok(verifyInclusionPath(l1, 1n, 2n, [l0], root));
  assert.ok(!verifyInclusionPath(l0, 1n, 2n, [l1], root), "wrong index");
  assert.ok(!verifyInclusionPath(l0, 0n, 2n, [l0], root), "wrong sibling");
});

test("a three-leaf tree proves the odd leaf with a one-element path", () => {
  const l0 = leaf(0), l1 = leaf(1), l2 = leaf(2);
  const left = nodeHashOf(l0, l1);
  const root = nodeHashOf(left, l2);
  assert.ok(verifyInclusionPath(l2, 2n, 3n, [left], root));
  assert.ok(verifyInclusionPath(l0, 0n, 3n, [l1, l2], root));
  assert.ok(verifyInclusionPath(l1, 1n, 3n, [l0, l2], root));
});

test("out-of-range index and empty tree fail", () => {
  const l0 = leaf(0);
  assert.ok(!verifyInclusionPath(l0, 0n, 0n, [], l0));
  assert.ok(!verifyInclusionPath(l0, 1n, 1n, [], l0));
  assert.ok(verifyInclusionPath(l0, 0n, 1n, [], l0), "single leaf is its own root");
});

test("the real Rekor v2 fixture proof reaches its root", () => {
  const f = fixtureEntry();
  const p = f.response.inclusionProof;
  const lh = leafHashOf(fromBase64(f.response.canonicalizedBody));
  assert.ok(verifyInclusion(lh, { logIndex: p.logIndex, treeSize: p.treeSize, rootHash: p.rootHash, hashes: p.hashes, checkpoint: p.checkpoint.envelope }));
});

test("a flipped hash, a shifted index, or a malformed number fails the fixture proof", () => {
  const f = fixtureEntry();
  const p = f.response.inclusionProof;
  const lh = leafHashOf(fromBase64(f.response.canonicalizedBody));
  const proof = { logIndex: p.logIndex, treeSize: p.treeSize, rootHash: p.rootHash, hashes: [...p.hashes], checkpoint: p.checkpoint.envelope };
  const flipped = fromBase64(proof.hashes[0]!); flipped[0] = flipped[0]! ^ 1;
  assert.ok(!verifyInclusion(lh, { ...proof, hashes: [toBase64(flipped), ...proof.hashes.slice(1)] }));
  assert.ok(!verifyInclusion(lh, { ...proof, logIndex: String(BigInt(proof.logIndex) + 1n) }));
  assert.ok(!verifyInclusion(lh, { ...proof, logIndex: "x" }));
});
```

- [ ] **Step 7: Run, then commit**

Run: `cd /c/Users/ARABA/Workspace/SaaS/receipt && npm run build && npm run typecheck && npm test`
Expected: all existing tests plus the nine new ones pass.

```bash
git add src/anchor package.json test/helpers/fixture.ts test/anchor-artifact.test.ts test/anchor-merkle.test.ts
git commit -m "anchor: types, artifact, bytes, and RFC 6962 inclusion proofs

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Checkpoints, the C2SP signed note

**Files:**
- Create: `src/anchor/checkpoint.ts`
- Modify: `src/anchor/index.ts`
- Test: `test/anchor-checkpoint.test.ts`

**Interfaces:**
- Consumes: `LogKey` (Task 1), `fromBase64`, `toBase64`, `bytesEqual` (Task 1).
- Produces: `parseCheckpoint(note): ParsedCheckpoint`, `ed25519RawFromSpki(der): Uint8Array | null`, `checkpointKeyId(origin, publicKeyDer): string`, `verifyCheckpoint(note, logKeys): CheckpointResult` with `{ ok, origin, size, root, keyId?, signedBy?, cosigned, reason? }`.

- [ ] **Step 1: Failing tests**

`test/anchor-checkpoint.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { parseCheckpoint, checkpointKeyId, verifyCheckpoint, ed25519RawFromSpki } from "../src/anchor/checkpoint.js";
import { fromBase64, toBase64 } from "../src/anchor/bytes.js";
import { fixtureEntry, fixtureLogKey, fixtureLogId, FIXTURE_ORIGIN } from "./helpers/fixture.js";

const note = () => fixtureEntry().response.inclusionProof.checkpoint.envelope;

test("parseCheckpoint splits origin, size, root, and every signature line", () => {
  const p = parseCheckpoint(note());
  assert.equal(p.origin, FIXTURE_ORIGIN);
  assert.equal(p.size, fixtureEntry().response.inclusionProof.treeSize);
  assert.equal(p.root, fixtureEntry().response.inclusionProof.rootHash);
  assert.ok(p.text.endsWith("\n") && !p.text.includes("\n\n"));
  assert.ok(p.signatures.length >= 1);
  assert.ok(p.signatures.some((s) => s.name === FIXTURE_ORIGIN));
  for (const s of p.signatures) { assert.equal(s.keyId.length, 4); assert.ok(s.signature.length > 0); }
});

test("checkpointKeyId follows the C2SP Ed25519 rule and matches the log id", () => {
  assert.equal(checkpointKeyId(FIXTURE_ORIGIN, fromBase64(fixtureLogKey.publicKey)), fixtureLogId);
  assert.equal(checkpointKeyId(FIXTURE_ORIGIN, fromBase64(fixtureLogKey.publicKey)), fixtureEntry().response.logId.keyId);
});

test("ed25519RawFromSpki extracts 32 bytes and rejects other key types", () => {
  assert.equal(ed25519RawFromSpki(fromBase64(fixtureLogKey.publicKey))?.length, 32);
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  assert.equal(ed25519RawFromSpki(new Uint8Array(publicKey.export({ type: "spki", format: "der" }))), null);
  assert.throws(() => checkpointKeyId("x", new Uint8Array(publicKey.export({ type: "spki", format: "der" }))), /only Ed25519/);
});

test("verifyCheckpoint accepts the real note under the real log key and lists cosigners", () => {
  const r = verifyCheckpoint(note(), [fixtureLogKey]);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.signedBy, FIXTURE_ORIGIN);
  assert.equal(r.keyId, fixtureLogId);
  assert.ok(!r.cosigned.includes(FIXTURE_ORIGIN));
});

test("verifyCheckpoint fails with the named reason when no trusted key matches", () => {
  assert.equal(verifyCheckpoint(note(), []).reason, "untrusted log key");
  assert.equal(verifyCheckpoint(note(), [{ origin: "other.log", publicKey: fixtureLogKey.publicKey }]).reason, "untrusted log key");
  const { publicKey } = generateKeyPairSync("ed25519");
  const wrong = { origin: FIXTURE_ORIGIN, publicKey: toBase64(new Uint8Array(publicKey.export({ type: "spki", format: "der" }))) };
  assert.equal(verifyCheckpoint(note(), [wrong]).reason, "untrusted log key", "a key with a different id never gets tried");
});

test("verifyCheckpoint fails on a tampered note or a forged signature", () => {
  const n = note();
  const tamperedRoot = n.replace(/^(.*\n\d+\n)([A-Za-z0-9+/=]+)\n/, (_m, head: string, root: string) => `${head}${root.slice(0, -2)}AA\n`);
  assert.notEqual(tamperedRoot, n);
  assert.equal(verifyCheckpoint(tamperedRoot, [fixtureLogKey]).ok, false);
  // a note signed by a key we trust, but the trust list says another origin owns it
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const der = new Uint8Array(publicKey.export({ type: "spki", format: "der" }));
  const text = "my.log\n5\n" + toBase64(new Uint8Array(32)) + "\n";
  const keyId = fromBase64(checkpointKeyId("my.log", der));
  const sig = new Uint8Array(sign(null, Buffer.from(text, "utf8"), privateKey));
  const line = toBase64(new Uint8Array([...keyId.subarray(0, 4), ...sig]));
  const mine = `${text}\n— my.log ${line}\n`;
  assert.equal(verifyCheckpoint(mine, [{ origin: "my.log", publicKey: toBase64(der) }]).ok, true);
  const forged = mine.replace(line, toBase64(new Uint8Array([...keyId.subarray(0, 4), ...sig.map((b, i) => (i === 10 ? b ^ 1 : b))])));
  assert.equal(verifyCheckpoint(forged, [{ origin: "my.log", publicKey: toBase64(der) }]).reason, "checkpoint: signature does not verify");
});

test("parseCheckpoint throws on notes that are not notes", () => {
  assert.throws(() => parseCheckpoint("no blank line"), /blank line/);
  assert.throws(() => parseCheckpoint("o\nx\nr\n\nnot a signature\n"), /signature line/);
  assert.throws(() => parseCheckpoint("o\n5\nr\n\n"), /no signatures/);
});
```

- [ ] **Step 2: Run to see them fail**

Run: `npx tsx --test test/anchor-checkpoint.test.ts`
Expected: fails to import `../src/anchor/checkpoint.js`.

- [ ] **Step 3: Implement**

`src/anchor/checkpoint.ts`:

```ts
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { LogKey } from "./types.js";
import { bytesEqual, fromBase64, toBase64 } from "./bytes.js";

/** SubjectPublicKeyInfo prefix of an Ed25519 key. The raw 32-byte key follows it. */
const ED25519_SPKI_PREFIX = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

export interface CheckpointSignature { name: string; keyId: Uint8Array; signature: Uint8Array }
export interface ParsedCheckpoint {
  origin: string;
  size: string;
  root: string;
  /** The signed text, every line newline terminated, without the blank line. */
  text: string;
  signatures: CheckpointSignature[];
}

/** Split a C2SP signed note into its text and its signature lines. Throws when it is not one. */
export function parseCheckpoint(note: string): ParsedCheckpoint {
  const sep = note.indexOf("\n\n");
  if (sep < 0) throw new Error("checkpoint: no blank line between text and signatures");
  const text = note.slice(0, sep + 1);
  const lines = text.split("\n");
  const origin = lines[0];
  const size = lines[1];
  const root = lines[2];
  if (!origin || !size || !root || !/^[0-9]+$/.test(size)) throw new Error("checkpoint: malformed text");
  const signatures: CheckpointSignature[] = [];
  for (const line of note.slice(sep + 2).split("\n")) {
    if (!line) continue;
    if (!line.startsWith("— ")) throw new Error("checkpoint: malformed signature line");
    const parts = line.slice(2).split(" ");
    const name = parts[0];
    const sig = parts[1];
    if (!name || !sig || parts.length !== 2) throw new Error("checkpoint: malformed signature line");
    const raw = fromBase64(sig);
    if (raw.length < 5) throw new Error("checkpoint: signature too short");
    signatures.push({ name, keyId: raw.subarray(0, 4), signature: raw.subarray(4) });
  }
  if (signatures.length === 0) throw new Error("checkpoint: no signatures");
  return { origin, size, root, text, signatures };
}

/** The raw 32-byte Ed25519 key inside SPKI DER, or null when the DER holds another key type. */
export function ed25519RawFromSpki(der: Uint8Array): Uint8Array | null {
  if (der.length !== 44) return null;
  if (!bytesEqual(der.subarray(0, 12), ED25519_SPKI_PREFIX)) return null;
  return der.subarray(12);
}

/**
 * The C2SP key id of an Ed25519 log key, sha256(origin || "\n" || 0x01 || raw key),
 * base64 of all 32 bytes. The first four bytes prefix every signature line.
 */
export function checkpointKeyId(origin: string, publicKeyDer: Uint8Array): string {
  const raw = ed25519RawFromSpki(publicKeyDer);
  if (!raw) throw new Error("checkpoint: only Ed25519 log keys are supported");
  const h = createHash("sha256");
  h.update(Buffer.from(origin + "\n", "utf8"));
  h.update(new Uint8Array([1]));
  h.update(raw);
  return toBase64(new Uint8Array(h.digest()));
}

export interface CheckpointResult {
  ok: boolean;
  origin: string;
  size: string;
  root: string;
  keyId?: string;
  signedBy?: string;
  cosigned: string[];
  reason?: string;
}

/**
 * Verify the origin's own signature line with a trusted key for that origin.
 * Other signers are reported as cosigned and not verified.
 */
export function verifyCheckpoint(note: string, logKeys: ReadonlyArray<LogKey>): CheckpointResult {
  let parsed: ParsedCheckpoint;
  try { parsed = parseCheckpoint(note); }
  catch (e) { return { ok: false, origin: "", size: "", root: "", cosigned: [], reason: (e as Error).message }; }
  const { origin, size, root, text, signatures } = parsed;
  const cosigned = signatures.filter((s) => s.name !== origin).map((s) => s.name);
  const own = signatures.find((s) => s.name === origin);
  if (!own) return { ok: false, origin, size, root, cosigned, reason: "checkpoint: no signature by the origin" };
  const message = Buffer.from(text, "utf8");
  for (const k of logKeys) {
    if (k.origin !== origin) continue;
    const der = fromBase64(k.publicKey);
    let keyId: string;
    try { keyId = checkpointKeyId(origin, der); }
    catch (e) { return { ok: false, origin, size, root, cosigned, reason: (e as Error).message }; }
    if (!bytesEqual(fromBase64(keyId).subarray(0, 4), own.keyId)) continue;
    const key = createPublicKey({ key: Buffer.from(der), format: "der", type: "spki" });
    const good = cryptoVerify(null, message, key, own.signature);
    return good
      ? { ok: true, origin, size, root, keyId, signedBy: origin, cosigned }
      : { ok: false, origin, size, root, keyId, cosigned, reason: "checkpoint: signature does not verify" };
  }
  return { ok: false, origin, size, root, cosigned, reason: "untrusted log key" };
}
```

Append to `src/anchor/index.ts`:

```ts
export { parseCheckpoint, ed25519RawFromSpki, checkpointKeyId, verifyCheckpoint } from "./checkpoint.js";
export type { ParsedCheckpoint, CheckpointSignature, CheckpointResult } from "./checkpoint.js";
```

- [ ] **Step 4: Run, then commit**

Run: `npm run build && npm run typecheck && npm test`
Expected: green, including the seven checkpoint tests.

```bash
git add src/anchor/checkpoint.ts src/anchor/index.ts test/anchor-checkpoint.test.ts
git commit -m "anchor: C2SP checkpoints, Ed25519 verification, and the key id rule

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Witness signer, the hashedrekord body, and the FakeLog helper

**Files:**
- Create: `src/anchor/signer.ts`, `src/anchor/body.ts`, `test/helpers/fake-log.ts`
- Modify: `src/anchor/index.ts`
- Test: `test/anchor-signer.test.ts`

**Interfaces:**
- Consumes: Task 1 and Task 2 exports.
- Produces: `P256Signer` with `static generate()`, `static fromPem(pem)`, `toPem()`, `publicKeyDer(): string` (base64 SPKI), `sign(bytes): string` (base64 DER); `verifyArtifactSignature(artifact, signatureB64, publicKeyDerB64): boolean`; `KEY_DETAILS`, `decodeBody(canonicalizedBodyB64): HashedRekordBody | null`, `buildRequest(digest, signatureB64, publicKeyDerB64): RekorRequest`; test helper `FakeLog` with `origin`, `url`, `logKey`, `keyId`, `add(request)`, `entry(index)`, `fetch()`, and `rootOf(leaves)`, `pathFor(index, leaves)`.

- [ ] **Step 1: Failing tests**

`test/anchor-signer.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { P256Signer, verifyArtifactSignature } from "../src/anchor/signer.js";
import { decodeBody, buildRequest, KEY_DETAILS } from "../src/anchor/body.js";
import { artifactOf, digestOf } from "../src/anchor/artifact.js";
import { leafHashOf, verifyInclusion } from "../src/anchor/merkle.js";
import { verifyCheckpoint } from "../src/anchor/checkpoint.js";
import { fromBase64, toBase64 } from "../src/anchor/bytes.js";
import { fixtureEntry } from "./helpers/fixture.js";
import { FakeLog } from "./helpers/fake-log.js";

const HEAD = "b".repeat(64);

test("P256Signer signs an artifact that verifyArtifactSignature accepts, and rejects a changed byte", () => {
  const s = P256Signer.generate();
  const artifact = artifactOf("purse", 3, HEAD);
  const sig = s.sign(artifact);
  assert.ok(verifyArtifactSignature(artifact, sig, s.publicKeyDer()));
  const changed = new Uint8Array(artifact); changed[changed.length - 2] ^= 1;
  assert.ok(!verifyArtifactSignature(changed, sig, s.publicKeyDer()));
  assert.ok(!verifyArtifactSignature(artifact, sig, P256Signer.generate().publicKeyDer()));
  assert.ok(!verifyArtifactSignature(artifact, "not base64!!", s.publicKeyDer()));
});

test("P256Signer round-trips through PEM and refuses a non P-256 key", async () => {
  const s = P256Signer.generate();
  const back = P256Signer.fromPem(s.toPem());
  assert.equal(back.publicKeyDer(), s.publicKeyDer());
  const { generateKeyPairSync } = await import("node:crypto");
  const ed = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  assert.throws(() => P256Signer.fromPem(ed), /P-256/);
});

test("decodeBody reads the real fixture body and buildRequest reproduces the real request", () => {
  const f = fixtureEntry();
  const b = decodeBody(f.response.canonicalizedBody);
  assert.ok(b);
  assert.equal(b.digest, f.request.hashedRekordRequestV002.digest);
  assert.equal(b.signature, f.request.hashedRekordRequestV002.signature.content);
  assert.equal(b.publicKey, f.request.hashedRekordRequestV002.signature.verifier.publicKey.rawBytes);
  assert.equal(b.keyDetails, KEY_DETAILS);
  const artifact = artifactOf(f.artifact.stream, f.artifact.seq, f.artifact.head);
  assert.deepEqual(buildRequest(digestOf(artifact), b.signature, b.publicKey), f.request);
  assert.ok(verifyArtifactSignature(artifact, b.signature, b.publicKey), "the real witness signature verifies over the rebuilt artifact");
});

test("decodeBody returns null for anything that is not a hashedrekord 0.0.2", () => {
  assert.equal(decodeBody(toBase64(new TextEncoder().encode("{}"))), null);
  assert.equal(decodeBody(toBase64(new TextEncoder().encode(JSON.stringify({ apiVersion: "0.0.1", kind: "hashedrekord" })))), null);
  assert.equal(decodeBody("%%%"), null);
});

test("FakeLog builds entries whose proofs and checkpoints verify with the real verifiers", () => {
  const log = new FakeLog();
  const s = P256Signer.generate();
  const replies = [0, 1, 2, 3, 4].map((i) => {
    const artifact = artifactOf("t", i, HEAD);
    return log.add(buildRequest(digestOf(artifact), s.sign(artifact), s.publicKeyDer()) as never);
  });
  for (const r of replies) {
    const lh = leafHashOf(fromBase64(r.canonicalizedBody));
    const p = r.inclusionProof;
    assert.ok(verifyInclusion(lh, { logIndex: p.logIndex, treeSize: p.treeSize, rootHash: p.rootHash, hashes: p.hashes, checkpoint: p.checkpoint.envelope }), `entry ${r.logIndex}`);
  }
  // an old entry re-proven at the current size still verifies
  const again = log.entry(1);
  assert.equal(again.inclusionProof.treeSize, "5");
  assert.ok(verifyInclusion(leafHashOf(fromBase64(again.canonicalizedBody)), { ...again.inclusionProof, checkpoint: again.inclusionProof.checkpoint.envelope }));
  const cp = verifyCheckpoint(again.inclusionProof.checkpoint.envelope, [log.logKey]);
  assert.equal(cp.ok, true, cp.reason);
  assert.equal(cp.keyId, log.keyId);
  assert.equal(again.logId.keyId, log.keyId);
});
```

- [ ] **Step 2: Run to see them fail**

Run: `npx tsx --test test/anchor-signer.test.ts`
Expected: import failures.

- [ ] **Step 3: Implement the signer and the body**

`src/anchor/signer.ts`:

```ts
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { fromBase64, toBase64 } from "./bytes.js";

const CURVE = "prime256v1";

function assertP256(key: KeyObject): void {
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== CURVE) {
    throw new Error("witness key must be an EC P-256 key");
  }
}

/** The witness's signing key. One per witness. */
export class P256Signer {
  private constructor(private readonly privateKey: KeyObject, private readonly publicKey: KeyObject) {}

  static generate(): P256Signer {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    return new P256Signer(privateKey, publicKey);
  }

  static fromPem(pem: string): P256Signer {
    const privateKey = createPrivateKey(pem);
    assertP256(privateKey);
    return new P256Signer(privateKey, createPublicKey(privateKey));
  }

  /** PKCS8 PEM, the form WITNESS_KEY_FILE holds. */
  toPem(): string {
    return this.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  }

  /** base64 SubjectPublicKeyInfo DER, the form anchors and Rekor carry. */
  publicKeyDer(): string {
    return toBase64(new Uint8Array(this.publicKey.export({ type: "spki", format: "der" }) as Buffer));
  }

  /** ECDSA with SHA-256 over the bytes, DER encoded, base64. */
  sign(bytes: Uint8Array): string {
    return toBase64(new Uint8Array(cryptoSign("sha256", bytes, { key: this.privateKey, dsaEncoding: "der" })));
  }
}

/** True when the signature verifies over the artifact under the given P-256 public key. False on any malformed input. */
export function verifyArtifactSignature(artifact: Uint8Array, signatureB64: string, publicKeyDerB64: string): boolean {
  try {
    const key = createPublicKey({ key: Buffer.from(fromBase64(publicKeyDerB64)), format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== CURVE) return false;
    return cryptoVerify("sha256", artifact, { key, dsaEncoding: "der" }, fromBase64(signatureB64));
  } catch {
    return false;
  }
}
```

`src/anchor/body.ts`:

```ts
import { fromBase64, toBase64 } from "./bytes.js";

export const KEY_DETAILS = "PKIX_ECDSA_P256_SHA_256";

export interface HashedRekordBody { digest: string; signature: string; publicKey: string; keyDetails: string }

export interface RekorRequest {
  hashedRekordRequestV002: {
    digest: string;
    signature: { content: string; verifier: { keyDetails: string; publicKey: { rawBytes: string } } };
  };
}

interface BodyShape {
  apiVersion?: string;
  kind?: string;
  spec?: { hashedRekordV002?: { data?: { algorithm?: string; digest?: string }; signature?: { content?: string; verifier?: { keyDetails?: string; publicKey?: { rawBytes?: string } } } } };
}

/** Decode a hashedrekord 0.0.2 canonicalized body. Null when the bytes are not that. */
export function decodeBody(canonicalizedBodyB64: string): HashedRekordBody | null {
  try {
    const j = JSON.parse(Buffer.from(fromBase64(canonicalizedBodyB64)).toString("utf8")) as BodyShape;
    if (j.kind !== "hashedrekord" || j.apiVersion !== "0.0.2") return null;
    const s = j.spec?.hashedRekordV002;
    const digest = s?.data?.digest;
    const signature = s?.signature?.content;
    const publicKey = s?.signature?.verifier?.publicKey?.rawBytes;
    const keyDetails = s?.signature?.verifier?.keyDetails;
    if (s?.data?.algorithm !== "SHA2_256" || !digest || !signature || !publicKey || !keyDetails) return null;
    return { digest, signature, publicKey, keyDetails };
  } catch {
    return null;
  }
}

/** The Rekor v2 write request for a signed artifact digest. */
export function buildRequest(digest: Uint8Array, signatureB64: string, publicKeyDerB64: string): RekorRequest {
  return {
    hashedRekordRequestV002: {
      digest: toBase64(digest),
      signature: { content: signatureB64, verifier: { keyDetails: KEY_DETAILS, publicKey: { rawBytes: publicKeyDerB64 } } },
    },
  };
}
```

- [ ] **Step 4: The FakeLog helper**

`test/helpers/fake-log.ts`:

```ts
import { createHash, generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { leafHashOf, nodeHashOf } from "../../src/anchor/merkle.js";
import { checkpointKeyId } from "../../src/anchor/checkpoint.js";
import { fromBase64, toBase64 } from "../../src/anchor/bytes.js";
import type { RekorRequest } from "../../src/anchor/body.js";

export interface FakeReply {
  logIndex: string;
  logId: { keyId: string };
  kindVersion: { kind: string; version: string };
  integratedTime: string;
  canonicalizedBody: string;
  inclusionProof: { logIndex: string; treeSize: string; rootHash: string; hashes: string[]; checkpoint: { envelope: string } };
}

/** RFC 6962 root of a list of leaf hashes. */
export function rootOf(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return new Uint8Array(createHash("sha256").digest());
  if (leaves.length === 1) return leaves[0]!;
  const k = largestPowerOfTwoBelow(leaves.length);
  return nodeHashOf(rootOf(leaves.slice(0, k)), rootOf(leaves.slice(k)));
}

/** RFC 6962 inclusion path for the leaf at `index`, leaf to root. */
export function pathFor(index: number, leaves: Uint8Array[]): Uint8Array[] {
  if (leaves.length <= 1) return [];
  const k = largestPowerOfTwoBelow(leaves.length);
  if (index < k) return [...pathFor(index, leaves.slice(0, k)), rootOf(leaves.slice(k))];
  return [...pathFor(index - k, leaves.slice(k)), rootOf(leaves.slice(0, k))];
}

function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * A tiny Rekor-shaped log for tests. Real RFC 6962 trees over canonicalized
 * bodies, real C2SP checkpoints signed with a throwaway Ed25519 key.
 */
export class FakeLog {
  readonly origin: string;
  readonly url: string;
  readonly publicKeyDer: string;
  readonly keyId: string;
  private readonly key: KeyObject;
  private readonly bodies: Uint8Array[] = [];

  constructor(origin = "fake.log.test", url = "https://fake.log.test") {
    this.origin = origin;
    this.url = url;
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    this.key = privateKey;
    this.publicKeyDer = toBase64(new Uint8Array(publicKey.export({ type: "spki", format: "der" }) as Buffer));
    this.keyId = checkpointKeyId(origin, fromBase64(this.publicKeyDer));
  }

  get logKey(): { origin: string; publicKey: string } {
    return { origin: this.origin, publicKey: this.publicKeyDer };
  }

  get size(): number {
    return this.bodies.length;
  }

  /** Append the body a Rekor v2 would build for this request and return the reply. */
  add(request: RekorRequest): FakeReply {
    const r = request.hashedRekordRequestV002;
    const body = JSON.stringify({
      apiVersion: "0.0.2",
      kind: "hashedrekord",
      spec: { hashedRekordV002: { data: { algorithm: "SHA2_256", digest: r.digest }, signature: { content: r.signature.content, verifier: { keyDetails: r.signature.verifier.keyDetails, publicKey: { rawBytes: r.signature.verifier.publicKey.rawBytes } } } } },
    });
    this.bodies.push(new TextEncoder().encode(body));
    return this.entry(this.bodies.length - 1);
  }

  /** The reply for entry `index`, proven against the current tree. */
  entry(index: number): FakeReply {
    const body = this.bodies[index];
    if (!body) throw new Error(`no entry ${index}`);
    const leaves = this.bodies.map(leafHashOf);
    const size = leaves.length;
    const root = rootOf(leaves);
    const path = pathFor(index, leaves);
    const text = `${this.origin}\n${size}\n${toBase64(root)}\n`;
    const sig = new Uint8Array(cryptoSign(null, Buffer.from(text, "utf8"), this.key));
    const line = toBase64(new Uint8Array([...fromBase64(this.keyId).subarray(0, 4), ...sig]));
    const envelope = `${text}\n— ${this.origin} ${line}\n`;
    return {
      logIndex: String(index),
      logId: { keyId: this.keyId },
      kindVersion: { kind: "hashedrekord", version: "0.0.2" },
      integratedTime: "0",
      canonicalizedBody: toBase64(body),
      inclusionProof: { logIndex: String(index), treeSize: String(size), rootHash: toBase64(root), hashes: path.map(toBase64), checkpoint: { envelope } },
    };
  }

  /** A fetch replacement that answers POST {url}/api/v2/log/entries with 201 and a reply. */
  fetch(status = 201): typeof fetch {
    const impl = async (input: unknown, init?: { method?: string; body?: unknown }) => {
      const url = String(input);
      if (!url.endsWith("/api/v2/log/entries") || init?.method !== "POST") return new Response("not found", { status: 404 });
      if (status !== 201) return new Response("nope", { status });
      const reply = this.add(JSON.parse(String(init.body)) as RekorRequest);
      return new Response(JSON.stringify(reply), { status: 201, headers: { "content-type": "application/json" } });
    };
    return impl as unknown as typeof fetch;
  }
}
```

Append to `src/anchor/index.ts`:

```ts
export { P256Signer, verifyArtifactSignature } from "./signer.js";
export { KEY_DETAILS, decodeBody, buildRequest } from "./body.js";
export type { HashedRekordBody, RekorRequest } from "./body.js";
```

- [ ] **Step 5: Run, then commit**

Run: `npm run build && npm run typecheck && npm test`
Expected: green, including the five signer and body tests.

```bash
git add src/anchor/signer.ts src/anchor/body.ts src/anchor/index.ts test/helpers/fake-log.ts test/anchor-signer.test.ts
git commit -m "anchor: the witness signer, the hashedrekord body, and a fake log for tests

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: verifyAnchored

**Files:**
- Create: `src/anchor/verify.ts`
- Modify: `src/anchor/index.ts`
- Test: `test/helpers/anchors.ts`, `test/anchor-verify.test.ts`

**Interfaces:**
- Consumes: everything from Tasks 1 to 3, `verifyChain` from `../hash.js`, `Receipt` from `../types.js`.
- Produces: `verifyAnchorProof(anchor, trust): AnchorCheck` (steps 1 to 4), `verifyAnchored(records, anchors, trust): AnchoredVerifyResult` (adds step 5); test helper `anchorWith(log, signer, stream, seq, head, at?): Anchor` and `chainOf(n, stream?): Receipt[]`.

- [ ] **Step 1: The test helper**

`test/helpers/anchors.ts`:

```ts
import { MemoryStore } from "../../src/store.js";
import { makeReceipt } from "../../src/chain.js";
import type { Receipt } from "../../src/types.js";
import type { Anchor } from "../../src/anchor/types.js";
import { artifactOf, digestOf } from "../../src/anchor/artifact.js";
import { buildRequest } from "../../src/anchor/body.js";
import type { P256Signer } from "../../src/anchor/signer.js";
import type { FakeLog } from "./fake-log.js";

/** A deterministic chain of n receipts. */
export function chainOf(n: number): Receipt[] {
  const store = new MemoryStore<{ n: number }>();
  let seq = 0;
  const opts = { now: () => "2026-09-08T00:00:00.000Z", newId: () => `id-${++seq}` };
  for (let i = 0; i < n; i++) makeReceipt(store, { kind: "test", payload: { n: i } }, opts);
  return store.all();
}

/** Sign and submit one head to a FakeLog and shape the reply into an Anchor, as RekorV2 will. */
export function anchorWith(log: FakeLog, signer: P256Signer, stream: string, seq: number, head: string, at = "2026-09-08T00:00:00.000Z"): Anchor {
  const artifact = artifactOf(stream, seq, head);
  const signature = signer.sign(artifact);
  const publicKey = signer.publicKeyDer();
  const r = log.add(buildRequest(digestOf(artifact), signature, publicKey));
  return {
    v: 1, stream, seq, head, at,
    witness: { alg: "ecdsa-p256", publicKey },
    signature,
    log: { url: log.url, keyId: r.logId.keyId },
    entry: { logIndex: r.logIndex, canonicalizedBody: r.canonicalizedBody },
    proof: { logIndex: r.inclusionProof.logIndex, treeSize: r.inclusionProof.treeSize, rootHash: r.inclusionProof.rootHash, hashes: r.inclusionProof.hashes, checkpoint: r.inclusionProof.checkpoint.envelope },
  };
}
```

- [ ] **Step 2: Failing tests**

`test/anchor-verify.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyAnchored, verifyAnchorProof } from "../src/anchor/verify.js";
import { P256Signer } from "../src/anchor/signer.js";
import { toBase64 } from "../src/anchor/bytes.js";
import type { Anchor, AnchorTrust } from "../src/anchor/types.js";
import type { Receipt } from "../src/types.js";
import { FakeLog } from "./helpers/fake-log.js";
import { anchorWith, chainOf } from "./helpers/anchors.js";
import { fixtureAnchor, fixtureTrust } from "./helpers/fixture.js";

function setup(n = 6) {
  const log = new FakeLog();
  const signer = P256Signer.generate();
  const records = chainOf(n);
  const trust: AnchorTrust = { logKeys: [log.logKey], witnessKeys: [signer.publicKeyDer()] };
  return { log, signer, records, trust };
}

test("the real fixture anchor verifies on its own and fails binding, since no chain has that head", () => {
  const a = fixtureAnchor();
  const alone = verifyAnchorProof(a, fixtureTrust);
  assert.equal(alone.ok, true, alone.reason);
  assert.ok(alone.cosigned.length >= 1, "the public log's checkpoint carried cosignatures");
  const r = verifyAnchored([], [a], fixtureTrust);
  assert.equal(r.ok, false);
  assert.equal(r.coveredUpTo, null);
  assert.equal(r.anchors[0]?.reason, "record missing at seq 0");
});

test("a chain with two anchors verifies, coveredUpTo is the highest anchored seq", () => {
  const { log, signer, records, trust } = setup(6);
  const a2 = anchorWith(log, signer, "purse", 2, records[2]!.hash);
  const a5 = anchorWith(log, signer, "purse", 5, records[5]!.hash);
  const r = verifyAnchored(records, [a2, a5], trust);
  assert.equal(r.ok, true, JSON.stringify(r.anchors));
  assert.equal(r.coveredUpTo, 5);
  assert.deepEqual(r.anchors.map((c) => c.ok), [true, true]);
  assert.equal(r.chain.ok, true);
});

test("no anchors means chain-only, ok with coveredUpTo null", () => {
  const { records, trust } = setup(3);
  const r = verifyAnchored(records, [], trust);
  assert.equal(r.ok, true);
  assert.equal(r.coveredUpTo, null);
});

test("any single-byte change at or below coveredUpTo fails the anchor that covers it, even when the chain is rebuilt", async () => {
  const { log, signer, records, trust } = setup(5);
  const a4 = anchorWith(log, signer, "purse", 4, records[4]!.hash);
  const { hashRecord } = await import("../src/hash.js");
  for (let i = 0; i <= 4; i++) {
    // alter record i, then recompute every hash from i on so the chain verifies again
    const rebuilt: Receipt[] = records.map((r) => ({ ...r, payload: { ...(r.payload as { n: number }) } }));
    (rebuilt[i]!.payload as { n: number }).n += 1000;
    for (let j = i; j < rebuilt.length; j++) {
      const prev = j === 0 ? rebuilt[0]!.prevHash : rebuilt[j - 1]!.hash;
      const { hash: _h, ...rest } = { ...rebuilt[j]!, prevHash: prev };
      rebuilt[j] = { ...rest, hash: hashRecord(rest) };
    }
    const r = verifyAnchored(rebuilt, [a4], trust);
    assert.equal(r.chain.ok, true, `rebuilt chain ${i} verifies on its own`);
    assert.equal(r.ok, false, `anchor catches the rewrite at ${i}`);
    assert.equal(r.anchors[0]?.reason, "head mismatch at seq 4");
    assert.equal(r.coveredUpTo, null);
  }
});

test("truncation below coveredUpTo fails, truncation above it does not", () => {
  const { log, signer, records, trust } = setup(6);
  const a3 = anchorWith(log, signer, "purse", 3, records[3]!.hash);
  const cut = verifyAnchored(records.slice(0, 3), [a3], trust);
  assert.equal(cut.ok, false);
  assert.equal(cut.anchors[0]?.reason, "record missing at seq 3");
  const tail = verifyAnchored(records.slice(0, 5), [a3], trust);
  assert.equal(tail.ok, true);
  assert.equal(tail.coveredUpTo, 3);
});

test("a rotated witness key keeps old anchors valid when both keys are trusted, and names the untrusted one otherwise", () => {
  const { log, signer, records } = setup(6);
  const second = P256Signer.generate();
  const a1 = anchorWith(log, signer, "purse", 1, records[1]!.hash);
  const a4 = anchorWith(log, second, "purse", 4, records[4]!.hash);
  const both: AnchorTrust = { logKeys: [log.logKey], witnessKeys: [signer.publicKeyDer(), second.publicKeyDer()] };
  assert.equal(verifyAnchored(records, [a1, a4], both).coveredUpTo, 4);
  const onlyFirst: AnchorTrust = { logKeys: [log.logKey], witnessKeys: [signer.publicKeyDer()] };
  const r = verifyAnchored(records, [a1, a4], onlyFirst);
  assert.equal(r.ok, false);
  assert.equal(r.coveredUpTo, 1);
  assert.equal(r.anchors[1]?.reason, "untrusted witness key");
});

test("an untrusted log key fails with the named reason", () => {
  const { log, signer, records } = setup(2);
  const a1 = anchorWith(log, signer, "purse", 1, records[1]!.hash);
  const r = verifyAnchored(records, [a1], { logKeys: [], witnessKeys: [signer.publicKeyDer()] });
  assert.equal(r.anchors[0]?.reason, "untrusted log key");
});

test("an anchor whose signature, body, proof, or key id was altered fails with a specific reason", () => {
  const { log, signer, records, trust } = setup(3);
  const good = anchorWith(log, signer, "purse", 2, records[2]!.hash);
  const other = P256Signer.generate();
  const cases: [Partial<Anchor>, string][] = [
    [{ signature: other.sign(new Uint8Array([1])) }, "witness signature does not verify"],
    [{ head: "0".repeat(64) }, "witness signature does not verify"],
    [{ entry: { ...good.entry, canonicalizedBody: anchorWith(log, signer, "purse", 1, records[1]!.hash).entry.canonicalizedBody } }, "log entry digest differs from the artifact digest"],
    [{ proof: { ...good.proof, rootHash: toBase64(new Uint8Array(32)) } }, "inclusion proof does not reach the root"],
    [{ log: { ...good.log, keyId: "AAAA" } }, "anchor log key id differs from the signing key"],
    [{ v: 2 as unknown as 1 }, "unsupported anchor version"],
  ];
  for (const [patch, reason] of cases) {
    const r = verifyAnchored(records, [{ ...good, ...patch }], trust);
    assert.equal(r.anchors[0]?.reason, reason, JSON.stringify(patch).slice(0, 80));
  }
});

test("verifyAnchored is pure", () => {
  const { log, signer, records, trust } = setup(4);
  const a = anchorWith(log, signer, "purse", 3, records[3]!.hash);
  const before = JSON.stringify({ records, a, trust });
  const r1 = verifyAnchored(records, [a], trust);
  const r2 = verifyAnchored(records, [a], trust);
  assert.deepEqual(r1, r2);
  assert.equal(JSON.stringify({ records, a, trust }), before);
});
```

- [ ] **Step 3: Run to see them fail**

Run: `npx tsx --test test/anchor-verify.test.ts`
Expected: import failure on `../src/anchor/verify.js`.

- [ ] **Step 4: Implement**

`src/anchor/verify.ts`:

```ts
import { verifyChain } from "../hash.js";
import type { Receipt } from "../types.js";
import type { Anchor, AnchorCheck, AnchorTrust, AnchoredVerifyResult } from "./types.js";
import { artifactOf, digestOf } from "./artifact.js";
import { bytesEqual, fromBase64 } from "./bytes.js";
import { decodeBody, KEY_DETAILS } from "./body.js";
import { leafHashOf, verifyInclusion } from "./merkle.js";
import { verifyCheckpoint } from "./checkpoint.js";
import { verifyArtifactSignature } from "./signer.js";

function fail(a: Anchor, reason: string, cosigned: string[] = []): AnchorCheck {
  return { seq: a.seq, ok: false, reason, logIndex: a.entry.logIndex, cosigned };
}

/**
 * Steps 1 to 4 of the spec: the anchor against its own proof and the trust set.
 * No chain is involved, so a witness can use this on a reply before storing it.
 */
export function verifyAnchorProof(a: Anchor, trust: AnchorTrust): AnchorCheck {
  if (a.v !== 1) return fail(a, "unsupported anchor version");
  let artifact: Uint8Array;
  try { artifact = artifactOf(a.stream, a.seq, a.head); }
  catch (e) { return fail(a, (e as Error).message); }
  if (a.witness.alg !== "ecdsa-p256") return fail(a, "unsupported witness algorithm");
  if (!trust.witnessKeys.includes(a.witness.publicKey)) return fail(a, "untrusted witness key");
  if (!verifyArtifactSignature(artifact, a.signature, a.witness.publicKey)) return fail(a, "witness signature does not verify");
  const body = decodeBody(a.entry.canonicalizedBody);
  if (!body) return fail(a, "log entry body is not a hashedrekord 0.0.2");
  if (body.keyDetails !== KEY_DETAILS || body.publicKey !== a.witness.publicKey) return fail(a, "log entry verifier key differs from the witness key");
  if (!bytesEqual(fromBase64(body.digest), digestOf(artifact))) return fail(a, "log entry digest differs from the artifact digest");
  if (body.signature !== a.signature) return fail(a, "log entry signature differs from the anchor signature");
  if (!verifyInclusion(leafHashOf(fromBase64(a.entry.canonicalizedBody)), a.proof)) return fail(a, "inclusion proof does not reach the root");
  const cp = verifyCheckpoint(a.proof.checkpoint, trust.logKeys);
  if (!cp.ok) return fail(a, cp.reason ?? "checkpoint does not verify", cp.cosigned);
  if (cp.root !== a.proof.rootHash || cp.size !== a.proof.treeSize) return fail(a, "checkpoint root or size differs from the proof", cp.cosigned);
  if (cp.keyId !== undefined && a.log.keyId !== cp.keyId) return fail(a, "anchor log key id differs from the signing key", cp.cosigned);
  return { seq: a.seq, ok: true, logIndex: a.entry.logIndex, cosigned: cp.cosigned };
}

/**
 * The full promise. Each anchor's proof, then the chain: the record at the
 * anchored position must carry the anchored head. `coveredUpTo` is the highest
 * seq an anchor vouched for; below it a rewrite or a truncation is named.
 */
export function verifyAnchored(records: ReadonlyArray<Receipt>, anchors: ReadonlyArray<Anchor>, trust: AnchorTrust): AnchoredVerifyResult {
  const chain = verifyChain(records);
  const checks = anchors.map((a) => {
    const proof = verifyAnchorProof(a, trust);
    if (!proof.ok) return proof;
    const rec = records[a.seq];
    if (!rec) return fail(a, `record missing at seq ${a.seq}`, proof.cosigned);
    if (rec.hash !== a.head) return fail(a, `head mismatch at seq ${a.seq}`, proof.cosigned);
    return proof;
  });
  const okSeqs = checks.filter((c) => c.ok).map((c) => c.seq);
  const coveredUpTo = okSeqs.length ? Math.max(...okSeqs) : null;
  return { ok: chain.ok && checks.every((c) => c.ok), coveredUpTo, anchors: checks, chain };
}
```

Append to `src/anchor/index.ts`:

```ts
export { verifyAnchorProof, verifyAnchored } from "./verify.js";
```

- [ ] **Step 5: Run, then commit**

Run: `npm run build && npm run typecheck && npm test`
Expected: green, including the nine verify tests. If the rewrite property test fails on `coveredUpTo`, the anchor is correctly failing and `coveredUpTo` must be `null` because no anchor verified; check the assertion order, not the verifier.

```bash
git add src/anchor/verify.ts src/anchor/index.ts test/helpers/anchors.ts test/anchor-verify.test.ts
git commit -m "anchor: verifyAnchored, the proof steps and the chain binding

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: The Rekor v2 client

**Files:**
- Create: `src/anchor/rekor.ts`
- Modify: `src/anchor/index.ts`
- Test: `test/anchor-rekor.test.ts`

**Interfaces:**
- Consumes: `P256Signer`, `artifactOf`, `digestOf`, `buildRequest`, `verifyAnchorProof`, `Anchor`, `LogKey`.
- Produces: `RekorV2` with `constructor({ url, logKeys, timeoutMs?, fetch?, now? })` and `submit(stream, seq, head, signer): Promise<Anchor>`.

- [ ] **Step 1: Failing tests**

`test/anchor-rekor.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { RekorV2 } from "../src/anchor/rekor.js";
import { P256Signer } from "../src/anchor/signer.js";
import { verifyAnchored } from "../src/anchor/verify.js";
import { FakeLog } from "./helpers/fake-log.js";
import { chainOf } from "./helpers/anchors.js";
import { fixtureLogKey, fixtureLogId } from "./helpers/fixture.js";

test("submit signs, posts, verifies the reply, and returns an anchor that verifies against the chain", async () => {
  const log = new FakeLog();
  const signer = P256Signer.generate();
  const records = chainOf(4);
  const rekor = new RekorV2({ url: log.url + "/", logKeys: [log.logKey], fetch: log.fetch(), now: () => "2026-09-08T10:00:00.000Z" });
  const a = await rekor.submit("purse", 3, records[3]!.hash, signer);
  assert.equal(a.v, 1);
  assert.equal(a.at, "2026-09-08T10:00:00.000Z");
  assert.equal(a.log.url, log.url, "trailing slash trimmed");
  assert.equal(a.log.keyId, log.keyId);
  assert.equal(a.witness.publicKey, signer.publicKeyDer());
  const r = verifyAnchored(records, [a], { logKeys: [log.logKey], witnessKeys: [signer.publicKeyDer()] });
  assert.equal(r.ok, true, JSON.stringify(r.anchors));
  assert.equal(r.coveredUpTo, 3);
});

test("submit refuses a reply from a log whose key is not trusted", async () => {
  const log = new FakeLog();
  const rekor = new RekorV2({ url: log.url, logKeys: [fixtureLogKey], fetch: log.fetch() });
  await assert.rejects(rekor.submit("purse", 0, "c".repeat(64), P256Signer.generate()), /reply did not verify, untrusted log key/);
});

test("submit surfaces an HTTP failure with the status", async () => {
  const log = new FakeLog();
  const rekor = new RekorV2({ url: log.url, logKeys: [log.logKey], fetch: log.fetch(503) });
  await assert.rejects(rekor.submit("purse", 0, "c".repeat(64), P256Signer.generate()), /rekor: 503/);
});

test("submit refuses a reply missing fields", async () => {
  const bad = (async () => new Response(JSON.stringify({ logIndex: "1" }), { status: 201 })) as unknown as typeof fetch;
  const rekor = new RekorV2({ url: "https://x.test", logKeys: [], fetch: bad });
  await assert.rejects(rekor.submit("purse", 0, "c".repeat(64), P256Signer.generate()), /missing fields/);
});

test("the constructor rejects a url without a scheme", () => {
  assert.throws(() => new RekorV2({ url: "log.example", logKeys: [] }), /http/);
});

test("live: the public log accepts a throwaway anchor and the reply verifies under the pinned key", { skip: process.env.REKOR_LIVE !== "1" }, async () => {
  const rekor = new RekorV2({ url: "https://log2025-1.rekor.sigstore.dev", logKeys: [fixtureLogKey], timeoutMs: 30000 });
  const head = randomBytes(32).toString("hex");
  const a = await rekor.submit("live-test", 0, head, P256Signer.generate());
  assert.equal(a.log.keyId, fixtureLogId);
  assert.match(a.entry.logIndex, /^[0-9]+$/);
  console.log("live anchor at log index", a.entry.logIndex);
});
```

- [ ] **Step 2: Run to see them fail**

Run: `npx tsx --test test/anchor-rekor.test.ts`
Expected: import failure.

- [ ] **Step 3: Implement**

`src/anchor/rekor.ts`:

```ts
import type { Anchor, LogKey } from "./types.js";
import type { P256Signer } from "./signer.js";
import { artifactOf, digestOf } from "./artifact.js";
import { buildRequest } from "./body.js";
import { verifyAnchorProof } from "./verify.js";

export interface RekorV2Options {
  /** The instance, e.g. https://log2025-1.rekor.sigstore.dev. Rotates by year; configure, never compile in. */
  url: string;
  /** The log keys the reply must be signed by. From Sigstore's trust root, pinned by the operator. */
  logKeys: ReadonlyArray<LogKey>;
  /** Default 30000. The client guide asks for at least 20 seconds. */
  timeoutMs?: number;
  fetch?: typeof fetch;
  now?: () => string;
}

interface EntryReply {
  logIndex?: string;
  logId?: { keyId?: string };
  canonicalizedBody?: string;
  inclusionProof?: { logIndex?: string; treeSize?: string; rootHash?: string; hashes?: string[]; checkpoint?: { envelope?: string } };
}

/** Submits one anchor to a Rekor v2 log and verifies the reply before returning it. */
export class RekorV2 {
  private readonly url: string;
  private readonly logKeys: ReadonlyArray<LogKey>;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => string;

  constructor(opts: RekorV2Options) {
    this.url = opts.url.replace(/\/+$/, "");
    if (!/^https?:\/\//.test(this.url)) throw new Error("rekor: url must start with http:// or https://");
    this.logKeys = opts.logKeys;
    this.timeoutMs = opts.timeoutMs ?? 30000;
    this.fetchImpl = opts.fetch ?? fetch;
    this.now = opts.now ?? (() => new Date().toISOString());
  }

  async submit(stream: string, seq: number, head: string, signer: P256Signer): Promise<Anchor> {
    const artifact = artifactOf(stream, seq, head);
    const signature = signer.sign(artifact);
    const publicKey = signer.publicKeyDer();
    const res = await this.fetchImpl(`${this.url}/api/v2/log/entries`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(buildRequest(digestOf(artifact), signature, publicKey)),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (res.status !== 201 && res.status !== 200) {
      throw new Error(`rekor: ${res.status} ${(await res.text()).slice(0, 200)}`);
    }
    const reply = (await res.json()) as EntryReply;
    const p = reply.inclusionProof;
    if (!reply.logIndex || !reply.logId?.keyId || !reply.canonicalizedBody || !p?.logIndex || !p.treeSize || !p.rootHash || !p.hashes || !p.checkpoint?.envelope) {
      throw new Error("rekor: reply is missing fields");
    }
    const anchor: Anchor = {
      v: 1, stream, seq, head, at: this.now(),
      witness: { alg: "ecdsa-p256", publicKey },
      signature,
      log: { url: this.url, keyId: reply.logId.keyId },
      entry: { logIndex: reply.logIndex, canonicalizedBody: reply.canonicalizedBody },
      proof: { logIndex: p.logIndex, treeSize: p.treeSize, rootHash: p.rootHash, hashes: p.hashes, checkpoint: p.checkpoint.envelope },
    };
    const check = verifyAnchorProof(anchor, { logKeys: this.logKeys, witnessKeys: [publicKey] });
    if (!check.ok) throw new Error(`rekor: reply did not verify, ${check.reason}`);
    return anchor;
  }
}
```

Append to `src/anchor/index.ts`:

```ts
export { RekorV2 } from "./rekor.js";
export type { RekorV2Options } from "./rekor.js";
```

- [ ] **Step 4: Run, then commit**

Run: `npm run build && npm run typecheck && npm test`
Expected: green; the live test reports skipped. Then once, by hand: `REKOR_LIVE=1 npx tsx --test test/anchor-rekor.test.ts` and record the log index it prints in the task report. It writes one throwaway entry to the public log.

```bash
git add src/anchor/rekor.ts src/anchor/index.ts test/anchor-rekor.test.ts
git commit -m "anchor: the Rekor v2 client, verified reply or no anchor

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: Anchor stores

**Files:**
- Create: `src/anchor/store.ts`
- Modify: `src/anchor/index.ts`
- Test: `test/anchor-store.test.ts`

**Interfaces:**
- Consumes: `AnchorStore`, `Anchor`, `SqlClient` from `../postgres.js`.
- Produces: `MemoryAnchorStore`, `anchorSchema(table?): string[]`, `PostgresAnchorStore(client, { table? })` with `open()`, `append(a)`, `list(stream, sinceSeq?)`, `last(stream)`.

- [ ] **Step 1: Failing tests**

`test/anchor-store.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { PGlite } from "@electric-sql/pglite";
import { MemoryAnchorStore, PostgresAnchorStore, anchorSchema } from "../src/anchor/store.js";
import { P256Signer } from "../src/anchor/signer.js";
import type { AnchorStore } from "../src/anchor/types.js";
import { FakeLog } from "./helpers/fake-log.js";
import { anchorWith, chainOf } from "./helpers/anchors.js";

async function exercise(name: string, make: () => Promise<AnchorStore>) {
  await test(`${name}: append, list since, last, and the unique seq rule`, async () => {
    const store = await make();
    const log = new FakeLog();
    const signer = P256Signer.generate();
    const records = chainOf(5);
    const a1 = anchorWith(log, signer, "purse", 1, records[1]!.hash);
    const a3 = anchorWith(log, signer, "purse", 3, records[3]!.hash);
    const other = anchorWith(log, signer, "other", 0, records[0]!.hash);
    assert.equal(await store.last("purse"), null);
    await store.append(a3);
    await store.append(a1);
    await store.append(other);
    assert.deepEqual((await store.list("purse")).map((a) => a.seq), [1, 3], "ordered by seq regardless of insert order");
    assert.deepEqual((await store.list("purse", 1)).map((a) => a.seq), [3]);
    assert.deepEqual(await store.last("purse"), a3);
    assert.deepEqual(await store.list("other"), [other]);
    await assert.rejects(store.append({ ...a3, head: "d".repeat(64) }), /unique|exists|duplicate/i);
    assert.deepEqual(await store.last("purse"), a3, "a rejected append changes nothing");
  });
}

await exercise("MemoryAnchorStore", async () => new MemoryAnchorStore());
await exercise("PostgresAnchorStore on PGlite", async () => {
  const db = new PGlite();
  const store = new PostgresAnchorStore(db, { table: "anchors_test" });
  await store.open();
  await store.open();
  return store;
});

test("anchorSchema rejects a bad table name and open is idempotent", async () => {
  assert.throws(() => anchorSchema("drop table"), /invalid table name/);
  const db = new PGlite();
  const store = new PostgresAnchorStore(db);
  await store.open();
  await store.open();
  const { rows } = await db.query("SELECT count(*)::int AS n FROM anchors");
  assert.equal((rows[0] as { n: number }).n, 0);
});
```

- [ ] **Step 2: Run to see them fail**

Run: `npx tsx --test test/anchor-store.test.ts`
Expected: import failure.

- [ ] **Step 3: Implement**

`src/anchor/store.ts`:

```ts
import type { SqlClient } from "../postgres.js";
import type { Anchor, AnchorStore } from "./types.js";

/** In-memory, for tests and single-process witnesses that do not need durability. */
export class MemoryAnchorStore implements AnchorStore {
  private readonly rows: Anchor[] = [];

  async append(a: Anchor): Promise<void> {
    if (this.rows.some((r) => r.stream === a.stream && r.seq === a.seq)) {
      throw new Error(`anchor exists for stream ${a.stream} seq ${a.seq}`);
    }
    this.rows.push(structuredClone(a));
  }

  async list(stream: string, sinceSeq = -1): Promise<Anchor[]> {
    return this.rows
      .filter((r) => r.stream === stream && r.seq > sinceSeq)
      .sort((x, y) => x.seq - y.seq)
      .map((r) => structuredClone(r));
  }

  async last(stream: string): Promise<Anchor | null> {
    const all = await this.list(stream);
    return all.length ? all[all.length - 1]! : null;
  }
}

const IDENT = /^[a-z_][a-z0-9_]*$/;

/** The schema, as executed by open(). Exposed so operators can run it themselves. */
export function anchorSchema(table = "anchors"): string[] {
  if (!IDENT.test(table) || table.length > 63) {
    throw new Error(`PostgresAnchorStore: invalid table name "${table}" (letters, digits, underscores, max 63)`);
  }
  return [
    `CREATE TABLE IF NOT EXISTS ${table} (
  n BIGSERIAL PRIMARY KEY,
  stream TEXT NOT NULL,
  seq BIGINT NOT NULL,
  head TEXT NOT NULL,
  at TIMESTAMPTZ NOT NULL,
  record TEXT NOT NULL,
  UNIQUE (stream, seq)
)`,
  ];
}

/**
 * Append-only anchors beside the receipts. `record` is the canonical Anchor
 * JSON, read back verbatim. Nothing here updates or deletes.
 */
export class PostgresAnchorStore implements AnchorStore {
  private readonly table: string;

  constructor(private readonly client: SqlClient, opts: { table?: string } = {}) {
    this.table = opts.table ?? "anchors";
    anchorSchema(this.table);
  }

  async open(): Promise<void> {
    for (const sql of anchorSchema(this.table)) await this.client.query(sql);
  }

  async append(a: Anchor): Promise<void> {
    await this.client.query(
      `INSERT INTO ${this.table} (stream, seq, head, at, record) VALUES ($1, $2, $3, $4, $5)`,
      [a.stream, a.seq, a.head, a.at, JSON.stringify(a)],
    );
  }

  async list(stream: string, sinceSeq = -1): Promise<Anchor[]> {
    const { rows } = await this.client.query(
      `SELECT record FROM ${this.table} WHERE stream = $1 AND seq > $2 ORDER BY seq`,
      [stream, sinceSeq],
    );
    return rows.map((r) => JSON.parse(String(r.record)) as Anchor);
  }

  async last(stream: string): Promise<Anchor | null> {
    const { rows } = await this.client.query(
      `SELECT record FROM ${this.table} WHERE stream = $1 ORDER BY seq DESC LIMIT 1`,
      [stream],
    );
    const r = rows[0];
    return r ? (JSON.parse(String(r.record)) as Anchor) : null;
  }
}
```

Append to `src/anchor/index.ts`:

```ts
export { MemoryAnchorStore, PostgresAnchorStore, anchorSchema } from "./store.js";
```

- [ ] **Step 4: Run, then commit**

Run: `npm run build && npm run typecheck && npm test`
Expected: green, including the three store tests.

```bash
git add src/anchor/store.ts src/anchor/index.ts test/anchor-store.test.ts
git commit -m "anchor: memory and Postgres anchor stores, append-only

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: The receipt-verify CLI, README, CHANGELOG

**Files:**
- Create: `src/cli.ts`
- Modify: `README.md`, `CHANGELOG.md`
- Test: `test/cli.test.ts`

**Interfaces:**
- Consumes: `verifyAnchored`, `Anchor`, `AnchorTrust`, `Receipt`.
- Produces: `dist/cli.js` as the `receipt-verify` bin.

- [ ] **Step 1: Failing test**

`test/cli.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { P256Signer } from "../src/anchor/signer.js";
import { FakeLog } from "./helpers/fake-log.js";
import { anchorWith, chainOf } from "./helpers/anchors.js";

const CLI = join(process.cwd(), "dist", "cli.js");
const run = (args: string[]) => execFileSync(process.execPath, [CLI, ...args], { encoding: "utf8", stdio: "pipe" });

function files() {
  const dir = mkdtempSync(join(tmpdir(), "receipt-verify-"));
  const log = new FakeLog();
  const signer = P256Signer.generate();
  const records = chainOf(4);
  const a = anchorWith(log, signer, "purse", 3, records[3]!.hash);
  const chain = join(dir, "chain.jsonl");
  writeFileSync(chain, records.map((r) => JSON.stringify(r)).join("\n") + "\n");
  const chainJson = join(dir, "chain.json");
  writeFileSync(chainJson, JSON.stringify(records));
  const anchors = join(dir, "anchors.json");
  writeFileSync(anchors, JSON.stringify({ anchors: [a] }));
  return { dir, log, signer, records, chain, chainJson, anchors };
}

test("receipt-verify passes a good chain and prints the result", () => {
  const f = files();
  const out = JSON.parse(run([f.chain, "--anchors", f.anchors, "--log-key", `${f.log.origin}=${f.log.publicKeyDer}`, "--witness-key", f.signer.publicKeyDer()])) as { ok: boolean; coveredUpTo: number };
  assert.equal(out.ok, true);
  assert.equal(out.coveredUpTo, 3);
  const out2 = JSON.parse(run([f.chainJson, "--anchors", f.anchors, "--log-key", `${f.log.origin}=${f.log.publicKeyDer}`, "--witness-key", f.signer.publicKeyDer()])) as { ok: boolean };
  assert.equal(out2.ok, true, "a JSON array chain works too");
});

test("receipt-verify exits 1 on a rewritten chain and names the seq", () => {
  const f = files();
  const cut = join(f.dir, "cut.jsonl");
  writeFileSync(cut, f.records.slice(0, 2).map((r) => JSON.stringify(r)).join("\n"));
  let code = 0; let stdout = "";
  try { stdout = run([cut, "--anchors", f.anchors, "--log-key", `${f.log.origin}=${f.log.publicKeyDer}`, "--witness-key", f.signer.publicKeyDer()]); }
  catch (e) { const err = e as { status: number; stdout: string }; code = err.status; stdout = err.stdout; }
  assert.equal(code, 1);
  assert.match(stdout, /record missing at seq 3/);
});

test("receipt-verify exits 2 with usage when a key is missing", () => {
  const f = files();
  assert.throws(() => run([f.chain, "--anchors", f.anchors]), (e: unknown) => (e as { status: number }).status === 2);
});
```

- [ ] **Step 2: Run to see it fail**

Run: `npm run build && npx tsx --test test/cli.test.ts`
Expected: `dist/cli.js` not found.

- [ ] **Step 3: Implement**

`src/cli.ts`:

```ts
#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { verifyAnchored } from "./anchor/verify.js";
import type { Anchor, AnchorTrust } from "./anchor/types.js";
import type { Receipt } from "./types.js";

const args = process.argv.slice(2);

function usage(): never {
  process.stderr.write(
    "receipt-verify <chain.json | chain.jsonl> --anchors <file | witness url> --log-key <origin>=<base64 DER> [--log-key ...] --witness-key <base64 DER> [--witness-key ...]\n",
  );
  process.exit(2);
}

const positional = args.filter((a, i) => !a.startsWith("--") && !(i > 0 && args[i - 1]!.startsWith("--")));
const values = (name: string): string[] => args.flatMap((a, i) => (a === name && args[i + 1] !== undefined ? [args[i + 1]!] : []));

const chainFile = positional[0];
const anchorsArg = values("--anchors")[0];
if (!chainFile || !anchorsArg || args.includes("--help") || args.includes("-h")) usage();

const trust: AnchorTrust = {
  logKeys: values("--log-key").map((v) => {
    const i = v.indexOf("=");
    if (i <= 0) usage();
    return { origin: v.slice(0, i), publicKey: v.slice(i + 1) };
  }),
  witnessKeys: values("--witness-key"),
};
if (trust.logKeys.length === 0 || trust.witnessKeys.length === 0) usage();

function readRecords(file: string): Receipt[] {
  const text = readFileSync(file, "utf8").trim();
  if (text.startsWith("[")) return JSON.parse(text) as Receipt[];
  return text.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line) as Receipt);
}

async function readAnchors(src: string): Promise<Anchor[]> {
  let text: string;
  if (/^https?:\/\//.test(src)) {
    const res = await fetch(src.replace(/\/+$/, "") + "/anchors");
    if (!res.ok) throw new Error(`anchors: ${res.status} from ${src}`);
    text = await res.text();
  } else {
    text = readFileSync(src, "utf8");
  }
  const j = JSON.parse(text) as Anchor[] | { anchors: Anchor[] };
  return Array.isArray(j) ? j : j.anchors;
}

async function main(): Promise<void> {
  const result = verifyAnchored(readRecords(chainFile), await readAnchors(anchorsArg), trust);
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  process.exit(result.ok ? 0 : 1);
}

main().catch((e) => {
  process.stderr.write(`receipt-verify: ${(e as Error).message}\n`);
  process.exit(2);
});
```

- [ ] **Step 4: README and CHANGELOG**

Append this section to `README.md` before its final "Connected" or license line if one exists, otherwise at the end. No colons in the prose outside code and URLs.

````markdown
## Anchoring the head

A chain in your own hands is tamper-evident to you and meaningless to everyone else, because whoever holds the whole log can rebuild it. The `anchor` subpath commits the head to a public transparency log and lets anyone verify the chain against those commitments with nothing from the writer.

```ts
import { RekorV2, P256Signer, verifyAnchored, PostgresAnchorStore } from "@olurabian/receipt/anchor";

const signer = P256Signer.fromPem(readFileSync(process.env.WITNESS_KEY_FILE, "utf8"));
const rekor = new RekorV2({ url: process.env.REKOR_URL, logKeys: [{ origin: "log2025-1.rekor.sigstore.dev", publicKey: process.env.REKOR_LOG_KEY }] });
const anchor = await rekor.submit("purse", records.length - 1, records.at(-1).hash, signer);   // verified before it returns
await anchors.append(anchor);

const result = verifyAnchored(records, await anchors.list("purse"), { logKeys: [...], witnessKeys: [signer.publicKeyDer()] });
// { ok, coveredUpTo, anchors: [{ seq, ok, reason?, logIndex, cosigned }], chain }
```

What an anchor proves. Everything at or below `coveredUpTo` is what it was when the log recorded the head. A rewrite there breaks the anchor and is named by seq. A truncation there is a missing record and is named too. Above `coveredUpTo` the chain is tamper-evident only. Order is proven by the log index. Wall-clock time is not, the `at` field is the witness clock.

The two keys you pin. This package ships neither.

1. The log key. In the `sigstore/root-signing` repository, `targets/trusted_root.json`, the `tlogs` entry whose `baseUrl` is your `REKOR_URL`, field `publicKey.rawBytes`. Its C2SP key id, `checkpointKeyId(origin, key)`, must equal the `logId.keyId` a reply carries.
2. The witness key. The witness prints its public key on first run and serves it on `GET /`. Pin it the way you pin an SSH host key. A rotated witness is a new key; old anchors stay valid under the old one.

The verifier from the command line, with the chain from the broker's audit endpoint and the anchors from a witness.

```sh
npx receipt-verify chain.jsonl --anchors https://witness.example.com \
  --log-key log2025-1.rekor.sigstore.dev=<base64 DER> \
  --witness-key <base64 DER>
```

Exit 0 when `ok`, 1 when the chain or an anchor fails, 2 on a usage or read error. The public instance's URL rotates by year, so configure it, never compile it in. Only Ed25519 log keys are supported for checkpoints in this version.
````

Prepend to `CHANGELOG.md` under the heading style it already uses:

```markdown
## 0.3.0

- New subpath `@olurabian/receipt/anchor`. Anchors a chain head to a Rekor v2 transparency log and verifies a chain against its anchors, `verifyAnchored`, with RFC 6962 inclusion proofs and C2SP checkpoint verification on `node:crypto`. Zero dependencies still.
- `RekorV2` client that verifies every reply before returning an anchor, `P256Signer` for the witness key, `MemoryAnchorStore` and `PostgresAnchorStore`.
- `receipt-verify` command.
- Test fixtures captured from a real public log entry, public data only.
```

- [ ] **Step 5: Run, then commit**

Run: `npm run build && npm run typecheck && npm test && npm pack --dry-run 2>&1 | grep -E "dist/cli.js|dist/anchor/index.js"`
Expected: green, both files listed, no bin warning.

Sweep: `grep -nE "^[^\`#|].*(:|—)" README.md | grep -v "https\?://"` returns only lines inside code fences or none.

```bash
git add src/cli.ts test/cli.test.ts README.md CHANGELOG.md
git commit -m "receipt-verify, the README section on anchoring, and the 0.3.0 changelog

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8: Gate and final review

- [ ] **Step 1:** `rm -rf node_modules dist && npm ci --no-audit --no-fund && npx allow-scripts && npm run build && npm run typecheck && npm test` in the receipt repo. All green, live test skipped.
- [ ] **Step 2:** `npm pack --dry-run` lists `dist/anchor/*.js`, `dist/anchor/*.d.ts`, `dist/cli.js`, README, LICENSE, no fixtures, no tests. `package.json` has no `dependencies` key.
- [ ] **Step 3:** Confirm nothing published: `npm view @olurabian/receipt version` is `0.2.0`.
- [ ] **Step 4:** Final review on the most capable model over the whole subpath with the Global Constraints as the lens, with attention to: every verification step in the spec has a test that fails when it is skipped; `verifyAnchorProof` never trusts a value it did not recompute (digest, key id, root); the checkpoint verifier cannot be satisfied by a cosigner's line; `RekorV2` cannot return an unverified anchor; the CLI cannot exit 0 on a failed result; the README's two pins are right; no colon or em dash in README prose.

---

### Task 9: Release (only after ARABA confirms)

`main` is protected. The release is: push the branch, wait for the checks on the release commit, fast-forward `main`, then publish.

```bash
cd /c/Users/ARABA/Workspace/SaaS/receipt
git push origin HEAD:release/anchor-0.3.0
# wait until the `test` and `gitleaks (secrets)` check-runs on this SHA are success
gh api repos/ArabianAnalyst/receipt/commits/$(git rev-parse HEAD)/check-runs --jq '[.check_runs[] | {name, conclusion}]'
git push origin main
git push origin --delete release/anchor-0.3.0
npm run build && npm run typecheck && npm test && npm pack --dry-run && npm publish --access public && npm view @olurabian/receipt version
```

Expected `0.3.0`. Smoke from a clean directory: `npm i @olurabian/receipt@0.3.0` then `node -e "import('@olurabian/receipt/anchor').then(m => console.log(Object.keys(m).length))"` prints a number above 20, and `npx receipt-verify --help` prints usage and exits 2.

## Self-review

**Spec coverage.** Verifier promise and its five steps (Task 4). Artifact format (Task 1). Anchor record and `seq` semantics (Task 1 types). Rekor v2 request, reply, leaf hash, inclusion, checkpoint, key id rule, cosigners reported not required (Tasks 1, 2, 5). Subpath exports as listed in the spec (Tasks 1 to 6; `checkpointKeyId`, `leafHashOf`, `verifyInclusion`, `verifyCheckpoint`, `artifactOf`, `P256Signer`, `RekorV2`, `AnchorStore`, `MemoryAnchorStore`, `PostgresAnchorStore`). The spec's `verifyInclusion(leafHash, proof)` signature is kept; `verifyInclusionPath` is the lower-level form. `anchors` table schema exactly as the spec (Task 6). CLI flags and exit codes (Task 7). No log key shipped, untrusted key reasons (Tasks 2, 4). Reply verified before return (Task 5). Tests listed in the spec: fixture-backed unit tests (Tasks 1 to 3), property tests for rewrite, truncation, rotation, untrusted key, purity (Task 4), live test gated (Task 5). The witness process, the broker's `anchoredUpTo`, and blackbox are Plan 2, not here.

**Placeholder scan.** None. Every code step carries its code.

**Type consistency.** `InclusionProof.checkpoint` is the envelope string everywhere (types, fixture helper, FakeLog, RekorV2, verify). `AnchorTrust.logKeys` is `ReadonlyArray<LogKey>` and `witnessKeys` `ReadonlyArray<string>`; `RekorV2` passes `this.logKeys` as is. `verifyCheckpoint` returns `size` and `root` as strings compared with `proof.treeSize` and `proof.rootHash`, both strings. `FakeLog.add` takes `RekorRequest`; `buildRequest` returns `RekorRequest`; the signer test casts with `as never` only where the reply type is not needed. `anchorWith` returns an `Anchor` shaped exactly as `RekorV2.submit` builds it.
