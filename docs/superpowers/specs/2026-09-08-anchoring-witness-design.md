# Anchoring the chain head, the witness (approved 2026-09-08)

## Goal

A hash chain proves no single entry was edited. It does not prove the record was not rebuilt, and it cannot see truncation at the tail. This item commits the chain head to a place the writer cannot reach and anyone can read, so a rewrite or a truncation after any anchor is detected and named by position. Deadlatch roadmap Phase 1, item 1.3. The public argument is the log post "A Log Is Not Proof".

Decisions taken by ARABA on 2026-09-07: the anchor target is **Sigstore Rekor v2**, the public transparency log; the anchorer is **a separate witness process on a schedule**, not the broker; the shape is **approach A**, an `anchor` subpath in `@olurabian/receipt` with zero dependencies plus a witness command in the broker image.

Design sections 1 to 4 were approved in conversation on 2026-09-07 and 2026-09-08. This document is the spec they argued for.

## Two plans, one spec

1. **Receipt** (this repository): the `anchor` subpath, the stores, the CLI, the fixtures and tests, released as 0.3.0.
2. **Witness** (the purse repository, `deploy/broker`): the witness command, its port and readiness, the compose service and Fly process group, the broker's `anchoredUpTo`, the README section, released as image 0.2.0. It depends on receipt 0.3.0 from the registry.

blackbox's minor follows the second plan as a one-task change.

## What the verifier promises

`verifyAnchored(records, anchors, trust, opts?: { stream?: string })` is pure. For each anchor it checks, in order:

1. The witness signature over the anchored artifact, under the witness key carried in the anchor.
2. The Rekor entry body decodes to a hashedrekord whose digest is the artifact's digest and whose verifier key is that same witness key.
3. The Merkle inclusion of the body's leaf hash against the proof's root hash and tree size.
4. The checkpoint's signature by a log key the caller trusts, with the checkpoint's root and size equal to the proof's.
5. The chain: `records[anchor.seq].hash` equals `anchor.head`.

When the caller names a stream in `opts.stream`, each anchor's own `stream` is checked against it before step 5, and without a named stream every anchor must agree on one stream or all of them fail.

Then it runs `verifyChain` over the records. The result:

```ts
interface AnchoredVerifyResult {
  ok: boolean;                       // chain ok and every anchor ok
  coveredUpTo: number | null;        // highest anchored seq that verified, null when none
  anchors: { seq: number; ok: boolean; reason?: string; logIndex: string; cosigned: string[] }[];
  chain: VerifyResult;
  stream: string | null;             // opts.stream, or the anchors' shared stream, null when there are none
}
```

A rewrite of anything at or before `coveredUpTo` breaks an anchor and is named by `seq`. A truncation below `coveredUpTo` fails because the record at that seq is missing. Anything after `coveredUpTo` is tamper-evident only, the promise the chain already makes, and the number says where that boundary is.

Not promised: wall-clock time. `at` is the witness's clock and is informational. Order is proven by the log index. Omission is the write-ahead boundary, a different item.

## The anchored artifact

The witness anchors a small canonical text, not the bare hash, so an anchor binds the stream and the position and cannot be replayed for another:

```
deadlatch-anchor-v1\n<stream>\n<seq>\n<head>\n
```

UTF-8, `seq` in decimal, `head` in lowercase hex. `digest = sha256(artifact)`. The witness signature is ECDSA P-256 with SHA-256 over the artifact bytes, DER encoded, key details `PKIX_ECDSA_P256_SHA_256`. The hashedrekord's `data.digest` is `digest`. The verifier rebuilds the artifact from the anchor's `stream`, `seq`, `head` and never trusts a digest it did not recompute.

## The anchor record

```ts
interface Anchor {
  v: 1;
  stream: string;
  seq: number;                              // 0-based position of the anchored receipt in the stream
  head: string;                             // that receipt's hash
  at: string;                               // ISO time from the witness clock, informational
  witness: { alg: "ecdsa-p256"; publicKey: string };   // base64 SPKI DER
  signature: string;                        // base64 DER, over the artifact bytes
  log: { url: string; keyId: string };      // the Rekor instance used and its log id (base64, 32 bytes)
  entry: { logIndex: string; canonicalizedBody: string };   // as returned, base64 body
  proof: { logIndex: string; treeSize: string; rootHash: string; hashes: string[]; checkpoint: string };
}
```

`seq` is the position within the stream, 0-based, the index into the array `verifyChain` receives. It is not the receipts table's `seq` column, which is a 1-based serial shared across streams. `InclusionProof` is the type of `proof` above.

Nothing in it is secret. Anchors are published in full.

## Rekor v2, as observed

Captured from a real submission on 2026-09-08 (fixture `test/fixtures/rekor-v2/fixture-entry.json`, a throwaway key and a random head, log index 101306751 on `log2025-1.rekor.sigstore.dev`).

- Write: `POST {REKOR_URL}/api/v2/log/entries`, JSON `{ hashedRekordRequestV002: { digest, signature: { content, verifier: { keyDetails: "PKIX_ECDSA_P256_SHA_256", publicKey: { rawBytes } } } } }`, all base64. Reply 201 in about six seconds. Clients set a timeout of at least twenty seconds.
- Reply: `logIndex` (decimal string), `logId.keyId` (base64, 32 bytes), `kindVersion { kind: "hashedrekord", version: "0.0.2" }`, `integratedTime: "0"` (always, ignore), `inclusionProof { logIndex, rootHash, treeSize, hashes[], checkpoint { envelope } }`, `canonicalizedBody` (base64 of the JSON body). No inclusion promise, no signed entry timestamp.
- Body: `{"apiVersion":"0.0.2","kind":"hashedrekord","spec":{"hashedRekordV002":{"data":{"algorithm":"SHA2_256","digest":"…"},"signature":{"content":"…","verifier":{"keyDetails":"PKIX_ECDSA_P256_SHA_256","publicKey":{"rawBytes":"…"}}}}}}`.
- Leaf hash: RFC 6962, `sha256(0x00 || canonicalizedBody bytes)`. Inclusion proof: RFC 6962 path verification with `logIndex` and `treeSize`, the computed root must equal `rootHash` and the checkpoint's root line.
- Checkpoint: a C2SP signed note. Lines: origin (`log2025-1.rekor.sigstore.dev`), tree size in decimal, root hash in base64, a blank line, then one or more signature lines `— <name> <base64(4-byte key id || signature)>`. The observed checkpoint carried the log's own signature and three co-signatures from independent witnesses (`witness.stagemole.eu`, `staging.witness.transparency.goog/ring-any-bells`, `witness.navigli.sunlight.geomys.org`). The log's signature is the line whose name equals the origin line; the verifier requires that one, verified with the trusted key for that origin, and reports the other signers' names as `cosigned` without verifying them.
- The log key: Ed25519 (`PKIX_ED25519`) for `log2025-1`, published in Sigstore's trust root (`targets/trusted_root.json` in the `sigstore/root-signing` repository, `tlogs[].publicKey.rawBytes`, base64 DER, with `baseUrl` and `validFor`). The 4-byte id in a signature line is the prefix of the C2SP key id, `sha256(origin || 0x0A || 0x01 || raw 32-byte key)` for Ed25519, and the reply's `logId.keyId` is that full hash. The verifier matches a trusted key by computing this id, never by trusting the reply's key id alone.
- The instance URL rotates by year and must not be compiled in. The witness reads it from configuration; each anchor records the URL and key id it used, so old anchors verify after a rotation.

## `@olurabian/receipt` 0.3.0, subpath `@olurabian/receipt/anchor`

Zero dependencies. `node:crypto` for SHA-256, ECDSA P-256, and Ed25519. Global `fetch` for the log.

```ts
export type { Anchor, AnchorTrust, AnchoredVerifyResult, InclusionProof };
export interface AnchorTrust { logKeys: { origin: string; publicKey: string }[]; witnessKeys: string[] }  // base64 SPKI DER
export function verifyAnchored(records: ReadonlyArray<Receipt>, anchors: ReadonlyArray<Anchor>, trust: AnchorTrust, opts?: { stream?: string }): AnchoredVerifyResult;
export function artifactOf(stream: string, seq: number, head: string): Uint8Array;
export function leafHashOf(data: Uint8Array): Uint8Array;
export function verifyInclusion(leafHash: Uint8Array, proof: InclusionProof): boolean;
export function verifyCheckpoint(note: string, logKeys: AnchorTrust["logKeys"]): { ok: boolean; origin: string; size: string; root: string; signedBy?: string; cosigned: string[] };
export function checkpointKeyId(origin: string, publicKeyDer: Uint8Array): string;      // base64, C2SP
export class P256Signer { static generate(): P256Signer; static fromPem(pem: string): P256Signer; toPem(): string; publicKeyDer(): string; sign(bytes: Uint8Array): string }
export class RekorV2 { constructor(opts: { url: string; logKeys: AnchorTrust["logKeys"]; timeoutMs?: number; fetch?: typeof fetch; now?: () => string }); submit(stream: string, seq: number, head: string, signer: P256Signer): Promise<Anchor> }
export function verifyAnchorProof(anchor: Anchor, trust: AnchorTrust): AnchorCheck;
export function verifyArtifactSignature(artifact: Uint8Array, signatureB64: string, publicKeyDerB64: string): boolean;
export function decodeBody(canonicalizedBodyB64: string): HashedRekordBody | null;
export function buildRequest(digest: Uint8Array, signatureB64: string, publicKeyDerB64: string): RekorRequest;
export const KEY_DETAILS: "PKIX_ECDSA_P256_SHA_256";
export interface AnchorStore { append(a: Anchor): Promise<void>; list(stream: string, sinceSeq?: number): Promise<Anchor[]>; last(stream: string): Promise<Anchor | null> }
export class MemoryAnchorStore implements AnchorStore {}
export class PostgresAnchorStore implements AnchorStore { constructor(client: SqlClient, opts?: { table?: string }); open(): Promise<void> }
export const ARTIFACT_PREFIX = "deadlatch-anchor-v1";
export function digestOf(artifact: Uint8Array): Uint8Array;
export function nodeHashOf(left: Uint8Array, right: Uint8Array): Uint8Array;
export function verifyInclusionPath(leafHash: Uint8Array, index: bigint, size: bigint, path: ReadonlyArray<Uint8Array>, root: Uint8Array): boolean;
export function parseCheckpoint(note: string): ParsedCheckpoint;
export function ed25519RawFromSpki(der: Uint8Array): Uint8Array | null;
export function anchorSchema(table?: string): string[];
export function toBase64(bytes: Uint8Array): string;
export function fromBase64(s: string): Uint8Array;
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean;
export function concat(...parts: Uint8Array[]): Uint8Array;
```

`RekorV2.submit` verifies the reply itself with `verifyInclusion` and `verifyCheckpoint` before returning an `Anchor`; a reply that does not verify is an error, never an anchor. The package ships no log key. A verifier handed an anchor whose checkpoint no trusted key signs returns `ok: false` with `reason: "untrusted log key"`.

The `anchors` table, created by `PostgresAnchorStore.open()`:

```sql
CREATE TABLE IF NOT EXISTS anchors (
  n BIGSERIAL PRIMARY KEY,
  stream TEXT NOT NULL,
  seq BIGINT NOT NULL,
  head TEXT NOT NULL,
  at TIMESTAMPTZ NOT NULL,
  record TEXT NOT NULL,
  UNIQUE (stream, seq)
)
```

`record` is the canonical Anchor JSON, read back verbatim. Append-only by contract; nothing in the package updates or deletes.

**CLI.** `bin/receipt-verify.js`, exposed as `receipt-verify`: `receipt-verify <chain.json|chain.jsonl> --anchors <anchors.json | witness url> --log-key <origin>=<base64 DER> --witness-key <base64 DER>` prints the `AnchoredVerifyResult` as JSON and exits 0 only when `ok` is true and at least one anchor verified, 1 when the chain or an anchor fails or nothing was anchored (with one line on stderr saying so), and 2 on a usage or read error. When `--anchors` is a URL it fetches `<url>/anchors`. No interactive mode.

## The witness

Lives in the broker image, `node dist/witness.js`, its own machine or compose service. Same `DATABASE_URL`; it reads `receipts` and writes only `anchors` and `witness_events`. Runtime dependencies stay those the image already has; the witness uses the receipt subpath and `pg`.

**Configuration.** `DATABASE_URL` (required). `WITNESS_STREAM` (default `PURSE_STREAM`, then `purse`). `WITNESS_KEY_FILE` or `WITNESS_KEY_PEM` (at least one; PEM, PKCS8; the file wins when it exists; a missing file is generated on first run, the public key logged and served; `node dist/witness.js keygen` prints a fresh key for a secret store). `WITNESS_TRUSTED_KEYS` (optional, comma-separated public keys of earlier witness keys whose anchors still count on `/verify` and readiness). `REKOR_URL` (default `https://log2025-1.rekor.sigstore.dev`, documented as a rotating value). `REKOR_LOG_KEY` (required; `<origin>=<base64 DER>`, the pinned log key; the README shows where it comes from). `REKOR_TIMEOUT_MS` (default 30000). `WITNESS_INTERVAL_MS` (default 300000). `WITNESS_MAX_LAG` (default 2, intervals). `WITNESS_PORT` (default 8082), `WITNESS_BIND` (default 0.0.0.0). `OTEL_EXPORTER_OTLP_*` as the broker. A misconfiguration is a fatal, specific error at boot.

**The tick.** Load the stream, `verifyChain`. Empty stream: nothing, readiness green. Chain broken: append a `witness_events` row `{ kind: "chain-broken", brokenAt, id, reason }`, anchor nothing, readiness red. Head equal to the last anchor's head: nothing. Head moved: first look for an existing `anchors` row at that seq, by the SQL columns. A well-formed row with the same head signed by a trusted key is adopted as the last anchor; any other row (a different head, an untrusted key, a malformed record) is one `{ kind: "anchor-conflict" }` row per seq and no submission, so a second witness or a corrupt row never causes a resubmission loop. Otherwise `RekorV2.submit(stream, seq, head, signer)`, append the anchor, append `{ kind: "anchored", detail }`, log one line with the log index. Rekor failure: append `{ kind: "anchor-failed", reason }`, retry next tick; readiness stays green while the last anchor is younger than the window.

**Port.** Read-only, no token. `GET /` (service, version, stream, witness public key, log url and key id, interval). `GET /anchors?since=<seq>` (the anchors, newest last). `GET /verify` (runs `verifyAnchored` over the live chain and anchors with the pinned log key and its own witness key, returns the full result). `GET /events?since=<n>` (at most one thousand rows per call). `GET /healthz` (200 when the process is up). `GET /readyz` (200 only when the last tick completed within `WITNESS_MAX_LAG` intervals, the chain verified, and either the head equals the last anchor's head or the last anchor is younger than `WITNESS_MAX_LAG` intervals; otherwise 503 with the reason).

**Key.** One P-256 key per witness. Rotation is a new witness with a new key file; old anchors stay valid because each carries the key that signed it. The key never enters the broker's environment.

**Telemetry.** Spans `deadlatch.witness.tick` and `deadlatch.witness.anchor`, counters `deadlatch.witness.anchors` and `deadlatch.witness.failures`, gauge `deadlatch.witness.lag` (receipts appended since the last anchor), through `@opentelemetry/api` on the SDK the image already starts when the OTLP endpoint is set, service name `purse-witness`.

**The broker.** Admin `GET /verify` gains `anchoredUpTo` (seq) and `anchors` (count) read from the `anchors` table when it exists, `null` when it does not.

## blackbox

`verify(records, { anchors, trust })` accepts anchors and returns `coveredUpTo` alongside its result. No change to the record shape. Minor release.

## Trust and pinning

Two keys make an anchor meaningful, and neither comes from this code:

- The log key, from Sigstore's trust root, pinned by the operator in `REKOR_LOG_KEY` and by the verifier in `--log-key`. The README shows the exact file and field, and the check that the computed key id matches the reply's `logId.keyId`.
- The witness key, generated by the operator's witness and published by it on `GET /`. A verifier pins it the way they pin an SSH host key.

A sceptic needs nothing from the operator beyond those two public keys and the chain, and nothing from this project beyond a verifier they can read.

## Failure modes

- Witness key file lost: old anchors verify under the old public key, new anchors come from a new key, `GET /` shows the new key. Documented, not handled.
- Rekor down: lag grows, readiness goes red, nothing else. No local fallback that pretends to be an anchor.
- Rekor instance rotated: new anchors carry the new URL and key id; old anchors still verify against the old key, which the trust root keeps with `validFor`.
- Anchors from an untrusted witness key: the verifier says so and fails.
- Two witnesses on one stream: both anchor the same heads; `UNIQUE (stream, seq)` means the second insert for a seq fails and is logged as an event. Run one witness per stream.

## Testing

- Unit tests on the proof math against the captured fixture: leaf hash, inclusion proof, checkpoint parse and Ed25519 verification with the real `log2025-1` key, key id derivation, and the hashedrekord body decode. The fixture is public data; no private key is committed.
- Property tests: any single-byte change in any record at or below `coveredUpTo` fails an anchor by that seq; truncation below `coveredUpTo` fails; a rotated witness key keeps old anchors valid; an untrusted log key fails with the named reason; `verifyAnchored` is pure.
- Witness integration on PGlite with a fake Rekor that returns real proof structures built from the fixture, covering the tick's four branches and readiness.
- One live test, skipped unless `REKOR_LIVE=1`, that submits a throwaway artifact to the public instance and verifies the reply with the pinned key.
- Existing suites stay green; receipt's colon and em-dash sweep extends to any new prose the package prints.

## Rollout

1. Receipt 0.3.0, the subpath and the CLI. Own go.
2. Broker image 0.2.0, the witness command, compose `witness` service, `fly.toml` second process group, the broker's `anchoredUpTo`, README section "The witness" with the two pins. Own go.
3. Fly reference deployment gains a witness machine in its own process group with the key as `WITNESS_KEY_PEM` (Fly volumes mount root-owned and the image runs as a non-root user; Fly secrets are app-wide, so the broker machines receive the variable too and never read it); its `GET /verify`, reached by machine exec, is the artefact. A log follow-up on deadlatch.dev shows a real anchor and the verifier call.
4. blackbox minor.

## Definition of done

A sceptic, given only the reference deployment's public witness URL, the chain from the broker's `/audit`, Sigstore's published log key, and the witness's published key, runs `receipt-verify` and gets `ok: true, coveredUpTo: N` with nothing from this project in the trust set beyond the verifier they can read. Then one receipt is rewritten in a copy and the same command names the seq.

## Non-goals

Wall-clock time (a follow-up with an RFC 3161 timestamp from Sigstore's timestamp authority). Omission, the write-ahead boundary. Per-receipt signing. The hosted witness. Anchoring Tripwire's own records. A browser verifier. Requiring co-signatures from external witnesses (reported, not required, in this version).
