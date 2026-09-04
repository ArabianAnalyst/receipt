# Receipt engine design (approved 2026-09-04)

## Goal

Extract the hash-chain engine that Purse and blackbox each carry as ~50 lines of near-identical code into one zero-dependency package, `@olurabian/receipt`, so that:

- there is **one receipt spec** across the Deadlatch stack (enforce, prove, watch),
- there is **one verifier** any third party (an evidence hub, a peer tool, an auditor) can `npm i` to check a chain without trusting the writer,
- Purse and blackbox keep their public names and stay free of third-party dependencies.

This is Phase 0, Week 1 of the Deadlatch roadmap. Decision taken by ARABA: *extract the engine* (not spec-only).

## The receipt (spec v1)

```ts
interface Receipt<P = unknown> {
  id: string;        // uuid
  ts: string;        // ISO-8601
  kind: string;      // "decision" (Purse) | "action" (blackbox) | future kinds
  payload: P;        // the typed, kind-specific body
  prevHash: string;  // previous receipt's hash, or GENESIS (64 zeros) for the first
  hash: string;      // sha256 hex over the canonical form below
}
```

**Canonicalization (the only thing a verifier must match byte-for-byte):**

```
hash = sha256( JSON.stringify({ id, ts, kind, payload, prevHash }) )   // exactly this key order
```

`payload` is serialized as constructed by the producer; `JSON.stringify` drops `undefined` fields, so optional fields that were never set do not change the hash. `GENESIS = "0".repeat(64)`.

**Chain rules:** `records[0].prevHash === GENESIS`; `records[i].prevHash === records[i-1].hash`; every `hash` recomputes from its own contents. Altering, inserting, removing, or reordering any receipt breaks one of these.

**Verify result:**

```ts
interface VerifyResult { ok: boolean; brokenAt?: number; id?: string; reason?: string }
```

`brokenAt` is the index of the first broken receipt (matches Purse's existing semantics and deadlatch-otel's `VerifyResultLike`); `id` is that receipt's id (what blackbox reported before).

## Package API (`@olurabian/receipt` 0.1.0)

- `GENESIS`
- `canonicalize(rec)`, `hashRecord(rec)`, `verifyChain(records)`
- `makeReceipt(store, { kind, payload }, { now?, newId? })` — assigns id, ts, prevHash, hash and appends
- `MemoryStore<P>`, `JsonlStore<P>(path?)` — append-only; `JsonlStore` without a path is in-memory, with a path it persists one JSON line per receipt and reloads on construction
- Types: `Receipt<P>`, `ReceiptInput<P>`, `Store<P>`, `VerifyResult`, `MakeOptions`

Zero runtime dependencies. Node ≥ 18. ESM, TypeScript strict, `NodeNext`. Tests use `node:test` via `tsx --test`.

## Consumers

**Purse (0.2.2 → 0.3.0).** `AuditRecord` becomes `Receipt<DecisionPayload>` where `DecisionPayload = { request, status, reason, policyVersion, event?, explain?, grantId?, receipt? }` and `kind = "decision"`. `audit.ts` becomes a thin adapter: `JsonlAuditStore` (name kept, extends `JsonlStore<DecisionPayload>`), `makeRecord(store, input)` (signature kept, wraps `makeReceipt`), and re-exports of `verifyChain`, `hashRecord`, `GENESIS`. `broker.ts` needs no changes. Internal reads move from `r.status` to `r.payload.status`.

**blackbox (0.1.1 → 0.2.0).** `ActionRecord` becomes `Receipt<ActionPayload>` where `ActionPayload = { action, input?, outcome, error?, latencyMs?, cost?, meta? }` and `kind = "action"`. `MemoryStore`/`JsonlStore` names kept (thin subclasses). `hash.ts` re-exports the engine. `query()` filters on `payload`.

**Tripwire (0.1.0 → 0.1.1).** `fromBlackbox()` accepts receipt envelopes (unwraps `payload`) as well as bare action records.

**deadlatch-otel (0.1.0 → 0.1.1).** `instrumentRecorder` reads `action`/`outcome` from `rec.payload` when present, falling back to the flat shape, so both blackbox generations are instrumented.

## Breaking change, and why now

Nesting fields under `payload` is a breaking change for anyone reading Purse or blackbox records directly. It is taken now because (a) the integrator has not yet built ingestion against the old flat shape, so the handover to the integrator is regenerated as spec v1 before he codes, and (b) it is the price of one verifier for the whole stack. Pre-1.0 minor bumps signal the break.

## Supply chain

Every repo in this change gets LavaMoat `allow-scripts` (`.npmrc ignore-scripts=true`, an explicit allowlist, `npx allow-scripts` in CI). Purse already has it; blackbox, tripwire, deadlatch-otel, and the new receipt package get it in this plan.

## Non-goals (later phases)

Per-receipt signatures (ed25519), a Postgres store, external anchoring (the Witness), and any change to Tripwire's own record type. `@olurabian/receipt` is designed so those layer on without changing the envelope.
