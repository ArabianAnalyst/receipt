# Postgres store design (approved 2026-09-04)

## Goal

Give `@olurabian/receipt` a production store so a partner can run Purse and blackbox against Postgres instead of a JSONL file, with no change to either product's synchronous API. This is Phase 0 of the Deadlatch roadmap, item "Postgres audit store". The definition of done for the phase is a broker running against Postgres, routing a spend, producing a receipt that verifies, in under an hour from the docs alone.

Decision taken by ARABA: **write-through with the synchronous API kept.** The alternatives (an async contract across the stack, or Postgres as a read-only mirror) were rejected for blast radius and for failing the definition of done respectively.

## Shape

`PostgresStore<P>` implements the existing synchronous `Store<P>` (`lastHash()`, `append()`, `all()`) and adds three members:

```ts
static open<P>(client: SqlClient, opts?: PostgresStoreOptions): Promise<PostgresStore<P>>
flush(): Promise<void>      // resolves when every queued append is durable; rejects with the latched error
pending(): number           // appends queued but not yet durable
```

```ts
interface SqlClient {
  query(text: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}
interface PostgresStoreOptions {
  stream?: string;        // default "default". One table serves many products; each product is one stream.
  table?: string;         // default "receipts"
  migrate?: boolean;      // default true. Runs CREATE TABLE IF NOT EXISTS and the indexes on open.
  retries?: number;       // default 3. Transient insert failures retried with backoff before latching.
}
```

The package stays zero-dependency. `SqlClient` is satisfied directly by `pg` (`Client`/`Pool`), by `@neondatabase/serverless` (`Pool`), and by `@electric-sql/pglite`. postgres.js needs a three-line adapter, shown in the README.

## Schema

One table, many streams. Every column except `record` and `payload` is indexed for queries; `record` is the source of truth.

```sql
CREATE TABLE IF NOT EXISTS receipts (
  seq        BIGSERIAL PRIMARY KEY,
  stream     TEXT        NOT NULL,
  id         TEXT        NOT NULL,
  ts         TIMESTAMPTZ NOT NULL,
  kind       TEXT        NOT NULL,
  prev_hash  TEXT        NOT NULL,
  hash       TEXT        NOT NULL,
  payload    JSONB       NOT NULL,   -- query copy only, never read back for hashing
  record     TEXT        NOT NULL,   -- the exact canonical JSON of the whole receipt
  UNIQUE (stream, id),
  UNIQUE (stream, hash),
  UNIQUE (stream, prev_hash)         -- rejects a fork: two writers on one head cannot both land
);
CREATE INDEX IF NOT EXISTS receipts_stream_seq ON receipts (stream, seq);
```

**Why `record` text and not `payload` jsonb for reload.** Postgres normalises jsonb key order (shorter keys first, then bytewise). A payload read back from jsonb re-stringifies in a different order and no longer hashes to the stored `hash`. Proven on this machine on 2026-09-04: `{"z":1,"a":{...}}` came back as `{"a":{...},"z":1}`. Reload therefore parses `record`, which preserves the producer's bytes exactly. `payload` exists so operators can query decisions in SQL.

**Why `UNIQUE (stream, prev_hash)`.** A hash chain is linear. Two appends that both claim the same previous hash are a fork, which only happens when two processes write one stream. The constraint makes the database refuse the second one. JSONL cannot give this guarantee, which is why the docs describe the JSONL store as single-writer.

## Open and load

`PostgresStore.open(client, opts)`:

1. If `migrate` is true, runs the schema above (idempotent).
2. Selects the stream's rows ordered by `seq`, parses each `record`, and holds them in memory.
3. Runs `verifyChain` over what it loaded. If the chain is broken it throws `PostgresStore: stream "<stream>" fails verification at index N (<reason>)` and does not return a store. A damaged trail is never silently continued, the same stance as the JSONL corrupt-line rule and the Purse 0.2-file rule.
4. Returns a store whose `lastHash()` is the loaded tip.

`open` is the only async step a consumer must await. After it, the store is a normal synchronous `Store<P>`.

## Write-through semantics

- `append(rec)` pushes `rec` onto the in-memory array immediately (so `lastHash()` and `all()` are consistent for the next synchronous call) and enqueues one INSERT carrying every column, with `record = JSON.stringify(rec)`.
- Inserts run strictly in order, one in flight at a time, so `seq` order equals chain order.
- `flush()` returns a promise that resolves once the queue is empty and the last insert has committed. Purse's broker awaits it before money moves (below).
- A transient failure (connection reset, timeout) is retried `retries` times with backoff (100 ms, 400 ms, 1600 ms). A unique-constraint violation is never retried: it means a fork or a duplicate and is a hard error.
- The first hard error **latches** the store as degraded. From then on `append()` throws synchronously with the latched message, `flush()` rejects with it, and `pending()` still reports the backlog. Recovery is an operator action: fix the database, restart the process, `open` reloads and re-verifies. A queue that fails is never silently dropped and never silently retried forever.
- `all()` returns a copy of the in-memory array, as `MemoryStore` does. Memory holds the whole stream in this version; a windowed load is a later phase.

## Consumers

**Purse (0.3.0 → 0.3.1).** `PurseOptions.store` and `BrokerOptions.store` already accept any `Store<DecisionPayload>`, so no constructor change. Two behavioural additions:

- `Broker.execute(grantId)` awaits `store.flush()` (when the store has one) after it records the claim and **before** it calls the executor, and again after it records the execution outcome and before it returns. A spend never executes ahead of its durable decision, and `execute()` never resolves ahead of its durable receipt. If `flush()` rejects, `execute()` records nothing further and rethrows, so the money path fails closed.
- `Purse.flush()` and `Broker.flush()` passthroughs (no-ops on stores without `flush`) for graceful shutdown.
- `Purse.authorize()` stays synchronous. Its receipt is durable within the next event-loop turn under normal operation, and the README says so.

**blackbox (0.2.0).** `createRecorder({ store })` already accepts any `Store<ActionPayload>`. README gains a Postgres example. No code change, no publish.

**Tripwire, deadlatch-otel.** Unchanged.

## Testing

Real SQL, no mocks, via `@electric-sql/pglite` as a devDependency of `receipt`:

- open migrates an empty database and returns GENESIS as the tip
- append then reopen continues the chain and verifies
- a payload with integer-like and non-ASCII keys survives a round trip (proves `record`, not jsonb, is read back)
- inserts land in append order under a burst of appends
- a second store on the same stream that appends on the same head is rejected and latches (fork)
- a broken row in the database makes `open` throw
- `flush()` resolves only after the last insert; `pending()` counts down
- a latched store throws from `append()` and rejects `flush()`

Purse: a test with a store whose `flush()` records call order proves `execute()` flushes before the executor runs and before it returns, and that a rejecting `flush()` stops the executor from running.

## Docs

- receipt README: a "Postgres" section with the `pg` and Neon examples, the postgres.js adapter, the stream rule (one writer per stream, the database enforces it), and what "degraded" means.
- Purse README: a "Production store" section showing `await PostgresStore.open(...)` passed as `store`, the `execute()` flush guarantee, and the `authorize()` note.
- blackbox README: the same example for the recorder.
- CHANGELOG entries for receipt 0.2.0 and purse 0.3.1.

## Non-goals

An asynchronous store contract or async product APIs. Bundling a database driver. The broker Docker image and env wiring (the next Phase 0 item). Schema migration tooling beyond the idempotent create. Windowed or paged loading. Multi-writer streams. Per-receipt signatures and external anchoring remain later phases.
