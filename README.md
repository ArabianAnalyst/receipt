# @olurabian/receipt

The Deadlatch receipt. A zero-dependency, hash-chained record envelope that a third party can verify without trusting the writer. It is the engine under [Purse](https://github.com/ArabianAnalyst/purse) (`kind: "decision"`) and [blackbox](https://github.com/ArabianAnalyst/blackbox) (`kind: "action"`), published on its own so anyone can verify a chain with one install.

```bash
npm i @olurabian/receipt
```

This package is ESM only and needs Node 18 or newer. Use `import`, not `require`.

```ts
import { makeReceipt, verifyChain, JsonlStore } from "@olurabian/receipt";

const store = new JsonlStore("receipts.jsonl");
makeReceipt(store, { kind: "decision", payload: { payee: "api.stripe.com", amount: 1200, status: "allowed" } });

verifyChain(store.all()); // { ok: true }
// after any edit, insert, removal, or reorder:
// { ok: false, brokenAt: 0, id: "…", reason: "hash mismatch (a record was altered)" }
```

Truncation at the tail is the one edit a chain cannot detect on its own. That is what an outside witness anchoring the chain head is for.

Verify a chain using nothing but `node:crypto` and `node:fs`, with no dependency on this package.

```js
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const receipts = JSON.parse(readFileSync("receipts.json", "utf8"));
const sha256 = (s) => createHash("sha256").update(s).digest("hex");

let prev = "0".repeat(64);
let ok = true;
receipts.forEach((r, i) => {
  const { id, ts, kind, payload, prevHash, hash } = r;
  const expect = sha256(JSON.stringify({ id, ts, kind, payload, prevHash }));
  if (prevHash !== prev || hash !== expect) { console.log("broken at index", i, r.id); ok = false; }
  prev = hash;
});
console.log("ok", ok);
```

## Postgres

For real deployments, `PostgresStore` keeps the same synchronous `Store` interface and writes every receipt through to Postgres in order. It takes any client with a `query(text, params)` method, so the package stays dependency free. `pg` and PGlite work as they are. Neon works over its `Pool`, or over HTTP when you ask for full results.

```js
import pg from "pg";
import { PostgresStore, makeReceipt } from "@olurabian/receipt";

const client = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const store = await PostgresStore.open(client, { stream: "purse" });

makeReceipt(store, { kind: "decision", payload: { status: "allowed" } });
await store.flush(); // resolves once the receipt is durable
```

```js
// Neon over WebSockets. On Node 18 also set neonConfig.webSocketConstructor = ws.
import { Pool } from "@neondatabase/serverless";
const client = new Pool({ connectionString: process.env.DATABASE_URL });

// Neon over HTTP
import { neon } from "@neondatabase/serverless";
const client = neon(process.env.DATABASE_URL, { fullResults: true });
```

With postgres.js, wrap it once.

```js
const client = { query: (text, params = []) => sql.unsafe(text, params).then((rows) => ({ rows })) };
```

What `open` does. It creates the table if it is missing, loads the stream in order, verifies the chain, and refuses to start on a broken one. One table holds many streams, one per product.

One writer per stream. The table has a unique constraint on the previous hash, so a second process appending on the same head is rejected by the database rather than corrupting the chain. Run one writer per stream.

Degraded means stopped. A transient insert failure is retried three times. A hard failure, including a rejected fork, latches the store. After that `append()` throws, `flush()` rejects, and `pending()` reports the backlog. Fix the database and restart the process, and `open` reloads and re-verifies. Read `degraded()` for the error. The constraint name tells you what happened. `_stream_prev_hash_key` is a fork, another writer landed on the same head. `_stream_id_key` is your own write, the insert committed but the reply was lost, and a restart reloads it cleanly. The whole stream is held in memory, so memory and start-up time grow with the stream.

Reload reads the canonical text. Postgres reorders keys inside `jsonb`, which would break the hash on reload, so the store keeps the exact receipt text in a `record` column and uses `payload` only for SQL queries.

Only `record` is covered by the hash. A SQL query over `payload` is convenience, not evidence. Someone with write access to the table can change `payload` without touching the chain. Verify with `PostgresStore.open()` or `verifyChain` before you rely on a number you read with SQL.

What is durable when. `append()` returns before the insert commits. If the process dies before the queued inserts land, everything `pending()` counts is lost, and nothing else. What remains in Postgres still verifies, because the loss is a tail. A crash and a deliberate truncation look the same to a verifier, so anchor the chain head if that matters to you. The JSONL store has a smaller window, one synchronous write, but it cannot survive the machine and cannot reject a fork. Wait on `flush()` whenever you need the guarantee.

## The receipt

```ts
{ id, ts, kind, payload, prevHash, hash }
```

`hash = sha256( JSON.stringify({ id, ts, kind, payload, prevHash }) )` in exactly that key order. `prevHash` of the first receipt is 64 zeros. That is the whole spec. Match it byte for byte in any language and you can verify a Deadlatch chain with nothing from us.

Receipts are produced by JavaScript's `JSON.stringify`, so a verifier written in another language must match its exact conventions.

- No whitespace
- UTF-8 output, non-ASCII characters left unescaped
- Only control characters, quotes, backslashes, and lone surrogates escaped
- JavaScript's key ordering, where integer-like keys sort first in numeric order

Python's default `json.dumps` differs on two of these. It adds whitespace after separators, and it escapes non-ASCII characters unless `ensure_ascii=False` is set.

`verifyChain` walks the chain and reports the index and id of the first receipt that fails, and why.

Part of [Deadlatch](https://deadlatch.dev), enforce, prove, watch. MIT.
