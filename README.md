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
