# Changelog

## 0.3.0

- New subpath `@olurabian/receipt/anchor`. Anchors a chain head to a Rekor v2 transparency log and verifies a chain against its anchors, `verifyAnchored`, with RFC 6962 inclusion proofs and C2SP checkpoint verification on `node:crypto`. Zero dependencies still.
- `RekorV2` client that verifies every reply before returning an anchor, `P256Signer` for the witness key, `MemoryAnchorStore` and `PostgresAnchorStore`.
- `receipt-verify` command.
- Test fixtures captured from a real public log entry, public data only.

## 0.2.0 (2026-09-04)

Adds `PostgresStore`, a write-through store over any SQL client with a `query(text, params)` method. Same synchronous interface as the other stores, ordered inserts, `flush()` and `pending()`, fork rejection at the database, and a fail-closed reload that verifies the chain. Adds `schema()` and the `SqlClient` and `PostgresStoreOptions` types. No breaking changes. Adds `degraded()`. `flush()` covers appends made while waiting. Permanent SQL errors latch on the first attempt.

## 0.1.0 (2026-09-04)

First release. The receipt envelope, canonical hashing, `verifyChain`, `makeReceipt`, and the in-memory and JSONL stores. Consumed by `@olurabian/purse` 0.3 and `@olurabian/blackbox` 0.2.
