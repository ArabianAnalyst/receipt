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
