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
