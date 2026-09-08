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
