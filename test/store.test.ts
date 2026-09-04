import { test } from "node:test";
import assert from "node:assert/strict";
import { rmSync, existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GENESIS } from "../src/types.js";
import { MemoryStore, JsonlStore } from "../src/store.js";
import type { Receipt } from "../src/types.js";

const rec = (id: string, prevHash: string): Receipt<{ a: number }> => ({
  id, ts: "2026-09-04T00:00:00.000Z", kind: "test", payload: { a: 1 }, prevHash, hash: "h" + id,
});

test("MemoryStore starts at GENESIS and tracks the tip", () => {
  const m = new MemoryStore<{ a: number }>();
  assert.equal(m.lastHash(), GENESIS);
  m.append(rec("1", GENESIS));
  m.append(rec("2", "h1"));
  assert.equal(m.lastHash(), "h2");
  assert.equal(m.all().length, 2);
  assert.notEqual(m.all(), m.all(), "all() returns a fresh array");
});

test("JsonlStore without a path is in-memory", () => {
  const j = new JsonlStore<{ a: number }>();
  j.append(rec("1", GENESIS));
  assert.equal(j.lastHash(), "h1");
});

test("JsonlStore persists one line per receipt and reloads", () => {
  const dir = mkdtempSync(join(tmpdir(), "receipt-"));
  const path = join(dir, "chain.jsonl");
  const j1 = new JsonlStore<{ a: number }>(path);
  j1.append(rec("1", GENESIS));
  j1.append(rec("2", "h1"));
  const j2 = new JsonlStore<{ a: number }>(path);
  assert.equal(j2.all().length, 2);
  assert.equal(j2.lastHash(), "h2");
  assert.equal(j2.all()[0]!.id, "1");
  rmSync(dir, { recursive: true, force: true });
  assert.equal(existsSync(path), false);
});

test("JsonlStore throws on corrupt JSONL line with file and line number", () => {
  const dir = mkdtempSync(join(tmpdir(), "receipt-"));
  const path = join(dir, "chain.jsonl");
  writeFileSync(path, JSON.stringify(rec("1", GENESIS)) + "\n" + '{"id":"r2","ts":');
  assert.throws(
    () => new JsonlStore(path),
    /corrupt line 2/,
    "corrupt line should throw with line number"
  );
  rmSync(dir, { recursive: true, force: true });
});
