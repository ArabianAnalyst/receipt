import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { P256Signer } from "../src/anchor/signer.js";
import { FakeLog } from "./helpers/fake-log.js";
import { anchorWith, chainOf } from "./helpers/anchors.js";

const CLI = join(process.cwd(), "dist", "cli.js");
const run = (args: string[]) => execFileSync(process.execPath, [CLI, ...args], { encoding: "utf8", stdio: "pipe" });

function files() {
  const dir = mkdtempSync(join(tmpdir(), "receipt-verify-"));
  const log = new FakeLog();
  const signer = P256Signer.generate();
  const records = chainOf(4);
  const a = anchorWith(log, signer, "purse", 3, records[3]!.hash);
  const chain = join(dir, "chain.jsonl");
  writeFileSync(chain, records.map((r) => JSON.stringify(r)).join("\n") + "\n");
  const chainJson = join(dir, "chain.json");
  writeFileSync(chainJson, JSON.stringify(records));
  const anchors = join(dir, "anchors.json");
  writeFileSync(anchors, JSON.stringify({ anchors: [a] }));
  return { dir, log, signer, records, chain, chainJson, anchors };
}

test("receipt-verify passes a good chain and prints the result", () => {
  const f = files();
  const out = JSON.parse(run([f.chain, "--anchors", f.anchors, "--log-key", `${f.log.origin}=${f.log.publicKeyDer}`, "--witness-key", f.signer.publicKeyDer()])) as { ok: boolean; coveredUpTo: number };
  assert.equal(out.ok, true);
  assert.equal(out.coveredUpTo, 3);
  const out2 = JSON.parse(run([f.chainJson, "--anchors", f.anchors, "--log-key", `${f.log.origin}=${f.log.publicKeyDer}`, "--witness-key", f.signer.publicKeyDer()])) as { ok: boolean };
  assert.equal(out2.ok, true, "a JSON array chain works too");
});

test("receipt-verify exits 1 on a rewritten chain and names the seq", () => {
  const f = files();
  const cut = join(f.dir, "cut.jsonl");
  writeFileSync(cut, f.records.slice(0, 2).map((r) => JSON.stringify(r)).join("\n"));
  let code = 0; let stdout = "";
  try { stdout = run([cut, "--anchors", f.anchors, "--log-key", `${f.log.origin}=${f.log.publicKeyDer}`, "--witness-key", f.signer.publicKeyDer()]); }
  catch (e) { const err = e as { status: number; stdout: string }; code = err.status; stdout = err.stdout; }
  assert.equal(code, 1);
  assert.match(stdout, /record missing at seq 3/);
});

test("receipt-verify exits 2 with usage when a key is missing", () => {
  const f = files();
  assert.throws(() => run([f.chain, "--anchors", f.anchors]), (e: unknown) => (e as { status: number }).status === 2);
});

test("receipt-verify exits 1 with a stderr note when no anchor was given at all", () => {
  const f = files();
  const empty = join(f.dir, "empty.json");
  writeFileSync(empty, JSON.stringify({ anchors: [] }));
  let code = 0; let stdout = ""; let stderr = "";
  try { stdout = run([f.chain, "--anchors", empty, "--log-key", `${f.log.origin}=${f.log.publicKeyDer}`, "--witness-key", f.signer.publicKeyDer()]); }
  catch (e) { const err = e as { status: number; stdout: string; stderr: string }; code = err.status; stdout = err.stdout; stderr = err.stderr; }
  assert.equal(code, 1);
  assert.match(stdout, /"ok": true/);
  assert.match(stderr, /receipt-verify: no anchor verified, the chain is tamper-evident only/);
});

test("receipt-verify exits 2 when the anchors file is neither an array nor an anchors object", () => {
  const f = files();
  const bad = join(f.dir, "bad-anchors.json");
  writeFileSync(bad, JSON.stringify({ items: [] }));
  let code = 0; let stderr = "";
  try { run([f.chain, "--anchors", bad, "--log-key", `${f.log.origin}=${f.log.publicKeyDer}`, "--witness-key", f.signer.publicKeyDer()]); }
  catch (e) { const err = e as { status: number; stderr: string }; code = err.status; stderr = err.stderr; }
  assert.equal(code, 2);
  assert.match(stderr, /anchors: expected an array or an object with an anchors array/);
});
