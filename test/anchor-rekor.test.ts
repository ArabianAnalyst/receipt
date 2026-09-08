import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { RekorV2 } from "../src/anchor/rekor.js";
import { P256Signer } from "../src/anchor/signer.js";
import { verifyAnchored } from "../src/anchor/verify.js";
import { FakeLog } from "./helpers/fake-log.js";
import { chainOf } from "./helpers/anchors.js";
import { fixtureLogKey, fixtureLogId } from "./helpers/fixture.js";

test("submit signs, posts, verifies the reply, and returns an anchor that verifies against the chain", async () => {
  const log = new FakeLog();
  const signer = P256Signer.generate();
  const records = chainOf(4);
  const rekor = new RekorV2({ url: log.url + "/", logKeys: [log.logKey], fetch: log.fetch(), now: () => "2026-09-08T10:00:00.000Z" });
  const a = await rekor.submit("purse", 3, records[3]!.hash, signer);
  assert.equal(a.v, 1);
  assert.equal(a.at, "2026-09-08T10:00:00.000Z");
  assert.equal(a.log.url, log.url, "trailing slash trimmed");
  assert.equal(a.log.keyId, log.keyId);
  assert.equal(a.witness.publicKey, signer.publicKeyDer());
  const r = verifyAnchored(records, [a], { logKeys: [log.logKey], witnessKeys: [signer.publicKeyDer()] });
  assert.equal(r.ok, true, JSON.stringify(r.anchors));
  assert.equal(r.coveredUpTo, 3);
});

test("submit refuses a reply from a log whose key is not trusted", async () => {
  const log = new FakeLog();
  const rekor = new RekorV2({ url: log.url, logKeys: [fixtureLogKey], fetch: log.fetch() });
  await assert.rejects(rekor.submit("purse", 0, "c".repeat(64), P256Signer.generate()), /reply did not verify, untrusted log key/);
});

test("submit surfaces an HTTP failure with the status", async () => {
  const log = new FakeLog();
  const rekor = new RekorV2({ url: log.url, logKeys: [log.logKey], fetch: log.fetch(503) });
  await assert.rejects(rekor.submit("purse", 0, "c".repeat(64), P256Signer.generate()), /rekor: 503/);
});

test("submit refuses a reply missing fields", async () => {
  const bad = (async () => new Response(JSON.stringify({ logIndex: "1" }), { status: 201 })) as unknown as typeof fetch;
  const rekor = new RekorV2({ url: "https://x.test", logKeys: [], fetch: bad });
  await assert.rejects(rekor.submit("purse", 0, "c".repeat(64), P256Signer.generate()), /missing fields/);
});

test("the constructor rejects a url without a scheme", () => {
  assert.throws(() => new RekorV2({ url: "log.example", logKeys: [] }), /http/);
});

test("submit rejects when the log does not answer within timeoutMs", async () => {
  let seen: AbortSignal | undefined;
  const hanging = ((_input: unknown, init?: { signal?: AbortSignal }) => {
    seen = init?.signal;
    return new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(init.signal!.reason as Error));
    });
  }) as unknown as typeof fetch;
  const keepAlive = setTimeout(() => {}, 5000); // AbortSignal.timeout's own timer is unref'd; hold the loop open until it fires
  try {
    const rekor = new RekorV2({ url: "https://x.test", logKeys: [], fetch: hanging, timeoutMs: 100 });
    await assert.rejects(
      rekor.submit("purse", 0, "c".repeat(64), P256Signer.generate()),
      (e: unknown) => ["TimeoutError", "AbortError"].includes((e as Error).name),
    );
  } finally {
    clearTimeout(keepAlive);
  }
  assert.ok(seen instanceof AbortSignal, "fetch received the abort signal");
});

test("submit refuses a reply that is not JSON", async () => {
  const bad = (async () => new Response("<html>", { status: 201 })) as unknown as typeof fetch;
  const rekor = new RekorV2({ url: "https://x.test", logKeys: [], fetch: bad });
  await assert.rejects(rekor.submit("purse", 0, "c".repeat(64), P256Signer.generate()), /rekor: reply is not JSON/);
});

test("live: the public log accepts a throwaway anchor and the reply verifies under the pinned key", { skip: process.env.REKOR_LIVE !== "1" }, async () => {
  const rekor = new RekorV2({ url: "https://log2025-1.rekor.sigstore.dev", logKeys: [fixtureLogKey], timeoutMs: 30000 });
  const head = randomBytes(32).toString("hex");
  const a = await rekor.submit("live-test", 0, head, P256Signer.generate());
  assert.equal(a.log.keyId, fixtureLogId);
  assert.match(a.entry.logIndex, /^[0-9]+$/);
  console.log("live anchor at log index", a.entry.logIndex);
});
