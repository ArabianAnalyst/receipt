import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyAnchored, verifyAnchorProof } from "../src/anchor/verify.js";
import { P256Signer } from "../src/anchor/signer.js";
import { toBase64 } from "../src/anchor/bytes.js";
import { artifactOf, digestOf } from "../src/anchor/artifact.js";
import { buildRequest } from "../src/anchor/body.js";
import type { Anchor, AnchorTrust } from "../src/anchor/types.js";
import type { Receipt } from "../src/types.js";
import { FakeLog } from "./helpers/fake-log.js";
import { anchorWith, chainOf } from "./helpers/anchors.js";
import { fixtureAnchor, fixtureTrust } from "./helpers/fixture.js";

function setup(n = 6) {
  const log = new FakeLog();
  const signer = P256Signer.generate();
  const records = chainOf(n);
  const trust: AnchorTrust = { logKeys: [log.logKey], witnessKeys: [signer.publicKeyDer()] };
  return { log, signer, records, trust };
}

test("the real fixture anchor verifies on its own and fails binding, since no chain has that head", () => {
  const a = fixtureAnchor();
  const alone = verifyAnchorProof(a, fixtureTrust);
  assert.equal(alone.ok, true, alone.reason);
  assert.ok(alone.cosigned.length >= 1, "the public log's checkpoint carried cosignatures");
  const r = verifyAnchored([], [a], fixtureTrust);
  assert.equal(r.ok, false);
  assert.equal(r.coveredUpTo, null);
  assert.equal(r.anchors[0]?.reason, "record missing at seq 0");
});

test("a chain with two anchors verifies, coveredUpTo is the highest anchored seq", () => {
  const { log, signer, records, trust } = setup(6);
  const a2 = anchorWith(log, signer, "purse", 2, records[2]!.hash);
  const a5 = anchorWith(log, signer, "purse", 5, records[5]!.hash);
  const r = verifyAnchored(records, [a2, a5], trust);
  assert.equal(r.ok, true, JSON.stringify(r.anchors));
  assert.equal(r.coveredUpTo, 5);
  assert.deepEqual(r.anchors.map((c) => c.ok), [true, true]);
  assert.equal(r.chain.ok, true);
});

test("no anchors means chain-only, ok with coveredUpTo null", () => {
  const { records, trust } = setup(3);
  const r = verifyAnchored(records, [], trust);
  assert.equal(r.ok, true);
  assert.equal(r.coveredUpTo, null);
});

test("any single-byte change at or below coveredUpTo fails the anchor that covers it, even when the chain is rebuilt", async () => {
  const { log, signer, records, trust } = setup(5);
  const a4 = anchorWith(log, signer, "purse", 4, records[4]!.hash);
  const { hashRecord } = await import("../src/hash.js");
  for (let i = 0; i <= 4; i++) {
    // alter record i, then recompute every hash from i on so the chain verifies again
    const rebuilt: Receipt[] = records.map((r) => ({ ...r, payload: { ...(r.payload as { n: number }) } }));
    (rebuilt[i]!.payload as { n: number }).n += 1000;
    for (let j = i; j < rebuilt.length; j++) {
      const prev = j === 0 ? rebuilt[0]!.prevHash : rebuilt[j - 1]!.hash;
      const { hash: _h, ...rest } = { ...rebuilt[j]!, prevHash: prev };
      rebuilt[j] = { ...rest, hash: hashRecord(rest) };
    }
    const r = verifyAnchored(rebuilt, [a4], trust);
    assert.equal(r.chain.ok, true, `rebuilt chain ${i} verifies on its own`);
    assert.equal(r.ok, false, `anchor catches the rewrite at ${i}`);
    assert.equal(r.anchors[0]?.reason, "head mismatch at seq 4");
    assert.equal(r.coveredUpTo, null);
  }
});

test("truncation below coveredUpTo fails, truncation above it does not", () => {
  const { log, signer, records, trust } = setup(6);
  const a3 = anchorWith(log, signer, "purse", 3, records[3]!.hash);
  const cut = verifyAnchored(records.slice(0, 3), [a3], trust);
  assert.equal(cut.ok, false);
  assert.equal(cut.anchors[0]?.reason, "record missing at seq 3");
  const tail = verifyAnchored(records.slice(0, 5), [a3], trust);
  assert.equal(tail.ok, true);
  assert.equal(tail.coveredUpTo, 3);
});

test("a rotated witness key keeps old anchors valid when both keys are trusted, and names the untrusted one otherwise", () => {
  const { log, signer, records } = setup(6);
  const second = P256Signer.generate();
  const a1 = anchorWith(log, signer, "purse", 1, records[1]!.hash);
  const a4 = anchorWith(log, second, "purse", 4, records[4]!.hash);
  const both: AnchorTrust = { logKeys: [log.logKey], witnessKeys: [signer.publicKeyDer(), second.publicKeyDer()] };
  assert.equal(verifyAnchored(records, [a1, a4], both).coveredUpTo, 4);
  const onlyFirst: AnchorTrust = { logKeys: [log.logKey], witnessKeys: [signer.publicKeyDer()] };
  const r = verifyAnchored(records, [a1, a4], onlyFirst);
  assert.equal(r.ok, false);
  assert.equal(r.coveredUpTo, 1);
  assert.equal(r.anchors[1]?.reason, "untrusted witness key");
});

test("an untrusted log key fails with the named reason", () => {
  const { log, signer, records } = setup(2);
  const a1 = anchorWith(log, signer, "purse", 1, records[1]!.hash);
  const r = verifyAnchored(records, [a1], { logKeys: [], witnessKeys: [signer.publicKeyDer()] });
  assert.equal(r.anchors[0]?.reason, "untrusted log key");
});

test("an anchor whose signature, body, proof, or key id was altered fails with a specific reason", () => {
  const { log, signer, records, trust } = setup(3);
  const good = anchorWith(log, signer, "purse", 2, records[2]!.hash);
  const other = P256Signer.generate();
  const cases: [Partial<Anchor>, string][] = [
    [{ signature: other.sign(new Uint8Array([1])) }, "witness signature does not verify"],
    [{ head: "0".repeat(64) }, "witness signature does not verify"],
    [{ entry: { ...good.entry, canonicalizedBody: anchorWith(log, signer, "purse", 1, records[1]!.hash).entry.canonicalizedBody } }, "log entry digest differs from the artifact digest"],
    [{ proof: { ...good.proof, rootHash: toBase64(new Uint8Array(32)) } }, "inclusion proof does not reach the root"],
    [{ log: { ...good.log, keyId: "AAAA" } }, "anchor log key id differs from the signing key"],
    [{ v: 2 as unknown as 1 }, "unsupported anchor version"],
  ];
  for (const [patch, reason] of cases) {
    const r = verifyAnchored(records, [{ ...good, ...patch }], trust);
    assert.equal(r.anchors[0]?.reason, reason, JSON.stringify(patch).slice(0, 80));
  }
});

test("verifyAnchored is pure", () => {
  const { log, signer, records, trust } = setup(4);
  const a = anchorWith(log, signer, "purse", 3, records[3]!.hash);
  const before = JSON.stringify({ records, a, trust });
  const r1 = verifyAnchored(records, [a], trust);
  const r2 = verifyAnchored(records, [a], trust);
  assert.deepEqual(r1, r2);
  assert.equal(JSON.stringify({ records, a, trust }), before);
});

test("a valid inclusion proof with a checkpoint from another tree size fails on root or size", () => {
  const { log, signer, records, trust } = setup(6);
  const good = anchorWith(log, signer, "purse", 2, records[2]!.hash);
  // grow the log so the same entry can be re-proven against a bigger tree
  anchorWith(log, signer, "purse", 3, records[3]!.hash);
  anchorWith(log, signer, "purse", 4, records[4]!.hash);
  const later = log.entry(Number(good.entry.logIndex));

  // the inclusion proof still reaches good.proof.rootHash, but the checkpoint is for the bigger tree
  const mixedCheckpoint: Anchor = { ...good, proof: { ...good.proof, checkpoint: later.inclusionProof.checkpoint.envelope } };
  const r1 = verifyAnchored(records, [mixedCheckpoint], trust);
  assert.equal(r1.anchors[0]?.reason, "checkpoint root or size differs from the proof");

  // the mirror: keep good's checkpoint, but the inclusion proof now reaches the later root
  const mixedProof: Anchor = {
    ...good,
    proof: { ...good.proof, hashes: later.inclusionProof.hashes, rootHash: later.inclusionProof.rootHash, treeSize: later.inclusionProof.treeSize },
  };
  const r2 = verifyAnchored(records, [mixedProof], trust);
  assert.equal(r2.anchors[0]?.reason, "checkpoint root or size differs from the proof");
});

test("a break in the chain above coveredUpTo makes ok false while the anchor still stands", () => {
  const { log, signer, records, trust } = setup(6);
  const a2 = anchorWith(log, signer, "purse", 2, records[2]!.hash);
  const mutated = records.map((r, i) => (i === 4 ? { ...r, payload: { ...(r.payload as { n: number }), n: 999 } } : r));
  const r = verifyAnchored(mutated, [a2], trust);
  assert.equal(r.chain.ok, false);
  assert.equal(r.anchors[0]?.ok, true);
  assert.equal(r.coveredUpTo, 2);
  assert.equal(r.ok, false);
});

test("a log entry whose verifier key is not the witness key fails", () => {
  const { log, signer, records, trust } = setup(3);
  const other = P256Signer.generate();
  const artifact = artifactOf("purse", 2, records[2]!.hash);
  const signature = signer.sign(artifact);
  const r = log.add(buildRequest(digestOf(artifact), signature, other.publicKeyDer()));
  const a: Anchor = {
    v: 1, stream: "purse", seq: 2, head: records[2]!.hash, at: "2026-09-08T00:00:00.000Z",
    witness: { alg: "ecdsa-p256", publicKey: signer.publicKeyDer() },
    signature,
    log: { url: log.url, keyId: r.logId.keyId },
    entry: { logIndex: r.logIndex, canonicalizedBody: r.canonicalizedBody },
    proof: { logIndex: r.inclusionProof.logIndex, treeSize: r.inclusionProof.treeSize, rootHash: r.inclusionProof.rootHash, hashes: r.inclusionProof.hashes, checkpoint: r.inclusionProof.checkpoint.envelope },
  };
  const result = verifyAnchored(records, [a], trust);
  assert.equal(result.anchors[0]?.reason, "log entry verifier key differs from the witness key");
});

test("a log entry whose signature differs from the anchor's fails", () => {
  const { log, signer, records, trust } = setup(3);
  const artifact = artifactOf("purse", 2, records[2]!.hash);
  const sig1 = signer.sign(artifact);
  const sig2 = signer.sign(artifact);
  assert.notEqual(sig1, sig2, "ECDSA signatures are randomized, two signs of the same bytes differ");
  const r = log.add(buildRequest(digestOf(artifact), sig1, signer.publicKeyDer()));
  const a: Anchor = {
    v: 1, stream: "purse", seq: 2, head: records[2]!.hash, at: "2026-09-08T00:00:00.000Z",
    witness: { alg: "ecdsa-p256", publicKey: signer.publicKeyDer() },
    signature: sig2,
    log: { url: log.url, keyId: r.logId.keyId },
    entry: { logIndex: r.logIndex, canonicalizedBody: r.canonicalizedBody },
    proof: { logIndex: r.inclusionProof.logIndex, treeSize: r.inclusionProof.treeSize, rootHash: r.inclusionProof.rootHash, hashes: r.inclusionProof.hashes, checkpoint: r.inclusionProof.checkpoint.envelope },
  };
  const result = verifyAnchored(records, [a], trust);
  assert.equal(result.anchors[0]?.reason, "log entry signature differs from the anchor signature");
});

test("an unsupported witness algorithm fails", () => {
  const { log, signer, records, trust } = setup(3);
  const good = anchorWith(log, signer, "purse", 2, records[2]!.hash);
  const bad: Anchor = { ...good, witness: { ...good.witness, alg: "ed25519" as unknown as "ecdsa-p256" } };
  assert.equal(verifyAnchorProof(bad, trust).reason, "unsupported witness algorithm");
});

test("a log index that differs between entry and proof fails", () => {
  const { log, signer, records, trust } = setup(3);
  const good = anchorWith(log, signer, "purse", 2, records[2]!.hash);
  const bumped: Anchor = { ...good, entry: { ...good.entry, logIndex: String(Number(good.entry.logIndex) + 1) } };
  assert.equal(verifyAnchorProof(bumped, trust).reason, "log index differs between entry and proof");
});

test("an anchor minted for another stream passes without opts.stream but fails once the caller names the chain's stream", () => {
  const { log, signer, records, trust } = setup(3);
  const a = anchorWith(log, signer, "other", 2, records[2]!.hash);
  const noOpt = verifyAnchored(records, [a], trust);
  assert.equal(noOpt.anchors[0]?.ok, true, noOpt.anchors[0]?.reason);
  assert.equal(noOpt.stream, "other");
  const withOpt = verifyAnchored(records, [a], trust, { stream: "purse" });
  assert.equal(withOpt.anchors[0]?.reason, "anchor is for stream other, not purse");
  assert.equal(withOpt.stream, "purse");
});

test("two anchors for two streams without opts.stream fail with the span reason", () => {
  const { log, signer, records, trust } = setup(4);
  const a1 = anchorWith(log, signer, "purse", 1, records[1]!.hash);
  const a2 = anchorWith(log, signer, "other", 3, records[3]!.hash);
  const r = verifyAnchored(records, [a1, a2], trust);
  assert.equal(r.anchors[0]?.reason, "anchors span more than one stream");
  assert.equal(r.anchors[1]?.reason, "anchors span more than one stream");
  assert.equal(r.ok, false);
});

test("verifyAnchored reports stream null when there are no anchors and none was named", () => {
  const { records, trust } = setup(2);
  assert.equal(verifyAnchored(records, [], trust).stream, null);
});
