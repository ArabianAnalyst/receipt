import { test } from "node:test";
import assert from "node:assert/strict";
import { leafHashOf, nodeHashOf, verifyInclusionPath, verifyInclusion } from "../src/anchor/merkle.js";
import { fromBase64, toBase64 } from "../src/anchor/bytes.js";
import { fixtureEntry } from "./helpers/fixture.js";

const leaf = (n: number) => leafHashOf(new Uint8Array([n]));

test("a two-leaf tree proves both leaves", () => {
  const l0 = leaf(0), l1 = leaf(1);
  const root = nodeHashOf(l0, l1);
  assert.ok(verifyInclusionPath(l0, 0n, 2n, [l1], root));
  assert.ok(verifyInclusionPath(l1, 1n, 2n, [l0], root));
  assert.ok(!verifyInclusionPath(l0, 1n, 2n, [l1], root), "wrong index");
  assert.ok(!verifyInclusionPath(l0, 0n, 2n, [l0], root), "wrong sibling");
});

test("a three-leaf tree proves the odd leaf with a one-element path", () => {
  const l0 = leaf(0), l1 = leaf(1), l2 = leaf(2);
  const left = nodeHashOf(l0, l1);
  const root = nodeHashOf(left, l2);
  assert.ok(verifyInclusionPath(l2, 2n, 3n, [left], root));
  assert.ok(verifyInclusionPath(l0, 0n, 3n, [l1, l2], root));
  assert.ok(verifyInclusionPath(l1, 1n, 3n, [l0, l2], root));
});

test("out-of-range index and empty tree fail", () => {
  const l0 = leaf(0);
  assert.ok(!verifyInclusionPath(l0, 0n, 0n, [], l0));
  assert.ok(!verifyInclusionPath(l0, 1n, 1n, [], l0));
  assert.ok(verifyInclusionPath(l0, 0n, 1n, [], l0), "single leaf is its own root");
});

test("a two-leaf tree proof with the wrong number of path elements fails", () => {
  const l0 = leaf(0), l1 = leaf(1);
  const root = nodeHashOf(l0, l1);
  assert.ok(!verifyInclusionPath(l0, 0n, 2n, [l1, leaf(2), leaf(3)], root), "three path elements for a two-leaf tree");
  assert.ok(!verifyInclusionPath(l0, 0n, 2n, [], root), "zero path elements for a two-leaf tree");
});

test("the real Rekor v2 fixture proof reaches its root", () => {
  const f = fixtureEntry();
  const p = f.response.inclusionProof;
  const lh = leafHashOf(fromBase64(f.response.canonicalizedBody));
  assert.ok(verifyInclusion(lh, { logIndex: p.logIndex, treeSize: p.treeSize, rootHash: p.rootHash, hashes: p.hashes, checkpoint: p.checkpoint.envelope }));
});

test("a flipped hash, a shifted index, or a malformed number fails the fixture proof", () => {
  const f = fixtureEntry();
  const p = f.response.inclusionProof;
  const lh = leafHashOf(fromBase64(f.response.canonicalizedBody));
  const proof = { logIndex: p.logIndex, treeSize: p.treeSize, rootHash: p.rootHash, hashes: [...p.hashes], checkpoint: p.checkpoint.envelope };
  const flipped = fromBase64(proof.hashes[0]!); flipped[0] = flipped[0]! ^ 1;
  assert.ok(!verifyInclusion(lh, { ...proof, hashes: [toBase64(flipped), ...proof.hashes.slice(1)] }));
  assert.ok(!verifyInclusion(lh, { ...proof, logIndex: String(BigInt(proof.logIndex) + 1n) }));
  assert.ok(!verifyInclusion(lh, { ...proof, logIndex: "x" }));
});
