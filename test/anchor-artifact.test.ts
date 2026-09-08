import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { artifactOf, digestOf, ARTIFACT_PREFIX } from "../src/anchor/artifact.js";
import { toBase64, fromBase64, bytesEqual, concat } from "../src/anchor/bytes.js";
import { fixtureEntry } from "./helpers/fixture.js";

const HEAD = "a".repeat(64);

test("artifactOf is the four-line text, newline terminated", () => {
  const text = new TextDecoder().decode(artifactOf("purse", 6, HEAD));
  assert.equal(text, `${ARTIFACT_PREFIX}\npurse\n6\n${HEAD}\n`);
});

test("artifactOf rejects a bad stream, seq, or head", () => {
  assert.throws(() => artifactOf("", 0, HEAD), /stream/);
  assert.throws(() => artifactOf("a\nb", 0, HEAD), /stream/);
  assert.throws(() => artifactOf("purse", -1, HEAD), /seq/);
  assert.throws(() => artifactOf("purse", 1.5, HEAD), /seq/);
  assert.throws(() => artifactOf("purse", 0, HEAD.toUpperCase()), /head/);
  assert.throws(() => artifactOf("purse", 0, "abc"), /head/);
});

test("digestOf matches the digest the real log recorded for the fixture artifact", () => {
  const f = fixtureEntry();
  const artifact = artifactOf(f.artifact.stream, f.artifact.seq, f.artifact.head);
  assert.equal(new TextDecoder().decode(artifact), f.artifact.text);
  assert.equal(toBase64(digestOf(artifact)), f.request.hashedRekordRequestV002.digest);
  assert.equal(toBase64(digestOf(artifact)), createHash("sha256").update(f.artifact.text).digest("base64"));
});

test("bytes helpers round-trip and compare", () => {
  const a = new Uint8Array([1, 2, 3]);
  assert.deepEqual(fromBase64(toBase64(a)), a);
  assert.ok(bytesEqual(a, new Uint8Array([1, 2, 3])));
  assert.ok(!bytesEqual(a, new Uint8Array([1, 2, 4])));
  assert.ok(!bytesEqual(a, new Uint8Array([1, 2])));
  assert.deepEqual(concat(new Uint8Array([1]), new Uint8Array([2, 3])), a);
});
