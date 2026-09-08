import { test } from "node:test";
import assert from "node:assert/strict";
import { P256Signer, verifyArtifactSignature } from "../src/anchor/signer.js";
import { decodeBody, buildRequest, KEY_DETAILS } from "../src/anchor/body.js";
import { artifactOf, digestOf } from "../src/anchor/artifact.js";
import { leafHashOf, verifyInclusion } from "../src/anchor/merkle.js";
import { verifyCheckpoint } from "../src/anchor/checkpoint.js";
import { fromBase64, toBase64 } from "../src/anchor/bytes.js";
import { fixtureEntry } from "./helpers/fixture.js";
import { FakeLog } from "./helpers/fake-log.js";

const HEAD = "b".repeat(64);

test("P256Signer signs an artifact that verifyArtifactSignature accepts, and rejects a changed byte", () => {
  const s = P256Signer.generate();
  const artifact = artifactOf("purse", 3, HEAD);
  const sig = s.sign(artifact);
  assert.ok(verifyArtifactSignature(artifact, sig, s.publicKeyDer()));
  const changed = new Uint8Array(artifact); changed[changed.length - 2] ^= 1;
  assert.ok(!verifyArtifactSignature(changed, sig, s.publicKeyDer()));
  assert.ok(!verifyArtifactSignature(artifact, sig, P256Signer.generate().publicKeyDer()));
  assert.ok(!verifyArtifactSignature(artifact, "not base64!!", s.publicKeyDer()));
});

test("verifyArtifactSignature rejects a P-384 public key", async () => {
  const { generateKeyPairSync } = await import("node:crypto");
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
  const der = new Uint8Array(publicKey.export({ type: "spki", format: "der" }));
  const artifact = artifactOf("purse", 3, HEAD);
  assert.equal(verifyArtifactSignature(artifact, toBase64(new Uint8Array([1, 2, 3])), toBase64(der)), false);
});

test("P256Signer round-trips through PEM and refuses a non P-256 key", async () => {
  const s = P256Signer.generate();
  const back = P256Signer.fromPem(s.toPem());
  assert.equal(back.publicKeyDer(), s.publicKeyDer());
  const { generateKeyPairSync } = await import("node:crypto");
  const ed = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  assert.throws(() => P256Signer.fromPem(ed), /P-256/);
});

test("decodeBody reads the real fixture body and buildRequest reproduces the real request", () => {
  const f = fixtureEntry();
  const b = decodeBody(f.response.canonicalizedBody);
  assert.ok(b);
  assert.equal(b.digest, f.request.hashedRekordRequestV002.digest);
  assert.equal(b.signature, f.request.hashedRekordRequestV002.signature.content);
  assert.equal(b.publicKey, f.request.hashedRekordRequestV002.signature.verifier.publicKey.rawBytes);
  assert.equal(b.keyDetails, KEY_DETAILS);
  const artifact = artifactOf(f.artifact.stream, f.artifact.seq, f.artifact.head);
  assert.deepEqual(buildRequest(digestOf(artifact), b.signature, b.publicKey), f.request);
  assert.ok(verifyArtifactSignature(artifact, b.signature, b.publicKey), "the real witness signature verifies over the rebuilt artifact");
});

test("decodeBody returns null for anything that is not a hashedrekord 0.0.2", () => {
  assert.equal(decodeBody(toBase64(new TextEncoder().encode("{}"))), null);
  assert.equal(decodeBody(toBase64(new TextEncoder().encode(JSON.stringify({ apiVersion: "0.0.1", kind: "hashedrekord" })))), null);
  assert.equal(decodeBody("%%%"), null);
});

test("FakeLog builds entries whose proofs and checkpoints verify with the real verifiers", () => {
  const log = new FakeLog();
  const s = P256Signer.generate();
  const replies = [0, 1, 2, 3, 4].map((i) => {
    const artifact = artifactOf("t", i, HEAD);
    return log.add(buildRequest(digestOf(artifact), s.sign(artifact), s.publicKeyDer()) as never);
  });
  for (const r of replies) {
    const lh = leafHashOf(fromBase64(r.canonicalizedBody));
    const p = r.inclusionProof;
    assert.ok(verifyInclusion(lh, { logIndex: p.logIndex, treeSize: p.treeSize, rootHash: p.rootHash, hashes: p.hashes, checkpoint: p.checkpoint.envelope }), `entry ${r.logIndex}`);
  }
  // an old entry re-proven at the current size still verifies
  const again = log.entry(1);
  assert.equal(again.inclusionProof.treeSize, "5");
  assert.ok(verifyInclusion(leafHashOf(fromBase64(again.canonicalizedBody)), { ...again.inclusionProof, checkpoint: again.inclusionProof.checkpoint.envelope }));
  const cp = verifyCheckpoint(again.inclusionProof.checkpoint.envelope, [log.logKey]);
  assert.equal(cp.ok, true, cp.reason);
  assert.equal(cp.keyId, log.keyId);
  assert.equal(again.logId.keyId, log.keyId);
});
