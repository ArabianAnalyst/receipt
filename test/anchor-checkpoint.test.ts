import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { parseCheckpoint, checkpointKeyId, verifyCheckpoint, ed25519RawFromSpki } from "../src/anchor/checkpoint.js";
import { fromBase64, toBase64 } from "../src/anchor/bytes.js";
import { fixtureEntry, fixtureLogKey, fixtureLogId, FIXTURE_ORIGIN } from "./helpers/fixture.js";

const note = () => fixtureEntry().response.inclusionProof.checkpoint.envelope;

test("parseCheckpoint splits origin, size, root, and every signature line", () => {
  const p = parseCheckpoint(note());
  assert.equal(p.origin, FIXTURE_ORIGIN);
  assert.equal(p.size, fixtureEntry().response.inclusionProof.treeSize);
  assert.equal(p.root, fixtureEntry().response.inclusionProof.rootHash);
  assert.ok(p.text.endsWith("\n") && !p.text.includes("\n\n"));
  assert.ok(p.signatures.length >= 1);
  assert.ok(p.signatures.some((s) => s.name === FIXTURE_ORIGIN));
  for (const s of p.signatures) { assert.equal(s.keyId.length, 4); assert.ok(s.signature.length > 0); }
});

test("checkpointKeyId follows the C2SP Ed25519 rule and matches the log id", () => {
  assert.equal(checkpointKeyId(FIXTURE_ORIGIN, fromBase64(fixtureLogKey.publicKey)), fixtureLogId);
  assert.equal(checkpointKeyId(FIXTURE_ORIGIN, fromBase64(fixtureLogKey.publicKey)), fixtureEntry().response.logId.keyId);
});

test("ed25519RawFromSpki extracts 32 bytes and rejects other key types", () => {
  assert.equal(ed25519RawFromSpki(fromBase64(fixtureLogKey.publicKey))?.length, 32);
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  assert.equal(ed25519RawFromSpki(new Uint8Array(publicKey.export({ type: "spki", format: "der" }))), null);
  assert.throws(() => checkpointKeyId("x", new Uint8Array(publicKey.export({ type: "spki", format: "der" }))), /only Ed25519/);
});

test("verifyCheckpoint accepts the real note under the real log key and lists cosigners", () => {
  const r = verifyCheckpoint(note(), [fixtureLogKey]);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.signedBy, FIXTURE_ORIGIN);
  assert.equal(r.keyId, fixtureLogId);
  assert.ok(!r.cosigned.includes(FIXTURE_ORIGIN));
});

test("verifyCheckpoint fails with the named reason when no trusted key matches", () => {
  assert.equal(verifyCheckpoint(note(), []).reason, "untrusted log key");
  assert.equal(verifyCheckpoint(note(), [{ origin: "other.log", publicKey: fixtureLogKey.publicKey }]).reason, "untrusted log key");
  const { publicKey } = generateKeyPairSync("ed25519");
  const wrong = { origin: FIXTURE_ORIGIN, publicKey: toBase64(new Uint8Array(publicKey.export({ type: "spki", format: "der" }))) };
  assert.equal(verifyCheckpoint(note(), [wrong]).reason, "untrusted log key", "a key with a different id never gets tried");
});

test("verifyCheckpoint fails on a tampered note or a forged signature", () => {
  const n = note();
  const tamperedRoot = n.replace(/^(.*\n\d+\n)([A-Za-z0-9+/=]+)\n/, (_m, head: string, root: string) => `${head}${root.slice(0, -2)}AA\n`);
  assert.notEqual(tamperedRoot, n);
  assert.equal(verifyCheckpoint(tamperedRoot, [fixtureLogKey]).ok, false);
  // a note signed by a key we trust, but the trust list says another origin owns it
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const der = new Uint8Array(publicKey.export({ type: "spki", format: "der" }));
  const text = "my.log\n5\n" + toBase64(new Uint8Array(32)) + "\n";
  const keyId = fromBase64(checkpointKeyId("my.log", der));
  const sig = new Uint8Array(sign(null, Buffer.from(text, "utf8"), privateKey));
  const line = toBase64(new Uint8Array([...keyId.subarray(0, 4), ...sig]));
  const mine = `${text}\n— my.log ${line}\n`;
  assert.equal(verifyCheckpoint(mine, [{ origin: "my.log", publicKey: toBase64(der) }]).ok, true);
  const forged = mine.replace(line, toBase64(new Uint8Array([...keyId.subarray(0, 4), ...sig.map((b, i) => (i === 10 ? b ^ 1 : b))])));
  assert.equal(verifyCheckpoint(forged, [{ origin: "my.log", publicKey: toBase64(der) }]).reason, "checkpoint: signature does not verify");
});

test("parseCheckpoint throws on notes that are not notes", () => {
  assert.throws(() => parseCheckpoint("no blank line"), /blank line/);
  assert.throws(() => parseCheckpoint("o\n5\nr\n\nnot a signature\n"), /signature line/);
  assert.throws(() => parseCheckpoint("o\n5\nr\n\n"), /no signatures/);
});

test("a note whose only signature line is by a cosigner name fails with the named reason", () => {
  const line = toBase64(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]));
  const note = `o\n5\nr\n\n— cosigner ${line}\n`;
  const r = verifyCheckpoint(note, [{ origin: "o", publicKey: fixtureLogKey.publicKey }]);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "checkpoint: no signature by the origin");
});

test("parseCheckpoint throws on malformed text, a size that is not decimal", () => {
  assert.throws(() => parseCheckpoint("o\nx\nr\n\n— o AAAAAAAA\n"), /malformed text/);
});

test("parseCheckpoint throws when a signature line's base64 decodes to fewer than five bytes", () => {
  const short = toBase64(new Uint8Array([1, 2, 3, 4]));
  assert.throws(() => parseCheckpoint(`o\n5\nr\n\n— o ${short}\n`), /signature too short/);
});

test("verifyCheckpoint tries every trusted key for the origin, not just the first", () => {
  const { publicKey } = generateKeyPairSync("ed25519");
  const wrongKeySameOrigin = { origin: FIXTURE_ORIGIN, publicKey: toBase64(new Uint8Array(publicKey.export({ type: "spki", format: "der" }))) };
  const r = verifyCheckpoint(note(), [wrongKeySameOrigin, fixtureLogKey]);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.keyId, fixtureLogId);
});
