import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { LogKey } from "./types.js";
import { bytesEqual, fromBase64, toBase64 } from "./bytes.js";

/** SubjectPublicKeyInfo prefix of an Ed25519 key. The raw 32-byte key follows it. */
const ED25519_SPKI_PREFIX = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

export interface CheckpointSignature { name: string; keyId: Uint8Array; signature: Uint8Array }
export interface ParsedCheckpoint {
  origin: string;
  size: string;
  root: string;
  /** The signed text, every line newline terminated, without the blank line. */
  text: string;
  signatures: CheckpointSignature[];
}

/** Split a C2SP signed note into its text and its signature lines. Throws when it is not one. */
export function parseCheckpoint(note: string): ParsedCheckpoint {
  const sep = note.indexOf("\n\n");
  if (sep < 0) throw new Error("checkpoint: no blank line between text and signatures");
  const text = note.slice(0, sep + 1);
  const lines = text.split("\n");
  const origin = lines[0];
  const size = lines[1];
  const root = lines[2];
  if (!origin || !size || !root || !/^[0-9]+$/.test(size)) throw new Error("checkpoint: malformed text");
  const signatures: CheckpointSignature[] = [];
  for (const line of note.slice(sep + 2).split("\n")) {
    if (!line) continue;
    if (!line.startsWith("— ")) throw new Error("checkpoint: malformed signature line");
    const parts = line.slice(2).split(" ");
    const name = parts[0];
    const sig = parts[1];
    if (!name || !sig || parts.length !== 2) throw new Error("checkpoint: malformed signature line");
    const raw = fromBase64(sig);
    if (raw.length < 5) throw new Error("checkpoint: signature too short");
    signatures.push({ name, keyId: raw.subarray(0, 4), signature: raw.subarray(4) });
  }
  if (signatures.length === 0) throw new Error("checkpoint: no signatures");
  return { origin, size, root, text, signatures };
}

/** The raw 32-byte Ed25519 key inside SPKI DER, or null when the DER holds another key type. */
export function ed25519RawFromSpki(der: Uint8Array): Uint8Array | null {
  if (der.length !== 44) return null;
  if (!bytesEqual(der.subarray(0, 12), ED25519_SPKI_PREFIX)) return null;
  return der.subarray(12);
}

/**
 * The C2SP key id of an Ed25519 log key, sha256(origin || "\n" || 0x01 || raw key),
 * base64 of all 32 bytes. The first four bytes prefix every signature line.
 */
export function checkpointKeyId(origin: string, publicKeyDer: Uint8Array): string {
  const raw = ed25519RawFromSpki(publicKeyDer);
  if (!raw) throw new Error("checkpoint: only Ed25519 log keys are supported");
  const h = createHash("sha256");
  h.update(Buffer.from(origin + "\n", "utf8"));
  h.update(new Uint8Array([1]));
  h.update(raw);
  return toBase64(new Uint8Array(h.digest()));
}

export interface CheckpointResult {
  ok: boolean;
  origin: string;
  size: string;
  root: string;
  keyId?: string;
  signedBy?: string;
  cosigned: string[];
  reason?: string;
}

/**
 * Verify the origin's own signature line with a trusted key for that origin.
 * Other signers are reported as cosigned and not verified.
 */
export function verifyCheckpoint(note: string, logKeys: ReadonlyArray<LogKey>): CheckpointResult {
  let parsed: ParsedCheckpoint;
  try { parsed = parseCheckpoint(note); }
  catch (e) { return { ok: false, origin: "", size: "", root: "", cosigned: [], reason: (e as Error).message }; }
  const { origin, size, root, text, signatures } = parsed;
  const cosigned = signatures.filter((s) => s.name !== origin).map((s) => s.name);
  const own = signatures.find((s) => s.name === origin);
  if (!own) return { ok: false, origin, size, root, cosigned, reason: "checkpoint: no signature by the origin" };
  const message = Buffer.from(text, "utf8");
  for (const k of logKeys) {
    if (k.origin !== origin) continue;
    const der = fromBase64(k.publicKey);
    let keyId: string;
    try { keyId = checkpointKeyId(origin, der); }
    catch (e) { return { ok: false, origin, size, root, cosigned, reason: (e as Error).message }; }
    if (!bytesEqual(fromBase64(keyId).subarray(0, 4), own.keyId)) continue;
    const key = createPublicKey({ key: Buffer.from(der), format: "der", type: "spki" });
    const good = cryptoVerify(null, message, key, own.signature);
    return good
      ? { ok: true, origin, size, root, keyId, signedBy: origin, cosigned }
      : { ok: false, origin, size, root, keyId, cosigned, reason: "checkpoint: signature does not verify" };
  }
  return { ok: false, origin, size, root, cosigned, reason: "untrusted log key" };
}
