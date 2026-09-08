import { createHash } from "node:crypto";
import { bytesEqual, fromBase64 } from "./bytes.js";
import type { InclusionProof } from "./types.js";

function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

/** RFC 6962 leaf hash, sha256(0x00 || data). */
export function leafHashOf(data: Uint8Array): Uint8Array {
  return sha256(new Uint8Array([0]), data);
}

/** RFC 6962 interior node, sha256(0x01 || left || right). */
export function nodeHashOf(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(new Uint8Array([1]), left, right);
}

/**
 * RFC 9162 section 2.1.3.2. True when the path from the leaf at `index` in a
 * tree of `size` leaves reaches `root`.
 */
export function verifyInclusionPath(
  leafHash: Uint8Array,
  index: bigint,
  size: bigint,
  path: ReadonlyArray<Uint8Array>,
  root: Uint8Array,
): boolean {
  if (index < 0n || size <= 0n || index >= size) return false;
  let fn = index;
  let sn = size - 1n;
  let r = leafHash;
  for (const p of path) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      r = nodeHashOf(p, r);
      if ((fn & 1n) === 0n) {
        while (fn !== 0n && (fn & 1n) === 0n) { fn >>= 1n; sn >>= 1n; }
      }
    } else {
      r = nodeHashOf(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && bytesEqual(r, root);
}

/** Verify a Rekor-shaped proof for a leaf hash. False on any malformed number. */
export function verifyInclusion(leafHash: Uint8Array, proof: InclusionProof): boolean {
  let index: bigint;
  let size: bigint;
  try { index = BigInt(proof.logIndex); size = BigInt(proof.treeSize); } catch { return false; }
  return verifyInclusionPath(leafHash, index, size, proof.hashes.map(fromBase64), fromBase64(proof.rootHash));
}
