import { verifyChain } from "../hash.js";
import type { Receipt } from "../types.js";
import type { Anchor, AnchorCheck, AnchorTrust, AnchoredVerifyResult } from "./types.js";
import { artifactOf, digestOf } from "./artifact.js";
import { bytesEqual, fromBase64 } from "./bytes.js";
import { decodeBody, KEY_DETAILS } from "./body.js";
import { leafHashOf, verifyInclusion } from "./merkle.js";
import { verifyCheckpoint } from "./checkpoint.js";
import { verifyArtifactSignature } from "./signer.js";

function fail(a: Anchor, reason: string, cosigned: string[] = []): AnchorCheck {
  return { seq: a.seq, ok: false, reason, logIndex: a.entry.logIndex, cosigned };
}

/**
 * Steps 1 to 4 of the spec: the anchor against its own proof and the trust set.
 * No chain is involved, so a witness can use this on a reply before storing it.
 */
export function verifyAnchorProof(a: Anchor, trust: AnchorTrust): AnchorCheck {
  if (a.v !== 1) return fail(a, "unsupported anchor version");
  if (a.entry.logIndex !== a.proof.logIndex) return fail(a, "log index differs between entry and proof");
  let artifact: Uint8Array;
  try { artifact = artifactOf(a.stream, a.seq, a.head); }
  catch (e) { return fail(a, (e as Error).message); }
  if (a.witness.alg !== "ecdsa-p256") return fail(a, "unsupported witness algorithm");
  if (!trust.witnessKeys.includes(a.witness.publicKey)) return fail(a, "untrusted witness key");
  if (!verifyArtifactSignature(artifact, a.signature, a.witness.publicKey)) return fail(a, "witness signature does not verify");
  const body = decodeBody(a.entry.canonicalizedBody);
  if (!body) return fail(a, "log entry body is not a hashedrekord 0.0.2");
  if (body.keyDetails !== KEY_DETAILS || body.publicKey !== a.witness.publicKey) return fail(a, "log entry verifier key differs from the witness key");
  if (!bytesEqual(fromBase64(body.digest), digestOf(artifact))) return fail(a, "log entry digest differs from the artifact digest");
  if (body.signature !== a.signature) return fail(a, "log entry signature differs from the anchor signature");
  if (!verifyInclusion(leafHashOf(fromBase64(a.entry.canonicalizedBody)), a.proof)) return fail(a, "inclusion proof does not reach the root");
  const cp = verifyCheckpoint(a.proof.checkpoint, trust.logKeys);
  if (!cp.ok) return fail(a, cp.reason ?? "checkpoint does not verify", cp.cosigned);
  if (cp.root !== a.proof.rootHash || cp.size !== a.proof.treeSize) return fail(a, "checkpoint root or size differs from the proof", cp.cosigned);
  if (cp.keyId !== undefined && a.log.keyId !== cp.keyId) return fail(a, "anchor log key id differs from the signing key", cp.cosigned);
  return { seq: a.seq, ok: true, logIndex: a.entry.logIndex, cosigned: cp.cosigned };
}

/**
 * The full promise. Each anchor's proof, then the chain: the record at the
 * anchored position must carry the anchored head. `coveredUpTo` is the highest
 * seq an anchor vouched for; below it a rewrite or a truncation is named.
 *
 * `opts.stream`, when given, binds the check to that stream: an anchor minted
 * for another stream fails before the record check. Without it, every anchor
 * must agree on one stream or all of them fail; a single stream trivially
 * agrees with itself.
 */
export function verifyAnchored(
  records: ReadonlyArray<Receipt>,
  anchors: ReadonlyArray<Anchor>,
  trust: AnchorTrust,
  opts?: { stream?: string },
): AnchoredVerifyResult {
  const chain = verifyChain(records);
  const streams = new Set(anchors.map((a) => a.stream));
  const sharedStream = anchors.length > 0 && streams.size === 1 ? anchors[0]!.stream : null;
  const spanning = !opts?.stream && anchors.length > 0 && streams.size > 1;
  const stream = opts?.stream ?? sharedStream;
  const checks = anchors.map((a) => {
    const proof = verifyAnchorProof(a, trust);
    if (!proof.ok) return proof;
    if (opts?.stream !== undefined && a.stream !== opts.stream) {
      return fail(a, `anchor is for stream ${a.stream}, not ${opts.stream}`, proof.cosigned);
    }
    if (spanning) return fail(a, "anchors span more than one stream", proof.cosigned);
    const rec = records[a.seq];
    if (!rec) return fail(a, `record missing at seq ${a.seq}`, proof.cosigned);
    if (rec.hash !== a.head) return fail(a, `head mismatch at seq ${a.seq}`, proof.cosigned);
    return proof;
  });
  const okSeqs = checks.filter((c) => c.ok).map((c) => c.seq);
  const coveredUpTo = okSeqs.length ? Math.max(...okSeqs) : null;
  return { ok: chain.ok && checks.every((c) => c.ok), coveredUpTo, anchors: checks, chain, stream };
}
