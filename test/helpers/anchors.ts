import { MemoryStore } from "../../src/store.js";
import { makeReceipt } from "../../src/chain.js";
import type { Receipt } from "../../src/types.js";
import type { Anchor } from "../../src/anchor/types.js";
import { artifactOf, digestOf } from "../../src/anchor/artifact.js";
import { buildRequest } from "../../src/anchor/body.js";
import type { P256Signer } from "../../src/anchor/signer.js";
import type { FakeLog } from "./fake-log.js";

/** A deterministic chain of n receipts. */
export function chainOf(n: number): Receipt[] {
  const store = new MemoryStore<{ n: number }>();
  let seq = 0;
  const opts = { now: () => "2026-09-08T00:00:00.000Z", newId: () => `id-${++seq}` };
  for (let i = 0; i < n; i++) makeReceipt(store, { kind: "test", payload: { n: i } }, opts);
  return store.all();
}

/** Sign and submit one head to a FakeLog and shape the reply into an Anchor, as RekorV2 will. */
export function anchorWith(log: FakeLog, signer: P256Signer, stream: string, seq: number, head: string, at = "2026-09-08T00:00:00.000Z"): Anchor {
  const artifact = artifactOf(stream, seq, head);
  const signature = signer.sign(artifact);
  const publicKey = signer.publicKeyDer();
  const r = log.add(buildRequest(digestOf(artifact), signature, publicKey));
  return {
    v: 1, stream, seq, head, at,
    witness: { alg: "ecdsa-p256", publicKey },
    signature,
    log: { url: log.url, keyId: r.logId.keyId },
    entry: { logIndex: r.logIndex, canonicalizedBody: r.canonicalizedBody },
    proof: { logIndex: r.inclusionProof.logIndex, treeSize: r.inclusionProof.treeSize, rootHash: r.inclusionProof.rootHash, hashes: r.inclusionProof.hashes, checkpoint: r.inclusionProof.checkpoint.envelope },
  };
}
