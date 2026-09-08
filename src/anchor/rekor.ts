import type { Anchor, LogKey } from "./types.js";
import type { P256Signer } from "./signer.js";
import { artifactOf, digestOf } from "./artifact.js";
import { buildRequest } from "./body.js";
import { verifyAnchorProof } from "./verify.js";

export interface RekorV2Options {
  /** The instance, e.g. https://log2025-1.rekor.sigstore.dev. Rotates by year; configure, never compile in. */
  url: string;
  /** The log keys the reply must be signed by. From Sigstore's trust root, pinned by the operator. */
  logKeys: ReadonlyArray<LogKey>;
  /** Default 30000. The client guide asks for at least 20 seconds. */
  timeoutMs?: number;
  fetch?: typeof fetch;
  now?: () => string;
}

interface EntryReply {
  logIndex?: string;
  logId?: { keyId?: string };
  canonicalizedBody?: string;
  inclusionProof?: { logIndex?: string; treeSize?: string; rootHash?: string; hashes?: string[]; checkpoint?: { envelope?: string } };
}

/** Submits one anchor to a Rekor v2 log and verifies the reply before returning it. */
export class RekorV2 {
  private readonly url: string;
  private readonly logKeys: ReadonlyArray<LogKey>;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => string;

  constructor(opts: RekorV2Options) {
    this.url = opts.url.replace(/\/+$/, "");
    if (!/^https?:\/\//.test(this.url)) throw new Error("rekor: url must start with http:// or https://");
    this.logKeys = opts.logKeys;
    this.timeoutMs = opts.timeoutMs ?? 30000;
    this.fetchImpl = opts.fetch ?? fetch;
    this.now = opts.now ?? (() => new Date().toISOString());
  }

  async submit(stream: string, seq: number, head: string, signer: P256Signer): Promise<Anchor> {
    const artifact = artifactOf(stream, seq, head);
    const signature = signer.sign(artifact);
    const publicKey = signer.publicKeyDer();
    const res = await this.fetchImpl(`${this.url}/api/v2/log/entries`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(buildRequest(digestOf(artifact), signature, publicKey)),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (res.status !== 201 && res.status !== 200) {
      throw new Error(`rekor: ${res.status} ${(await res.text()).slice(0, 200)}`);
    }
    const reply = (await res.json()) as EntryReply;
    const p = reply.inclusionProof;
    if (!reply.logIndex || !reply.logId?.keyId || !reply.canonicalizedBody || !p?.logIndex || !p.treeSize || !p.rootHash || !p.hashes || !p.checkpoint?.envelope) {
      throw new Error("rekor: reply is missing fields");
    }
    const anchor: Anchor = {
      v: 1, stream, seq, head, at: this.now(),
      witness: { alg: "ecdsa-p256", publicKey },
      signature,
      log: { url: this.url, keyId: reply.logId.keyId },
      entry: { logIndex: reply.logIndex, canonicalizedBody: reply.canonicalizedBody },
      proof: { logIndex: p.logIndex, treeSize: p.treeSize, rootHash: p.rootHash, hashes: p.hashes, checkpoint: p.checkpoint.envelope },
    };
    const check = verifyAnchorProof(anchor, { logKeys: this.logKeys, witnessKeys: [publicKey] });
    if (!check.ok) throw new Error(`rekor: reply did not verify, ${check.reason}`);
    return anchor;
  }
}
