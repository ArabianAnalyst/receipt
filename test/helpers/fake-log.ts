import { createHash, generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { leafHashOf, nodeHashOf } from "../../src/anchor/merkle.js";
import { checkpointKeyId } from "../../src/anchor/checkpoint.js";
import { fromBase64, toBase64 } from "../../src/anchor/bytes.js";
import type { RekorRequest } from "../../src/anchor/body.js";

export interface FakeReply {
  logIndex: string;
  logId: { keyId: string };
  kindVersion: { kind: string; version: string };
  integratedTime: string;
  canonicalizedBody: string;
  inclusionProof: { logIndex: string; treeSize: string; rootHash: string; hashes: string[]; checkpoint: { envelope: string } };
}

/** RFC 6962 root of a list of leaf hashes. */
export function rootOf(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return new Uint8Array(createHash("sha256").digest());
  if (leaves.length === 1) return leaves[0]!;
  const k = largestPowerOfTwoBelow(leaves.length);
  return nodeHashOf(rootOf(leaves.slice(0, k)), rootOf(leaves.slice(k)));
}

/** RFC 6962 inclusion path for the leaf at `index`, leaf to root. */
export function pathFor(index: number, leaves: Uint8Array[]): Uint8Array[] {
  if (leaves.length <= 1) return [];
  const k = largestPowerOfTwoBelow(leaves.length);
  if (index < k) return [...pathFor(index, leaves.slice(0, k)), rootOf(leaves.slice(k))];
  return [...pathFor(index - k, leaves.slice(k)), rootOf(leaves.slice(0, k))];
}

function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * A tiny Rekor-shaped log for tests. Real RFC 6962 trees over canonicalized
 * bodies, real C2SP checkpoints signed with a throwaway Ed25519 key.
 */
export class FakeLog {
  readonly origin: string;
  readonly url: string;
  readonly publicKeyDer: string;
  readonly keyId: string;
  private readonly key: KeyObject;
  private readonly bodies: Uint8Array[] = [];

  constructor(origin = "fake.log.test", url = "https://fake.log.test") {
    this.origin = origin;
    this.url = url;
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    this.key = privateKey;
    this.publicKeyDer = toBase64(new Uint8Array(publicKey.export({ type: "spki", format: "der" }) as Buffer));
    this.keyId = checkpointKeyId(origin, fromBase64(this.publicKeyDer));
  }

  get logKey(): { origin: string; publicKey: string } {
    return { origin: this.origin, publicKey: this.publicKeyDer };
  }

  get size(): number {
    return this.bodies.length;
  }

  /** Append the body a Rekor v2 would build for this request and return the reply. */
  add(request: RekorRequest): FakeReply {
    const r = request.hashedRekordRequestV002;
    const body = JSON.stringify({
      apiVersion: "0.0.2",
      kind: "hashedrekord",
      spec: { hashedRekordV002: { data: { algorithm: "SHA2_256", digest: r.digest }, signature: { content: r.signature.content, verifier: { keyDetails: r.signature.verifier.keyDetails, publicKey: { rawBytes: r.signature.verifier.publicKey.rawBytes } } } } },
    });
    this.bodies.push(new TextEncoder().encode(body));
    return this.entry(this.bodies.length - 1);
  }

  /** The reply for entry `index`, proven against the current tree. */
  entry(index: number): FakeReply {
    const body = this.bodies[index];
    if (!body) throw new Error(`no entry ${index}`);
    const leaves = this.bodies.map(leafHashOf);
    const size = leaves.length;
    const root = rootOf(leaves);
    const path = pathFor(index, leaves);
    const text = `${this.origin}\n${size}\n${toBase64(root)}\n`;
    const sig = new Uint8Array(cryptoSign(null, Buffer.from(text, "utf8"), this.key));
    const line = toBase64(new Uint8Array([...fromBase64(this.keyId).subarray(0, 4), ...sig]));
    const envelope = `${text}\n— ${this.origin} ${line}\n`;
    return {
      logIndex: String(index),
      logId: { keyId: this.keyId },
      kindVersion: { kind: "hashedrekord", version: "0.0.2" },
      integratedTime: "0",
      canonicalizedBody: toBase64(body),
      inclusionProof: { logIndex: String(index), treeSize: String(size), rootHash: toBase64(root), hashes: path.map(toBase64), checkpoint: { envelope } },
    };
  }

  /** A fetch replacement that answers POST {url}/api/v2/log/entries with 201 and a reply. */
  fetch(status = 201): typeof fetch {
    const impl = async (input: unknown, init?: { method?: string; body?: unknown }) => {
      const url = String(input);
      if (!url.endsWith("/api/v2/log/entries") || init?.method !== "POST") return new Response("not found", { status: 404 });
      if (status !== 201) return new Response("nope", { status });
      const reply = this.add(JSON.parse(String(init.body)) as RekorRequest);
      return new Response(JSON.stringify(reply), { status: 201, headers: { "content-type": "application/json" } });
    };
    return impl as unknown as typeof fetch;
  }
}
