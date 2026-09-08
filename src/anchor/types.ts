import type { VerifyResult } from "../types.js";

/** A Rekor v2 inclusion proof as returned, strings kept as strings. */
export interface InclusionProof {
  logIndex: string;
  treeSize: string;
  rootHash: string;      // base64
  hashes: string[];      // base64, leaf to root
  checkpoint: string;    // the C2SP signed note envelope
}

/** One anchoring event. Nothing in it is secret. */
export interface Anchor {
  v: 1;
  stream: string;
  /** 0-based position of the anchored receipt in the stream. Not the receipts table's seq column. */
  seq: number;
  /** That receipt's hash, 64 lowercase hex. */
  head: string;
  /** Witness clock, ISO-8601, informational. */
  at: string;
  witness: { alg: "ecdsa-p256"; publicKey: string };   // base64 SPKI DER
  /** base64 DER ECDSA signature over the artifact bytes. */
  signature: string;
  log: { url: string; keyId: string };                 // keyId base64, 32 bytes
  entry: { logIndex: string; canonicalizedBody: string };
  proof: InclusionProof;
}

export interface LogKey { origin: string; publicKey: string }   // publicKey base64 SPKI DER

export interface AnchorTrust {
  logKeys: ReadonlyArray<LogKey>;
  witnessKeys: ReadonlyArray<string>;                   // base64 SPKI DER
}

export interface AnchorCheck {
  seq: number;
  ok: boolean;
  reason?: string;
  logIndex: string;
  cosigned: string[];
}

export interface AnchoredVerifyResult {
  ok: boolean;
  coveredUpTo: number | null;
  anchors: AnchorCheck[];
  chain: VerifyResult;
  /** The stream the check ran against, opts.stream or the anchors' shared stream, null when there are no anchors. */
  stream: string | null;
}

/** Append-only by contract. Nothing in this package updates or deletes an anchor. */
export interface AnchorStore {
  append(a: Anchor): Promise<void>;
  list(stream: string, sinceSeq?: number): Promise<Anchor[]>;
  last(stream: string): Promise<Anchor | null>;
}
