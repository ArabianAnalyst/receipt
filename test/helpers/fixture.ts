import { readFileSync } from "node:fs";
import type { Anchor, AnchorTrust } from "../../src/anchor/types.js";

interface FixtureFile {
  captured: string;
  log: string;
  artifact: { stream: string; seq: number; head: string; text: string };
  request: { hashedRekordRequestV002: { digest: string; signature: { content: string; verifier: { keyDetails: string; publicKey: { rawBytes: string } } } } };
  response: {
    logIndex: string;
    logId: { keyId: string };
    canonicalizedBody: string;
    inclusionProof: { logIndex: string; treeSize: string; rootHash: string; hashes: string[]; checkpoint: { envelope: string } };
  };
}

const read = <T>(name: string): T => JSON.parse(readFileSync(new URL(`../fixtures/rekor-v2/${name}`, import.meta.url), "utf8")) as T;

export const fixtureEntry = (): FixtureFile => read<FixtureFile>("fixture-entry.json");
const logKeyFile = read<{ baseUrl: string; publicKey: { rawBytes: string }; logId: { keyId: string } }>("log2025-1-key.json");

export const FIXTURE_ORIGIN = "log2025-1.rekor.sigstore.dev";

export function fixtureAnchor(): Anchor {
  const f = fixtureEntry();
  const r = f.response;
  return {
    v: 1,
    stream: f.artifact.stream,
    seq: f.artifact.seq,
    head: f.artifact.head,
    at: f.captured,
    witness: { alg: "ecdsa-p256", publicKey: f.request.hashedRekordRequestV002.signature.verifier.publicKey.rawBytes },
    signature: f.request.hashedRekordRequestV002.signature.content,
    log: { url: f.log, keyId: r.logId.keyId },
    entry: { logIndex: r.logIndex, canonicalizedBody: r.canonicalizedBody },
    proof: { logIndex: r.inclusionProof.logIndex, treeSize: r.inclusionProof.treeSize, rootHash: r.inclusionProof.rootHash, hashes: r.inclusionProof.hashes, checkpoint: r.inclusionProof.checkpoint.envelope },
  };
}

export const fixtureLogKey = { origin: FIXTURE_ORIGIN, publicKey: logKeyFile.publicKey.rawBytes };
export const fixtureLogId = logKeyFile.logId.keyId;
export const fixtureTrust: AnchorTrust = { logKeys: [fixtureLogKey], witnessKeys: [fixtureAnchor().witness.publicKey] };
