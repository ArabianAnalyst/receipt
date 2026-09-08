import { fromBase64, toBase64 } from "./bytes.js";

export const KEY_DETAILS = "PKIX_ECDSA_P256_SHA_256";

export interface HashedRekordBody { digest: string; signature: string; publicKey: string; keyDetails: string }

export interface RekorRequest {
  hashedRekordRequestV002: {
    digest: string;
    signature: { content: string; verifier: { keyDetails: string; publicKey: { rawBytes: string } } };
  };
}

interface BodyShape {
  apiVersion?: string;
  kind?: string;
  spec?: { hashedRekordV002?: { data?: { algorithm?: string; digest?: string }; signature?: { content?: string; verifier?: { keyDetails?: string; publicKey?: { rawBytes?: string } } } } };
}

/** Decode a hashedrekord 0.0.2 canonicalized body. Null when the bytes are not that. */
export function decodeBody(canonicalizedBodyB64: string): HashedRekordBody | null {
  try {
    const j = JSON.parse(Buffer.from(fromBase64(canonicalizedBodyB64)).toString("utf8")) as BodyShape;
    if (j.kind !== "hashedrekord" || j.apiVersion !== "0.0.2") return null;
    const s = j.spec?.hashedRekordV002;
    const digest = s?.data?.digest;
    const signature = s?.signature?.content;
    const publicKey = s?.signature?.verifier?.publicKey?.rawBytes;
    const keyDetails = s?.signature?.verifier?.keyDetails;
    if (s?.data?.algorithm !== "SHA2_256" || !digest || !signature || !publicKey || !keyDetails) return null;
    return { digest, signature, publicKey, keyDetails };
  } catch {
    return null;
  }
}

/** The Rekor v2 write request for a signed artifact digest. */
export function buildRequest(digest: Uint8Array, signatureB64: string, publicKeyDerB64: string): RekorRequest {
  return {
    hashedRekordRequestV002: {
      digest: toBase64(digest),
      signature: { content: signatureB64, verifier: { keyDetails: KEY_DETAILS, publicKey: { rawBytes: publicKeyDerB64 } } },
    },
  };
}
