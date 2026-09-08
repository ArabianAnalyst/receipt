import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { fromBase64, toBase64 } from "./bytes.js";

const CURVE = "prime256v1";

function assertP256(key: KeyObject): void {
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== CURVE) {
    throw new Error("witness key must be an EC P-256 key");
  }
}

/** The witness's signing key. One per witness. */
export class P256Signer {
  private constructor(private readonly privateKey: KeyObject, private readonly publicKey: KeyObject) {}

  static generate(): P256Signer {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    return new P256Signer(privateKey, publicKey);
  }

  static fromPem(pem: string): P256Signer {
    const privateKey = createPrivateKey(pem);
    assertP256(privateKey);
    return new P256Signer(privateKey, createPublicKey(privateKey));
  }

  /** PKCS8 PEM, the form WITNESS_KEY_FILE holds. */
  toPem(): string {
    return this.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  }

  /** base64 SubjectPublicKeyInfo DER, the form anchors and Rekor carry. */
  publicKeyDer(): string {
    return toBase64(new Uint8Array(this.publicKey.export({ type: "spki", format: "der" }) as Buffer));
  }

  /** ECDSA with SHA-256 over the bytes, DER encoded, base64. */
  sign(bytes: Uint8Array): string {
    return toBase64(new Uint8Array(cryptoSign("sha256", bytes, { key: this.privateKey, dsaEncoding: "der" })));
  }
}

/** True when the signature verifies over the artifact under the given P-256 public key. False on any malformed input. */
export function verifyArtifactSignature(artifact: Uint8Array, signatureB64: string, publicKeyDerB64: string): boolean {
  try {
    const key = createPublicKey({ key: Buffer.from(fromBase64(publicKeyDerB64)), format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== CURVE) return false;
    return cryptoVerify("sha256", artifact, { key, dsaEncoding: "der" }, fromBase64(signatureB64));
  } catch {
    return false;
  }
}
