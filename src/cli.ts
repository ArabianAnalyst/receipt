#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { verifyAnchored } from "./anchor/verify.js";
import type { Anchor, AnchorTrust } from "./anchor/types.js";
import type { Receipt } from "./types.js";

const args = process.argv.slice(2);

function usage(): never {
  process.stderr.write(
    "receipt-verify <chain.json | chain.jsonl> --anchors <file | witness url> --log-key <origin>=<base64 DER> [--log-key ...] --witness-key <base64 DER> [--witness-key ...]\n",
  );
  process.exit(2);
}

const positional = args.filter((a, i) => !a.startsWith("--") && !(i > 0 && args[i - 1]!.startsWith("--")));
const values = (name: string): string[] => args.flatMap((a, i) => (a === name && args[i + 1] !== undefined ? [args[i + 1]!] : []));

const chainFile = positional[0];
const anchorsArg = values("--anchors")[0];
if (!chainFile || !anchorsArg || args.includes("--help") || args.includes("-h")) usage();

const trust: AnchorTrust = {
  logKeys: values("--log-key").map((v) => {
    const i = v.indexOf("=");
    if (i <= 0) usage();
    return { origin: v.slice(0, i), publicKey: v.slice(i + 1) };
  }),
  witnessKeys: values("--witness-key"),
};
if (trust.logKeys.length === 0 || trust.witnessKeys.length === 0) usage();

function readRecords(file: string): Receipt[] {
  const text = readFileSync(file, "utf8").trim();
  if (text.startsWith("[")) return JSON.parse(text) as Receipt[];
  return text.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line) as Receipt);
}

async function readAnchors(src: string): Promise<Anchor[]> {
  let text: string;
  if (/^https?:\/\//.test(src)) {
    const res = await fetch(src.replace(/\/+$/, "") + "/anchors");
    if (!res.ok) throw new Error(`anchors: ${res.status} from ${src}`);
    text = await res.text();
  } else {
    text = readFileSync(src, "utf8");
  }
  const j = JSON.parse(text) as Anchor[] | { anchors: Anchor[] };
  return Array.isArray(j) ? j : j.anchors;
}

async function main(): Promise<void> {
  const result = verifyAnchored(readRecords(chainFile!), await readAnchors(anchorsArg!), trust);
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  process.exit(result.ok ? 0 : 1);
}

main().catch((e) => {
  process.stderr.write(`receipt-verify: ${(e as Error).message}\n`);
  process.exit(2);
});
