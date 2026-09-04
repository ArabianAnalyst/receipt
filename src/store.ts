import { appendFileSync, readFileSync, existsSync } from "node:fs";
import { GENESIS } from "./types.js";
import type { Receipt, Store } from "./types.js";

/** In-memory append-only store. lastHash() returns the tip of the chain. */
export class MemoryStore<P = unknown> implements Store<P> {
  protected records: Receipt<P>[] = [];

  lastHash(): string {
    const last = this.records[this.records.length - 1];
    return last ? last.hash : GENESIS;
  }

  append(rec: Receipt<P>): void {
    this.records.push(rec);
  }

  all(): Receipt<P>[] {
    return [...this.records];
  }
}

/**
 * Append-only JSONL store, one receipt per line. Pass a path to persist and
 * reload across restarts; omit it for an in-memory store. A corrupt or
 * partially-written line throws a clear error on construction rather than
 * being silently skipped, so a damaged log is never shortened.
 */
export class JsonlStore<P = unknown> extends MemoryStore<P> {
  constructor(private readonly path?: string) {
    super();
    if (path && existsSync(path)) {
      const lines = readFileSync(path, "utf8").split("\n");
      const records: Receipt<P>[] = [];
      lines.forEach((line, i) => {
        if (line.trim() === "") return;          // blank or trailing newline: skip, but the index still counts
        try {
          // No runtime shape check: malformed-but-parseable lines are caught later by verifyChain.
          records.push(JSON.parse(line) as Receipt<P>);
        } catch (e) {
          throw new Error(`JsonlStore: corrupt line ${i + 1} in ${path}: ${(e as Error).message}`);
        }
      });
      this.records = records;
    }
  }

  append(rec: Receipt<P>): void {
    super.append(rec);
    if (this.path) appendFileSync(this.path, JSON.stringify(rec) + "\n");
  }
}
