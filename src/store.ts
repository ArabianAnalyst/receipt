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
 * reload across restarts; omit it for an in-memory store.
 */
export class JsonlStore<P = unknown> extends MemoryStore<P> {
  constructor(private readonly path?: string) {
    super();
    if (path && existsSync(path)) {
      this.records = readFileSync(path, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l) as Receipt<P>);
    }
  }

  append(rec: Receipt<P>): void {
    super.append(rec);
    if (this.path) appendFileSync(this.path, JSON.stringify(rec) + "\n");
  }
}
