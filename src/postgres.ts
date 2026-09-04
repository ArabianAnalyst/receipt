import { GENESIS } from "./types.js";
import type { Receipt, Store } from "./types.js";
import { verifyChain } from "./hash.js";

/** The one thing a database driver must provide. pg, Neon serverless, and PGlite satisfy it as-is. */
export interface SqlClient {
  query(text: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

export interface PostgresStoreOptions {
  /** One table serves many products; each product writes one stream. Default "default". */
  stream?: string;
  /** Table name. Default "receipts". Letters, digits, underscores only. */
  table?: string;
  /** Run CREATE TABLE IF NOT EXISTS and the index on open. Default true. */
  migrate?: boolean;
  /** Retries for transient insert failures before the store latches. Default 3. */
  retries?: number;
  /** Backoff per retry in milliseconds. Default [100, 400, 1600]. Tests pass zeros. */
  backoffMs?: number[];
}

const IDENT = /^[a-z_][a-z0-9_]*$/;

/** The schema, as executed by open(). Exposed so operators can run it themselves. */
export function schema(table = "receipts"): string[] {
  if (!IDENT.test(table)) throw new Error(`PostgresStore: invalid table name "${table}"`);
  return [
    `CREATE TABLE IF NOT EXISTS ${table} (
  seq BIGSERIAL PRIMARY KEY,
  stream TEXT NOT NULL,
  id TEXT NOT NULL,
  ts TIMESTAMPTZ NOT NULL,
  kind TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  payload JSONB NOT NULL,
  record TEXT NOT NULL,
  UNIQUE (stream, id),
  UNIQUE (stream, hash),
  UNIQUE (stream, prev_hash)
)`,
    `CREATE INDEX IF NOT EXISTS ${table}_stream_seq ON ${table} (stream, seq)`,
  ];
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Write-through Postgres store. Synchronous Store<P> for callers; every append is queued
 * as one ordered INSERT. Reload reads the canonical `record` text, never `payload` jsonb,
 * because jsonb reorders keys and would break the hash. The UNIQUE (stream, prev_hash)
 * constraint makes the database reject a fork. The first hard error latches the store.
 */
export class PostgresStore<P = unknown> implements Store<P> {
  private records: Receipt<P>[] = [];
  private queue: Receipt<P>[] = [];
  private chain: Promise<void> = Promise.resolve();
  private latched: Error | null = null;
  private readonly stream: string;
  private readonly table: string;
  private readonly retries: number;
  private readonly backoffMs: number[];

  private constructor(private readonly client: SqlClient, opts: PostgresStoreOptions) {
    this.stream = opts.stream ?? "default";
    this.table = opts.table ?? "receipts";
    if (!IDENT.test(this.table)) throw new Error(`PostgresStore: invalid table name "${this.table}"`);
    this.retries = opts.retries ?? 3;
    this.backoffMs = opts.backoffMs ?? [100, 400, 1600];
  }

  /** Migrate (optional), load the stream in order, verify it, and return a synchronous store. */
  static async open<P = unknown>(client: SqlClient, opts: PostgresStoreOptions = {}): Promise<PostgresStore<P>> {
    const store = new PostgresStore<P>(client, opts);
    if (opts.migrate ?? true) {
      for (const stmt of schema(store.table)) await client.query(stmt);
    }
    const { rows } = await client.query(`SELECT record FROM ${store.table} WHERE stream = $1 ORDER BY seq`, [store.stream]);
    store.records = rows.map((r) => JSON.parse(String(r.record)) as Receipt<P>);
    const v = verifyChain(store.records);
    if (!v.ok) {
      throw new Error(`PostgresStore: stream "${store.stream}" fails verification at index ${v.brokenAt} (${v.reason})`);
    }
    return store;
  }

  lastHash(): string {
    const last = this.records[this.records.length - 1];
    return last ? last.hash : GENESIS;
  }

  append(rec: Receipt<P>): void {
    if (this.latched) throw new Error(`PostgresStore: degraded, ${this.latched.message}`);
    this.records.push(rec);
    this.queue.push(rec);
    this.chain = this.chain.then(() => this.insert(rec));
  }

  all(): Receipt<P>[] {
    return [...this.records];
  }

  /** Appends queued but not yet durable. */
  pending(): number {
    return this.queue.length;
  }

  /** Resolves when every queued append is durable. Rejects with the latched error. */
  async flush(): Promise<void> {
    await this.chain;
    if (this.latched) throw new Error(`PostgresStore: degraded, ${this.latched.message}`);
  }

  private async insert(rec: Receipt<P>): Promise<void> {
    if (this.latched) return;
    const sql = `INSERT INTO ${this.table} (stream, id, ts, kind, prev_hash, hash, payload, record) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`;
    const params = [this.stream, rec.id, rec.ts, rec.kind, rec.prevHash, rec.hash, JSON.stringify(rec.payload), JSON.stringify(rec)];
    for (let attempt = 0; ; attempt++) {
      try {
        await this.client.query(sql, params);
        this.queue.shift();
        return;
      } catch (e) {
        const err = e as Error & { code?: string };
        const unique = err.code === "23505" || /unique constraint/i.test(err.message);
        if (unique || attempt >= this.retries) {
          this.latched = new Error(`insert of receipt ${rec.id} failed after ${attempt + 1} attempt(s): ${err.message}`);
          return;
        }
        await sleep(this.backoffMs[Math.min(attempt, this.backoffMs.length - 1)] ?? 0);
      }
    }
  }
}
