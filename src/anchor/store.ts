import type { SqlClient } from "../postgres.js";
import type { Anchor, AnchorStore } from "./types.js";

/** In-memory, for tests and single-process witnesses that do not need durability. */
export class MemoryAnchorStore implements AnchorStore {
  private readonly rows: Anchor[] = [];

  async append(a: Anchor): Promise<void> {
    if (this.rows.some((r) => r.stream === a.stream && r.seq === a.seq)) {
      throw new Error(`anchor exists for stream ${a.stream} seq ${a.seq}`);
    }
    this.rows.push(structuredClone(a));
  }

  async list(stream: string, sinceSeq = -1): Promise<Anchor[]> {
    return this.rows
      .filter((r) => r.stream === stream && r.seq > sinceSeq)
      .sort((x, y) => x.seq - y.seq)
      .map((r) => structuredClone(r));
  }

  async last(stream: string): Promise<Anchor | null> {
    const all = await this.list(stream);
    return all.length ? all[all.length - 1]! : null;
  }
}

const IDENT = /^[a-z_][a-z0-9_]*$/;

/** The schema, as executed by open(). Exposed so operators can run it themselves. */
export function anchorSchema(table = "anchors"): string[] {
  if (!IDENT.test(table) || table.length > 63) {
    throw new Error(`PostgresAnchorStore: invalid table name "${table}" (letters, digits, underscores, max 63)`);
  }
  return [
    `CREATE TABLE IF NOT EXISTS ${table} (
  n BIGSERIAL PRIMARY KEY,
  stream TEXT NOT NULL,
  seq BIGINT NOT NULL,
  head TEXT NOT NULL,
  at TIMESTAMPTZ NOT NULL,
  record TEXT NOT NULL,
  UNIQUE (stream, seq)
)`,
  ];
}

/**
 * Append-only anchors beside the receipts. `record` is the canonical Anchor
 * JSON, read back verbatim. Nothing here updates or deletes.
 */
export class PostgresAnchorStore implements AnchorStore {
  private readonly table: string;

  constructor(private readonly client: SqlClient, opts: { table?: string } = {}) {
    this.table = opts.table ?? "anchors";
    anchorSchema(this.table);
  }

  async open(): Promise<void> {
    for (const sql of anchorSchema(this.table)) await this.client.query(sql);
  }

  async append(a: Anchor): Promise<void> {
    await this.client.query(
      `INSERT INTO ${this.table} (stream, seq, head, at, record) VALUES ($1, $2, $3, $4, $5)`,
      [a.stream, a.seq, a.head, a.at, JSON.stringify(a)],
    );
  }

  async list(stream: string, sinceSeq = -1): Promise<Anchor[]> {
    const { rows } = await this.client.query(
      `SELECT record FROM ${this.table} WHERE stream = $1 AND seq > $2 ORDER BY seq`,
      [stream, sinceSeq],
    );
    return rows.map((r) => JSON.parse(String(r.record)) as Anchor);
  }

  async last(stream: string): Promise<Anchor | null> {
    const { rows } = await this.client.query(
      `SELECT record FROM ${this.table} WHERE stream = $1 ORDER BY seq DESC LIMIT 1`,
      [stream],
    );
    const r = rows[0];
    return r ? (JSON.parse(String(r.record)) as Anchor) : null;
  }
}
