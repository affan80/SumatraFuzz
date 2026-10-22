import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { isNonNilUuid } from '@sumatrafuzz/worker-protocol';

export type TrustPermission =
  | 'capabilities:read'
  | 'input-bundles:write'
  | 'runs:start'
  | 'runs:read'
  | 'runs:stop'
  | 'events:read'
  | 'artifacts:read';
export interface TrustProvisionInput {
  readonly fingerprint: string;
  readonly controllerId: string;
  readonly permissions: readonly TrustPermission[];
  readonly notBefore: string;
  readonly notAfter: string;
}
export interface TrustRecord extends TrustProvisionInput {
  readonly status: 'active' | 'revoked';
  readonly generation: number;
  readonly revision: number;
}
export interface TrustRevisionChange {
  readonly revision: number;
  /** Previously installed fingerprints whose authorization may have changed (at most two). */
  readonly fingerprints: readonly string[];
}
export interface WorkerTrustRepository {
  readonly revision: number;
  subscribe(listener: (change: TrustRevisionChange) => void): () => void;
  resolveFingerprint(fingerprint: string, now: Date): TrustRecord | null;
  listActive(): readonly TrustRecord[];
  provision(input: TrustProvisionInput): TrustRecord;
  rotate(input: TrustProvisionInput, overlapUntil: Date, now: Date): TrustRecord;
  revoke(fingerprint: string): TrustRecord | null;
  unpair(controllerId: string): number;
}

export interface TrustStoreOpenOptions {
  /** Explicit local policy, at most 24 hours; not persisted as trust authority. */
  readonly maxRotationOverlapMs?: number;
}
export type TrustStoreErrorCode =
  | 'invalid_request'
  | 'conflict'
  | 'capacity'
  | 'corrupt'
  | 'unsupported_version'
  | 'database';
export class TrustStoreError extends Error {
  constructor(readonly code: TrustStoreErrorCode) {
    super(`Worker trust store: ${code}`);
    this.name = 'TrustStoreError';
  }
}

type Handle = import('better-sqlite3').Database;
const Database = createRequire(import.meta.url)('better-sqlite3') as new (file: string) => Handle;
const schema = readFileSync(new URL('./trust-schema.sql', import.meta.url), 'utf8');
const MAX_RECORDS = 4096;
const MAX_OVERLAP_MS = 24 * 60 * 60 * 1000;
const permissions: ReadonlySet<string> = new Set([
  'capabilities:read',
  'input-bundles:write',
  'runs:start',
  'runs:read',
  'runs:stop',
  'events:read',
  'artifacts:read',
]);
const inputKeys = ['fingerprint', 'controllerId', 'permissions', 'notBefore', 'notAfter'];
type CertificateRow = {
  fingerprint: string;
  controller_id: string;
  permissions: string;
  not_before: string;
  not_after: string;
  status: string;
  generation: number;
  revision: number;
};
type ControllerRow = {
  controller_id: string;
  paired: number;
  last_generation: number;
  revision: number;
};
function invalid(): never {
  throw new TrustStoreError('invalid_request');
}
function assertFingerprint(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) invalid();
}
function assertController(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !isNonNilUuid(value) || value !== value.toLowerCase()) invalid();
}
function timestamp(value: unknown): number {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))
    invalid();
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) invalid();
  return time;
}
function dateTime(value: Date): number {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) invalid();
  return value.getTime();
}
function validateInput(value: TrustProvisionInput, exact = true): void {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  if (
    exact &&
    (Object.keys(value).length !== inputKeys.length ||
      Object.keys(value).some((key) => !inputKeys.includes(key)))
  )
    invalid();
  assertFingerprint(value.fingerprint);
  assertController(value.controllerId);
  if (
    !Array.isArray(value.permissions) ||
    value.permissions.length > permissions.size ||
    new Set(value.permissions).size !== value.permissions.length ||
    value.permissions.some(
      (permission) => typeof permission !== 'string' || !permissions.has(permission),
    )
  )
    invalid();
  if (timestamp(value.notBefore) >= timestamp(value.notAfter)) invalid();
}
function positive(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}
function wrap(error: unknown): TrustStoreError {
  return error instanceof TrustStoreError ? error : new TrustStoreError('database');
}
function record(row: CertificateRow, revision: number): TrustRecord {
  try {
    const value = {
      fingerprint: row.fingerprint,
      controllerId: row.controller_id,
      permissions: JSON.parse(row.permissions) as TrustPermission[],
      notBefore: row.not_before,
      notAfter: row.not_after,
      status: row.status,
      generation: row.generation,
      revision: row.revision,
    };
    validateInput(value, false);
    if (
      (value.status !== 'active' && value.status !== 'revoked') ||
      !positive(value.generation) ||
      value.generation > MAX_RECORDS ||
      !positive(value.revision) ||
      value.revision > revision
    )
      throw new Error();
    return Object.freeze({
      ...value,
      status: value.status,
      permissions: Object.freeze([...value.permissions]),
    });
  } catch {
    throw new TrustStoreError('corrupt');
  }
}

/** Operator-only persistence. Callers must verify signed provisioning evidence first. */
export class SqliteWorkerTrustStore implements WorkerTrustRepository {
  private readonly listeners = new Set<(change: TrustRevisionChange) => void>();
  private constructor(
    private readonly db: Handle,
    private readonly maxOverlapMs: number,
  ) {}

  static open(file: string, options: TrustStoreOpenOptions = {}): SqliteWorkerTrustStore {
    if (
      typeof file !== 'string' ||
      !file ||
      file.length > 4096 ||
      !options ||
      typeof options !== 'object' ||
      Object.keys(options).some((key) => key !== 'maxRotationOverlapMs')
    )
      invalid();
    const overlap = options.maxRotationOverlapMs ?? MAX_OVERLAP_MS;
    if (!Number.isSafeInteger(overlap) || overlap < 1 || overlap > MAX_OVERLAP_MS) invalid();
    let db: Handle | undefined;
    try {
      db = new Database(file);
      db.pragma('busy_timeout = 5000');
      db.pragma('foreign_keys = ON');
      db.pragma('synchronous = FULL');
      if (db.pragma('journal_mode = WAL', { simple: true }) !== 'wal')
        throw new TrustStoreError('database');
      const store = new SqliteWorkerTrustStore(db, overlap);
      db.transaction(() => {
        const version = db?.pragma('user_version', { simple: true });
        if (version !== 0 && version !== 1) throw new TrustStoreError('unsupported_version');
        if (version === 0) {
          db?.exec(schema);
          db?.pragma('user_version = 1');
        }
        if (
          db?.pragma('quick_check(1)', { simple: true }) !== 'ok' ||
          (db.pragma('foreign_key_check') as unknown[]).length > 0
        )
          throw new TrustStoreError('corrupt');
        store.validateIntegrity();
      }).immediate();
      return store;
    } catch (error) {
      db?.close();
      throw wrap(error);
    }
  }

  close(): void {
    try {
      if (this.db.open) this.db.close();
      this.listeners.clear();
    } catch (error) {
      throw wrap(error);
    }
  }
  /** All service mutations must use this instance; external-process writes do not publish events. */
  subscribe(listener: (change: TrustRevisionChange) => void): () => void {
    if (typeof listener !== 'function') invalid();
    if (!this.db.open) throw new TrustStoreError('database');
    if (this.listeners.size >= 16) throw new TrustStoreError('capacity');
    const subscriber = (change: TrustRevisionChange) => listener(change);
    this.listeners.add(subscriber);
    return () => {
      this.listeners.delete(subscriber);
    };
  }
  get revision(): number {
    try {
      const rows = this.db.prepare('SELECT singleton, revision FROM trust_metadata').all() as {
        singleton: number;
        revision: number;
      }[];
      const row = rows[0];
      if (
        rows.length !== 1 ||
        row?.singleton !== 1 ||
        !Number.isSafeInteger(row.revision) ||
        row.revision < 0
      )
        throw new TrustStoreError('corrupt');
      return row.revision;
    } catch (error) {
      throw wrap(error);
    }
  }
  resolveFingerprint(fingerprint: string, now: Date): TrustRecord | null {
    assertFingerprint(fingerprint);
    const time = dateTime(now);
    try {
      return this.db.transaction(() => {
        const revision = this.revision;
        const row = this.db
          .prepare('SELECT * FROM trust_certificates WHERE fingerprint = ?')
          .get(fingerprint) as CertificateRow | undefined;
        if (!row) return null;
        const value = record(row, revision);
        const owner = this.db
          .prepare('SELECT * FROM trust_controllers WHERE controller_id = ?')
          .get(value.controllerId) as ControllerRow | undefined;
        if (
          !owner ||
          (owner.paired !== 0 && owner.paired !== 1) ||
          !positive(owner.revision) ||
          owner.revision > revision ||
          !positive(owner.last_generation) ||
          owner.last_generation < value.generation ||
          (owner.paired === 0 && value.status === 'active')
        )
          throw new TrustStoreError('corrupt');
        return value.status === 'active' &&
          timestamp(value.notBefore) <= time &&
          time < timestamp(value.notAfter)
          ? value
          : null;
      })();
    } catch (error) {
      throw wrap(error);
    }
  }
  /** Lists nonrevoked certificates, including future/expired ones; use resolve for authorization. */
  listActive(): readonly TrustRecord[] {
    try {
      return this.db.transaction(() => {
        this.validateIntegrity();
        return Object.freeze(
          (
            this.db
              .prepare(
                "SELECT * FROM trust_certificates WHERE status = 'active' ORDER BY controller_id, generation",
              )
              .all() as CertificateRow[]
          ).map((row) => record(row, this.revision)),
        );
      })();
    } catch (error) {
      throw wrap(error);
    }
  }
  provision(input: TrustProvisionInput): TrustRecord {
    validateInput(input);
    return this.mutate(() => {
      this.ensureNewFingerprint(input.fingerprint);
      const owner = this.db
        .prepare('SELECT * FROM trust_controllers WHERE controller_id = ?')
        .get(input.controllerId) as ControllerRow | undefined;
      if (owner?.paired === 1) throw new TrustStoreError('conflict');
      const paired = this.db
        .prepare('SELECT COUNT(*) AS count FROM trust_controllers WHERE paired = 1')
        .get() as { count: number };
      if (paired.count >= 16) throw new TrustStoreError('capacity');
      const revision = this.nextRevision();
      const generation = (owner?.last_generation ?? 0) + 1;
      this.db
        .prepare(
          'INSERT INTO trust_controllers(controller_id, paired, last_generation, revision) VALUES (?, 1, ?, ?) ON CONFLICT(controller_id) DO UPDATE SET paired = 1, last_generation = excluded.last_generation, revision = excluded.revision',
        )
        .run(input.controllerId, generation, revision);
      return this.insert(input, generation, revision);
    });
  }
  rotate(input: TrustProvisionInput, overlapUntil: Date, now: Date): TrustRecord {
    validateInput(input);
    const time = dateTime(now);
    const until = dateTime(overlapUntil);
    if (
      until <= time ||
      until - time > this.maxOverlapMs ||
      timestamp(input.notBefore) > time ||
      timestamp(input.notAfter) < until
    )
      invalid();
    return this.mutate(() => {
      this.ensureNewFingerprint(input.fingerprint);
      const owner = this.db
        .prepare('SELECT * FROM trust_controllers WHERE controller_id = ?')
        .get(input.controllerId) as ControllerRow | undefined;
      if (owner?.paired !== 1) throw new TrustStoreError('conflict');
      const active = (
        this.db
          .prepare(
            "SELECT * FROM trust_certificates WHERE controller_id = ? AND status = 'active' ORDER BY generation",
          )
          .all(input.controllerId) as CertificateRow[]
      ).map((row) => record(row, this.revision));
      const current = active.filter((value) => timestamp(value.notAfter) > time);
      const previous = current[0];
      if (
        current.length !== 1 ||
        !previous ||
        timestamp(previous.notBefore) > time ||
        timestamp(previous.notAfter) < until
      )
        throw new TrustStoreError('conflict');
      const revision = this.nextRevision();
      this.db
        .prepare(
          "UPDATE trust_certificates SET status = 'revoked', revision = ? WHERE controller_id = ? AND status = 'active' AND not_after <= ?",
        )
        .run(revision, input.controllerId, now.toISOString());
      this.db
        .prepare('UPDATE trust_certificates SET not_after = ?, revision = ? WHERE fingerprint = ?')
        .run(overlapUntil.toISOString(), revision, previous.fingerprint);
      const generation = owner.last_generation + 1;
      this.db
        .prepare(
          'UPDATE trust_controllers SET last_generation = ?, revision = ? WHERE controller_id = ?',
        )
        .run(generation, revision, input.controllerId);
      return this.insert(input, generation, revision);
    });
  }
  revoke(fingerprint: string): TrustRecord | null {
    assertFingerprint(fingerprint);
    return this.mutate(() => {
      const row = this.db
        .prepare('SELECT * FROM trust_certificates WHERE fingerprint = ?')
        .get(fingerprint) as CertificateRow | undefined;
      if (!row) return null;
      if (row.status === 'revoked') return record(row, this.revision);
      const revision = this.nextRevision();
      this.db
        .prepare(
          "UPDATE trust_certificates SET status = 'revoked', revision = ? WHERE fingerprint = ?",
        )
        .run(revision, fingerprint);
      return record({ ...row, status: 'revoked', revision }, revision);
    });
  }
  unpair(controllerId: string): number {
    assertController(controllerId);
    return this.mutate(() => {
      const owner = this.db
        .prepare('SELECT * FROM trust_controllers WHERE controller_id = ?')
        .get(controllerId) as ControllerRow | undefined;
      if (!owner || owner.paired === 0) return this.revision;
      const revision = this.nextRevision();
      this.db
        .prepare(
          "UPDATE trust_certificates SET status = 'revoked', revision = ? WHERE controller_id = ? AND status = 'active'",
        )
        .run(revision, controllerId);
      this.db
        .prepare('UPDATE trust_controllers SET paired = 0, revision = ? WHERE controller_id = ?')
        .run(revision, controllerId);
      return revision;
    });
  }
  private mutate<T>(operation: () => T): T {
    try {
      const result = this.db
        .transaction(() => {
          this.validateIntegrity();
          const previousRevision = this.revision;
          const installed = new Set(
            (
              this.db
                .prepare("SELECT fingerprint FROM trust_certificates WHERE status = 'active'")
                .all() as { fingerprint: string }[]
            ).map((row) => row.fingerprint),
          );
          const value = operation();
          this.validateIntegrity();
          const revision = this.revision;
          if (revision === previousRevision) return { value, change: undefined };
          const changed = (
            this.db
              .prepare(
                'SELECT fingerprint FROM trust_certificates WHERE revision = ? ORDER BY fingerprint',
              )
              .all(revision) as { fingerprint: string }[]
          ).map((row) => row.fingerprint);
          // A rotation can retire two old generations and add a third fingerprint.
          // Only the previously installed fingerprints can own established sockets.
          const previous = changed.filter((fingerprint) => installed.has(fingerprint));
          const fingerprints = previous.length > 0 ? previous : changed;
          if (fingerprints.length > 2) throw new TrustStoreError('corrupt');
          const change: TrustRevisionChange = Object.freeze({
            revision,
            fingerprints: Object.freeze(fingerprints),
          });
          return { value, change };
        })
        .immediate();
      // Notification follows SQLite commit; listener failures never change the committed outcome.
      if (result.change)
        for (const listener of [...this.listeners]) {
          try {
            listener(result.change);
          } catch {
            /* Listener health is not trust authority. */
          }
        }
      return result.value;
    } catch (error) {
      throw wrap(error);
    }
  }
  private ensureNewFingerprint(fingerprint: string): void {
    if (this.db.prepare('SELECT 1 FROM trust_certificates WHERE fingerprint = ?').get(fingerprint))
      throw new TrustStoreError('conflict');
    const count = this.db.prepare('SELECT COUNT(*) AS count FROM trust_certificates').get() as {
      count: number;
    };
    if (count.count >= MAX_RECORDS) throw new TrustStoreError('capacity');
  }
  private nextRevision(): number {
    const revision = this.revision + 1;
    if (!Number.isSafeInteger(revision)) throw new TrustStoreError('capacity');
    this.db.prepare('UPDATE trust_metadata SET revision = ? WHERE singleton = 1').run(revision);
    return revision;
  }
  private insert(input: TrustProvisionInput, generation: number, revision: number): TrustRecord {
    this.db
      .prepare(
        "INSERT INTO trust_certificates(fingerprint, controller_id, permissions, not_before, not_after, status, generation, revision) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)",
      )
      .run(
        input.fingerprint,
        input.controllerId,
        JSON.stringify(input.permissions),
        input.notBefore,
        input.notAfter,
        generation,
        revision,
      );
    return record(
      {
        fingerprint: input.fingerprint,
        controller_id: input.controllerId,
        permissions: JSON.stringify(input.permissions),
        not_before: input.notBefore,
        not_after: input.notAfter,
        status: 'active',
        generation,
        revision,
      },
      revision,
    );
  }
  private validateIntegrity(): void {
    try {
      const revision = this.revision;
      const owners = this.db.prepare('SELECT * FROM trust_controllers').all() as ControllerRow[];
      const rows = this.db
        .prepare('SELECT * FROM trust_certificates ORDER BY controller_id, generation')
        .all() as CertificateRow[];
      if (
        rows.length > MAX_RECORDS ||
        owners.length > rows.length ||
        owners.filter((owner) => owner.paired === 1).length > 16
      )
        throw new Error();
      let maxRevision = 0;
      const ownerMap = new Map(
        owners.map((owner) => {
          assertController(owner.controller_id);
          if (
            (owner.paired !== 0 && owner.paired !== 1) ||
            !positive(owner.last_generation) ||
            owner.last_generation > MAX_RECORDS ||
            !positive(owner.revision) ||
            owner.revision > revision
          )
            throw new Error();
          maxRevision = Math.max(maxRevision, owner.revision);
          return [owner.controller_id, { owner, count: 0, active: 0 }];
        }),
      );
      for (const row of rows) {
        const value = record(row, revision);
        const state = ownerMap.get(value.controllerId);
        if (!state || value.generation !== state.count + 1) throw new Error();
        state.count++;
        if (value.status === 'active') {
          state.active++;
          if (state.owner.paired !== 1 || state.active > 2) throw new Error();
        }
        maxRevision = Math.max(maxRevision, value.revision);
      }
      for (const state of ownerMap.values())
        if (state.owner.last_generation !== state.count) throw new Error();
      if (maxRevision !== revision) throw new Error();
    } catch (error) {
      if (error instanceof TrustStoreError && error.code === 'database') throw error;
      throw new TrustStoreError('corrupt');
    }
  }
}
