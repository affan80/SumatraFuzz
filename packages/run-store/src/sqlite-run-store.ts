import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import {
  asRunId,
  type ControllerId,
  type EventType,
  isNonNilUuid,
  type RunEvent,
  type RunId,
  type RunState,
  type StopReason,
  validTransition,
} from '@sumatrafuzz/worker-protocol';
import { StoreError } from './errors.js';

type DatabaseHandle = import('better-sqlite3').Database;
type DatabaseConstructor = new (file: string, options?: object) => DatabaseHandle;
const Database = createRequire(import.meta.url)('better-sqlite3') as DatabaseConstructor;
const TERMINAL_STATES = new Set<RunState>(['completed', 'failed', 'interrupted']);
const ALL_STATES = new Set<RunState>([
  'created',
  'preparing',
  'running',
  'stopping',
  'completed',
  'failed',
  'interrupted',
]);
const EVENT_TYPES = new Set<EventType>([
  'state_changed',
  'process_teardown',
  'metric_sample',
  'evidence_finalized',
  'error',
]);
const STOP_REASONS = new Set<StopReason>([
  'requested',
  'time_limit',
  'cpu_limit',
  'memory_limit',
  'disk_limit',
  'native_exit',
  'process_failure',
  'worker_restart',
]);
const MAX_SQLITE_INTEGER = 9_223_372_036_854_775_807n;
const migrationSql = readFileSync(new URL('./migrations/0001_worker.sql', import.meta.url), 'utf8');

export type ClaimOutcome = { kind: 'new' | 'existing'; runId: RunId } | { kind: 'worker_busy' };

export interface TeardownReceipt {
  readonly jobId: string;
  readonly stoppedAtUtc: string;
  readonly remainingProcesses: number;
  readonly exitCode: number | null;
  readonly stopReason: StopReason;
}

export interface StoreOpenOptions {
  readonly maxDatabasePages?: number;
}

export interface FinalArtifact {
  readonly artifactId: string;
  readonly sha256: string;
  readonly relativePath: string;
  readonly sizeBytes: number;
}

export interface ActiveRunSnapshot {
  readonly runId: RunId;
  readonly controllerId: ControllerId;
  readonly state: RunState;
  readonly lastSequence: bigint;
}

function validateFinalArtifact(artifact: FinalArtifact): void {
  if (
    !/^[A-Za-z0-9_-]{1,128}$/.test(artifact.artifactId) ||
    !/^[0-9a-f]{64}$/.test(artifact.sha256) ||
    typeof artifact.relativePath !== 'string' ||
    artifact.relativePath.length > 1024 ||
    artifact.relativePath.startsWith('/') ||
    artifact.relativePath.includes('\\') ||
    artifact.relativePath.includes(':') ||
    artifact.relativePath.split('/').some(
      (part) =>
        !part ||
        part === '.' ||
        part === '..' ||
        [...part].some((character) => {
          const code = character.charCodeAt(0);
          return code < 0x20 || code === 0x7f;
        }),
    ) ||
    !Number.isSafeInteger(artifact.sizeBytes) ||
    artifact.sizeBytes < 0
  ) {
    throw new StoreError('invalid_request');
  }
}

function wrapDatabaseError(error: unknown): StoreError {
  if (error instanceof StoreError) return error;
  return new StoreError('database', 'SQLite operation failed', { cause: error });
}

function isBusy(error: unknown): boolean {
  if (typeof error !== 'object' || error === null || !('code' in error)) return false;
  const code = String((error as { code: unknown }).code);
  return code === 'SQLITE_BUSY' || code === 'SQLITE_LOCKED';
}

function validState(value: string): value is RunState {
  return ALL_STATES.has(value as RunState);
}

function assertUuid(value: string): void {
  if (!isNonNilUuid(value)) throw new StoreError('invalid_request');
}

function assertDigest(value: string): void {
  if (!/^[0-9a-f]{64}$/i.test(value)) throw new StoreError('invalid_request');
}

function assertEventType(value: string): asserts value is EventType {
  if (!EVENT_TYPES.has(value as EventType)) throw new StoreError('invalid_request');
}

function assertTeardownReceipt(receipt: TeardownReceipt): void {
  if (
    !receipt ||
    typeof receipt.jobId !== 'string' ||
    receipt.jobId.length === 0 ||
    typeof receipt.stoppedAtUtc !== 'string' ||
    !receipt.stoppedAtUtc.endsWith('Z') ||
    !Number.isFinite(Date.parse(receipt.stoppedAtUtc)) ||
    receipt.remainingProcesses !== 0 ||
    (receipt.exitCode !== null && !Number.isInteger(receipt.exitCode)) ||
    !STOP_REASONS.has(receipt.stopReason)
  ) {
    throw new StoreError('invalid_request');
  }
}

function sameTeardownReceipt(left: TeardownReceipt, right: TeardownReceipt): boolean {
  return (
    left.jobId === right.jobId &&
    left.stoppedAtUtc === right.stoppedAtUtc &&
    left.remainingProcesses === right.remainingProcesses &&
    left.exitCode === right.exitCode &&
    left.stopReason === right.stopReason
  );
}

export class SqliteRunStore {
  private constructor(private readonly db: DatabaseHandle) {}

  static open(filePath: string, options: StoreOpenOptions = {}): SqliteRunStore {
    let db: DatabaseHandle | undefined;
    try {
      db = new Database(filePath);
      db.defaultSafeIntegers(true);
      db.pragma('busy_timeout = 5000');
      db.pragma('foreign_keys = ON');
      db.pragma('synchronous = FULL');
      let walReady = false;
      for (let attempt = 0; attempt < 16; attempt += 1) {
        try {
          const result = db.pragma('journal_mode = WAL', { simple: true });
          if (result !== 'wal') throw new StoreError('database', 'WAL mode is unavailable');
          walReady = true;
          break;
        } catch (error) {
          if (!isBusy(error) || attempt === 15) throw error;
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 80);
        }
      }
      if (!walReady) throw new StoreError('database', 'WAL initialization exhausted retries');

      db.transaction(() => {
        const versionResult = db?.pragma('user_version', { simple: true }) as number | bigint;
        const version = typeof versionResult === 'bigint' ? Number(versionResult) : versionResult;
        if (!Number.isInteger(version) || version < 0 || version > 1) {
          throw new StoreError('unsupported_version');
        }
        db?.exec(migrationSql);
        if (version === 0) db?.pragma('user_version = 1');
      }).immediate();

      const quickCheck = db.pragma('quick_check(1)', { simple: true });
      if (quickCheck !== 'ok') throw new StoreError('corrupt');
      if ((db.pragma('foreign_key_check') as unknown[]).length > 0) {
        throw new StoreError('corrupt', 'journal contains broken foreign keys');
      }
      if (options.maxDatabasePages !== undefined) {
        if (!Number.isSafeInteger(options.maxDatabasePages) || options.maxDatabasePages < 1) {
          throw new StoreError('invalid_request');
        }
        const appliedPages = db.pragma(`max_page_count = ${options.maxDatabasePages}`, {
          simple: true,
        }) as number | bigint;
        if (BigInt(appliedPages) > BigInt(options.maxDatabasePages)) {
          throw new StoreError('invalid_request', 'database already exceeds configured page cap');
        }
      }
      const store = new SqliteRunStore(db);
      store.validateJournalIntegrity();
      return store;
    } catch (error) {
      db?.close();
      throw wrapDatabaseError(error);
    }
  }

  close(): void {
    try {
      this.db.close();
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  claimWorkerSlot(
    controllerId: ControllerId,
    requestId: string,
    payloadDigest: string,
    runId: RunId,
  ): ClaimOutcome {
    assertUuid(controllerId);
    assertUuid(requestId);
    assertUuid(runId);
    assertDigest(payloadDigest);
    try {
      return this.db
        .transaction((): ClaimOutcome => {
          const earlier = this.db
            .prepare(
              'SELECT payload_digest, run_id FROM command_idempotency WHERE controller_id = ? AND request_id = ?',
            )
            .get(controllerId, requestId) as { payload_digest: string; run_id: string } | undefined;
          if (earlier) {
            if (earlier.payload_digest !== payloadDigest) {
              throw new StoreError('idempotency_conflict');
            }
            assertUuid(earlier.run_id);
            return { kind: 'existing', runId: asRunId(earlier.run_id) };
          }

          const active = this.db.prepare('SELECT run_id FROM worker_slot WHERE slot = 1').get() as
            | { run_id: string }
            | undefined;
          if (active) return { kind: 'worker_busy' };

          this.db
            .prepare("INSERT INTO run_state(run_id, state, last_seq) VALUES (?, 'created', 0)")
            .run(runId);
          this.db.prepare('INSERT INTO worker_slot(slot, run_id) VALUES (1, ?)').run(runId);
          this.db
            .prepare(
              'INSERT INTO command_idempotency(controller_id, request_id, payload_digest, run_id) VALUES (?, ?, ?, ?)',
            )
            .run(controllerId, requestId, payloadDigest, runId);
          return { kind: 'new', runId };
        })
        .immediate();
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  ownsRun(controllerId: ControllerId, runId: RunId): boolean {
    assertUuid(controllerId);
    assertUuid(runId);
    try {
      return Boolean(
        this.db
          .prepare(
            'SELECT 1 AS owned FROM command_idempotency WHERE controller_id = ? AND run_id = ? LIMIT 1',
          )
          .get(controllerId, runId),
      );
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  findRequest(
    controllerId: ControllerId,
    requestId: string,
  ): { runId: RunId; payloadDigest: string } | null {
    assertUuid(controllerId);
    assertUuid(requestId);
    try {
      const row = this.db
        .prepare(
          'SELECT run_id, payload_digest FROM command_idempotency WHERE controller_id = ? AND request_id = ?',
        )
        .get(controllerId, requestId) as { run_id: string; payload_digest: string } | undefined;
      if (!row) return null;
      assertUuid(row.run_id);
      assertDigest(row.payload_digest);
      return { runId: asRunId(row.run_id), payloadDigest: row.payload_digest };
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  runSnapshot(runId: RunId): { state: RunState; lastSequence: bigint } {
    assertUuid(runId);
    try {
      const row = this.db
        .prepare('SELECT state, last_seq FROM run_state WHERE run_id = ?')
        .get(runId) as { state: string; last_seq: bigint } | undefined;
      if (!row || !validState(row.state) || row.last_seq < 0n)
        throw new StoreError('invalid_request');
      return { state: row.state, lastSequence: row.last_seq };
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  activeRunSnapshot(): ActiveRunSnapshot | null {
    try {
      const row = this.db
        .prepare(
          `SELECT s.run_id, s.state, s.last_seq, c.controller_id
           FROM worker_slot w
           JOIN run_state s ON s.run_id = w.run_id
           JOIN command_idempotency c ON c.run_id = s.run_id
           WHERE w.slot = 1
           ORDER BY c.rowid
           LIMIT 1`,
        )
        .get() as
        | { run_id: string; state: string; last_seq: bigint; controller_id: string }
        | undefined;
      if (!row) return null;
      if (!validState(row.state) || row.last_seq < 0n) throw new StoreError('corrupt');
      assertUuid(row.run_id);
      assertUuid(row.controller_id);
      return {
        runId: asRunId(row.run_id),
        controllerId: row.controller_id as ControllerId,
        state: row.state,
        lastSequence: row.last_seq,
      };
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  appendMetricSample(
    runId: RunId,
    sample: {
      readonly time_utc: string;
      readonly cpu_percent: number;
      readonly memory_bytes: number;
      readonly disk_bytes: number;
      readonly process_count: number;
    },
  ): bigint {
    assertUuid(runId);
    if (
      !Number.isFinite(sample.cpu_percent) ||
      sample.cpu_percent < 0 ||
      !Number.isSafeInteger(sample.memory_bytes) ||
      sample.memory_bytes < 0 ||
      !Number.isSafeInteger(sample.disk_bytes) ||
      sample.disk_bytes < 0 ||
      !Number.isSafeInteger(sample.process_count) ||
      sample.process_count < 0 ||
      !Number.isFinite(Date.parse(sample.time_utc))
    ) {
      throw new StoreError('invalid_request');
    }
    try {
      return this.db
        .transaction(() => {
          const row = this.db
            .prepare('SELECT state, last_seq FROM run_state WHERE run_id = ?')
            .get(runId) as { state: string; last_seq: bigint } | undefined;
          if (row?.state !== 'running' || row.last_seq < 0n) {
            throw new StoreError('invalid_transition');
          }
          const sequence = row.last_seq + 1n;
          if (sequence > MAX_SQLITE_INTEGER) throw new StoreError('corrupt');
          const update = this.db
            .prepare(
              'UPDATE run_state SET last_seq = ? WHERE run_id = ? AND state = ? AND last_seq = ?',
            )
            .run(sequence, runId, 'running', row.last_seq);
          if (update.changes !== 1) throw new StoreError('invalid_transition');
          this.db
            .prepare(
              'INSERT INTO events(run_id, seq, time_utc, event_type, payload) VALUES (?, ?, ?, ?, ?)',
            )
            .run(
              runId,
              sequence,
              sample.time_utc,
              JSON.stringify('metric_sample'),
              JSON.stringify(sample),
            );
          return sequence;
        })
        .immediate();
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  recordTeardownReceipt(runId: RunId, receipt: TeardownReceipt): bigint {
    assertUuid(runId);
    assertTeardownReceipt(receipt);
    try {
      return this.db
        .transaction(() => {
          const row = this.db
            .prepare('SELECT state, last_seq FROM run_state WHERE run_id = ?')
            .get(runId) as { state: string; last_seq: bigint } | undefined;
          if (row?.state !== 'stopping' || row.last_seq < 0n) {
            throw new StoreError('invalid_transition');
          }
          const earlier = this.db
            .prepare('SELECT 1 FROM events WHERE run_id = ? AND event_type = ? LIMIT 1')
            .get(runId, JSON.stringify('process_teardown'));
          if (earlier) throw new StoreError('invalid_transition');
          const sequence = row.last_seq + 1n;
          if (sequence > MAX_SQLITE_INTEGER) throw new StoreError('corrupt');
          const update = this.db
            .prepare(
              'UPDATE run_state SET last_seq = ? WHERE run_id = ? AND state = ? AND last_seq = ?',
            )
            .run(sequence, runId, 'stopping', row.last_seq);
          if (update.changes !== 1) throw new StoreError('invalid_transition');
          this.db
            .prepare(
              'INSERT INTO events(run_id, seq, time_utc, event_type, payload) VALUES (?, ?, ?, ?, ?)',
            )
            .run(
              runId,
              sequence,
              receipt.stoppedAtUtc,
              JSON.stringify('process_teardown'),
              JSON.stringify(receipt),
            );
          return sequence;
        })
        .immediate();
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  teardownReceipt(runId: RunId): TeardownReceipt | null {
    assertUuid(runId);
    try {
      const row = this.db
        .prepare(
          'SELECT payload FROM events WHERE run_id = ? AND event_type = ? ORDER BY seq DESC LIMIT 1',
        )
        .get(runId, JSON.stringify('process_teardown')) as { payload: string } | undefined;
      if (!row) return null;
      const receipt = JSON.parse(row.payload) as TeardownReceipt;
      assertTeardownReceipt(receipt);
      if (receipt.remainingProcesses !== 0) throw new StoreError('corrupt');
      return receipt;
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  finalizeAfterTeardown(
    runId: RunId,
    next: Extract<RunState, 'completed' | 'failed' | 'interrupted'>,
    artifacts: readonly FinalArtifact[],
    receipt: TeardownReceipt,
  ): void {
    assertUuid(runId);
    assertTeardownReceipt(receipt);
    if (!validTransition('stopping', next) || artifacts.length > 10_000) {
      throw new StoreError('invalid_request');
    }
    if (next === 'completed' && artifacts.length === 0) throw new StoreError('invalid_request');
    try {
      this.db
        .transaction(() => {
          const row = this.db
            .prepare('SELECT state, last_seq FROM run_state WHERE run_id = ?')
            .get(runId) as { state: string; last_seq: bigint } | undefined;
          if (row?.state !== 'stopping' || row.last_seq < 0n) {
            throw new StoreError('invalid_transition');
          }
          if (this.db.prepare('SELECT 1 FROM evidence_index WHERE run_id = ? LIMIT 1').get(runId)) {
            throw new StoreError('invalid_transition');
          }
          const teardownRow = this.db
            .prepare(
              'SELECT payload FROM events WHERE run_id = ? AND event_type = ? ORDER BY seq DESC LIMIT 1',
            )
            .get(runId, JSON.stringify('process_teardown')) as { payload: string } | undefined;
          if (!teardownRow) throw new StoreError('invalid_transition');
          const recordedReceipt = JSON.parse(teardownRow.payload) as TeardownReceipt;
          assertTeardownReceipt(recordedReceipt);
          if (!sameTeardownReceipt(recordedReceipt, receipt)) throw new StoreError('corrupt');
          const seen = new Set<string>();
          const insertArtifact = this.db.prepare(
            'INSERT INTO evidence_index(run_id, artifact_id, sha256, relative_path, size_bytes, is_final) VALUES (?, ?, ?, ?, ?, 1)',
          );
          let totalBytes = 0n;
          for (const artifact of artifacts) {
            validateFinalArtifact(artifact);
            if (seen.has(artifact.artifactId)) throw new StoreError('invalid_request');
            seen.add(artifact.artifactId);
            totalBytes += BigInt(artifact.sizeBytes);
            insertArtifact.run(
              runId,
              artifact.artifactId,
              artifact.sha256,
              artifact.relativePath,
              artifact.sizeBytes,
            );
          }

          let sequence = row.last_seq;
          const insertEvent = this.db.prepare(
            'INSERT INTO events(run_id, seq, time_utc, event_type, payload) VALUES (?, ?, ?, ?, ?)',
          );
          const append = (eventType: EventType, payload: unknown, time: string): void => {
            sequence += 1n;
            if (sequence > MAX_SQLITE_INTEGER) throw new StoreError('corrupt');
            insertEvent.run(
              runId,
              sequence,
              time,
              JSON.stringify(eventType),
              JSON.stringify(payload),
            );
          };
          const finalizedAt = new Date().toISOString();
          if (artifacts.length > 0) {
            append(
              'evidence_finalized',
              {
                artifact_count: artifacts.length,
                total_bytes: totalBytes.toString(),
              },
              finalizedAt,
            );
          }
          append('state_changed', { from: 'stopping', to: next }, finalizedAt);
          const update = this.db
            .prepare(
              'UPDATE run_state SET state = ?, last_seq = ? WHERE run_id = ? AND state = ? AND last_seq = ?',
            )
            .run(next, sequence, runId, 'stopping', row.last_seq);
          if (update.changes !== 1) throw new StoreError('invalid_transition');
          const release = this.db
            .prepare('DELETE FROM worker_slot WHERE slot = 1 AND run_id = ?')
            .run(runId);
          if (release.changes !== 1) throw new StoreError('invalid_transition');
        })
        .immediate();
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  finalArtifacts(runId: RunId): FinalArtifact[] {
    assertUuid(runId);
    try {
      const rows = this.db
        .prepare(
          'SELECT artifact_id, sha256, relative_path, size_bytes FROM evidence_index WHERE run_id = ? AND is_final = 1 ORDER BY artifact_id',
        )
        .all(runId) as Array<{
        artifact_id: string;
        sha256: string;
        relative_path: string;
        size_bytes: bigint;
      }>;
      return rows.map((row) => {
        if (row.size_bytes < 0n || row.size_bytes > BigInt(Number.MAX_SAFE_INTEGER))
          throw new StoreError('corrupt');
        const artifact = {
          artifactId: row.artifact_id,
          sha256: row.sha256,
          relativePath: row.relative_path,
          sizeBytes: Number(row.size_bytes),
        };
        try {
          validateFinalArtifact(artifact);
        } catch {
          throw new StoreError('corrupt');
        }
        return artifact;
      });
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  transitionState(runId: RunId, expected: RunState, next: RunState, eventType: EventType): bigint {
    assertUuid(runId);
    assertEventType(eventType);
    if (!validTransition(expected, next)) throw new StoreError('invalid_transition');
    try {
      return this.db
        .transaction(() => {
          const row = this.db
            .prepare('SELECT state, last_seq FROM run_state WHERE run_id = ?')
            .get(runId) as { state: string; last_seq: bigint } | undefined;
          if (!row || !validState(row.state) || row.state !== expected || row.last_seq < 0n) {
            throw new StoreError('invalid_transition');
          }
          const sequence = row.last_seq + 1n;
          if (sequence > MAX_SQLITE_INTEGER) throw new StoreError('corrupt');
          const timestamp = new Date().toISOString();
          const payload = JSON.stringify({ from: expected, to: next });
          const update = this.db
            .prepare(
              'UPDATE run_state SET state = ?, last_seq = ? WHERE run_id = ? AND state = ? AND last_seq = ?',
            )
            .run(next, sequence, runId, expected, row.last_seq);
          if (update.changes !== 1) throw new StoreError('invalid_transition');
          this.db
            .prepare(
              'INSERT INTO events(run_id, seq, time_utc, event_type, payload) VALUES (?, ?, ?, ?, ?)',
            )
            .run(runId, sequence, timestamp, JSON.stringify(eventType), payload);
          return sequence;
        })
        .immediate();
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  releaseAfterTeardown(runId: RunId, receipt: TeardownReceipt): void {
    assertUuid(runId);
    assertTeardownReceipt(receipt);
    try {
      this.db
        .transaction(() => {
          const row = this.db
            .prepare('SELECT state, last_seq FROM run_state WHERE run_id = ?')
            .get(runId) as { state: string; last_seq: bigint } | undefined;
          if (!row || !validState(row.state) || !TERMINAL_STATES.has(row.state)) {
            throw new StoreError('invalid_transition');
          }
          const sequence = row.last_seq + 1n;
          if (sequence > MAX_SQLITE_INTEGER) throw new StoreError('corrupt');
          const update = this.db
            .prepare('UPDATE run_state SET last_seq = ? WHERE run_id = ? AND last_seq = ?')
            .run(sequence, runId, row.last_seq);
          if (update.changes !== 1) throw new StoreError('invalid_transition');
          this.db
            .prepare(
              'INSERT INTO events(run_id, seq, time_utc, event_type, payload) VALUES (?, ?, ?, ?, ?)',
            )
            .run(
              runId,
              sequence,
              receipt.stoppedAtUtc,
              JSON.stringify('process_teardown'),
              JSON.stringify(receipt),
            );
          const result = this.db
            .prepare('DELETE FROM worker_slot WHERE slot = 1 AND run_id = ?')
            .run(runId);
          if (result.changes !== 1) throw new StoreError('invalid_transition');
        })
        .immediate();
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  runState(runId: RunId): RunState {
    assertUuid(runId);
    try {
      const row = this.db.prepare('SELECT state FROM run_state WHERE run_id = ?').get(runId) as
        | { state: string }
        | undefined;
      if (!row || !validState(row.state)) throw new StoreError('invalid_transition');
      return row.state;
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  readEventsAfter(runId: RunId, sequence: bigint, limit: number): RunEvent[] {
    assertUuid(runId);
    if (sequence < 0n || !Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) {
      throw new StoreError('invalid_request');
    }
    try {
      const rows = this.db
        .prepare(
          'SELECT seq, time_utc, event_type, payload FROM events WHERE run_id = ? AND seq > ? ORDER BY seq LIMIT ?',
        )
        .all(runId, sequence, BigInt(limit)) as Array<{
        seq: bigint;
        time_utc: string;
        event_type: string;
        payload: string;
      }>;
      return rows.map((row) => {
        const eventType = JSON.parse(row.event_type) as unknown;
        const payload = JSON.parse(row.payload) as unknown;
        if (
          typeof row.seq !== 'bigint' ||
          row.seq <= 0n ||
          !Number.isFinite(Date.parse(row.time_utc)) ||
          typeof eventType !== 'string' ||
          !EVENT_TYPES.has(eventType as EventType)
        ) {
          throw new StoreError('corrupt');
        }
        return {
          run_id: runId,
          seq: row.seq,
          time_utc: new Date(row.time_utc).toISOString(),
          event_type: eventType as EventType,
          payload,
        };
      });
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }

  private validateJournalIntegrity(): void {
    try {
      const runs = this.db
        .prepare(
          `SELECT rs.run_id, rs.state, rs.last_seq,
                  COUNT(ev.seq) AS event_count, COALESCE(MAX(ev.seq), 0) AS max_seq
           FROM run_state rs LEFT JOIN events ev ON ev.run_id = rs.run_id
           GROUP BY rs.run_id`,
        )
        .safeIntegers()
        .all() as Array<{
        run_id: string;
        state: string;
        last_seq: bigint;
        event_count: bigint;
        max_seq: bigint;
      }>;
      let requiresSlot: string | undefined;
      for (const row of runs) {
        assertUuid(row.run_id);
        if (!validState(row.state) || row.last_seq < 0n) throw new StoreError('corrupt');
        if (row.event_count !== row.last_seq || row.max_seq !== row.last_seq) {
          throw new StoreError('corrupt', 'event log does not match durable run sequence');
        }
        if (!TERMINAL_STATES.has(row.state)) {
          if (requiresSlot) throw new StoreError('corrupt', 'multiple active runs in journal');
          requiresSlot = row.run_id;
        }
      }
      const slot = this.db.prepare('SELECT run_id FROM worker_slot WHERE slot = 1').get() as
        | { run_id: string }
        | undefined;
      if (requiresSlot && slot?.run_id !== requiresSlot) {
        throw new StoreError('corrupt', 'active campaign is missing its durable worker slot');
      }
    } catch (error) {
      throw wrapDatabaseError(error);
    }
  }
}
