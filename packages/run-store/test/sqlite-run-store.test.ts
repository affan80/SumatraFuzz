import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { asControllerId, asRunId } from '@sumatrafuzz/worker-protocol';
import Database from 'better-sqlite3';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteRunStore, StoreError } from '../src/index.js';

const dirs: string[] = [];
const makeDir = async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'sumatrafuzz-store-'));
  dirs.push(directory);
  return directory;
};
const ids = () => ({
  controllerId: asControllerId('a11ce007-0000-4000-8000-000000000007'),
  requestId: 'a11ce008-0000-4000-8000-000000000008',
  runId: asRunId('a11ce009-0000-4000-8000-000000000009'),
});
const claim = (store: SqliteRunStore, overrides: Partial<ReturnType<typeof ids>> = {}) => {
  const value = { ...ids(), ...overrides };
  return store.claimWorkerSlot(value.controllerId, value.requestId, 'a'.repeat(64), value.runId);
};

afterEach(async () => {
  await Promise.all(
    dirs.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe('worker SQLite schema and recovery', () => {
  it('migrates a version-zero database transactionally and preserves other data', async () => {
    const directory = await makeDir();
    const file = path.join(directory, 'legacy.db');
    const db = new Database(file);
    db.exec(
      "CREATE TABLE existing_data(value TEXT NOT NULL); INSERT INTO existing_data VALUES ('keep');",
    );
    db.close();
    SqliteRunStore.open(file).close();
    const reopened = new Database(file);
    expect(reopened.pragma('user_version', { simple: true })).toBe(1);
    expect(reopened.prepare('SELECT value FROM existing_data').get()).toEqual({ value: 'keep' });
    reopened.close();
  });

  it('rejects corrupt database bytes without overwriting them', async () => {
    const directory = await makeDir();
    const file = path.join(directory, 'corrupt.db');
    const original = Buffer.from('not an sqlite database');
    await writeFile(file, original);
    expect(() => SqliteRunStore.open(file)).toThrow(StoreError);
    expect(await readFile(file)).toEqual(original);
  });

  it('rejects a future schema version', async () => {
    const directory = await makeDir();
    const file = path.join(directory, 'future.db');
    const db = new Database(file);
    db.pragma('user_version = 2');
    db.close();
    expect(() => SqliteRunStore.open(file)).toThrow(
      expect.objectContaining({ code: 'unsupported_version' }),
    );
  });

  it('refuses active-state rows with missing lease or event tail', async () => {
    const directory = await makeDir();
    const file = path.join(directory, 'corrupt-journal.db');
    const store = SqliteRunStore.open(file);
    claim(store);
    store.close();
    const db = new Database(file);
    db.prepare('DELETE FROM worker_slot').run();
    db.close();
    expect(() => SqliteRunStore.open(file)).toThrow(expect.objectContaining({ code: 'corrupt' }));

    const missingTailFile = path.join(directory, 'missing-tail.db');
    const secondStore = SqliteRunStore.open(missingTailFile);
    const value = ids();
    claim(secondStore);
    secondStore.transitionState(value.runId, 'created', 'preparing', 'state_changed');
    secondStore.close();
    const secondDb = new Database(missingTailFile);
    secondDb.prepare('DELETE FROM events WHERE run_id = ? AND seq = 1').run(value.runId);
    secondDb.close();
    expect(() => SqliteRunStore.open(missingTailFile)).toThrow(
      expect.objectContaining({ code: 'corrupt' }),
    );
  });
});

describe('worker slot and transactional journal', () => {
  it('makes the request idempotent and rejects payload conflict', async () => {
    const directory = await makeDir();
    const store = SqliteRunStore.open(path.join(directory, 'journal.db'));
    const value = ids();
    expect(claim(store)).toEqual({ kind: 'new', runId: value.runId });
    expect(claim(store)).toEqual({ kind: 'existing', runId: value.runId });
    expect(() =>
      store.claimWorkerSlot(value.controllerId, value.requestId, 'b'.repeat(64), value.runId),
    ).toThrow(StoreError);
    store.close();
  });

  it('binds every stored run to its creating controller for object-level authorization', async () => {
    const directory = await makeDir();
    const store = SqliteRunStore.open(path.join(directory, 'run-ownership.db'));
    const value = ids();
    claim(store);
    expect(store.ownsRun(value.controllerId, value.runId)).toBe(true);
    expect(store.ownsRun(asControllerId('a11ce030-0000-4000-8000-000000000030'), value.runId)).toBe(
      false,
    );
    expect(store.ownsRun(value.controllerId, asRunId('a11ce031-0000-4000-8000-000000000031'))).toBe(
      false,
    );
    store.close();
  });

  it('keeps the exclusive slot across reopen and returns busy for a second claim', async () => {
    const directory = await makeDir();
    const file = path.join(directory, 'slot.db');
    const store = SqliteRunStore.open(file);
    claim(store);
    store.close();
    const reopened = SqliteRunStore.open(file);
    const second = ids();
    expect(
      reopened.claimWorkerSlot(
        second.controllerId,
        'a11ce010-0000-4000-8000-000000000010',
        'b'.repeat(64),
        asRunId('a11ce011-0000-4000-8000-000000000011'),
      ),
    ).toEqual({ kind: 'worker_busy' });
    reopened.close();
  });

  it('serializes competing claims made through independent SQLite connections', async () => {
    const directory = await makeDir();
    const file = path.join(directory, 'racing-claims.db');
    const first = SqliteRunStore.open(file);
    const second = SqliteRunStore.open(file);
    const one = {
      controllerId: asControllerId('a11ce015-0000-4000-8000-000000000015'),
      requestId: 'a11ce016-0000-4000-8000-000000000016',
      runId: asRunId('a11ce017-0000-4000-8000-000000000017'),
      digest: 'c'.repeat(64),
    };
    const two = {
      controllerId: asControllerId('a11ce018-0000-4000-8000-000000000018'),
      requestId: 'a11ce019-0000-4000-8000-000000000019',
      runId: asRunId('a11ce020-0000-4000-8000-000000000020'),
      digest: 'd'.repeat(64),
    };
    const results = await Promise.all([
      Promise.resolve().then(() =>
        first.claimWorkerSlot(one.controllerId, one.requestId, one.digest, one.runId),
      ),
      Promise.resolve().then(() =>
        second.claimWorkerSlot(two.controllerId, two.requestId, two.digest, two.runId),
      ),
    ]);
    expect(results.filter((result) => result.kind === 'new')).toHaveLength(1);
    expect(results.filter((result) => result.kind === 'worker_busy')).toHaveLength(1);
    first.close();
    second.close();
  });

  it('commits state and ordered events together and replays with bigint sequence', async () => {
    const directory = await makeDir();
    const file = path.join(directory, 'events.db');
    const store = SqliteRunStore.open(file);
    const value = ids();
    claim(store);
    expect(store.transitionState(value.runId, 'created', 'preparing', 'state_changed')).toBe(1n);
    expect(store.transitionState(value.runId, 'preparing', 'running', 'state_changed')).toBe(2n);
    expect(store.readEventsAfter(value.runId, 0n, 20).map((event) => event.seq)).toEqual([1n, 2n]);
    expect(store.runState(value.runId)).toBe('running');
    expect(() =>
      store.transitionState(value.runId, 'created', 'completed', 'state_changed'),
    ).toThrow(StoreError);
    store.close();
  });

  it('rolls back state and event sequence when an event write fails', async () => {
    const directory = await makeDir();
    const file = path.join(directory, 'rollback.db');
    const store = SqliteRunStore.open(file);
    const value = ids();
    claim(store);
    const db = new Database(file);
    db.exec(
      "CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'injected'); END;",
    );
    db.close();
    expect(() =>
      store.transitionState(value.runId, 'created', 'preparing', 'state_changed'),
    ).toThrow();
    expect(store.runState(value.runId)).toBe('created');
    expect(store.readEventsAfter(value.runId, 0n, 10)).toEqual([]);
    store.close();
  });

  it('rolls back state and event sequence when SQLite reaches its page limit', async () => {
    const directory = await makeDir();
    const file = path.join(directory, 'sqlite-full.db');
    const firstStore = SqliteRunStore.open(file);
    const value = ids();
    claim(firstStore);
    firstStore.close();
    const db = new Database(file);
    db.exec(
      `CREATE TRIGGER fill_before_event BEFORE INSERT ON events BEGIN
         INSERT INTO evidence_index(run_id, artifact_id, sha256, relative_path, size_bytes)
         VALUES (NEW.run_id, 'full-trigger', '${'a'.repeat(64)}', zeroblob(50000000), 50000000);
       END;`,
    );
    const pages = db.pragma('page_count', { simple: true }) as number;
    db.close();
    const store = SqliteRunStore.open(file, { maxDatabasePages: pages });
    try {
      store.transitionState(value.runId, 'created', 'preparing', 'state_changed');
      expect.fail('the page limit must produce SQLITE_FULL');
    } catch (error) {
      expect(error).toMatchObject({ code: 'database', cause: { code: 'SQLITE_FULL' } });
    }
    expect(store.runState(value.runId)).toBe('created');
    expect(store.readEventsAfter(value.runId, 0n, 10)).toEqual([]);
    store.close();
  });

  it('releases the slot only after a terminal state and zero-process teardown receipt', async () => {
    const directory = await makeDir();
    const file = path.join(directory, 'teardown.db');
    const store = SqliteRunStore.open(file);
    const value = ids();
    claim(store);
    expect(() =>
      store.releaseAfterTeardown(value.runId, {
        jobId: 'job-1',
        stoppedAtUtc: '2026-10-19T12:00:00.000Z',
        remainingProcesses: 0,
        exitCode: null,
        stopReason: 'requested',
      }),
    ).toThrow(StoreError);
    store.transitionState(value.runId, 'created', 'preparing', 'state_changed');
    store.transitionState(value.runId, 'preparing', 'running', 'state_changed');
    store.transitionState(value.runId, 'running', 'stopping', 'state_changed');
    store.transitionState(value.runId, 'stopping', 'completed', 'state_changed');
    expect(() =>
      store.releaseAfterTeardown(value.runId, {
        jobId: 'job-1',
        stoppedAtUtc: '2026-10-19T12:00:00.000Z',
        remainingProcesses: 1,
        exitCode: 0,
        stopReason: 'requested',
      }),
    ).toThrow(StoreError);
    store.releaseAfterTeardown(value.runId, {
      jobId: 'job-1',
      stoppedAtUtc: '2026-10-19T12:00:00.000Z',
      remainingProcesses: 0,
      exitCode: 0,
      stopReason: 'requested',
    });
    expect(store.readEventsAfter(value.runId, 4n, 10)).toEqual([
      expect.objectContaining({
        seq: 5n,
        event_type: 'process_teardown',
        payload: {
          jobId: 'job-1',
          stoppedAtUtc: '2026-10-19T12:00:00.000Z',
          remainingProcesses: 0,
          exitCode: 0,
          stopReason: 'requested',
        },
      }),
    ]);
    const nextRunId = asRunId('a11ce014-0000-4000-8000-000000000014');
    expect(
      store.claimWorkerSlot(
        asControllerId('a11ce012-0000-4000-8000-000000000012'),
        'a11ce013-0000-4000-8000-000000000013',
        'b'.repeat(64),
        nextRunId,
      ),
    ).toEqual({ kind: 'new', runId: nextRunId });
    store.close();
  });

  it('rejects invalid replay limits and preserves sequences above Number.MAX_SAFE_INTEGER', async () => {
    const directory = await makeDir();
    const file = path.join(directory, 'precision.db');
    const store = SqliteRunStore.open(file);
    const value = ids();
    claim(store);
    expect(() => store.readEventsAfter(value.runId, 0n, 0)).toThrow();
    expect(() => store.readEventsAfter(value.runId, 0n, 10_001)).toThrow();
    const high = 9007199254740993n;
    const db = new Database(file);
    db.prepare('UPDATE run_state SET last_seq=? WHERE run_id=?').run(high, value.runId);
    db.prepare(
      'INSERT INTO events(run_id, seq, time_utc, event_type, payload) VALUES(?, ?, ?, ?, ?)',
    ).run(value.runId, high, '2026-10-19T12:00:00.000Z', '"state_changed"', '{}');
    db.close();
    expect(store.transitionState(value.runId, 'created', 'preparing', 'state_changed')).toBe(
      high + 1n,
    );
    expect(store.readEventsAfter(value.runId, high, 10)[0]?.seq).toBe(high + 1n);
    store.close();
  });
});
