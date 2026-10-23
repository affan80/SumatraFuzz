import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteWorkerTrustStore, type TrustProvisionInput } from '../src/trust-store.js';

const dirs: string[] = [];
const stores: SqliteWorkerTrustStore[] = [];
const controller = (n = 1) => `a11ce007-0000-4000-8000-${String(n).padStart(12, '0')}`;
const fingerprint = (n = 1) => n.toString(16).padStart(64, '0');
const now = new Date('2026-10-22T12:00:00.000Z');
const input = (n = 1, overrides: Partial<TrustProvisionInput> = {}): TrustProvisionInput => ({
  fingerprint: fingerprint(n),
  controllerId: controller(n),
  permissions: ['runs:read'],
  notBefore: '2026-10-22T00:00:00.000Z',
  notAfter: '2026-10-24T00:00:00.000Z',
  ...overrides,
});
async function file() {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sf-trust-'));
  dirs.push(dir);
  return path.join(dir, 'trust.db');
}
function open(name: string) {
  const store = SqliteWorkerTrustStore.open(name);
  stores.push(store);
  return store;
}
afterEach(async () => {
  for (const store of stores.splice(0)) store.close();
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { force: true, recursive: true })));
});

describe('persistent worker trust', () => {
  it('migrates version zero atomically and retains trust across reopen', async () => {
    const name = await file();
    const db = new Database(name);
    db.exec("CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES ('keep')");
    db.close();
    const store = open(name);
    expect(store.revision).toBe(0);
    expect(store.provision(input())).toEqual({
      ...input(),
      status: 'active',
      generation: 1,
      revision: 1,
    });
    store.close();
    const second = open(name);
    expect(second.resolveFingerprint(fingerprint(), now)?.controllerId).toBe(controller());
    expect(second.revision).toBe(1);
    const raw = new Database(name);
    expect(raw.pragma('user_version', { simple: true })).toBe(1);
    expect(raw.prepare('SELECT value FROM unrelated').get()).toEqual({ value: 'keep' });
    raw.close();
  });

  it('uses inclusive not-before and exclusive not-after without authorizing expired rows', async () => {
    const store = open(await file());
    store.provision(input());
    expect(
      store.resolveFingerprint(fingerprint(), new Date('2026-10-21T23:59:59.999Z')),
    ).toBeNull();
    expect(store.resolveFingerprint(fingerprint(), new Date(input().notBefore))).not.toBeNull();
    expect(store.resolveFingerprint(fingerprint(), new Date(input().notAfter))).toBeNull();
    expect(store.resolveFingerprint(fingerprint(99), now)).toBeNull();
  });

  it('rejects duplicate fingerprints and controller collisions without advancing revision', async () => {
    const store = open(await file());
    store.provision(input());
    expect(() => store.provision(input(2, { fingerprint: fingerprint() }))).toThrow();
    expect(() => store.provision(input(2, { controllerId: controller() }))).toThrow();
    expect(store.revision).toBe(1);
    expect(store.listActive()).toHaveLength(1);
  });

  it('makes an exact active provisioning replay idempotent for first-run recovery', async () => {
    const store = open(await file());
    const provisioned = store.provision(input());
    expect(store.provision(input())).toEqual(provisioned);
    expect(store.revision).toBe(1);
    expect(() => store.provision(input(1, { permissions: ['runs:stop'] }))).toThrow();
    expect(store.revision).toBe(1);
  });

  it('persists revocation tombstones and forbids replay or rebinding after unpair', async () => {
    const name = await file();
    const store = open(name);
    store.provision(input());
    expect(store.revoke(fingerprint())).toMatchObject({ status: 'revoked', revision: 2 });
    expect(store.revoke(fingerprint())).toMatchObject({ revision: 2 });
    expect(store.revision).toBe(2);
    store.close();
    const reopened = open(name);
    expect(reopened.resolveFingerprint(fingerprint(), now)).toBeNull();
    expect(() => reopened.provision(input())).toThrow();
    expect(() => reopened.provision(input(2, { fingerprint: fingerprint() }))).toThrow();
    expect(reopened.unpair(controller())).toBe(3);
    const replacement = reopened.provision(input(2, { controllerId: controller() }));
    expect(replacement).toMatchObject({ generation: 2, revision: 4 });
    expect(() => reopened.provision(input(3, { fingerprint: fingerprint() }))).toThrow();
    expect(reopened.revoke(fingerprint(99))).toBeNull();
  });

  it('rotates with explicit overlap then denies old fingerprint at the overlap boundary', async () => {
    const store = open(await file());
    store.provision(input());
    const overlap = new Date('2026-10-22T13:00:00.000Z');
    const replacement = store.rotate(input(2, { controllerId: controller() }), overlap, now);
    expect(replacement).toMatchObject({ generation: 2, revision: 2 });
    expect(store.resolveFingerprint(fingerprint(), now)).toMatchObject({
      notAfter: overlap.toISOString(),
      revision: 2,
    });
    expect(store.resolveFingerprint(fingerprint(), overlap)).toBeNull();
    expect(store.resolveFingerprint(fingerprint(2), overlap)).not.toBeNull();
    expect(() => store.rotate(input(3, { controllerId: controller() }), overlap, now)).toThrow();
    expect(store.revision).toBe(2);
    store.rotate(
      input(3, { controllerId: controller() }),
      new Date('2026-10-22T14:00:00.000Z'),
      overlap,
    );
    expect(store.listActive()).toHaveLength(2);
    expect(store.unpair(controller())).toBe(4);
    expect(store.listActive()).toEqual([]);
    expect(store.resolveFingerprint(fingerprint(2), now)).toBeNull();
  });

  it.each(['2026-10-22T12:00:00.000Z', '2026-10-23T12:00:00.001Z', '2026-10-25T00:00:00.000Z'])(
    'rejects an invalid overlap %s atomically',
    async (until) => {
      const store = open(await file());
      store.provision(input());
      expect(() =>
        store.rotate(input(2, { controllerId: controller() }), new Date(until), now),
      ).toThrow();
      expect(store.revision).toBe(1);
      expect(store.resolveFingerprint(fingerprint(), now)?.notAfter).toBe(input().notAfter);
      expect(store.resolveFingerprint(fingerprint(2), now)).toBeNull();
    },
  );

  it('enforces the 16 paired controller bound and releases slots only through unpair', async () => {
    const store = open(await file());
    for (let n = 1; n <= 16; n++) store.provision(input(n));
    expect(() => store.provision(input(17))).toThrow();
    store.revoke(fingerprint());
    expect(() => store.provision(input(17))).toThrow();
    store.unpair(controller());
    expect(store.provision(input(17)).revision).toBe(19);
  });

  it('retains all 4096 tombstones and fails closed when fingerprint capacity is exhausted', async () => {
    const name = await file();
    open(name);
    const db = new Database(name);
    db.transaction(() => {
      db.prepare('UPDATE trust_metadata SET revision = 4096').run();
      db.prepare('INSERT INTO trust_controllers VALUES (?, 1, 4096, 4096)').run(controller());
      const insert = db.prepare('INSERT INTO trust_certificates VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
      for (let n = 1; n <= 4096; n++) {
        insert.run(
          fingerprint(n),
          controller(),
          '["runs:read"]',
          input().notBefore,
          input().notAfter,
          n === 4096 ? 'active' : 'revoked',
          n,
          n,
        );
      }
    })();
    db.close();
    const store = open(name);
    expect(() => store.provision(input(4097))).toThrow(
      expect.objectContaining({ code: 'capacity' }),
    );
    expect(() =>
      store.rotate(
        input(4097, { controllerId: controller() }),
        new Date('2026-10-22T13:00:00.000Z'),
        now,
      ),
    ).toThrow(expect.objectContaining({ code: 'capacity' }));
    expect(store.revision).toBe(4096);
    expect(store.resolveFingerprint(fingerprint(), now)).toBeNull();
    expect(store.resolveFingerprint(fingerprint(4096), now)).not.toBeNull();
    store.unpair(controller());
    expect(() => store.provision(input(4097))).toThrow(
      expect.objectContaining({ code: 'capacity' }),
    );
  });

  it('rolls back earlier rotation changes and revision on a SQLite write failure', async () => {
    const name = await file();
    const store = open(name);
    store.provision(input());
    const db = new Database(name);
    db.exec(
      "CREATE TRIGGER fail_insert BEFORE INSERT ON trust_certificates BEGIN SELECT RAISE(ABORT, 'forced failure'); END",
    );
    expect(() =>
      store.rotate(
        input(2, { controllerId: controller() }),
        new Date('2026-10-22T13:00:00.000Z'),
        now,
      ),
    ).toThrow();
    expect(store.revision).toBe(1);
    expect(store.resolveFingerprint(fingerprint(), now)?.notAfter).toBe(input().notAfter);
    db.exec('DROP TRIGGER fail_insert');
    db.close();
    expect(
      store.rotate(
        input(2, { controllerId: controller() }),
        new Date('2026-10-22T13:00:00.000Z'),
        now,
      ).generation,
    ).toBe(2);
  });

  it.each([
    { fingerprint: 'AA'.repeat(32) },
    { fingerprint: 7 },
    { controllerId: '00000000-0000-0000-0000-000000000000' },
    { controllerId: 1 },
    { permissions: ['unknown'] },
    { permissions: ['runs:read', 'runs:read'] },
    { permissions: 'runs:read' },
    { notBefore: '2026-10-22' },
    { notAfter: '2026-10-21T00:00:00.000Z' },
    { privateKey: 'secret' },
    { status: 'active' },
  ])('rejects malformed runtime provision data %j', async (bad) => {
    const store = open(await file());
    expect(() => store.provision({ ...input(), ...bad } as TrustProvisionInput)).toThrow();
    expect(store.revision).toBe(0);
    expect(store.listActive()).toEqual([]);
  });

  it('rejects malformed lookup and operator inputs without coercion', async () => {
    const store = open(await file());
    expect(() => store.resolveFingerprint(1 as unknown as string, now)).toThrow();
    expect(() => store.resolveFingerprint(fingerprint(), new Date(Number.NaN))).toThrow();
    expect(() => store.unpair(1 as unknown as string)).toThrow();
    expect(() => store.revoke({} as string)).toThrow();
    expect(() => store.provision(null as unknown as TrustProvisionInput)).toThrow();
  });

  it('returns detached immutable permission snapshots', async () => {
    const store = open(await file());
    const permissions = ['runs:read'] as TrustProvisionInput['permissions'];
    const record = store.provision(input(1, { permissions }));
    expect(Object.isFrozen(record)).toBe(true);
    expect(Object.isFrozen(record.permissions)).toBe(true);
    expect(store.resolveFingerprint(fingerprint(), now)?.permissions).toEqual(['runs:read']);
  });
});

describe('trust database integrity', () => {
  it('rejects future schema versions and preserves corrupt bytes', async () => {
    const name = await file();
    const db = new Database(name);
    db.pragma('user_version = 2');
    db.close();
    expect(() => open(name)).toThrow(expect.objectContaining({ code: 'unsupported_version' }));
    const corrupt = await file();
    const bytes = Buffer.from('not a database');
    await writeFile(corrupt, bytes);
    expect(() => open(corrupt)).toThrow();
    expect(await readFile(corrupt)).toEqual(bytes);
  });

  it('rolls back a conflicting schema migration without claiming version one', async () => {
    const name = await file();
    const db = new Database(name);
    db.exec('CREATE TABLE trust_certificates(wrong_column TEXT)');
    db.close();
    expect(() => open(name)).toThrow();
    const raw = new Database(name);
    expect(raw.pragma('user_version', { simple: true })).toBe(0);
    expect(
      raw.prepare("SELECT name FROM sqlite_master WHERE name = 'trust_metadata'").get(),
    ).toBeUndefined();
    raw.close();
  });

  it.each([
    'UPDATE trust_metadata SET revision = 0',
    'UPDATE trust_certificates SET permissions = \'["unknown"]\'',
    'DELETE FROM trust_metadata',
    'UPDATE trust_controllers SET last_generation = 2',
    'UPDATE trust_controllers SET paired = 0',
    'DELETE FROM trust_certificates',
  ])('fails closed on logical state corruption: %s', async (sql) => {
    const name = await file();
    open(name).provision(input());
    const db = new Database(name);
    db.exec(sql);
    db.close();
    expect(() => open(name)).toThrow(expect.objectContaining({ code: 'corrupt' }));
  });
});

describe('bounded committed trust notifications', () => {
  it('publishes immutable revision changes only after the mutation is visible to another handle', async () => {
    const name = await file();
    const store = open(name);
    const changes: unknown[] = [];
    const unsubscribe = store.subscribe((change) => {
      const second = open(name);
      expect(second.revision).toBe(change.revision);
      expect(Object.isFrozen(change)).toBe(true);
      expect(Object.isFrozen(change.fingerprints)).toBe(true);
      changes.push(change);
    });
    store.provision(input());
    expect(changes).toEqual([{ revision: 1, fingerprints: [fingerprint()] }]);
    store.revoke(fingerprint());
    store.revoke(fingerprint());
    expect(changes).toHaveLength(2);
    unsubscribe();
    store.unpair(controller());
    expect(changes).toHaveLength(2);
  });

  it('isolates listener failures and caps subscriptions at 16', async () => {
    const store = open(await file());
    const remove = store.subscribe(() => {
      throw new Error('listener failure');
    });
    for (let n = 1; n < 16; n++) store.subscribe(() => {});
    expect(() => store.subscribe(() => {})).toThrow();
    expect(store.provision(input()).revision).toBe(1);
    remove();
    expect(() => store.subscribe(() => {})).not.toThrow();
  });

  it('never publishes a rejected or rolled-back rotation', async () => {
    const name = await file();
    const store = open(name);
    store.provision(input());
    const changes: unknown[] = [];
    store.subscribe((change) => changes.push(change));
    const db = new Database(name);
    db.exec(
      "CREATE TRIGGER notification_failure BEFORE INSERT ON trust_certificates BEGIN SELECT RAISE(ABORT, 'forced failure'); END",
    );
    expect(() =>
      store.rotate(
        input(2, { controllerId: controller() }),
        new Date('2026-10-22T13:00:00.000Z'),
        now,
      ),
    ).toThrow();
    db.close();
    expect(changes).toEqual([]);
    expect(store.revision).toBe(1);
  });

  it('bounds rotation and unpair notifications to the two previously installed fingerprints', async () => {
    const store = open(await file());
    store.provision(input());
    store.rotate(
      input(2, { controllerId: controller() }),
      new Date('2026-10-22T13:00:00.000Z'),
      now,
    );
    const changes: unknown[] = [];
    store.subscribe((change) => changes.push(change));
    store.rotate(
      input(3, { controllerId: controller() }),
      new Date('2026-10-22T14:00:00.000Z'),
      new Date('2026-10-22T13:00:00.000Z'),
    );
    expect(changes).toEqual([{ revision: 3, fingerprints: [fingerprint(), fingerprint(2)] }]);
    store.unpair(controller());
    expect(changes).toEqual([
      { revision: 3, fingerprints: [fingerprint(), fingerprint(2)] },
      { revision: 4, fingerprints: [fingerprint(2), fingerprint(3)] },
    ]);
  });
});

it('rejects reentrant trust mutation during notification so revisions remain ordered', async () => {
  const store = open(await file());
  const errors: unknown[] = [];
  const revisions: number[] = [];
  store.subscribe(() => {
    try {
      store.revoke(fingerprint());
    } catch (error) {
      errors.push(error instanceof Error && 'code' in error ? error.code : 'unsafe');
    }
  });
  store.subscribe((change) => revisions.push(change.revision));
  store.provision(input());
  expect(errors).toEqual(['conflict']);
  expect(revisions).toEqual([1]);
  expect(store.revision).toBe(1);
  expect(store.resolveFingerprint(fingerprint(), now)?.status).toBe('active');
  expect(store.revoke(fingerprint())?.revision).toBe(2);
  expect(revisions).toEqual([1, 2]);
});
