import { describe, expect, it } from 'vitest';
import { AuditedTrustAdministration } from '../src/audited-trust-administration.js';
import type { AuditHealth, AuditRecord, SecurityAudit } from '../src/security-audit.js';
import type {
  TrustProvisionInput,
  TrustRecord,
  WorkerTrustRepository,
} from '../src/trust-store.js';

const controllerId = '22222222-2222-4222-8222-222222222222';
const fingerprint = 'a'.repeat(64);
const requestId = '33333333-3333-4333-8333-333333333333';
const input: TrustProvisionInput = {
  fingerprint,
  controllerId,
  permissions: ['runs:read'],
  notBefore: '2026-10-23T00:00:00.000Z',
  notAfter: '2026-10-24T00:00:00.000Z',
};

function fixture(options: { failAt?: number; mutationFailure?: boolean } = {}) {
  let revision = 0;
  let mutationCalls = 0;
  let health: AuditHealth = { state: 'healthy', reason: 'none', sequence: 0 };
  const records: AuditRecord[] = [];
  const repository: WorkerTrustRepository = {
    get revision() {
      return revision;
    },
    close() {},
    subscribe() {
      return () => {};
    },
    resolveFingerprint() {
      return null;
    },
    listActive() {
      return [];
    },
    provision(value) {
      mutationCalls += 1;
      if (options.mutationFailure) throw new Error('private database path');
      revision += 1;
      return {
        ...value,
        status: 'active',
        generation: 1,
        revision,
      } satisfies TrustRecord;
    },
    rotate(value) {
      return this.provision(value);
    },
    revoke() {
      mutationCalls += 1;
      revision += 1;
      return null;
    },
    unpair() {
      mutationCalls += 1;
      revision += 1;
      return 1;
    },
  };
  let appendCalls = 0;
  const audit: SecurityAudit = {
    get health() {
      return health;
    },
    async append(record) {
      appendCalls += 1;
      if (appendCalls === options.failAt) {
        health = { state: 'degraded', reason: 'storage', sequence: records.length };
        throw new Error('secret audit path');
      }
      records.push(record);
      health = { state: 'healthy', reason: 'none', sequence: records.length };
      return records.length;
    },
    async verifyAndRecover() {
      return health;
    },
    async close() {
      health = { state: 'closed', reason: 'none', sequence: records.length };
    },
  };
  return {
    repository,
    audit,
    records,
    get mutationCalls() {
      return mutationCalls;
    },
    setHealth(value: AuditHealth) {
      health = value;
    },
    admin: new AuditedTrustAdministration(
      repository,
      audit,
      () => new Date('2026-10-23T12:00:00.000Z'),
      () => requestId,
    ),
  };
}

describe('audited worker trust administration', () => {
  it('records redacted intent before provision and observed result afterward', async () => {
    const state = fixture();
    const result = await state.admin.provision(input);

    expect(result.revision).toBe(1);
    expect(state.records.map(({ decision, trustRevision }) => [decision, trustRevision])).toEqual([
      ['intent', 0],
      ['success', 1],
    ]);
    expect(state.records.map(({ action }) => action)).toEqual([
      'trust_provision',
      'trust_provision',
    ]);
    expect(state.records.every((record) => record.fingerprint === fingerprint)).toBe(true);
    expect(JSON.stringify(state.records)).not.toContain('notBefore');
    expect(JSON.stringify(state.records)).not.toContain('permissions');
  });

  it('audits rotation, revocation, and unpair mutations through the same boundary', async () => {
    const state = fixture();

    await state.admin.rotate(input, new Date('2026-10-23T12:30:00.000Z'));
    await state.admin.revoke(fingerprint);
    await state.admin.unpair(controllerId);

    expect(state.records.map(({ action, decision }) => [action, decision])).toEqual([
      ['trust_rotate', 'intent'],
      ['trust_rotate', 'success'],
      ['trust_revoke', 'intent'],
      ['trust_revoke', 'success'],
      ['trust_unpair', 'intent'],
      ['trust_unpair', 'success'],
    ]);
  });

  it('fails closed before mutation when audit health is degraded', async () => {
    const state = fixture();
    state.setHealth({ state: 'degraded', reason: 'integrity', sequence: 0 });

    await expect(state.admin.provision(input)).rejects.toThrow(
      'Worker trust administration failed',
    );
    expect(state.mutationCalls).toBe(0);
    expect(state.records).toEqual([]);
  });

  it('fails closed before mutation when the intent cannot be appended', async () => {
    const state = fixture({ failAt: 1 });

    await expect(state.admin.provision(input)).rejects.toThrow(
      'Worker trust administration failed',
    );
    expect(state.mutationCalls).toBe(0);
    expect(state.records).toEqual([]);
  });

  it('audits a safe failure result when the repository rejects the mutation', async () => {
    const state = fixture({ mutationFailure: true });

    await expect(state.admin.provision(input)).rejects.toThrow(
      'Worker trust administration failed',
    );
    expect(state.mutationCalls).toBe(1);
    expect(state.records.map(({ decision }) => decision)).toEqual(['intent', 'failure']);
    expect(state.records[1]?.errorCode).toBe('operation_failed');
    expect(JSON.stringify(state.records)).not.toContain('private database path');
  });

  it('reports post-commit audit failure without pretending the mutation was rolled back', async () => {
    const state = fixture({ failAt: 2 });

    await expect(state.admin.provision(input)).rejects.toThrow(
      'Worker trust administration failed',
    );
    expect(state.mutationCalls).toBe(1);
    expect(state.repository.revision).toBe(1);
    expect(state.records.map(({ decision }) => decision)).toEqual(['intent']);
  });
});
