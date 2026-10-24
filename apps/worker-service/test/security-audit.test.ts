import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { CredentialProtector } from '../src/pairing-provision.js';
import { type AuditRecord, FileSecurityAudit } from '../src/security-audit.js';

const roots: string[] = [];
const audits: FileSecurityAudit[] = [];
function protector(): CredentialProtector {
  const key = randomBytes(32);
  return {
    async protect(bytes) {
      const nonce = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, nonce);
      const encrypted = Buffer.concat([cipher.update(bytes), cipher.final()]);
      return Buffer.concat([nonce, cipher.getAuthTag(), encrypted]);
    },
    async unprotect(bytes) {
      const cipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
      cipher.setAuthTag(bytes.subarray(12, 28));
      return Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]);
    },
  };
}
function record(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    timestamp: '2026-10-22T12:00:00.000Z',
    requestId: '11111111-1111-4111-8111-111111111111',
    action: 'authorize',
    resource: 'capabilities',
    decision: 'allow',
    trustRevision: 0,
    ...overrides,
  };
}
async function fixture(
  overrides: { maxBytes?: number; maxSegmentBytes?: number; maxSegments?: number } = {},
) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sf-security-audit-'));
  roots.push(root);
  const options = {
    directory: path.join(root, 'audit'),
    protector: protector(),
    maxBytes: 128 * 1024,
    maxSegmentBytes: 2048,
    maxSegments: 64,
    ...overrides,
  };
  const audit = await FileSecurityAudit.open(options);
  audits.push(audit);
  return { root, options, audit };
}
async function reopen(options: Parameters<typeof FileSecurityAudit.open>[0]) {
  const audit = await FileSecurityAudit.open(options);
  audits.push(audit);
  return audit;
}
async function segments(directory: string) {
  return (await readdir(directory)).filter((name) => name.endsWith('.audit')).sort();
}
afterEach(async () => {
  for (const audit of audits.splice(0)) await audit.close();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('durable chained security audit', () => {
  it('serializes concurrent appenders and verifies the complete sequence after restart', async () => {
    const { audit, options } = await fixture();
    const sequences = await Promise.all(
      Array.from({ length: 20 }, () => audit.append(record({ requestId: randomUUID() }))),
    );
    expect(sequences).toEqual(Array.from({ length: 20 }, (_, index) => index + 1));
    expect(audit.health).toMatchObject({ state: 'healthy', sequence: 20 });
    await audit.close();
    const opened = await reopen(options);
    expect(await opened.verifyAndRecover()).toMatchObject({ state: 'healthy', sequence: 20 });
  });

  it('detects a changed record without rewriting the damaged chain', async () => {
    const { audit, options } = await fixture();
    await audit.append(record());
    await audit.close();
    const file = path.join(options.directory, (await segments(options.directory))[0] as string);
    const original = await readFile(file, 'utf8');
    const changed = original.replace('"decision":"allow"', '"decision":"deny"');
    expect(changed === original).toBe(false);
    await writeFile(file, changed);
    const opened = await reopen(options);
    expect(opened.health).toMatchObject({ state: 'degraded', reason: 'integrity' });
    await expect(opened.append(record())).rejects.toThrow();
    expect((await readFile(file, 'utf8')) === changed).toBe(true);
  });

  it('rejects a missing retained prefix or middle segment', async () => {
    for (const missing of [0, 1]) {
      const { audit, options } = await fixture({ maxSegmentBytes: 1024 });
      for (let n = 0; n < 8; n++) await audit.append(record());
      await audit.close();
      const files = await segments(options.directory);
      expect(files.length >= 3).toBe(true);
      await rm(path.join(options.directory, files[missing] as string));
      expect((await reopen(options)).health).toMatchObject({
        state: 'degraded',
        reason: 'integrity',
      });
    }
  });

  it('accepts a verified extension after a stale protected checkpoint and advances it', async () => {
    const { audit, options } = await fixture();
    await audit.append(record());
    const checkpoint = await readFile(path.join(options.directory, 'checkpoint.dpapi'));
    await audit.append(record());
    await audit.close();
    await writeFile(path.join(options.directory, 'checkpoint.dpapi'), checkpoint);
    const opened = await reopen(options);
    expect(opened.health).toMatchObject({ state: 'healthy', sequence: 2 });
    expect(
      (await readFile(path.join(options.directory, 'checkpoint.dpapi'))).equals(checkpoint),
    ).toBe(false);
  });

  it('rejects rollback behind the checkpoint and a partially truncated tail', async () => {
    for (const partial of [false, true]) {
      const { audit, options } = await fixture();
      await audit.append(record());
      const file = path.join(options.directory, (await segments(options.directory))[0] as string);
      const before = await readFile(file);
      await audit.append(record());
      await audit.close();
      const after = await readFile(file);
      await writeFile(file, partial ? after.subarray(0, after.length - 10) : before);
      expect((await reopen(options)).health).toMatchObject({
        state: 'degraded',
        reason: 'integrity',
      });
    }
  });

  it('fails closed when the checkpoint target is non-regular and recovers after restoration', async () => {
    const { audit, options } = await fixture();
    const checkpoint = path.join(options.directory, 'checkpoint.dpapi');
    const saved = path.join(options.directory, 'saved-checkpoint');
    await rename(checkpoint, saved);
    await mkdir(checkpoint);
    await expect(audit.append(record())).rejects.toThrow();
    expect(audit.health.state).toBe('degraded');
    await expect(audit.append(record())).rejects.toThrow();
    await rm(checkpoint, { recursive: true });
    await rename(saved, checkpoint);
    expect(await audit.verifyAndRecover()).toMatchObject({ state: 'healthy', sequence: 0 });
    expect(await audit.append(record())).toBe(1);
  });

  it('bounds retained segments without deleting continuity history', async () => {
    const { audit, options } = await fixture({ maxSegmentBytes: 1024, maxSegments: 2 });
    let failed = false;
    for (let n = 0; n < 20; n++) {
      try {
        await audit.append(record());
      } catch {
        failed = true;
        break;
      }
    }
    expect(failed).toBe(true);
    expect(audit.health).toMatchObject({ state: 'degraded', reason: 'quota' });
    expect((await segments(options.directory)).length).toBe(2);
    const first = await readFile(
      path.join(options.directory, (await segments(options.directory))[0] as string),
      'utf8',
    );
    expect(first.includes('"sequence":1')).toBe(true);
  });

  it('enforces the total disk quota before adding a record', async () => {
    const { audit, options } = await fixture({ maxBytes: 4096, maxSegmentBytes: 1024 });
    let failed = false;
    for (let n = 0; n < 30; n++) {
      try {
        await audit.append(record());
      } catch {
        failed = true;
        break;
      }
    }
    expect(failed).toBe(true);
    expect(audit.health).toMatchObject({ state: 'degraded', reason: 'quota' });
    const sizes = await Promise.all(
      (await readdir(options.directory)).map(
        async (name) => (await readFile(path.join(options.directory, name))).length,
      ),
    );
    expect(sizes.reduce((sum, size) => sum + size, 0) <= options.maxBytes).toBe(true);
  });

  it('detects checkpoint/key tampering and never replaces unreadable protected identity', async () => {
    for (const target of ['checkpoint.dpapi', 'key.dpapi']) {
      const { audit, options } = await fixture();
      await audit.append(record());
      await audit.close();
      const file = path.join(options.directory, target);
      const original = await readFile(file);
      original[original.length - 1] = (original[original.length - 1] as number) ^ 1;
      await writeFile(file, original);
      const opened = await reopen(options).catch(() => null);
      expect(opened === null || opened.health.state === 'degraded').toBe(true);
      expect((await readFile(file)).equals(original)).toBe(true);
    }
  });

  it('fails closed on unknown files and non-regular entries in the protected audit directory', async () => {
    const { audit, options } = await fixture();
    await audit.append(record());
    await audit.close();
    await writeFile(path.join(options.directory, 'unexpected.log'), 'untrusted');
    const opened = await reopen(options);
    expect(opened.health).toMatchObject({ state: 'degraded', reason: 'integrity' });
    await expect(opened.append(record())).rejects.toThrow();
  });

  it.each([
    { body: 'raw PDF bytes' },
    { message: '-----BEGIN PRIVATE KEY-----' },
    { stack: 'Error at /private/path' },
    { resource: '/absolute/worker/path' },
    { artifactId: 'C:\\worker\\secret.key' },
    { action: 'spawn_process' },
    { errorCode: 'PRIVATE_KEY=secret' },
    { fingerprint: 'certificate body' },
    { timestamp: '2026-10-22' },
    { trustRevision: -1 },
    { runId: 'not-a-uuid' },
  ])('rejects unsafe fields rather than persisting them: %j', async (unsafe) => {
    const { audit, options } = await fixture();
    await expect(audit.append({ ...record(), ...unsafe } as AuditRecord)).rejects.toThrow();
    expect(audit.health).toMatchObject({ state: 'healthy', sequence: 0 });
    const texts = await Promise.all(
      (await segments(options.directory)).map((name) =>
        readFile(path.join(options.directory, name), 'utf8'),
      ),
    );
    expect(texts.join('').includes('PRIVATE KEY')).toBe(false);
    expect(texts.join('').includes('/private/path')).toBe(false);
  });
});
