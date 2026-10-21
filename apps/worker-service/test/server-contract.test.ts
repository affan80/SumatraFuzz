import { X509Certificate } from 'node:crypto';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { request as httpsRequest } from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { createTlsFixture, issueCertificate } from '@sumatrafuzz/worker-security/test-fixtures';
import { describe, expect, it } from 'vitest';
import {
  assertProtocolVersion,
  createExclusiveRequestGate,
  createWorkerServer,
  parseArtifactRange,
  parseEventPageLimit,
  parseEventSequence,
  serializeBoundedJson,
  validateStartRequest,
} from '../src/server.js';

function authenticatedGet(
  baseUrl: string,
  requestPath: string,
  tls: Awaited<ReturnType<typeof createTlsFixture>>,
  maxVersion?: 'TLSv1.2',
): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const request = httpsRequest(
      new URL(requestPath, baseUrl),
      {
        ca: tls.ca,
        agent: false,
        ...(maxVersion ? { maxVersion } : {}),
        cert: tls.clientCert,
        key: tls.clientKey,
        headers: { 'x-sf-protocol-version': '1' },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer | string) =>
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)),
        );
        response.on('end', () => {
          try {
            resolve({
              status: response.statusCode ?? 0,
              body: JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown,
            });
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    request.on('error', reject);
    request.end();
  });
}

describe('worker API contract', () => {
  it('permits only one in-flight input import and releases the gate after completion', () => {
    const gate = createExclusiveRequestGate();
    const release = gate.tryAcquire();

    expect(release).toBeTypeOf('function');
    expect(gate.tryAcquire()).toBeUndefined();
    release?.();
    expect(gate.tryAcquire()).toBeTypeOf('function');
  });

  it('returns the signed controller identity and only its active run over mutual TLS', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'sf-server-contract-'));
    const tls = await createTlsFixture(root);
    const controllerId = '22222222-2222-4222-8222-222222222222';
    const activeStatus = {
      run_id: '33333333-3333-4333-8333-333333333333',
      worker_id: '11111111-1111-4111-8111-111111111111',
      state: 'running',
      last_event_seq: '2',
      stop_reason: null,
    };
    let currentRun: unknown = activeStatus;
    const server = await createWorkerServer({
      host: '127.0.0.1',
      mode: 'local',
      port: 0,
      workerId: activeStatus.worker_id,
      key: tls.workerKey,
      cert: tls.workerCert,
      ca: tls.ca,
      pairedControllers: new Map([[tls.fingerprint, controllerId]]),
      inputRoot: root,
      ensureInputCapacity: async () => {},
      maxInputBundleBytes: 64 * 1024 * 1024,
      store: { ownsRun: () => false },
      handlers: {
        capabilities: async (authenticatedControllerId: string) => ({
          worker_id: activeStatus.worker_id,
          controller_id: authenticatedControllerId,
          protocol_version: 1,
          target_lock_sha256: 'a'.repeat(64),
          max_limits: {
            max_duration_s: 60,
            max_memory_bytes: 1024,
            max_disk_bytes: 2048,
            max_cpu_percent: 50,
          },
        }),
        activeRun: async (authenticatedControllerId: string) =>
          authenticatedControllerId === controllerId ? currentRun : null,
      } as never,
    });

    try {
      const capabilities = await authenticatedGet(server.address, '/v1/capabilities', tls);
      expect(capabilities.status).toBe(200);
      expect(capabilities.body).toMatchObject({
        worker_id: activeStatus.worker_id,
        controller_id: controllerId,
      });

      const recovered = await authenticatedGet(server.address, '/v1/runs/active', tls);
      expect(recovered.status).toBe(200);
      expect(recovered.body).toEqual({ active_run: activeStatus });

      currentRun = null;
      const empty = await authenticatedGet(server.address, '/v1/runs/active', tls);
      expect(empty.status).toBe(200);
      expect(empty.body).toEqual({ active_run: null });
    } finally {
      await server.close();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('rejects invalid client leaves and TLS 1.2 before handler dispatch', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'sf-server-policy-'));
    const tls = await createTlsFixture(root);
    const cases: Array<{ cert: Buffer; key: Buffer }> = [];
    for (const [name, ext] of [
      [
        'ca-leaf',
        'basicConstraints=CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign\nextendedKeyUsage=clientAuth\n',
      ],
      ['missing-eku', 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n'],
      [
        'wrong-eku',
        'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n',
      ],
      ['missing-key-usage', 'basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n'],
    ] as const)
      cases.push(await issueCertificate(root, name, ext));
    cases.push(
      await issueCertificate(
        root,
        'expired',
        'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n',
        undefined,
        '-1',
      ),
    );
    const otherRoot = path.join(root, 'other');
    await mkdir(otherRoot);
    const other = await createTlsFixture(otherRoot);
    cases.push({ cert: other.clientCert, key: other.clientKey });
    let dispatches = 0;
    const server = await createWorkerServer({
      host: '127.0.0.1',
      mode: 'local',
      port: 0,
      workerId: '11111111-1111-4111-8111-111111111111',
      cert: tls.workerCert,
      key: tls.workerKey,
      ca: tls.ca,
      pairedControllers: new Map(
        [tls.clientCert, ...cases.map((item) => item.cert)].map((cert) => [
          new X509Certificate(cert).fingerprint256,
          '22222222-2222-4222-8222-222222222222',
        ]),
      ),
      inputRoot: root,
      ensureInputCapacity: async () => {},
      maxInputBundleBytes: 1024,
      store: { ownsRun: () => false },
      handlers: {
        capabilities: async () => {
          dispatches++;
          return {};
        },
      } as never,
    });
    try {
      for (const invalid of cases) {
        const outcome = await authenticatedGet(server.address, '/v1/capabilities', {
          ...tls,
          clientCert: Buffer.from(invalid.cert),
          clientKey: Buffer.from(invalid.key),
        }).catch(() => ({ status: 0 }));
        expect(outcome.status).not.toBe(200);
      }
      await expect(
        authenticatedGet(server.address, '/v1/capabilities', tls, 'TLSv1.2'),
      ).rejects.toThrow();
      expect(dispatches).toBe(0);
    } finally {
      await server.close();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('rejects absent, malformed, and unsupported protocol versions', () => {
    for (const version of [undefined, ['1'], '2', '01']) {
      expect(() => assertProtocolVersion(version)).toThrow(/protocol version/i);
    }
    expect(() => assertProtocolVersion('1')).not.toThrow();
  });

  it('requires request idempotency and binds request identity to the paired certificate', () => {
    const requestId = '22222222-2222-4222-8222-222222222222';
    const controllerId = '33333333-3333-4333-8333-333333333333';
    const request = {
      request_id: requestId,
      controller_id: controllerId,
      input_bundle_id: 'bundle-1',
      target_lock_sha256: 'a'.repeat(64),
      limits: {
        max_duration_s: 180,
        max_memory_bytes: 1024 * 1024 * 1024,
        max_disk_bytes: 1024 * 1024 * 1024,
        max_cpu_percent: 100,
      },
      label: 'integration fixture',
    };
    expect(validateStartRequest(request, requestId, controllerId)).toEqual(request);
    expect(() => validateStartRequest(request, undefined, controllerId)).toThrow(
      /Idempotency-Key/i,
    );
    expect(() => validateStartRequest(request, 'different', controllerId)).toThrow(
      /Idempotency-Key/i,
    );
    expect(() =>
      validateStartRequest(request, requestId, '44444444-4444-4444-8444-444444444444'),
    ).toThrow(/paired certificate/i);
    expect(() =>
      validateStartRequest({ ...request, controller_id: undefined }, requestId, controllerId),
    ).toThrow(/protocol validation/i);
    expect(() =>
      validateStartRequest(
        { ...request, request_id: '00000000-0000-0000-0000-000000000000' },
        '00000000-0000-0000-0000-000000000000',
        controllerId,
      ),
    ).toThrow(/non-nil UUID/i);
  });

  it('supports bounded single byte ranges and rejects traversal-like or multi-range values', () => {
    expect(parseArtifactRange('bytes=10-19', 100)).toEqual({ start: 10, end: 19 });
    expect(parseArtifactRange('bytes=90-', 100)).toEqual({ start: 90, end: 99 });
    expect(parseArtifactRange(undefined, 100)).toBeUndefined();
    expect(() => parseArtifactRange('bytes=100-', 100)).toThrow(/unsatisfiable/i);
    expect(() => parseArtifactRange('bytes=0-1,4-5', 100)).toThrow(/range/i);
    expect(parseArtifactRange('bytes=0-', 20 * 1024 * 1024)).toEqual({
      start: 0,
      end: 16 * 1024 * 1024 - 1,
    });
  });

  it('caps event replay pages and rejects malformed or unbounded limits', () => {
    expect(parseEventPageLimit(null)).toBe(100);
    expect(parseEventPageLimit('500')).toBe(500);
    for (const value of ['0', '501', '1000', '-1', '1.5', '999999', '']) {
      expect(() => parseEventPageLimit(value)).toThrow(/event page limit/i);
    }
  });

  it('accepts only event sequences representable by the SQLite journal', () => {
    expect(parseEventSequence('0')).toBe('0');
    expect(parseEventSequence('9223372036854775807')).toBe('9223372036854775807');
    for (const value of ['-1', '00', '9223372036854775808', '9'.repeat(100)]) {
      expect(() => parseEventSequence(value)).toThrow(/event replay sequence/i);
    }
  });

  it('serializes bigint values and rejects oversized JSON responses', () => {
    expect(serializeBoundedJson({ sequence: 12n })).toBe('{"sequence":"12"}\n');
    expect(() => serializeBoundedJson({ data: 'x'.repeat(4 * 1024 * 1024) })).toThrow(
      /response exceeds size limit/i,
    );
  });

  it('fails before listening when the binding, pairing records, or worker identity are unsafe', async () => {
    const base = {
      host: '127.0.0.1',
      mode: 'local' as const,
      port: 0,
      workerId: '11111111-1111-4111-8111-111111111111',
      key: Buffer.alloc(0),
      cert: Buffer.alloc(0),
      ca: Buffer.alloc(0),
      pairedControllers: new Map<string, string>(),
      inputRoot: '/unused',
      ensureInputCapacity: async () => {},
      maxInputBundleBytes: 64 * 1024 * 1024,
      store: { ownsRun: () => false },
      handlers: {} as never,
    };
    await expect(createWorkerServer({ ...base, mode: 'remote', host: '1.1.1.1' })).rejects.toThrow(
      /private|VPN/i,
    );
    await expect(createWorkerServer({ ...base, workerId: 'bad' })).rejects.toThrow(/UUID/i);
    await expect(
      createWorkerServer({
        ...base,
        pairedControllers: new Map([['not-a-fingerprint', '11111111-1111-4111-8111-111111111111']]),
      }),
    ).rejects.toThrow(/paired controller/i);
    await expect(
      createWorkerServer({
        ...base,
        pairedControllers: new Map([['a'.repeat(64), '00000000-0000-0000-0000-000000000000']]),
      }),
    ).rejects.toThrow(/paired controller/i);
  });
});
