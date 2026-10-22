import { X509Certificate } from 'node:crypto';
import { mkdir, mkdtemp, readdir, rm } from 'node:fs/promises';
import type { IncomingHttpHeaders } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect as netConnect } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { connect } from 'node:tls';
import { createTlsFixture, issueCertificate } from '@sumatrafuzz/worker-security/test-fixtures';
import { describe, expect, it, vi } from 'vitest';
import { ZipFile } from 'yazl';
import { type AdmissionPolicy, PROVISIONAL_ADMISSION_POLICY } from '../src/admission.js';
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

const controllerA = '22222222-2222-4222-8222-222222222222';
const controllerB = '44444444-4444-4444-8444-444444444444';
const ownedRun = '33333333-3333-4333-8333-333333333333';
const workerId = '11111111-1111-4111-8111-111111111111';
const requestId = '55555555-5555-4555-8555-555555555555';
const runStatus = {
  run_id: ownedRun,
  worker_id: workerId,
  state: 'running',
  last_event_seq: '0',
  stop_reason: null,
};
const startRequest = {
  request_id: requestId,
  controller_id: controllerA,
  input_bundle_id: 'bundle-1',
  target_lock_sha256: 'a'.repeat(64),
  limits: { max_duration_s: 60, max_memory_bytes: 1024, max_disk_bytes: 2048, max_cpu_percent: 50 },
  label: 'route authorization fixture',
};

function apiRequest(
  baseUrl: string,
  tls: Awaited<ReturnType<typeof createTlsFixture>>,
  method: string,
  requestPath: string,
  headers: Record<string, string | string[]> = {},
  payload?: Buffer,
): Promise<{ status: number; body: Buffer; headers: IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const request = httpsRequest(
      baseUrl,
      {
        method,
        path: requestPath,
        ca: tls.ca,
        cert: tls.clientCert,
        key: tls.clientKey,
        agent: false,
        headers: { 'x-sf-protocol-version': '1', ...headers },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        response.on('end', () =>
          resolve({
            status: response.statusCode ?? 0,
            body: Buffer.concat(chunks),
            headers: response.headers,
          }),
        );
        response.on('error', reject);
      },
    );
    request.on('error', reject);
    request.end(payload);
  });
}

function safeError(result: { status: number; body: Buffer }, status: number, code: string) {
  expect(result.status).toBe(status);
  const decoded = JSON.parse(result.body.toString('utf8')) as Record<string, unknown>;
  expect(decoded).toEqual({
    error: code,
    request_id: expect.stringMatching(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    ),
  });
  expect(decoded.request_id).not.toBe(requestId);
  return decoded;
}

async function withApiFixture(
  test: (fixture: {
    root: string;
    server: Awaited<ReturnType<typeof createWorkerServer>>;
    tlsA: Awaited<ReturnType<typeof createTlsFixture>>;
    tlsB: Awaited<ReturnType<typeof createTlsFixture>>;
    handlers: {
      [K in keyof import('../src/server.js').WorkerApiHandlers]: ReturnType<typeof vi.fn>;
    };
    ownsRun: ReturnType<typeof vi.fn>;
  }) => Promise<void>,
  admissionPolicy?: AdmissionPolicy,
) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sf-route-policy-'));
  const tlsA = await createTlsFixture(root);
  const second = await issueCertificate(
    root,
    'second-controller',
    'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n',
  );
  const tlsB = {
    ...tlsA,
    clientCert: Buffer.from(second.cert),
    clientKey: Buffer.from(second.key),
  };
  const ownsRun = vi.fn(
    (controller: string, run: string) => controller === controllerA && run === ownedRun,
  );
  const handlers = {
    capabilities: vi.fn(async (controller: string) => ({ controller_id: controller })),
    activeRun: vi.fn(async (controller: string) => (controller === controllerA ? runStatus : null)),
    startRun: vi.fn(async () => runStatus),
    getRun: vi.fn(async () => runStatus),
    stopRun: vi.fn(async () => runStatus),
    eventsAfter: vi.fn(async () => []),
    manifest: vi.fn(async () => ({ artifacts: [] })),
    artifactMetadata: vi.fn(async () => ({ etag: 'a'.repeat(64), totalBytes: 3 })),
    artifact: vi.fn(async () => ({
      etag: 'a'.repeat(64),
      totalBytes: 3,
      start: 0,
      end: 2,
      bytes: Buffer.from('pdf'),
    })),
  };
  const server = await createWorkerServer({
    host: '127.0.0.1',
    mode: 'local',
    port: 0,
    workerId,
    key: tlsA.workerKey,
    cert: tlsA.workerCert,
    ca: tlsA.ca,
    pairedControllers: new Map([
      [tlsA.fingerprint, controllerA],
      [new X509Certificate(second.cert).fingerprint256, controllerB],
    ]),
    inputRoot: root,
    ensureInputCapacity: async () => {},
    maxInputBundleBytes: 64 * 1024 * 1024,
    store: { ownsRun: ownsRun as never },
    ...(admissionPolicy ? { admissionPolicy } : {}),
    handlers,
  });
  try {
    await test({ root, server, tlsA, tlsB, handlers, ownsRun });
  } finally {
    await server.close();
    await rm(root, { recursive: true, force: true });
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

describe('worker API contract', () => {
  it('denies per-controller and global work before dispatch and returns capacity after completion', async () => {
    await withApiFixture(
      async ({ server, tlsA, tlsB, handlers }) => {
        const pending = deferred<unknown>();
        handlers.capabilities.mockImplementation(() => pending.promise);
        const first = apiRequest(server.address, tlsA, 'GET', '/v1/capabilities');
        await vi.waitFor(() => expect(handlers.capabilities).toHaveBeenCalledTimes(1));
        safeError(
          await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities'),
          429,
          'too_many_requests',
        );
        const second = apiRequest(server.address, tlsB, 'GET', '/v1/capabilities');
        await vi.waitFor(() => expect(handlers.capabilities).toHaveBeenCalledTimes(2));
        safeError(
          await apiRequest(server.address, tlsB, 'GET', '/v1/capabilities'),
          503,
          'service_unavailable',
        );
        expect(handlers.capabilities).toHaveBeenCalledTimes(2);
        pending.resolve({ ready: true });
        expect((await first).status).toBe(200);
        expect((await second).status).toBe(200);
        expect((await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities')).status).toBe(
          200,
        );
      },
      { ...PROVISIONAL_ADMISSION_POLICY, maxRequests: 2, maxRequestsPerController: 1 },
    );
  });

  it('enforces controller rate and artifact/replay gates before their expensive handlers', async () => {
    await withApiFixture(
      async ({ server, tlsA, handlers }) => {
        const metadata = deferred<{ etag: string; totalBytes: number }>();
        const events = deferred<[]>();
        handlers.artifactMetadata.mockImplementation(() => metadata.promise);
        handlers.eventsAfter.mockImplementation(() => events.promise);
        const artifact = apiRequest(
          server.address,
          tlsA,
          'GET',
          `/v1/runs/${ownedRun}/artifacts/seed`,
        );
        await vi.waitFor(() => expect(handlers.artifactMetadata).toHaveBeenCalledOnce());
        safeError(
          await apiRequest(server.address, tlsA, 'GET', `/v1/runs/${ownedRun}/artifacts/seed`),
          429,
          'too_many_requests',
        );
        expect(handlers.artifactMetadata).toHaveBeenCalledOnce();
        expect(handlers.artifact).not.toHaveBeenCalled();
        const replay = apiRequest(server.address, tlsA, 'GET', `/v1/runs/${ownedRun}/events`);
        await vi.waitFor(() => expect(handlers.eventsAfter).toHaveBeenCalledOnce());
        safeError(
          await apiRequest(server.address, tlsA, 'GET', `/v1/runs/${ownedRun}/events`),
          429,
          'too_many_requests',
        );
        expect(handlers.eventsAfter).toHaveBeenCalledOnce();
        metadata.resolve({ etag: 'a'.repeat(64), totalBytes: 3 });
        events.resolve([]);
        expect((await artifact).status).toBe(200);
        expect((await replay).status).toBe(200);
      },
      { ...PROVISIONAL_ADMISSION_POLICY, maxArtifactTransfersPerController: 1 },
    );
    await withApiFixture(
      async ({ server, tlsA, tlsB, handlers }) => {
        expect((await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities')).status).toBe(
          200,
        );
        safeError(
          await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities'),
          429,
          'too_many_requests',
        );
        expect((await apiRequest(server.address, tlsB, 'GET', '/v1/capabilities')).status).toBe(
          200,
        );
        expect(handlers.capabilities).toHaveBeenCalledTimes(2);
      },
      { ...PROVISIONAL_ADMISSION_POLICY, requestBurst: 1, requestsPerSecond: 1 },
    );
  });

  it('bounds the raw target and header bytes before body or handler use', async () => {
    await withApiFixture(async ({ server, tlsA, handlers }) => {
      safeError(
        await apiRequest(
          server.address,
          tlsA,
          'GET',
          `/v1/capabilities?padding=${'x'.repeat(4096)}`,
        ),
        414,
        'uri_too_long',
      );
      safeError(
        await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities', {
          'x-padding': 'x'.repeat(16 * 1024),
        }),
        431,
        'headers_too_large',
      );
      expect(handlers.capabilities).not.toHaveBeenCalled();
    });
  });

  it.each(['abort', 'idle', 'shutdown'] as const)(
    'cleans a partial JSON request on %s without launching work',
    async (reason) => {
      await withApiFixture(
        async ({ server, tlsA, handlers }) => {
          const request = httpsRequest(server.address, {
            path: '/v1/runs',
            method: 'POST',
            ca: tlsA.ca,
            cert: tlsA.clientCert,
            key: tlsA.clientKey,
            agent: false,
            headers: {
              'x-sf-protocol-version': '1',
              'content-type': 'application/json',
              'content-length': '100',
              expect: '100-continue',
            },
          });
          request.on('error', () => {});
          const continued = new Promise<void>((resolve) =>
            request.once('continue', () => resolve()),
          );
          const ended = new Promise<void>((resolve) => request.once('close', () => resolve()));
          request.flushHeaders();
          await continued;
          request.write('{');
          if (reason === 'abort') request.destroy();
          if (reason === 'shutdown') await server.close();
          await ended;
          await new Promise<void>((resolve) => setImmediate(resolve));
          expect(handlers.startRun).not.toHaveBeenCalled();
          if (reason !== 'shutdown')
            await vi.waitFor(async () =>
              expect(
                (await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities')).status,
              ).toBe(200),
            );
        },
        {
          ...PROVISIONAL_ADMISSION_POLICY,
          maxSockets: 1,
          maxRequests: 1,
          maxRequestsPerController: 1,
          idleTimeoutMs: 80,
        },
      );
    },
  );

  it.each(['deadline', 'revoke'] as const)(
    'keeps dispatched work counted after %s until it settles',
    async (reason) => {
      await withApiFixture(
        async ({ server, tlsA, handlers }) => {
          const pending = deferred<unknown>();
          handlers.capabilities.mockImplementationOnce(() => pending.promise);
          const first = apiRequest(server.address, tlsA, 'GET', '/v1/capabilities').catch(() => ({
            status: 0,
          }));
          await vi.waitFor(() => expect(handlers.capabilities).toHaveBeenCalledOnce());
          if (reason === 'revoke') server.disconnectController(controllerA);
          await first;
          safeError(
            await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities'),
            503,
            'service_unavailable',
          );
          expect(handlers.capabilities).toHaveBeenCalledOnce();
          pending.resolve({ ready: true });
          await new Promise<void>((resolve) => setImmediate(resolve));
          expect((await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities')).status).toBe(
            200,
          );
        },
        {
          ...PROVISIONAL_ADMISSION_POLICY,
          maxSockets: 1,
          maxRequests: 1,
          maxRequestsPerController: 1,
          requestTimeoutMs: 80,
        },
      );
    },
  );

  it('bounds initial sockets and incomplete TLS headers with local connections', async () => {
    await withApiFixture(
      async ({ server, tlsA, handlers }) => {
        const socket = netConnect({
          host: '127.0.0.1',
          port: Number(new URL(server.address).port),
        });
        await new Promise<void>((resolve) => socket.once('connect', resolve));
        await expect(apiRequest(server.address, tlsA, 'GET', '/v1/capabilities')).rejects.toThrow();
        const closed = new Promise<void>((resolve) => socket.once('close', () => resolve()));
        socket.destroy();
        await closed;
        await vi.waitFor(async () =>
          expect((await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities')).status).toBe(
            200,
          ),
        );
        const slow = connect({
          host: '127.0.0.1',
          port: Number(new URL(server.address).port),
          ca: tlsA.ca,
          cert: tlsA.clientCert,
          key: tlsA.clientKey,
        });
        slow.on('error', () => {});
        slow.once('secureConnect', () => slow.write('GET /v1/capabilities HTTP/1.1\r\nHost:'));
        await new Promise<void>((resolve) => slow.once('close', () => resolve()));
        expect(handlers.capabilities).toHaveBeenCalledOnce();
        await vi.waitFor(async () =>
          expect((await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities')).status).toBe(
            200,
          ),
        );
      },
      { ...PROVISIONAL_ADMISSION_POLICY, maxSockets: 1, headersTimeoutMs: 80 },
    );
  });

  it('releases an incomplete upload and the exclusive import gate at its absolute deadline', async () => {
    await withApiFixture(
      async ({ server, tlsA }) => {
        const request = httpsRequest(server.address, {
          path: '/v1/input-bundles',
          method: 'POST',
          ca: tlsA.ca,
          cert: tlsA.clientCert,
          key: tlsA.clientKey,
          agent: false,
          headers: {
            'x-sf-protocol-version': '1',
            'content-type': 'application/zip',
            'content-length': '100',
            expect: '100-continue',
          },
        });
        request.on('error', () => {});
        const continued = new Promise<void>((resolve) => request.once('continue', () => resolve()));
        const ended = new Promise<void>((resolve) => request.once('close', () => resolve()));
        request.flushHeaders();
        await continued;
        request.write('P');
        await ended;
        const zip = new ZipFile();
        zip.addBuffer(Buffer.from('%PDF-1.4\n%%EOF\n'), 'seed.pdf');
        zip.end();
        const chunks: Buffer[] = [];
        for await (const chunk of zip.outputStream) chunks.push(Buffer.from(chunk));
        const result = await apiRequest(
          server.address,
          tlsA,
          'POST',
          '/v1/input-bundles',
          { 'content-type': 'application/zip' },
          Buffer.concat(chunks),
        );
        expect(result.status).toBe(201);
      },
      {
        ...PROVISIONAL_ADMISSION_POLICY,
        maxRequests: 1,
        maxRequestsPerController: 1,
        uploadTimeoutMs: 80,
      },
    );
  });

  it('uses each TLS principal for capabilities, active run, start and bundle namespace despite identity headers', async () => {
    await withApiFixture(async ({ root, server, tlsA, tlsB, handlers }) => {
      const zip = new ZipFile();
      zip.addBuffer(Buffer.from('%PDF-1.4\n%%EOF\n'), 'seed.pdf');
      zip.end();
      const chunks: Buffer[] = [];
      for await (const chunk of zip.outputStream) chunks.push(Buffer.from(chunk));
      const archive = Buffer.concat(chunks);
      for (const [tls, controller, spoofed] of [
        [tlsA, controllerA, controllerB],
        [tlsB, controllerB, controllerA],
      ] as const) {
        const headers = {
          'x-controller-id': spoofed,
          'controller-id': spoofed,
          'x-request-id': requestId,
        };
        const capabilities = await apiRequest(
          server.address,
          tls,
          'GET',
          '/v1/capabilities',
          headers,
        );
        expect(JSON.parse(capabilities.body.toString())).toEqual({ controller_id: controller });
        expect(handlers.capabilities).toHaveBeenLastCalledWith(controller);
        const active = await apiRequest(server.address, tls, 'GET', '/v1/runs/active', headers);
        expect(JSON.parse(active.body.toString()).active_run).toEqual(
          controller === controllerA ? runStatus : null,
        );
        expect(handlers.activeRun).toHaveBeenLastCalledWith(controller);
        const payload = { ...startRequest, controller_id: controller };
        expect(
          (
            await apiRequest(
              server.address,
              tls,
              'POST',
              '/v1/runs',
              { ...headers, 'content-type': 'application/json', 'idempotency-key': requestId },
              Buffer.from(JSON.stringify(payload)),
            )
          ).status,
        ).toBe(202);
        expect(handlers.startRun).toHaveBeenLastCalledWith(controller, payload);
        const imported = await apiRequest(
          server.address,
          tls,
          'POST',
          '/v1/input-bundles',
          { ...headers, 'content-type': 'application/zip' },
          archive,
        );
        expect(imported.status).toBe(201);
        const bundle = JSON.parse(imported.body.toString()) as { input_bundle_id: string };
        expect(await readdir(path.join(root, controller, bundle.input_bundle_id))).toEqual([
          'seed.pdf',
        ]);
      }
      handlers.startRun.mockClear();
      safeError(
        await apiRequest(
          server.address,
          tlsB,
          'POST',
          '/v1/runs',
          {
            'content-type': 'application/json',
            'idempotency-key': requestId,
            'x-controller-id': controllerA,
          },
          Buffer.from(JSON.stringify(startRequest)),
        ),
        403,
        'forbidden',
      );
      expect(handlers.startRun).not.toHaveBeenCalled();
    });
  });

  it('denies every foreign run subresource before dispatch with the same safe response as unknown routes', async () => {
    await withApiFixture(async ({ server, tlsA, tlsB, handlers, ownsRun }) => {
      const routes = [
        ['GET', '', 'getRun'],
        ['POST', '/stop', 'stopRun'],
        ['GET', '/events', 'eventsAfter'],
        ['GET', '/manifest', 'manifest'],
        ['GET', '/artifacts/seed', 'artifact'],
      ] as const;
      const unknown = safeError(
        await apiRequest(server.address, tlsB, 'GET', '/v1/unknown'),
        404,
        'not_found',
      );
      for (const [method, suffix, handler] of routes) {
        const denied = safeError(
          await apiRequest(server.address, tlsB, method, `/v1/runs/${ownedRun}${suffix}`, {
            'x-controller-id': controllerA,
            'x-request-id': requestId,
          }),
          404,
          'not_found',
        );
        expect(denied.error).toBe(unknown.error);
        expect(denied.request_id).not.toBe(unknown.request_id);
        expect(handlers[handler]).not.toHaveBeenCalled();
        expect(handlers.artifactMetadata).not.toHaveBeenCalled();
        expect(ownsRun).toHaveBeenLastCalledWith(controllerB, ownedRun);
        const allowed = await apiRequest(
          server.address,
          tlsA,
          method,
          `/v1/runs/${ownedRun}${suffix}`,
        );
        expect(allowed.status).toBe(method === 'POST' ? 202 : 200);
        expect(handlers[handler].mock.calls.at(-1)?.slice(0, 2)).toEqual([controllerA, ownedRun]);
        expect(ownsRun.mock.invocationCallOrder.at(-1)).toBeLessThan(
          handlers[handler].mock.invocationCallOrder.at(-1) ?? 0,
        );
        if (suffix.includes('artifacts'))
          expect(handlers.artifactMetadata).toHaveBeenLastCalledWith(controllerA, ownedRun, 'seed');
        handlers[handler].mockClear();
        handlers.artifactMetadata.mockClear();
      }
      ownsRun.mockClear();
      safeError(
        await apiRequest(server.address, tlsA, 'PUT', `/v1/runs/${ownedRun}`),
        404,
        'not_found',
      );
      expect(ownsRun).not.toHaveBeenCalled();
    });
  });

  it('rejects path aliases before normalization or handler dispatch', async () => {
    await withApiFixture(async ({ server, tlsA, handlers, ownsRun }) => {
      for (const target of [
        '/v1//capabilities',
        '/v1/capabilities/',
        '/v1/../v1/capabilities',
        '/v1/%63apabilities',
        `/v1//runs/${ownedRun}`,
        `/v1/runs/${ownedRun}/`,
        `/v1/runs/${ownedRun}/manifest/`,
        '/v1/capabilities#fragment',
      ]) {
        safeError(await apiRequest(server.address, tlsA, 'GET', target), 404, 'not_found');
      }
      expect(ownsRun).not.toHaveBeenCalled();
      for (const handler of Object.values(handlers)) expect(handler).not.toHaveBeenCalled();
    });
  });

  it('rejects unsupported or duplicate content types before dispatch and input I/O', async () => {
    await withApiFixture(async ({ server, tlsA, handlers, root }) => {
      for (const [target, type] of [
        ['/v1/runs', 'application/zip'],
        ['/v1/input-bundles', 'application/json'],
        ['/v1/runs', undefined],
        ['/v1/runs', ['application/json', 'application/json']],
        ['/v1/runs', 'application/json; charset=latin1'],
      ] as const) {
        safeError(
          await apiRequest(
            server.address,
            tlsA,
            'POST',
            target,
            {
              'idempotency-key': requestId,
              ...(type === undefined
                ? {}
                : { 'content-type': typeof type === 'string' ? type : [...type] }),
            },
            Buffer.from(JSON.stringify(startRequest)),
          ),
          415,
          'unsupported_media_type',
        );
      }
      expect(handlers.startRun).not.toHaveBeenCalled();
      expect(await readdir(root)).not.toContain(controllerA);
    });
  });

  it('returns stable errors and generated IDs without reflecting internal exceptions or request IDs', async () => {
    await withApiFixture(async ({ server, tlsA, handlers }) => {
      handlers.capabilities.mockRejectedValueOnce(
        new Error('/private/worker/key.pem secret stack'),
      );
      safeError(
        await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities', {
          'x-request-id': requestId,
        }),
        500,
        'internal_error',
      );
      safeError(
        await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities', {
          'x-sf-protocol-version': '2',
        }),
        426,
        'protocol_version_unsupported',
      );
      safeError(
        await apiRequest(
          server.address,
          tlsA,
          'POST',
          '/v1/runs',
          { 'content-type': 'application/json' },
          Buffer.from('{secret'),
        ),
        400,
        'invalid_request',
      );
      handlers.capabilities.mockRejectedValueOnce(
        Object.assign(new Error('secret'), { status: 599 }),
      );
      safeError(
        await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities'),
        500,
        'internal_error',
      );
    });
  });

  it('bounds overload retry advice without reflecting exception fields', async () => {
    await withApiFixture(async ({ server, tlsA, handlers }) => {
      for (const [status, code] of [
        [429, 'too_many_requests'],
        [503, 'service_unavailable'],
      ] as const) {
        handlers.capabilities.mockRejectedValueOnce(
          Object.assign(new Error('private capacity detail'), {
            status,
            retryAfter: 'attacker-controlled retry advice',
          }),
        );
        const result = await apiRequest(server.address, tlsA, 'GET', '/v1/capabilities');
        safeError(result, status, code);
        expect(result.headers['retry-after']).toBe('1');
      }
    });
  });

  it('rejects ambiguous framing at the HTTP boundary without dispatch', async () => {
    await withApiFixture(async ({ server, tlsA, handlers }) => {
      for (const framing of [
        'Content-Length: 1\r\nContent-Length: 1',
        'Content-Length: 1\r\nTransfer-Encoding: chunked',
        'Transfer-Encoding: gzip, chunked',
      ]) {
        const raw = await new Promise<string>((resolve, reject) => {
          const socket = connect(
            {
              host: '127.0.0.1',
              port: Number(new URL(server.address).port),
              ca: tlsA.ca,
              cert: tlsA.clientCert,
              key: tlsA.clientKey,
            },
            () => {
              socket.write(
                `POST /v1/runs HTTP/1.1\r\nHost: worker\r\nX-SF-Protocol-Version: 1\r\nContent-Type: application/json\r\n${framing}\r\nConnection: close\r\n\r\nx`,
              );
            },
          );
          let received = '';
          socket.on('data', (data) => {
            received += data.toString();
          });
          socket.on('end', () => resolve(received));
          socket.on('error', reject);
        });
        expect(raw).toContain('400 Bad Request');
        safeError(
          { status: 400, body: Buffer.from(raw.split('\r\n\r\n')[1] ?? '') },
          400,
          'invalid_request',
        );
      }
      for (const handler of Object.values(handlers)) expect(handler).not.toHaveBeenCalled();
    });
  });

  it('rejects late framing fields beyond the parsed-header cap before application body reads', async () => {
    await withApiFixture(async ({ server, tlsA, handlers }) => {
      const payload = JSON.stringify(startRequest);
      const requestWithLateFraming = (
        framing: string,
        wireBody: string,
        paddingFields = 60,
      ): Promise<string> =>
        new Promise((resolve, reject) => {
          const socket = connect(
            {
              host: '127.0.0.1',
              port: Number(new URL(server.address).port),
              ca: tlsA.ca,
              cert: tlsA.clientCert,
              key: tlsA.clientKey,
            },
            () => {
              // Five required fields + sixty padding fields put framing at field 66.
              const padding = Array.from(
                { length: paddingFields },
                (_, index) => `X-Padding-${index}: x`,
              ).join('\r\n');
              socket.write(
                `POST /v1/runs HTTP/1.1\r\nHost: worker\r\nX-SF-Protocol-Version: 1\r\nContent-Type: application/json\r\nIdempotency-Key: ${requestId}\r\nConnection: close\r\n${padding}\r\n${framing}\r\n\r\n${wireBody}`,
              );
            },
          );
          const deadline = setTimeout(
            () => socket.destroy(new Error('worker waited for an over-limit request body')),
            2000,
          );
          let received = '';
          socket.on('data', (data) => {
            received += data.toString();
          });
          socket.on('end', () => {
            clearTimeout(deadline);
            resolve(received);
          });
          socket.on('error', (error) => {
            clearTimeout(deadline);
            reject(error);
          });
        });
      const atLimit = await requestWithLateFraming(
        `Content-Length: ${Buffer.byteLength(payload)}`,
        payload,
        58,
      );
      expect(atLimit).toContain('202 Accepted');
      expect(handlers.startRun).toHaveBeenCalledOnce();
      handlers.startRun.mockClear();
      const cases = [
        [
          'Transfer-Encoding: gzip, chunked',
          `${Buffer.byteLength(payload).toString(16)}\r\n${payload}\r\n0\r\n\r\n`,
        ],
        [`Content-Length: 0${Buffer.byteLength(payload)}`, payload],
        // A response while this declared body remains unsent proves rejection precedes body reads.
        ['Transfer-Encoding: gzip, chunked', ''],
        [`Content-Length: ${Buffer.byteLength(payload)}`, ''],
      ] as const;
      for (const [framing, wireBody] of cases) {
        const raw = await requestWithLateFraming(framing, wireBody);
        expect(raw).toContain('400 Bad Request');
        const headerEnd = raw.indexOf('\r\n\r\n');
        let bodyText = raw.slice(headerEnd + 4);
        if (/\r\ntransfer-encoding: chunked\r\n/i.test(raw.slice(0, headerEnd + 2))) {
          const chunks: string[] = [];
          while (bodyText !== '') {
            const sizeEnd = bodyText.indexOf('\r\n');
            const size = Number.parseInt(bodyText.slice(0, sizeEnd), 16);
            if (size === 0) break;
            expect(size).toBeGreaterThan(0);
            chunks.push(bodyText.slice(sizeEnd + 2, sizeEnd + 2 + size));
            bodyText = bodyText.slice(sizeEnd + 2 + size + 2);
          }
          bodyText = chunks.join('');
        }
        safeError({ status: 400, body: Buffer.from(bodyText) }, 400, 'invalid_request');
        for (const handler of Object.values(handlers)) expect(handler).not.toHaveBeenCalled();
      }
    });
  });

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
