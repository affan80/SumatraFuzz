import { describe, expect, it } from 'vitest';
import {
  createWorkerClient,
  normalizeCertificateFingerprint,
  validateWorkerUrl,
  verifyPinnedWorkerCertificate,
  type WorkerHttpRequest,
  type WorkerHttpResponse,
} from '../src/client.js';

const runId = '11111111-1111-4111-8111-111111111111';
const workerId = '22222222-2222-4222-8222-222222222222';
const fingerprint = 'a'.repeat(64);
const certificate = Buffer.from('test-only certificate');
const key = Buffer.from('test-only key');
const ca = Buffer.from('test-only CA');

function response(status: number, value: unknown): WorkerHttpResponse {
  return {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: Buffer.from(JSON.stringify(value)),
  };
}

function clientWith(respond: (request: WorkerHttpRequest) => Promise<WorkerHttpResponse>) {
  return createWorkerClient(
    {
      baseUrl: 'https://127.0.0.1:4242',
      controllerCertificate: certificate,
      controllerKey: key,
      trustedCa: ca,
      workerFingerprint: fingerprint,
      timeoutMs: 1000,
    },
    { request: respond },
  );
}

describe('authenticated worker client', () => {
  it('requires HTTPS and rejects URL credentials, query strings and fragments', () => {
    expect(() => validateWorkerUrl('http://127.0.0.1:4242')).toThrow(/HTTPS/i);
    expect(() => validateWorkerUrl('https://user:pass@127.0.0.1:4242')).toThrow(/URL/i);
    expect(() => validateWorkerUrl('https://worker.local/api?secret=x')).toThrow(/URL/i);
    expect(() => validateWorkerUrl('https://worker.local/#fragment')).toThrow(/URL/i);
  });

  it('normalizes certificate fingerprints and rejects an unpaired server certificate', () => {
    expect(normalizeCertificateFingerprint(`${'AA:'.repeat(31)}AA`)).toBe(fingerprint);
    expect(() => normalizeCertificateFingerprint('not-a-fingerprint')).toThrow(/fingerprint/i);
    expect(() => verifyPinnedWorkerCertificate('a'.repeat(64), 'b'.repeat(64))).toThrow(
      /identity/i,
    );
  });

  it('sends mTLS protocol and idempotency headers and validates returned run status', async () => {
    const calls: WorkerHttpRequest[] = [];
    const client = clientWith(async (request) => {
      calls.push(request);
      if (request.path === '/v1/capabilities') {
        return response(200, {
          worker_id: workerId,
          protocol_version: 1,
          target_lock_sha256: 'b'.repeat(64),
          max_limits: {
            max_duration_s: 300,
            max_memory_bytes: 1024 * 1024,
            max_disk_bytes: 1024 * 1024,
            max_cpu_percent: 80,
          },
        });
      }
      return response(202, {
        run_id: runId,
        worker_id: workerId,
        state: 'running',
        last_event_seq: '2',
        stop_reason: null,
      });
    });
    const run = await client.startRun({
      request_id: '33333333-3333-4333-8333-333333333333' as never,
      controller_id: '44444444-4444-4444-8444-444444444444' as never,
      input_bundle_id: 'seed-set-1',
      target_lock_sha256: 'b'.repeat(64),
      limits: {
        max_duration_s: 60,
        max_memory_bytes: 1024,
        max_disk_bytes: 2048,
        max_cpu_percent: 50,
      },
      label: 'safe run',
    });
    expect(run.last_event_seq).toBe(2n);
    expect(calls).toHaveLength(2);
    expect(calls[1]?.method).toBe('POST');
    expect(calls[1]?.path).toBe('/v1/runs');
    expect(calls[1]?.headers).toMatchObject({
      'x-sf-protocol-version': '1',
      'idempotency-key': '33333333-3333-4333-8333-333333333333',
    });
    expect(JSON.parse(calls[1]?.body?.toString('utf8') ?? '{}').request_id).toBe(
      '33333333-3333-4333-8333-333333333333',
    );
  });

  it('fails closed on protocol mismatch, malformed payloads, and oversized worker responses', async () => {
    const mismatch = clientWith(async () => response(426, { error: 'invalid_request' }));
    await expect(mismatch.capabilities()).rejects.toMatchObject({ status: 426 });

    const malformed = clientWith(async () =>
      response(200, {
        worker_id: workerId,
        protocol_version: 1,
        target_lock_sha256: 'short',
        max_limits: {},
      }),
    );
    await expect(malformed.capabilities()).rejects.toThrow(/capabilities/i);

    const oversized = clientWith(async () => ({
      status: 200,
      headers: {},
      body: Buffer.alloc(4 * 1024 * 1024 + 1),
    }));
    await expect(oversized.capabilities()).rejects.toThrow(/size limit/i);
  });

  it('replays only valid, ordered events belonging to the requested run', async () => {
    const sse = [
      `id: 1\ndata: ${JSON.stringify({ run_id: runId, seq: '1', time_utc: '2026-10-19T00:00:00.000Z', event_type: 'state_changed', payload: {} })}\n\n`,
      `id: 2\ndata: ${JSON.stringify({ run_id: runId, seq: '2', time_utc: '2026-10-19T00:00:01.000Z', event_type: 'state_changed', payload: {} })}\n\n`,
    ].join('');
    const client = clientWith(async () => ({
      status: 200,
      headers: { 'content-type': 'text/event-stream' },
      body: Buffer.from(sse),
    }));
    const events = await client.eventsAfter(runId, 0n);
    expect(events.map((event) => event.seq)).toEqual([1n, 2n]);

    const malformed = clientWith(async () => ({
      status: 200,
      headers: { 'content-type': 'text/event-stream' },
      body: Buffer.from(sse.replaceAll(runId, workerId)),
    }));
    await expect(malformed.eventsAfter(runId, 0n)).rejects.toThrow(/event/i);
  });

  it('destroys its TLS agent when closed', () => {
    const client = clientWith(async () => response(200, {}));
    expect(() => client.close()).not.toThrow();
  });
});
