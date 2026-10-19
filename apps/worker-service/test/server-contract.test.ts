import { describe, expect, it } from 'vitest';
import {
  assertProtocolVersion,
  createWorkerServer,
  parseArtifactRange,
  parseEventPageLimit,
  serializeBoundedJson,
  validateStartRequest,
} from '../src/server.js';

describe('worker API contract', () => {
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
  });
});
