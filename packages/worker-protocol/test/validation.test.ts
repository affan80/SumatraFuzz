import { describe, expect, it } from 'vitest';
import {
  decodeSequence,
  encodeSequence,
  RunRequestSchema,
  validateRunEvent,
  validateRunRequest,
  validateRunStatus,
  WorkerError,
  WorkerProtocolError,
} from '../src/index.js';

const validRequest = () => ({
  request_id: 'a11ce001-0000-4000-8000-000000000001',
  controller_id: 'a11ce002-0000-4000-8000-000000000002',
  input_bundle_id: 'bundle_A-01',
  target_lock_sha256: 'a'.repeat(64),
  limits: {
    max_duration_s: 60,
    max_memory_bytes: 1024,
    max_disk_bytes: 4096,
    max_cpu_percent: 90,
  },
  label: 'nightly campaign',
});

describe('RunRequest validation', () => {
  it('accepts a valid request with the exact wire fields', () => {
    expect(validateRunRequest(validRequest())).toEqual(validRequest());
  });

  it('rejects unknown fields and nil identities', () => {
    expect(() => validateRunRequest({ ...validRequest(), command: 'cmd.exe' })).toThrow(
      WorkerProtocolError,
    );
    expect(() =>
      validateRunRequest({ ...validRequest(), request_id: '00000000-0000-0000-0000-000000000000' }),
    ).toThrow(WorkerProtocolError);
  });

  it('rejects zero or out-of-range resource limits', () => {
    expect(() =>
      validateRunRequest({
        ...validRequest(),
        limits: { ...validRequest().limits, max_memory_bytes: 0 },
      }),
    ).toThrow(expect.objectContaining({ code: WorkerError.InvalidConfig }));
    expect(() =>
      validateRunRequest({
        ...validRequest(),
        limits: { ...validRequest().limits, max_cpu_percent: 101 },
      }),
    ).toThrow(WorkerProtocolError);
  });

  it('rejects labels exceeding Rust UTF-8 byte length and control characters', () => {
    expect(() => validateRunRequest({ ...validRequest(), label: 'é'.repeat(65) })).toThrow(
      WorkerProtocolError,
    );
    expect(() => validateRunRequest({ ...validRequest(), label: 'bad\nlabel' })).toThrow(
      WorkerProtocolError,
    );
  });
});

describe('wire schema and sequence precision', () => {
  it('exposes strict request properties', () => {
    expect(RunRequestSchema.additionalProperties).toBe(false);
  });

  it('round-trips SQLite event sequences above JavaScript safe integer range', () => {
    const sequence = 900719925474099312345n;
    expect(decodeSequence(encodeSequence(sequence))).toBe(sequence);
  });

  it('parses event and status sequences to bigint without precision loss', () => {
    const sequence = '900719925474099312345';
    const status = validateRunStatus({
      run_id: 'a11ce003-0000-4000-8000-000000000003',
      worker_id: 'a11ce004-0000-4000-8000-000000000004',
      state: 'running',
      last_event_seq: sequence,
      stop_reason: null,
    });
    const event = validateRunEvent({
      run_id: status.run_id,
      seq: sequence,
      time_utc: '2026-10-19T12:00:00.000Z',
      event_type: 'metric_sample',
      payload: { executions: 12 },
    });
    expect(status.last_event_seq).toBe(BigInt(sequence));
    expect(event.seq).toBe(BigInt(sequence));
  });

  it('validates native teardown as an explicit journal event', () => {
    expect(
      validateRunEvent({
        run_id: 'a11ce021-0000-4000-8000-000000000021',
        seq: '1',
        time_utc: '2026-10-19T12:00:00.000Z',
        event_type: 'process_teardown',
        payload: { jobId: 'job-1', remainingProcesses: 0 },
      }).event_type,
    ).toBe('process_teardown');
  });
});
