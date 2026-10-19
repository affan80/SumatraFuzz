import { createRequire } from 'node:module';
import { Ajv } from 'ajv';
import { WorkerError, WorkerProtocolError } from './errors.js';
import {
  decodeSequence,
  isNonNilUuid,
  type RunEvent,
  RunEventSchema,
  type RunRequest,
  RunRequestSchema,
  type RunStatus,
  RunStatusSchema,
} from './model.js';

const ajv = new Ajv({ allErrors: true, strict: true });
const addFormats = createRequire(import.meta.url)('ajv-formats') as (instance: Ajv) => Ajv;
addFormats(ajv);
const validateRequest = ajv.compile(RunRequestSchema);
const validateStatus = ajv.compile(RunStatusSchema);
const validateEvent = ajv.compile(RunEventSchema);

export function validateRunRequest(value: unknown): RunRequest {
  if (!validateRequest(value)) {
    throw new WorkerProtocolError(WorkerError.InvalidConfig, 'invalid campaign request');
  }

  const request = value as RunRequest;
  if (
    !isNonNilUuid(request.request_id) ||
    !isNonNilUuid(request.controller_id) ||
    new TextEncoder().encode(request.label).byteLength > 128
  ) {
    throw new WorkerProtocolError(WorkerError.InvalidConfig, 'invalid campaign request');
  }

  return request;
}

export function validateRunStatus(value: unknown): RunStatus {
  if (!validateStatus(value)) {
    throw new WorkerProtocolError(WorkerError.InvalidConfig, 'invalid run status');
  }
  const status = value as Omit<RunStatus, 'last_event_seq'> & { last_event_seq: string };
  if (!isNonNilUuid(status.run_id) || !isNonNilUuid(status.worker_id)) {
    throw new WorkerProtocolError(WorkerError.InvalidConfig, 'invalid run status');
  }
  return { ...status, last_event_seq: decodeSequence(status.last_event_seq) };
}

export function validateRunEvent(value: unknown): RunEvent {
  if (!validateEvent(value)) {
    throw new WorkerProtocolError(WorkerError.InvalidConfig, 'invalid run event');
  }
  const event = value as Omit<RunEvent, 'seq'> & { seq: string };
  if (!isNonNilUuid(event.run_id)) {
    throw new WorkerProtocolError(WorkerError.InvalidConfig, 'invalid run event');
  }
  return { ...event, seq: decodeSequence(event.seq) };
}
