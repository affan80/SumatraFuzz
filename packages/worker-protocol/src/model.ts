import { type Static, Type } from '@sinclair/typebox';

export const MIN_CAMPAIGN_MEMORY_BYTES = 16 * 1024 * 1024;

const Uuid = Type.String({
  pattern: '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
});
const PositiveSafeInteger = Type.Integer({ minimum: 1, maximum: Number.MAX_SAFE_INTEGER });
const DecimalSequence = Type.String({ pattern: '^(0|[1-9][0-9]*)$' });

export const RunStateSchema = Type.Union([
  Type.Literal('created'),
  Type.Literal('preparing'),
  Type.Literal('running'),
  Type.Literal('stopping'),
  Type.Literal('completed'),
  Type.Literal('failed'),
  Type.Literal('interrupted'),
]);

export const CampaignLimitsSchema = Type.Object(
  {
    max_duration_s: PositiveSafeInteger,
    max_memory_bytes: PositiveSafeInteger,
    max_disk_bytes: PositiveSafeInteger,
    max_cpu_percent: Type.Integer({ minimum: 1, maximum: 100 }),
  },
  { additionalProperties: false },
);

export const RunRequestSchema = Type.Object(
  {
    request_id: Uuid,
    controller_id: Uuid,
    input_bundle_id: Type.String({ minLength: 1, maxLength: 128, pattern: '^[A-Za-z0-9_-]+$' }),
    target_lock_sha256: Type.String({ minLength: 64, maxLength: 64, pattern: '^[0-9a-fA-F]{64}$' }),
    limits: CampaignLimitsSchema,
    label: Type.String({ maxLength: 128, pattern: '^[^\\u0000-\\u001f\\u007f-\\u009f]*$' }),
  },
  { additionalProperties: false },
);

export const StopReasonSchema = Type.Union([
  Type.Literal('requested'),
  Type.Literal('time_limit'),
  Type.Literal('cpu_limit'),
  Type.Literal('memory_limit'),
  Type.Literal('disk_limit'),
  Type.Literal('native_exit'),
  Type.Literal('process_failure'),
  Type.Literal('worker_restart'),
]);

export const RunStatusSchema = Type.Object(
  {
    run_id: Uuid,
    worker_id: Uuid,
    state: RunStateSchema,
    last_event_seq: DecimalSequence,
    stop_reason: Type.Union([StopReasonSchema, Type.Null()]),
  },
  { additionalProperties: false },
);

export const EventTypeSchema = Type.Union([
  Type.Literal('state_changed'),
  Type.Literal('process_teardown'),
  Type.Literal('metric_sample'),
  Type.Literal('evidence_finalized'),
  Type.Literal('error'),
]);

export const RunEventSchema = Type.Object(
  {
    run_id: Uuid,
    seq: DecimalSequence,
    time_utc: Type.String({ format: 'date-time' }),
    event_type: EventTypeSchema,
    payload: Type.Unknown(),
  },
  { additionalProperties: false },
);

export type RunId = string & { readonly __brand: 'RunId' };
export type WorkerId = string & { readonly __brand: 'WorkerId' };
export type ControllerId = string & { readonly __brand: 'ControllerId' };
export type RunState = Static<typeof RunStateSchema>;
export type CampaignLimits = Static<typeof CampaignLimitsSchema>;
export type RunRequest = Omit<Static<typeof RunRequestSchema>, 'request_id' | 'controller_id'> & {
  request_id: string & { readonly __brand: 'RequestId' };
  controller_id: ControllerId;
};
export type StopReason = Static<typeof StopReasonSchema>;
export type RunStatus = Omit<Static<typeof RunStatusSchema>, 'last_event_seq'> & {
  last_event_seq: bigint;
};
export type EventType = Static<typeof EventTypeSchema>;
export type RunEvent = Omit<Static<typeof RunEventSchema>, 'seq'> & { seq: bigint };

const transitions: ReadonlySet<string> = new Set([
  'created:preparing',
  'preparing:running',
  'preparing:failed',
  'running:stopping',
  'running:failed',
  'running:interrupted',
  'stopping:completed',
  'stopping:failed',
  'stopping:interrupted',
]);

export function validTransition(from: RunState, to: RunState): boolean {
  return transitions.has(`${from}:${to}`);
}

export function asRunId(value: string): RunId {
  return value as RunId;
}

export function asWorkerId(value: string): WorkerId {
  return value as WorkerId;
}

export function asControllerId(value: string): ControllerId {
  return value as ControllerId;
}

export function isNonNilUuid(value: string): boolean {
  return (
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value) &&
    value.toLowerCase() !== '00000000-0000-0000-0000-000000000000'
  );
}

export function encodeSequence(seq: bigint): string {
  if (seq < 0n) throw new RangeError('sequence must be nonnegative');
  return seq.toString(10);
}

export function decodeSequence(seq: string): bigint {
  if (!/^(0|[1-9][0-9]*)$/.test(seq)) throw new TypeError('sequence must be decimal');
  return BigInt(seq);
}
