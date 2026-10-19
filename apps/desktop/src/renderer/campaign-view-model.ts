const MAX_EXPANDED_BYTES = 64 * 1024 * 1024;
const MAX_SEQUENCE = 9_223_372_036_854_775_807n;
const RUN_STATES = new Set([
  'created',
  'preparing',
  'running',
  'stopping',
  'completed',
  'failed',
  'interrupted',
]);
const STOP_REASONS = new Set([
  'requested',
  'time_limit',
  'cpu_limit',
  'memory_limit',
  'disk_limit',
  'native_exit',
  'process_failure',
  'worker_restart',
]);

export interface InputBundleSummaryView {
  readonly archiveSha256: string;
  readonly fileCount: number;
  readonly expandedBytes: number;
}

export interface CampaignViewStatus {
  readonly connectionState: 'connected' | 'disconnected';
  readonly workerId: string | null;
  readonly policyLimits: {
    readonly max_duration_s: number;
    readonly max_memory_bytes: number;
    readonly max_disk_bytes: number;
    readonly max_cpu_percent: number;
  } | null;
  readonly inputBundle: InputBundleSummaryView | null;
  readonly campaignLabel: string | null;
  readonly runState: string | null;
  readonly stopReason: string | null;
}

function exactObject(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isUuid(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value) &&
    value.toLowerCase() !== '00000000-0000-0000-0000-000000000000'
  );
}

function parseLimits(value: unknown): CampaignViewStatus['policyLimits'] {
  if (
    !exactObject(value, [
      'max_duration_s',
      'max_memory_bytes',
      'max_disk_bytes',
      'max_cpu_percent',
    ]) ||
    !Number.isSafeInteger(value.max_duration_s) ||
    (value.max_duration_s as number) < 1 ||
    !Number.isSafeInteger(value.max_memory_bytes) ||
    (value.max_memory_bytes as number) < 1 ||
    !Number.isSafeInteger(value.max_disk_bytes) ||
    (value.max_disk_bytes as number) < 1 ||
    !Number.isInteger(value.max_cpu_percent) ||
    (value.max_cpu_percent as number) < 1 ||
    (value.max_cpu_percent as number) > 100
  ) {
    return null;
  }
  return {
    max_duration_s: value.max_duration_s as number,
    max_memory_bytes: value.max_memory_bytes as number,
    max_disk_bytes: value.max_disk_bytes as number,
    max_cpu_percent: value.max_cpu_percent as number,
  };
}

export function parseInputBundleSummary(value: unknown): InputBundleSummaryView | null {
  if (
    !exactObject(value, ['archive_sha256', 'file_count', 'expanded_bytes']) ||
    typeof value.archive_sha256 !== 'string' ||
    !/^[0-9a-f]{64}$/i.test(value.archive_sha256) ||
    !Number.isSafeInteger(value.file_count) ||
    (value.file_count as number) < 1 ||
    (value.file_count as number) > 1024 ||
    !Number.isSafeInteger(value.expanded_bytes) ||
    (value.expanded_bytes as number) < 1 ||
    (value.expanded_bytes as number) > MAX_EXPANDED_BYTES
  ) {
    return null;
  }
  return {
    archiveSha256: value.archive_sha256,
    fileCount: value.file_count as number,
    expandedBytes: value.expanded_bytes as number,
  };
}

function parseRun(
  value: unknown,
  workerId: string,
): { state: string; stopReason: string | null } | null {
  if (
    !exactObject(value, ['run_id', 'worker_id', 'state', 'last_event_seq', 'stop_reason']) ||
    !isUuid(value.run_id) ||
    value.worker_id !== workerId ||
    typeof value.state !== 'string' ||
    !(typeof value.last_event_seq === 'bigint'
      ? value.last_event_seq >= 0n && value.last_event_seq <= MAX_SEQUENCE
      : typeof value.last_event_seq === 'string' &&
        /^(0|[1-9][0-9]*)$/.test(value.last_event_seq) &&
        value.last_event_seq.length <= MAX_SEQUENCE.toString().length &&
        BigInt(value.last_event_seq) <= MAX_SEQUENCE) ||
    (value.stop_reason !== null && typeof value.stop_reason !== 'string')
  ) {
    return null;
  }
  return {
    state: RUN_STATES.has(value.state) ? value.state : 'Unknown state',
    stopReason:
      typeof value.stop_reason === 'string' && STOP_REASONS.has(value.stop_reason)
        ? value.stop_reason
        : null,
  };
}

export function parseCampaignStatus(value: unknown): CampaignViewStatus | null {
  if (
    !exactObject(value, [
      'connection_state',
      'worker_id',
      'max_limits',
      'imported_bundle',
      'campaign_label',
      'active_run',
    ]) ||
    (value.connection_state !== 'connected' && value.connection_state !== 'disconnected')
  ) {
    return null;
  }
  if (value.connection_state === 'disconnected') {
    if (
      value.worker_id !== null ||
      value.max_limits !== null ||
      value.imported_bundle !== null ||
      value.campaign_label !== null ||
      value.active_run !== null
    ) {
      return null;
    }
    return {
      connectionState: 'disconnected',
      workerId: null,
      policyLimits: null,
      inputBundle: null,
      campaignLabel: null,
      runState: null,
      stopReason: null,
    };
  }
  if (!isUuid(value.worker_id)) return null;
  const policyLimits = parseLimits(value.max_limits);
  if (!policyLimits) return null;
  const inputBundle =
    value.imported_bundle === null ? null : parseInputBundleSummary(value.imported_bundle);
  if (value.imported_bundle !== null && inputBundle === null) return null;
  const campaignLabel = value.campaign_label;
  if (
    campaignLabel !== null &&
    (typeof campaignLabel !== 'string' ||
      campaignLabel.length > 128 ||
      [...campaignLabel].some((character) => {
        const code = character.codePointAt(0) ?? 0;
        return code <= 0x1f || (code >= 0x7f && code <= 0x9f);
      }))
  ) {
    return null;
  }
  const run = value.active_run === null ? null : parseRun(value.active_run, value.worker_id);
  if (value.active_run !== null && run === null) return null;
  return {
    connectionState: 'connected',
    workerId: value.worker_id,
    policyLimits,
    inputBundle,
    campaignLabel,
    runState: run?.state ?? null,
    stopReason: run?.stopReason ?? null,
  };
}
