import { Agent, request as httpsRequest } from 'node:https';
import { checkServerIdentity, type PeerCertificate } from 'node:tls';
import {
  isNonNilUuid,
  type RunEvent,
  type RunRequest,
  type RunStatus,
  validateRunEvent,
  validateRunRequest,
  validateRunStatus,
} from '@sumatrafuzz/worker-protocol';
import { TLS_MIN_VERSION, validateEndpointCertificate } from '@sumatrafuzz/worker-security';

const PROTOCOL_VERSION = '1';
const MAX_EVENT_BYTES = 4 * 1024 * 1024;
const MAX_EVENT_COUNT = 500;
const MAX_ARCHIVE_BYTES = 32 * 1024 * 1024;
const MAX_EXPANDED_BYTES = 64 * 1024 * 1024;
const MAX_INPUT_FILES = 1024;
const MAX_SEQUENCE = '9223372036854775807';
const SHA256_FINGERPRINT = /^[0-9a-f]{64}$/;

export interface WorkerClientConfig {
  readonly baseUrl: string;
  readonly controllerCertificate: Buffer;
  readonly controllerKey: Buffer;
  readonly trustedCa: Buffer;
  readonly workerFingerprint: string;
  readonly timeoutMs?: number;
}

export interface WorkerHttpRequest {
  readonly method: 'GET' | 'POST';
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: Buffer;
}

export interface WorkerHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly body: Buffer;
}

export interface WorkerHttpTransport {
  request(request: WorkerHttpRequest): Promise<WorkerHttpResponse>;
  close?(): void;
}

export interface WorkerCapabilities {
  readonly worker_id: string;
  readonly controller_id: string;
  readonly protocol_version: 1;
  readonly target_lock_sha256: string;
  readonly max_limits: {
    readonly max_duration_s: number;
    readonly max_memory_bytes: number;
    readonly max_disk_bytes: number;
    readonly max_cpu_percent: number;
  };
}

export interface ImportedInputBundle {
  readonly input_bundle_id: string;
  readonly archive_sha256: string;
  readonly file_count: number;
  readonly expanded_bytes: number;
}

export interface WorkerClient {
  capabilities(): Promise<WorkerCapabilities>;
  importInputBundle(archive: Buffer): Promise<ImportedInputBundle>;
  activeRun(): Promise<RunStatus | null>;
  startRun(request: RunRequest): Promise<RunStatus>;
  getRun(runId: string): Promise<RunStatus>;
  stopRun(runId: string): Promise<RunStatus>;
  eventsAfter(runId: string, sequence: bigint): Promise<readonly RunEvent[]>;
  close(): void;
}

export class WorkerClientError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'WorkerClientError';
  }
}

export function validateWorkerUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError('worker URL is invalid');
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.pathname !== '/' ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    throw new TypeError('worker URL must be an HTTPS origin without credentials or path data');
  }
  return url;
}

export function normalizeCertificateFingerprint(value: string): string {
  const normalized = value.replaceAll(':', '').toLowerCase();
  if (!SHA256_FINGERPRINT.test(normalized)) {
    throw new TypeError('worker certificate fingerprint must be a SHA-256 fingerprint');
  }
  return normalized;
}

export function verifyPinnedWorkerCertificate(expected: string, actual: string): void {
  if (normalizeCertificateFingerprint(expected) !== normalizeCertificateFingerprint(actual)) {
    throw new Error('worker certificate identity does not match the paired fingerprint');
  }
}

export function createWorkerIdentityVerifier(
  expectedFingerprint: string,
): (host: string, cert: PeerCertificate) => Error | undefined {
  const expected = normalizeCertificateFingerprint(expectedFingerprint);
  return (host, cert) => {
    const hostnameError = checkServerIdentity(host, cert);
    if (hostnameError) return hostnameError;
    try {
      if (!cert.raw) throw new Error('worker certificate is missing');
      validateEndpointCertificate(cert.raw, 'server');
      verifyPinnedWorkerCertificate(expected, cert.fingerprint256 ?? '');
    } catch {
      return new Error('worker certificate identity does not match the paired fingerprint');
    }
    return undefined;
  };
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return (
    actual.length === keys.length && actual.every((key, index) => key === [...keys].sort()[index])
  );
}

function validateCapabilities(value: unknown): WorkerCapabilities {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('worker capabilities response is invalid');
  }
  const candidate = value as Record<string, unknown>;
  if (
    !exactKeys(candidate, [
      'worker_id',
      'controller_id',
      'protocol_version',
      'target_lock_sha256',
      'max_limits',
    ]) ||
    typeof candidate.worker_id !== 'string' ||
    !isNonNilUuid(candidate.worker_id) ||
    typeof candidate.controller_id !== 'string' ||
    !isNonNilUuid(candidate.controller_id) ||
    candidate.protocol_version !== 1 ||
    typeof candidate.target_lock_sha256 !== 'string' ||
    !/^[0-9a-f]{64}$/i.test(candidate.target_lock_sha256) ||
    typeof candidate.max_limits !== 'object' ||
    candidate.max_limits === null ||
    Array.isArray(candidate.max_limits)
  ) {
    throw new TypeError('worker capabilities response is invalid');
  }
  const limits = candidate.max_limits as Record<string, unknown>;
  const limitKeys = [
    'max_duration_s',
    'max_memory_bytes',
    'max_disk_bytes',
    'max_cpu_percent',
  ] as const;
  if (
    !exactKeys(limits, limitKeys) ||
    !Number.isSafeInteger(limits.max_duration_s) ||
    (limits.max_duration_s as number) < 1 ||
    !Number.isSafeInteger(limits.max_memory_bytes) ||
    (limits.max_memory_bytes as number) < 1 ||
    !Number.isSafeInteger(limits.max_disk_bytes) ||
    (limits.max_disk_bytes as number) < 1 ||
    !Number.isInteger(limits.max_cpu_percent) ||
    (limits.max_cpu_percent as number) < 1 ||
    (limits.max_cpu_percent as number) > 100
  ) {
    throw new TypeError('worker capabilities limits are invalid');
  }
  return {
    worker_id: candidate.worker_id,
    controller_id: candidate.controller_id,
    protocol_version: 1,
    target_lock_sha256: candidate.target_lock_sha256,
    max_limits: {
      max_duration_s: limits.max_duration_s as number,
      max_memory_bytes: limits.max_memory_bytes as number,
      max_disk_bytes: limits.max_disk_bytes as number,
      max_cpu_percent: limits.max_cpu_percent as number,
    },
  };
}

function validateImportedInputBundle(value: unknown): ImportedInputBundle {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('worker input bundle response is invalid');
  }
  const candidate = value as Record<string, unknown>;
  if (
    !exactKeys(candidate, ['input_bundle_id', 'archive_sha256', 'file_count', 'expanded_bytes']) ||
    typeof candidate.input_bundle_id !== 'string' ||
    !isNonNilUuid(candidate.input_bundle_id) ||
    typeof candidate.archive_sha256 !== 'string' ||
    !/^[0-9a-f]{64}$/i.test(candidate.archive_sha256) ||
    !Number.isSafeInteger(candidate.file_count) ||
    (candidate.file_count as number) < 1 ||
    (candidate.file_count as number) > MAX_INPUT_FILES ||
    !Number.isSafeInteger(candidate.expanded_bytes) ||
    (candidate.expanded_bytes as number) < 1 ||
    (candidate.expanded_bytes as number) > MAX_EXPANDED_BYTES
  ) {
    throw new TypeError('worker input bundle response is invalid');
  }
  return {
    input_bundle_id: candidate.input_bundle_id,
    archive_sha256: candidate.archive_sha256,
    file_count: candidate.file_count as number,
    expanded_bytes: candidate.expanded_bytes as number,
  };
}

function parseEvents(value: Buffer, runId: string, after: bigint): readonly RunEvent[] {
  if (value.byteLength > MAX_EVENT_BYTES)
    throw new RangeError('worker response exceeds size limit');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(value);
  const frames = text.split(/\r?\n\r?\n/).filter((frame) => frame.length > 0);
  if (frames.length > MAX_EVENT_COUNT) throw new RangeError('worker returned too many events');
  const events: RunEvent[] = [];
  let previous = after;
  for (const frame of frames) {
    let id: string | undefined;
    let data: string | undefined;
    for (const line of frame.split(/\r?\n/)) {
      if (line.startsWith('id: ')) {
        if (id !== undefined) throw new TypeError('worker event frame has duplicate IDs');
        id = line.slice(4);
      } else if (line.startsWith('data: ')) {
        if (data !== undefined) throw new TypeError('worker event frame has duplicate data');
        data = line.slice(6);
      } else {
        throw new TypeError('worker event frame is malformed');
      }
    }
    if (!id || !data || !/^(0|[1-9][0-9]*)$/.test(id) || id.length > MAX_SEQUENCE.length) {
      throw new TypeError('worker event frame is malformed');
    }
    const sequence = BigInt(id);
    if (sequence > BigInt(MAX_SEQUENCE) || sequence !== previous + 1n) {
      throw new TypeError('worker events are not contiguous and strictly ordered');
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(data) as unknown;
    } catch {
      throw new TypeError('worker event JSON is invalid');
    }
    const event = validateRunEvent(decoded);
    if (event.run_id !== runId || event.seq !== sequence) {
      throw new TypeError('worker event identity or sequence is invalid');
    }
    events.push(event);
    previous = sequence;
  }
  return events;
}

function createHttpsTransport(config: WorkerClientConfig, baseUrl: URL): WorkerHttpTransport {
  if (
    !config.controllerCertificate.length ||
    !config.controllerKey.length ||
    !config.trustedCa.length
  ) {
    throw new TypeError('worker client requires controller and CA certificates');
  }
  const verifyIdentity = createWorkerIdentityVerifier(config.workerFingerprint);
  const timeoutMs = config.timeoutMs ?? 15_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) {
    throw new RangeError('worker request timeout is invalid');
  }
  const agent = new Agent({
    ca: config.trustedCa,
    cert: config.controllerCertificate,
    key: config.controllerKey,
    keepAlive: true,
    maxSockets: 4,
    rejectUnauthorized: true,
    minVersion: TLS_MIN_VERSION,
    checkServerIdentity: verifyIdentity,
  });
  const timeoutMsValue = timeoutMs;
  return {
    request: (input) =>
      new Promise<WorkerHttpResponse>((resolve, reject) => {
        const url = new URL(input.path, baseUrl);
        let settled = false;
        const finishError = (error: Error): void => {
          if (settled) return;
          settled = true;
          clearTimeout(deadline);
          reject(error);
        };
        const request = httpsRequest(
          url,
          {
            method: input.method,
            agent,
            headers: input.headers,
            setHost: true,
          },
          (response) => {
            const chunks: Buffer[] = [];
            let size = 0;
            response.on('data', (chunk: Buffer | string) => {
              const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
              size += bytes.length;
              if (size > MAX_EVENT_BYTES) {
                request.destroy(new RangeError('worker response exceeds size limit'));
                return;
              }
              chunks.push(bytes);
            });
            response.once('error', finishError);
            response.once('end', () => {
              if (settled) return;
              settled = true;
              clearTimeout(deadline);
              resolve({
                status: response.statusCode ?? 0,
                headers: response.headers,
                body: Buffer.concat(chunks, size),
              });
            });
          },
        );
        const deadline = setTimeout(
          () => request.destroy(new Error('worker request timed out')),
          timeoutMsValue,
        );
        deadline.unref();
        request.once('error', finishError);
        if (input.body) request.write(input.body);
        request.end();
      }),
    close: () => agent.destroy(),
  };
}

export function createWorkerClient(
  config: WorkerClientConfig,
  injectedTransport?: WorkerHttpTransport,
): WorkerClient {
  const baseUrl = validateWorkerUrl(config.baseUrl);
  const transport = injectedTransport ?? createHttpsTransport(config, baseUrl);
  let closed = false;
  let capabilitiesPromise: Promise<WorkerCapabilities> | undefined;

  async function request(
    method: 'GET' | 'POST',
    path: string,
    body?: unknown,
  ): Promise<WorkerHttpResponse> {
    if (closed) throw new Error('worker client is closed');
    const headers: Record<string, string> = {
      accept: path.endsWith('/events') ? 'text/event-stream' : 'application/json',
      'x-sf-protocol-version': PROTOCOL_VERSION,
    };
    let encoded: Buffer | undefined;
    if (Buffer.isBuffer(body)) {
      if (body.byteLength < 1) throw new RangeError('worker input archive must not be empty');
      if (body.byteLength > MAX_ARCHIVE_BYTES)
        throw new RangeError('worker input archive exceeds size limit');
      encoded = body;
      headers['content-type'] = 'application/zip';
      headers['content-length'] = String(encoded.byteLength);
    } else if (body !== undefined) {
      encoded = Buffer.from(JSON.stringify(body));
      if (encoded.byteLength > 1024 * 1024)
        throw new RangeError('worker request exceeds size limit');
      headers['content-type'] = 'application/json';
      headers['content-length'] = String(encoded.byteLength);
      if (
        path === '/v1/runs' &&
        typeof body === 'object' &&
        body !== null &&
        'request_id' in body &&
        typeof body.request_id === 'string'
      ) {
        headers['idempotency-key'] = body.request_id;
      }
    }
    const result = await transport.request({
      method,
      path,
      headers,
      ...(encoded === undefined ? {} : { body: encoded }),
    });
    if (result.body.byteLength > MAX_EVENT_BYTES)
      throw new RangeError('worker response exceeds size limit');
    if (result.status < 200 || result.status >= 300) {
      const message =
        result.status === 426
          ? 'worker protocol version is incompatible'
          : result.status === 401 || result.status === 403
            ? 'worker authentication failed'
            : result.status === 409
              ? 'worker rejected the operation because its state conflicts'
              : `worker request failed with status ${result.status}`;
      throw new WorkerClientError(result.status, message);
    }
    return result;
  }

  function parseJsonResponse(result: WorkerHttpResponse): unknown {
    const contentType = Object.entries(result.headers).find(
      ([name]) => name.toLowerCase() === 'content-type',
    )?.[1];
    if (typeof contentType !== 'string' || !/^application\/json(?:\s*;|$)/i.test(contentType)) {
      throw new TypeError('worker response content type is invalid');
    }
    try {
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result.body)) as unknown;
    } catch {
      throw new TypeError('worker JSON response is invalid');
    }
  }

  async function json(method: 'GET' | 'POST', path: string, body?: unknown): Promise<unknown> {
    return parseJsonResponse(await request(method, path, body));
  }

  function getCapabilities(): Promise<WorkerCapabilities> {
    if (!capabilitiesPromise) {
      const pending = json('GET', '/v1/capabilities').then(validateCapabilities);
      const wrapped = pending.catch((error: unknown) => {
        if (capabilitiesPromise === wrapped) capabilitiesPromise = undefined;
        throw error;
      });
      capabilitiesPromise = wrapped;
    }
    return capabilitiesPromise;
  }

  return {
    async capabilities() {
      return getCapabilities();
    },
    async importInputBundle(archive) {
      if (!Buffer.isBuffer(archive)) throw new TypeError('worker input archive must be a Buffer');
      const result = await request('POST', '/v1/input-bundles', archive);
      return validateImportedInputBundle(parseJsonResponse(result));
    },
    async activeRun() {
      const capabilities = await getCapabilities();
      const value = await json('GET', '/v1/runs/active');
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError('worker active run response is invalid');
      }
      const candidate = value as Record<string, unknown>;
      if (!exactKeys(candidate, ['active_run'])) {
        throw new TypeError('worker active run response is invalid');
      }
      if (candidate.active_run === null) return null;
      const run = validateRunStatus(candidate.active_run);
      if (run.worker_id !== capabilities.worker_id) {
        throw new TypeError('active run response identity is invalid');
      }
      return run;
    },
    async startRun(input) {
      const runRequest = validateRunRequest(input);
      const capabilities = await getCapabilities();
      if (
        runRequest.target_lock_sha256.toLowerCase() !==
        capabilities.target_lock_sha256.toLowerCase()
      ) {
        throw new TypeError('run target lock does not match the worker capability');
      }
      const result = validateRunStatus(await json('POST', '/v1/runs', runRequest));
      if (result.worker_id !== capabilities.worker_id) {
        throw new TypeError('run response came from a different worker');
      }
      return result;
    },
    async getRun(runId) {
      if (!isNonNilUuid(runId)) throw new TypeError('run ID must be a non-nil UUID');
      const result = validateRunStatus(await json('GET', `/v1/runs/${runId}`));
      if (result.run_id !== runId || result.worker_id !== (await getCapabilities()).worker_id) {
        throw new TypeError('run response identity is invalid');
      }
      return result;
    },
    async stopRun(runId) {
      if (!isNonNilUuid(runId)) throw new TypeError('run ID must be a non-nil UUID');
      const result = validateRunStatus(await json('POST', `/v1/runs/${runId}/stop`));
      if (result.run_id !== runId || result.worker_id !== (await getCapabilities()).worker_id) {
        throw new TypeError('run response identity is invalid');
      }
      return result;
    },
    async eventsAfter(runId, sequence) {
      if (!isNonNilUuid(runId)) throw new TypeError('run ID must be a non-nil UUID');
      if (sequence < 0n || sequence > BigInt(MAX_SEQUENCE))
        throw new RangeError('invalid event sequence');
      const result = await request(
        'GET',
        `/v1/runs/${runId}/events?after=${sequence.toString()}&limit=${MAX_EVENT_COUNT}`,
      );
      const contentType = Object.entries(result.headers).find(
        ([name]) => name.toLowerCase() === 'content-type',
      )?.[1];
      if (typeof contentType !== 'string' || !/^text\/event-stream(?:\s*;|$)/i.test(contentType)) {
        throw new TypeError('worker event response content type is invalid');
      }
      return parseEvents(result.body, runId, sequence);
    },
    close() {
      if (closed) return;
      closed = true;
      transport.close?.();
    },
  };
}
