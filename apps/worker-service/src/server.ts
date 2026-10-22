import { randomUUID } from 'node:crypto';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import type { PeerCertificate, TLSSocket } from 'node:tls';
import type { SqliteRunStore } from '@sumatrafuzz/run-store';
import {
  asControllerId,
  asRunId,
  isNonNilUuid,
  type RunRequest,
  validateRunRequest,
  validateRunStatus,
} from '@sumatrafuzz/worker-protocol';
import { TLS_MIN_VERSION, validateEndpointCertificate } from '@sumatrafuzz/worker-security';
import { authorizePairedCertificate, type PeerCertificateIdentity } from './auth.js';
import { importInputBundleFrom, MAX_ARCHIVE_BYTES } from './input-bundles.js';
import { type BindMode, validateBindAddress } from './network-policy.js';
import { type AuthenticatedPrincipal, authorizeRoute } from './route-policy.js';

export interface WorkerEventRecord {
  readonly seq: string;
  readonly event: unknown;
}

export interface ArtifactChunk {
  readonly etag: string;
  readonly totalBytes: number;
  readonly start: number;
  readonly end: number;
  readonly bytes: Buffer;
}

export interface WorkerApiHandlers {
  capabilities(controllerId: string): Promise<unknown>;
  activeRun(controllerId: string): Promise<unknown>;
  startRun(controllerId: string, request: RunRequest): Promise<unknown>;
  getRun(controllerId: string, runId: string): Promise<unknown>;
  stopRun(controllerId: string, runId: string): Promise<unknown>;
  eventsAfter(
    controllerId: string,
    runId: string,
    sequence: string,
    limit: number,
  ): Promise<readonly WorkerEventRecord[]>;
  manifest(controllerId: string, runId: string): Promise<unknown>;
  artifactMetadata(
    controllerId: string,
    runId: string,
    artifactId: string,
  ): Promise<{ etag: string; totalBytes: number }>;
  artifact(
    controllerId: string,
    runId: string,
    artifactId: string,
    range: { start: number; end: number },
  ): Promise<ArtifactChunk>;
}

export interface WorkerServerConfig {
  readonly host: string;
  readonly mode: BindMode;
  readonly port: number;
  readonly workerId: string;
  readonly key: Buffer;
  readonly cert: Buffer;
  readonly ca: Buffer;
  readonly pairedControllers: ReadonlyMap<string, string>;
  readonly revokedFingerprints?: ReadonlySet<string>;
  readonly handlers: WorkerApiHandlers;
  readonly store: Pick<SqliteRunStore, 'ownsRun'>;
  readonly inputRoot: string;
  readonly ensureInputCapacity: (bytesToWrite: number) => Promise<void>;
  readonly maxInputBundleBytes: number;
  readonly maxRequestBytes?: number;
}

export interface WorkerServer {
  readonly address: string;
  close(): Promise<void>;
}

const DEFAULT_MAX_REQUEST_BYTES = MAX_ARCHIVE_BYTES;
const MAX_ARTIFACT_CHUNK_BYTES = 16 * 1024 * 1024;
const MAX_EVENT_PAGE_SIZE = 500;
const MAX_JSON_RESPONSE_BYTES = 4 * 1024 * 1024;
const WORKER_PROTOCOL_VERSION = '1';
const FINGERPRINT = /^[0-9a-f]{64}$/i;
const MAX_SQLITE_SEQUENCE = '9223372036854775807';
const MAX_REQUEST_HEADER_FIELDS = 64;

// Transitional operator-supplied pairing records grant this explicit fixed set.
// The persistent trust resolver supplies per-request permissions in the next slice.
const PAIRED_PERMISSIONS: AuthenticatedPrincipal['permissions'] = [
  'capabilities:read',
  'input-bundles:write',
  'runs:start',
  'runs:read',
  'runs:stop',
  'events:read',
  'artifacts:read',
];
const SAFE_ERROR_CODES = new Map([
  [400, 'invalid_request'],
  [401, 'unauthorized'],
  [403, 'forbidden'],
  [404, 'not_found'],
  [408, 'request_timeout'],
  [409, 'conflict'],
  [413, 'payload_too_large'],
  [415, 'unsupported_media_type'],
  [416, 'range_not_satisfiable'],
  [426, 'protocol_version_unsupported'],
  [429, 'too_many_requests'],
  [500, 'internal_error'],
  [503, 'service_unavailable'],
  [507, 'insufficient_storage'],
]);

function safeFailure(error: unknown, requestId: string): { status: number; value: object } {
  const candidate = error && typeof error === 'object' && 'status' in error ? error.status : 500;
  const status = typeof candidate === 'number' && SAFE_ERROR_CODES.has(candidate) ? candidate : 500;
  return { status, value: { error: SAFE_ERROR_CODES.get(status), request_id: requestId } };
}

function rejectRequest(status: number): never {
  throw Object.assign(new Error('worker request rejected'), { status });
}

/** Node rejects CL/TE conflicts and duplicate CL before dispatch; cover the remaining ambiguity. */
function validateRequestFraming(request: import('node:http').IncomingMessage): void {
  // maxHeadersCount truncates request.headers, not the parser's raw framing input.
  if (request.rawHeaders.length > MAX_REQUEST_HEADER_FIELDS * 2) rejectRequest(400);
  const values = (name: string): string[] =>
    request.rawHeaders.filter(
      (_value, index) => index % 2 === 1 && request.rawHeaders[index - 1]?.toLowerCase() === name,
    );
  const lengths = values('content-length');
  const encodings = values('transfer-encoding');
  const length = lengths[0];
  const encoding = encodings[0];
  if (
    lengths.length > 1 ||
    encodings.length > 1 ||
    (length !== undefined && encoding !== undefined) ||
    (length !== undefined &&
      (!/^(0|[1-9][0-9]*)$/.test(length) || !Number.isSafeInteger(Number(length)))) ||
    (encoding !== undefined && encoding.toLowerCase() !== 'chunked')
  )
    rejectRequest(400);
}

function requireContentType(
  request: import('node:http').IncomingMessage,
  expected: 'application/json' | 'application/zip',
): void {
  const values = request.rawHeaders.filter(
    (value, index) => index % 2 === 0 && value.toLowerCase() === 'content-type',
  );
  const type = request.headers['content-type'];
  const supported =
    expected === 'application/json'
      ? /^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*$/i
      : /^application\/zip\s*$/i;
  if (values.length !== 1 || typeof type !== 'string' || !supported.test(type)) rejectRequest(415);
}

function peerIdentity(peer: PeerCertificate, authorized: boolean): PeerCertificateIdentity | null {
  if (!peer.fingerprint256 || !peer.valid_from || !peer.valid_to) return null;
  return {
    fingerprint256: peer.fingerprint256,
    validFrom: peer.valid_from,
    validTo: peer.valid_to,
    authorized,
  };
}

export function serializeBoundedJson(value: unknown): string {
  const serialized = `${JSON.stringify(value, (_key, item: unknown) => (typeof item === 'bigint' ? item.toString() : item))}\n`;
  if (Buffer.byteLength(serialized) > MAX_JSON_RESPONSE_BYTES) {
    throw Object.assign(new Error('JSON response exceeds size limit'), { status: 413 });
  }
  return serialized;
}

function json(response: import('node:http').ServerResponse, status: number, value: unknown): void {
  const serialized = serializeBoundedJson(value);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  response.end(serialized);
}

async function body(request: import('node:http').IncomingMessage, limit: number): Promise<Buffer> {
  const pieces: Buffer[] = [];
  let length = 0;
  for await (const piece of request) {
    const chunk = Buffer.isBuffer(piece) ? piece : Buffer.from(piece);
    length += chunk.length;
    if (length > limit)
      throw Object.assign(new Error('request body exceeds configured limit'), { status: 413 });
    pieces.push(chunk);
  }
  return Buffer.concat(pieces, length);
}

export interface ExclusiveRequestGate {
  tryAcquire(): (() => void) | undefined;
}

/** A small synchronous gate prevents concurrent uploads from retaining multiple archives in RAM. */
export function createExclusiveRequestGate(): ExclusiveRequestGate {
  let acquired = false;
  return {
    tryAcquire() {
      if (acquired) return undefined;
      acquired = true;
      let released = false;
      return () => {
        if (!released) {
          released = true;
          acquired = false;
        }
      };
    },
  };
}

export function parseArtifactRange(
  value: string | undefined,
  size: number,
): { start: number; end: number } | undefined {
  if (!value) return undefined;
  const match = /^bytes=(\d+)-(\d*)$/.exec(value);
  if (!match) throw Object.assign(new Error('unsupported byte range'), { status: 416 });
  const start = Number(match[1]);
  const end = match[2] ? Number(match[2]) : size - 1;
  if (
    !Number.isSafeInteger(start) ||
    !Number.isSafeInteger(end) ||
    start < 0 ||
    end < start ||
    start >= size
  ) {
    throw Object.assign(new Error('unsatisfiable byte range'), { status: 416 });
  }
  return {
    start,
    end: Math.min(end, size - 1, start + MAX_ARTIFACT_CHUNK_BYTES - 1),
  };
}

export function validateStartRequest(
  payload: unknown,
  idempotencyKey: string | string[] | undefined,
  pairedControllerId: string,
): RunRequest {
  if (typeof payload === 'object' && payload !== null) {
    const candidate = payload as { request_id?: unknown; controller_id?: unknown };
    if (
      (typeof candidate.request_id === 'string' && !isNonNilUuid(candidate.request_id)) ||
      (typeof candidate.controller_id === 'string' && !isNonNilUuid(candidate.controller_id))
    ) {
      throw Object.assign(new Error('run request IDs must be non-nil UUIDs'), { status: 400 });
    }
  }
  let request: RunRequest;
  try {
    request = validateRunRequest(payload);
  } catch {
    throw Object.assign(new Error('run request failed protocol validation'), { status: 400 });
  }
  if (idempotencyKey !== request.request_id) {
    throw Object.assign(new Error('Idempotency-Key must match request_id'), { status: 400 });
  }
  if (request.controller_id !== pairedControllerId) {
    throw Object.assign(new Error('request controller does not match paired certificate'), {
      status: 403,
    });
  }
  return request;
}

export function parseEventSequence(value: string): string {
  if (
    !/^(0|[1-9][0-9]*)$/.test(value) ||
    value.length > MAX_SQLITE_SEQUENCE.length ||
    (value.length === MAX_SQLITE_SEQUENCE.length && value > MAX_SQLITE_SEQUENCE)
  ) {
    throw Object.assign(new Error('invalid event replay sequence'), { status: 400 });
  }
  return value;
}

export function parseEventPageLimit(value: string | null): number {
  if (value === null) return 100;
  if (!/^[1-9][0-9]{0,2}$/.test(value)) {
    throw Object.assign(new Error('invalid event page limit'), { status: 400 });
  }
  const limit = Number(value);
  if (limit > MAX_EVENT_PAGE_SIZE) {
    throw Object.assign(new Error('event page limit exceeds maximum'), { status: 400 });
  }
  return limit;
}

export function assertProtocolVersion(value: string | string[] | undefined): void {
  if (value !== WORKER_PROTOCOL_VERSION) {
    throw Object.assign(new Error('unsupported worker protocol version'), { status: 426 });
  }
}

export async function createWorkerServer(config: WorkerServerConfig): Promise<WorkerServer> {
  validateBindAddress(config.host, config.mode);
  if (!Number.isInteger(config.port) || config.port < 0 || config.port > 65535) {
    throw new RangeError('invalid worker service port');
  }
  if (!isNonNilUuid(config.workerId)) throw new TypeError('worker ID must be a non-nil UUID');
  const requestLimit = config.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES;
  if (!Number.isSafeInteger(config.maxInputBundleBytes) || config.maxInputBundleBytes < 1) {
    throw new RangeError('invalid worker input bundle disk limit');
  }
  if (
    !Number.isSafeInteger(requestLimit) ||
    requestLimit < 1024 ||
    requestLimit > MAX_ARCHIVE_BYTES
  )
    throw new RangeError('invalid request size limit');
  const pairedControllers = new Map<string, string>();
  for (const [fingerprint, controllerId] of config.pairedControllers) {
    const normalized = fingerprint.replaceAll(':', '').toLowerCase();
    if (!FINGERPRINT.test(normalized) || !isNonNilUuid(controllerId))
      throw new TypeError('invalid paired controller certificate record');
    if (pairedControllers.has(normalized))
      throw new TypeError('duplicate paired certificate fingerprint');
    pairedControllers.set(normalized, controllerId);
  }
  if (typeof config.ensureInputCapacity !== 'function')
    throw new TypeError('input bundle disk capacity check is required');
  validateEndpointCertificate(config.cert, 'server');
  const inputImportGate = createExclusiveRequestGate();

  const server: HttpsServer = createHttpsServer(
    {
      key: config.key,
      cert: config.cert,
      ca: config.ca,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: TLS_MIN_VERSION,
    },
    (request, response) => {
      const requestId = randomUUID();
      void (async () => {
        const socket = request.socket as TLSSocket;
        const peer = socket.getPeerCertificate(true);
        if (!socket.authorized || !peer.raw) rejectRequest(401);
        let fingerprint: string;
        try {
          validateEndpointCertificate(peer.raw, 'client');
          fingerprint = authorizePairedCertificate(
            peerIdentity(peer, socket.authorized),
            new Set(pairedControllers.keys()),
            config.revokedFingerprints ?? new Set(),
          );
        } catch {
          rejectRequest(401);
        }
        const controllerId = pairedControllers.get(fingerprint);
        if (!controllerId || !isNonNilUuid(controllerId)) rejectRequest(401);
        assertProtocolVersion(request.headers['x-sf-protocol-version']);
        const principal: AuthenticatedPrincipal = {
          controllerId,
          fingerprint,
          permissions: PAIRED_PERMISSIONS,
        };
        const target = request.url ?? '';
        const pathname = target.split('?')[0] ?? '';
        // Authorize the original target first: URL would normalize dot segments and hide aliases.
        const decision = authorizeRoute(principal, request.method ?? '', pathname);
        if (!decision.allowed || target.includes('#')) rejectRequest(404);
        if (
          decision.scope.kind !== 'controller' &&
          !config.store.ownsRun(asControllerId(controllerId), asRunId(decision.scope.runId))
        )
          rejectRequest(404);
        validateRequestFraming(request);
        const url = new URL(target, 'https://worker.invalid');

        if (decision.route === 'capabilities') {
          json(response, 200, await config.handlers.capabilities(controllerId));
          return;
        }
        if (decision.route === 'activeRun') {
          const activeRun = await config.handlers.activeRun(controllerId);
          json(response, 200, {
            active_run: activeRun === null ? null : validateRunStatus(activeRun),
          });
          return;
        }
        if (decision.route === 'importInputBundle') {
          requireContentType(request, 'application/zip');
          const release = inputImportGate.tryAcquire();
          if (!release) {
            request.resume();
            rejectRequest(429);
          }
          try {
            json(
              response,
              201,
              await importInputBundleFrom(
                config.inputRoot,
                controllerId,
                () => body(request, requestLimit),
                config.maxInputBundleBytes,
                { ensureCapacity: config.ensureInputCapacity },
              ),
            );
          } finally {
            release();
          }
          return;
        }
        if (decision.route === 'startRun') {
          requireContentType(request, 'application/json');
          const raw = await body(request, Math.min(requestLimit, 1024 * 1024));
          let payload: unknown;
          try {
            payload = JSON.parse(raw.toString('utf8')) as unknown;
          } catch {
            throw Object.assign(new Error('invalid JSON request body'), { status: 400 });
          }
          const runRequest = validateStartRequest(
            payload,
            request.headers['idempotency-key'],
            controllerId,
          );
          json(response, 202, await config.handlers.startRun(controllerId, runRequest));
          return;
        }
        if (decision.scope.kind !== 'controller') {
          const runId = decision.scope.runId;
          if (decision.route === 'getRun') {
            json(response, 200, await config.handlers.getRun(controllerId, runId));
            return;
          }
          if (decision.route === 'stopRun') {
            json(response, 202, await config.handlers.stopRun(controllerId, runId));
            return;
          }
          if (decision.route === 'eventsAfter') {
            const after = url.searchParams.get('after') ?? request.headers['last-event-id'] ?? '0';
            if (typeof after !== 'string')
              throw Object.assign(new Error('invalid event replay sequence'), { status: 400 });
            parseEventSequence(after);
            const limit = parseEventPageLimit(url.searchParams.get('limit'));
            const events = await config.handlers.eventsAfter(controllerId, runId, after, limit);
            if (events.length > limit)
              throw new Error('event handler exceeded the requested page size');
            const frames: string[] = [];
            let frameBytes = 0;
            for (const record of events) {
              if (!/^(0|[1-9][0-9]*)$/.test(record.seq))
                throw new Error('handler returned invalid event sequence');
              const frame = `id: ${record.seq}\ndata: ${JSON.stringify(record.event, (_key, item: unknown) => (typeof item === 'bigint' ? item.toString() : item))}\n\n`;
              const bytes = Buffer.byteLength(frame);
              if (bytes > 256 * 1024 || frameBytes + bytes > 4 * 1024 * 1024) {
                throw Object.assign(new Error('event replay page exceeds response size limit'), {
                  status: 413,
                });
              }
              frameBytes += bytes;
              frames.push(frame);
            }
            response.writeHead(200, {
              'content-type': 'text/event-stream; charset=utf-8',
              'cache-control': 'no-store',
              connection: 'close',
              'x-accel-buffering': 'no',
            });
            for (const frame of frames) response.write(frame);
            response.end();
            return;
          }
          if (decision.route === 'manifest') {
            json(response, 200, await config.handlers.manifest(controllerId, runId));
            return;
          }
          if (decision.route === 'artifact' && decision.scope.kind === 'artifact') {
            const artifactId = decision.scope.artifactId;
            const metadata = await config.handlers.artifactMetadata(
              controllerId,
              runId,
              artifactId,
            );
            if (
              !Number.isSafeInteger(metadata.totalBytes) ||
              metadata.totalBytes < 1 ||
              !FINGERPRINT.test(metadata.etag.replaceAll('"', ''))
            ) {
              throw new Error('artifact handler returned invalid metadata');
            }
            const ifRange = request.headers['if-range'];
            const rangeHeader =
              ifRange && ifRange !== `"${metadata.etag.replaceAll('"', '')}"`
                ? undefined
                : request.headers.range;
            const range = parseArtifactRange(
              typeof rangeHeader === 'string' ? rangeHeader : undefined,
              metadata.totalBytes,
            ) ?? {
              start: 0,
              end: Math.min(metadata.totalBytes - 1, MAX_ARTIFACT_CHUNK_BYTES - 1),
            };
            const chunk = await config.handlers.artifact(controllerId, runId, artifactId, range);
            if (
              chunk.bytes.length !== chunk.end - chunk.start + 1 ||
              chunk.totalBytes !== metadata.totalBytes ||
              chunk.etag.replaceAll('"', '') !== metadata.etag.replaceAll('"', '') ||
              chunk.start !== range.start ||
              chunk.end !== range.end
            ) {
              throw new Error('artifact handler returned inconsistent range data');
            }
            const partial = range.start !== 0 || range.end !== metadata.totalBytes - 1;
            response.writeHead(partial ? 206 : 200, {
              'content-type': 'application/octet-stream',
              'content-length': chunk.bytes.length,
              etag: `"${chunk.etag.replaceAll('"', '')}"`,
              'accept-ranges': 'bytes',
              'cache-control': 'no-store',
              ...(partial
                ? { 'content-range': `bytes ${chunk.start}-${chunk.end}/${chunk.totalBytes}` }
                : {}),
            });
            response.end(chunk.bytes);
            return;
          }
        }
        rejectRequest(404);
      })().catch((error: unknown) => {
        if (response.headersSent) {
          response.destroy(error instanceof Error ? error : new Error('worker request failed'));
          return;
        }
        request.resume();
        const failure = safeFailure(error, requestId);
        if (failure.status === 429 || failure.status === 503)
          response.setHeader('retry-after', '1');
        json(response, failure.status, failure.value);
      });
    },
  );
  server.on('clientError', (_error, socket) => {
    if (!socket.writable || socket.writableEnded) return;
    const failure = safeFailure({ status: 400 }, randomUUID());
    const serialized = serializeBoundedJson(failure.value);
    socket.end(
      `HTTP/1.1 400 Bad Request\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(serialized)}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n${serialized}`,
    );
  });
  server.headersTimeout = 15_000;
  server.requestTimeout = 10 * 60_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = MAX_REQUEST_HEADER_FIELDS;

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.port, config.host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error('worker server did not bind a TCP address');
  }
  return {
    address: `https://${config.host.includes(':') ? `[${config.host}]` : config.host}:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}
