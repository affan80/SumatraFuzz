import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import type { PeerCertificate, TLSSocket } from 'node:tls';
import type { SqliteRunStore } from '@sumatrafuzz/run-store';
import {
  asControllerId,
  asRunId,
  type RunRequest,
  validateRunRequest,
} from '@sumatrafuzz/worker-protocol';
import { authorizePairedCertificate, type PeerCertificateIdentity } from './auth.js';
import { type BindMode, validateBindAddress } from './network-policy.js';

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
  importInputBundle(controllerId: string, archive: Buffer): Promise<unknown>;
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
  readonly maxRequestBytes?: number;
}

export interface WorkerServer {
  readonly address: string;
  close(): Promise<void>;
}

const DEFAULT_MAX_REQUEST_BYTES = 512 * 1024 * 1024;
const MAX_ARTIFACT_CHUNK_BYTES = 16 * 1024 * 1024;
const MAX_EVENT_PAGE_SIZE = 500;
const MAX_JSON_RESPONSE_BYTES = 4 * 1024 * 1024;
const WORKER_PROTOCOL_VERSION = '1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FINGERPRINT = /^[0-9a-f]{64}$/i;

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
  if (!UUID.test(config.workerId)) throw new TypeError('worker ID must be a UUID');
  const requestLimit = config.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES;
  if (!Number.isSafeInteger(requestLimit) || requestLimit < 1024)
    throw new RangeError('invalid request size limit');
  const pairedControllers = new Map<string, string>();
  for (const [fingerprint, controllerId] of config.pairedControllers) {
    const normalized = fingerprint.replaceAll(':', '').toLowerCase();
    if (!FINGERPRINT.test(normalized) || !UUID.test(controllerId))
      throw new TypeError('invalid paired controller certificate record');
    if (pairedControllers.has(normalized))
      throw new TypeError('duplicate paired certificate fingerprint');
    pairedControllers.set(normalized, controllerId);
  }

  const server: HttpsServer = createHttpsServer(
    {
      key: config.key,
      cert: config.cert,
      ca: config.ca,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
    },
    (request, response) => {
      void (async () => {
        const socket = request.socket as TLSSocket;
        const peer = socket.getPeerCertificate(true);
        const fingerprint = authorizePairedCertificate(
          peerIdentity(peer, socket.authorized),
          new Set(pairedControllers.keys()),
          config.revokedFingerprints ?? new Set(),
        );
        const controllerId = pairedControllers.get(fingerprint);
        if (!controllerId || !UUID.test(controllerId))
          throw new Error('paired controller identity is invalid');
        assertProtocolVersion(request.headers['x-sf-protocol-version']);
        if (
          !request.url?.startsWith('/') ||
          request.url.startsWith('//') ||
          request.url.includes('\\')
        ) {
          throw Object.assign(new Error('origin-form request path required'), { status: 400 });
        }
        const url = new URL(request.url, 'https://worker.invalid');
        const segments = url.pathname.split('/').filter(Boolean);

        if (request.method === 'GET' && url.pathname === '/v1/capabilities') {
          json(response, 200, await config.handlers.capabilities(controllerId));
          return;
        }
        if (request.method === 'POST' && url.pathname === '/v1/input-bundles') {
          json(
            response,
            201,
            await config.handlers.importInputBundle(
              controllerId,
              await body(request, requestLimit),
            ),
          );
          return;
        }
        if (request.method === 'POST' && url.pathname === '/v1/runs') {
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
        if (segments[0] === 'v1' && segments[1] === 'runs' && UUID.test(segments[2] ?? '')) {
          const runId = segments[2] as string;
          if (!config.store.ownsRun(asControllerId(controllerId), asRunId(runId))) {
            throw Object.assign(new Error('run not found'), { status: 404 });
          }
          if (request.method === 'GET' && segments.length === 3) {
            json(response, 200, await config.handlers.getRun(controllerId, runId));
            return;
          }
          if (request.method === 'POST' && segments.length === 4 && segments[3] === 'stop') {
            json(response, 202, await config.handlers.stopRun(controllerId, runId));
            return;
          }
          if (request.method === 'GET' && segments.length === 4 && segments[3] === 'events') {
            const after = url.searchParams.get('after') ?? request.headers['last-event-id'] ?? '0';
            if (typeof after !== 'string' || !/^(0|[1-9][0-9]*)$/.test(after)) {
              throw Object.assign(new Error('invalid event replay sequence'), { status: 400 });
            }
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
          if (request.method === 'GET' && segments.length === 4 && segments[3] === 'manifest') {
            json(response, 200, await config.handlers.manifest(controllerId, runId));
            return;
          }
          if (
            request.method === 'GET' &&
            segments.length === 5 &&
            segments[3] === 'artifacts' &&
            /^[A-Za-z0-9_-]{1,128}$/.test(segments[4] ?? '')
          ) {
            const artifactId = segments[4] as string;
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
        json(response, 404, { error: 'not_found' });
      })().catch((error: unknown) => {
        if (response.headersSent) {
          response.destroy(error instanceof Error ? error : new Error('worker request failed'));
          return;
        }
        const status =
          error && typeof error === 'object' && 'status' in error ? Number(error.status) : 500;
        json(response, Number.isInteger(status) && status >= 400 && status <= 599 ? status : 500, {
          error: status === 500 ? 'internal_error' : 'invalid_request',
          message: status === 500 ? 'worker request failed' : 'request rejected',
        });
      });
    },
  );
  server.headersTimeout = 15_000;
  server.requestTimeout = 10 * 60_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 64;

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
