import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { lstat, mkdir, open, readdir, readFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { isNonNilUuid } from '@sumatrafuzz/worker-protocol';
import type { CredentialProtector } from './pairing-provision.js';

export type AuditAction =
  | 'authorize'
  | 'tls_rejected'
  | 'input_bundle_import'
  | 'run_start'
  | 'run_stop'
  | 'trust_provision'
  | 'trust_rotate'
  | 'trust_revoke'
  | 'trust_unpair';
export type AuditDecision = 'allow' | 'deny' | 'intent' | 'success' | 'failure';
export type AuditResource =
  | 'capabilities'
  | 'activeRun'
  | 'importInputBundle'
  | 'startRun'
  | 'getRun'
  | 'stopRun'
  | 'eventsAfter'
  | 'manifest'
  | 'artifact'
  | 'unknown'
  | 'trust';
export type AuditErrorCode =
  | 'invalid_request'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'resource_limit'
  | 'operation_failed'
  | 'audit_degraded'
  | 'request_timeout'
  | 'service_unavailable';
export interface AuditRecord {
  readonly timestamp: string;
  readonly requestId: string;
  readonly action: AuditAction;
  readonly resource?: AuditResource;
  readonly decision: AuditDecision;
  readonly trustRevision: number;
  readonly fingerprint?: string;
  readonly controllerId?: string;
  readonly runId?: string;
  readonly artifactId?: string;
  readonly errorCode?: AuditErrorCode;
  readonly payloadDigest?: string;
}
export interface AuditHealth {
  readonly state: 'healthy' | 'degraded' | 'closed';
  readonly reason: 'none' | 'integrity' | 'quota' | 'storage';
  readonly sequence: number;
}
export interface SecurityAudit {
  readonly health: AuditHealth;
  append(record: AuditRecord): Promise<number>;
  verifyAndRecover(): Promise<AuditHealth>;
  close(): Promise<void>;
}
export interface SecurityAuditOptions {
  readonly directory: string;
  readonly protector: CredentialProtector;
  readonly maxBytes: number;
  readonly maxSegmentBytes: number;
  readonly maxSegments: number;
}
export class AuditError extends Error {
  constructor(
    readonly code:
      | 'invalid_record'
      | 'integrity'
      | 'quota'
      | 'storage'
      | 'degraded'
      | 'closed'
      | 'busy',
  ) {
    super(`Worker security audit: ${code}`);
    this.name = 'AuditError';
  }
}
const ZERO = '0'.repeat(64);
const HEX = /^[0-9a-f]{64}$/;
const SEGMENT = /^([0-9]{10})\.audit$/;
const KEYS = [
  'timestamp',
  'requestId',
  'action',
  'resource',
  'decision',
  'trustRevision',
  'fingerprint',
  'controllerId',
  'runId',
  'artifactId',
  'errorCode',
  'payloadDigest',
] as const;
const ACTIONS: ReadonlySet<string> = new Set<AuditAction>([
  'authorize',
  'tls_rejected',
  'input_bundle_import',
  'run_start',
  'run_stop',
  'trust_provision',
  'trust_rotate',
  'trust_revoke',
  'trust_unpair',
]);
const DECISIONS = new Set(['allow', 'deny', 'intent', 'success', 'failure']);
const RESOURCES = new Set([
  'capabilities',
  'activeRun',
  'importInputBundle',
  'startRun',
  'getRun',
  'stopRun',
  'eventsAfter',
  'manifest',
  'artifact',
  'unknown',
  'trust',
]);
const ERRORS = new Set([
  'invalid_request',
  'unauthorized',
  'forbidden',
  'not_found',
  'conflict',
  'resource_limit',
  'operation_failed',
  'audit_degraded',
  'request_timeout',
  'service_unavailable',
]);
function requireAudit(
  condition: unknown,
  code: 'invalid_record' | 'integrity' | 'quota' | 'storage' = 'integrity',
): asserts condition {
  if (!condition) throw new AuditError(code);
}
function integer(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}
function uuid(value: unknown): value is string {
  return typeof value === 'string' && isNonNilUuid(value) && value === value.toLowerCase();
}
function exact(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  requireAudit(value && typeof value === 'object' && !Array.isArray(value));
  const actual = Object.keys(value);
  requireAudit(actual.length === keys.length && actual.every((key) => keys.includes(key)));
}
function parse(bytes: Buffer | string): unknown {
  return JSON.parse(
    typeof bytes === 'string' ? bytes : new TextDecoder('utf-8', { fatal: true }).decode(bytes),
  ) as unknown;
}
function safeRecord(value: AuditRecord): AuditRecord {
  try {
    requireAudit(value && typeof value === 'object' && !Array.isArray(value));
    requireAudit(Object.keys(value).every((key) => (KEYS as readonly string[]).includes(key)));
    const time = typeof value.timestamp === 'string' ? Date.parse(value.timestamp) : Number.NaN;
    requireAudit(
      Number.isFinite(time) &&
        new Date(time).toISOString() === value.timestamp &&
        value.timestamp.length === 24,
    );
    requireAudit(
      uuid(value.requestId) &&
        ACTIONS.has(value.action) &&
        DECISIONS.has(value.decision) &&
        integer(value.trustRevision),
    );
    requireAudit(value.resource === undefined || RESOURCES.has(value.resource));
    requireAudit(value.errorCode === undefined || ERRORS.has(value.errorCode));
    requireAudit(
      value.fingerprint === undefined ||
        (typeof value.fingerprint === 'string' && HEX.test(value.fingerprint)),
    );
    requireAudit(value.controllerId === undefined || uuid(value.controllerId));
    requireAudit(value.runId === undefined || uuid(value.runId));
    requireAudit(
      value.artifactId === undefined ||
        (typeof value.artifactId === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value.artifactId)),
    );
    requireAudit(
      value.payloadDigest === undefined ||
        (typeof value.payloadDigest === 'string' && HEX.test(value.payloadDigest)),
    );
    const output = Object.fromEntries(
      KEYS.filter((key) => value[key] !== undefined).map((key) => [key, value[key]]),
    ) as unknown as AuditRecord;
    requireAudit(Buffer.byteLength(JSON.stringify(output)) <= 2048);
    return Object.freeze(output);
  } catch {
    throw new AuditError('invalid_record');
  }
}
type Checkpoint = {
  format: 'audit-checkpoint-v1';
  logId: string;
  sequence: number;
  hash: string;
  segment: number;
};
type Header = {
  type: 'header';
  format: 'audit-segment-v1';
  logId: string;
  segment: number;
  sequence: number;
  hash: string;
  mac: string;
};
type Seal = { type: 'seal'; segment: number; sequence: number; hash: string; mac: string };
export class FileSecurityAudit implements SecurityAudit {
  #key: Buffer;
  private status: AuditHealth = Object.freeze({
    state: 'degraded',
    reason: 'integrity',
    sequence: 0,
  });
  private tail: Promise<unknown> = Promise.resolve();
  private queued = 0;
  private closed = false;
  private closing = false;
  private logId = '';
  private sequence = 0;
  private hash = ZERO;
  private segment = 1;
  private segmentBytes = 0;
  private sealed = false;
  private constructor(
    private readonly options: SecurityAuditOptions,
    key: Buffer,
  ) {
    this.#key = key;
  }
  get health(): AuditHealth {
    return this.status;
  }
  static async open(options: SecurityAuditOptions): Promise<FileSecurityAudit> {
    requireAudit(
      options &&
        typeof options.directory === 'string' &&
        path.isAbsolute(options.directory) &&
        options.directory.length <= 4096,
      'storage',
    );
    requireAudit(
      integer(options.maxBytes) &&
        options.maxBytes >= 4096 &&
        options.maxBytes <= 1024 * 1024 * 1024 &&
        integer(options.maxSegmentBytes) &&
        options.maxSegmentBytes >= 1024 &&
        options.maxSegmentBytes <= options.maxBytes &&
        integer(options.maxSegments) &&
        options.maxSegments >= 1 &&
        options.maxSegments <= 4096,
      'quota',
    );
    await mkdir(options.directory, { recursive: true, mode: 0o700 });
    const metadata = await lstat(options.directory);
    requireAudit(metadata.isDirectory() && !metadata.isSymbolicLink(), 'storage');
    const entries = await readdir(options.directory);
    let key: Buffer | undefined;
    try {
      if (entries.length === 0) {
        key = randomBytes(32);
        const protectedKey = await options.protector.protect(key);
        requireAudit(
          Buffer.isBuffer(protectedKey) &&
            protectedKey.length > 0 &&
            protectedKey.length <= 4096 &&
            !protectedKey.equals(key),
          'storage',
        );
        const store = new FileSecurityAudit(options, key);
        store.logId = randomUUID();
        const header = store.header(1, 0, ZERO);
        const checkpoint = await store.protectedCheckpoint({
          format: 'audit-checkpoint-v1',
          logId: store.logId,
          sequence: 0,
          hash: ZERO,
          segment: 1,
        });
        requireAudit(
          protectedKey.length + Buffer.byteLength(header) + checkpoint.length * 2 <=
            options.maxBytes,
          'quota',
        );
        await store.writeExclusive('key.dpapi', protectedKey);
        await store.writeExclusive(store.segmentName(1), Buffer.from(header));
        await store.replaceCheckpoint(checkpoint);
        store.segmentBytes = Buffer.byteLength(header);
        store.setHealth('healthy', 'none');
        return store;
      }
      const raw = await FileSecurityAudit.readBounded(options.directory, 'key.dpapi', 4096);
      key = await options.protector.unprotect(raw);
      requireAudit(Buffer.isBuffer(key) && key.length === 32, 'integrity');
      const store = new FileSecurityAudit(options, key);
      await store.verifyAndRecover();
      return store;
    } catch (error) {
      key?.fill(0);
      throw error instanceof AuditError ? error : new AuditError('storage');
    }
  }
  append(record: AuditRecord): Promise<number> {
    let safe: AuditRecord;
    try {
      safe = safeRecord(record);
    } catch (error) {
      return Promise.reject(error);
    }
    return this.enqueue(async () => {
      if (this.health.state !== 'healthy') throw new AuditError('degraded');
      try {
        const sequence = this.sequence + 1;
        requireAudit(Number.isSafeInteger(sequence), 'quota');
        let segment = this.segment;
        let header = '';
        let seal = '';
        let line = this.recordLine(safe, sequence, segment);
        const reservedSeal = Buffer.byteLength(
          this.seal(segment, sequence, parse(line) as Record<string, unknown>),
        );
        if (
          this.sealed ||
          this.segmentBytes + Buffer.byteLength(line) + reservedSeal > this.options.maxSegmentBytes
        ) {
          requireAudit(segment < this.options.maxSegments, 'quota');
          seal = this.sealed ? '' : this.seal(segment, this.sequence, { hash: this.hash });
          segment++;
          header = this.header(segment, this.sequence, this.hash);
          line = this.recordLine(safe, sequence, segment);
        }
        const parsed = parse(line) as { hash: string };
        const nextSize =
          (header ? Buffer.byteLength(header) : this.segmentBytes) + Buffer.byteLength(line);
        requireAudit(
          nextSize + Buffer.byteLength(this.seal(segment, sequence, parsed)) <=
            this.options.maxSegmentBytes,
          'quota',
        );
        const checkpoint = await this.protectedCheckpoint({
          format: 'audit-checkpoint-v1',
          logId: this.logId,
          sequence,
          hash: parsed.hash,
          segment,
        });
        requireAudit(
          (await this.diskBytes()) + Buffer.byteLength(seal + header + line) + checkpoint.length <=
            this.options.maxBytes,
          'quota',
        );
        if (seal) await this.appendDurable(this.segmentName(this.segment), seal);
        if (header) await this.writeExclusive(this.segmentName(segment), Buffer.from(header));
        await this.appendDurable(this.segmentName(segment), line);
        await this.replaceCheckpoint(checkpoint);
        this.sequence = sequence;
        this.hash = parsed.hash;
        this.segment = segment;
        this.segmentBytes = nextSize;
        this.sealed = false;
        this.setHealth('healthy', 'none');
        return sequence;
      } catch (error) {
        this.setHealth(
          'degraded',
          error instanceof AuditError && error.code === 'quota' ? 'quota' : 'storage',
        );
        throw error instanceof AuditError ? error : new AuditError('storage');
      }
    });
  }
  verifyAndRecover(): Promise<AuditHealth> {
    return this.enqueue(async () => {
      try {
        requireAudit((await this.diskBytes()) <= this.options.maxBytes, 'quota');
        const protectedBytes = await FileSecurityAudit.readBounded(
          this.options.directory,
          'checkpoint.dpapi',
          4096,
        );
        let plaintext: Buffer | undefined;
        let checkpoint: Checkpoint;
        try {
          plaintext = await this.options.protector.unprotect(protectedBytes);
          const value = parse(plaintext);
          exact(value, ['format', 'logId', 'sequence', 'hash', 'segment']);
          requireAudit(
            value.format === 'audit-checkpoint-v1' &&
              uuid(value.logId) &&
              integer(value.sequence) &&
              typeof value.hash === 'string' &&
              HEX.test(value.hash) &&
              integer(value.segment) &&
              value.segment >= 1 &&
              value.segment <= this.options.maxSegments,
          );
          checkpoint = value as unknown as Checkpoint;
        } finally {
          plaintext?.fill(0);
        }
        this.logId = checkpoint.logId;
        const entries = await readdir(this.options.directory);
        const files = entries.filter((name) => SEGMENT.test(name)).sort();
        const allowedEntries = new Set(['key.dpapi', 'checkpoint.dpapi', ...files]);
        requireAudit(
          entries.length === allowedEntries.size &&
            entries.every((name) => allowedEntries.has(name)),
        );
        requireAudit(files.length >= 1 && files.length <= this.options.maxSegments);
        let sequence = 0;
        let hash = ZERO;
        let checkpointSeen = checkpoint.sequence === 0 && checkpoint.hash === ZERO;
        let lastSize = 0;
        let sealed = false;
        for (const [index, name] of files.entries()) {
          const segment = index + 1;
          requireAudit(name === this.segmentName(segment));
          const bytes = await FileSecurityAudit.readBounded(
            this.options.directory,
            name,
            this.options.maxSegmentBytes,
          );
          requireAudit(bytes.at(-1) === 10);
          const lines = new TextDecoder('utf-8', { fatal: true })
            .decode(bytes)
            .slice(0, -1)
            .split('\n');
          requireAudit(lines.length >= 1 && lines.every((line) => line.length > 0));
          const header = parse(lines[0] as string);
          exact(header, ['type', 'format', 'logId', 'segment', 'sequence', 'hash', 'mac']);
          requireAudit(
            header.type === 'header' &&
              header.format === 'audit-segment-v1' &&
              header.logId === this.logId &&
              header.segment === segment &&
              header.sequence === sequence &&
              header.hash === hash &&
              this.validMac(header.mac, ['header', this.logId, segment, sequence, hash]),
          );
          sealed = false;
          for (const line of lines.slice(1)) {
            const value = parse(line);
            requireAudit(value && typeof value === 'object' && !Array.isArray(value));
            if ((value as { type?: unknown }).type === 'seal') {
              exact(value, ['type', 'segment', 'sequence', 'hash', 'mac']);
              requireAudit(
                !sealed &&
                  value.segment === segment &&
                  value.sequence === sequence &&
                  value.hash === hash &&
                  this.validMac(value.mac, ['seal', this.logId, segment, sequence, hash]),
              );
              sealed = true;
              continue;
            }
            requireAudit(!sealed);
            exact(value, ['sequence', 'previousHash', 'record', 'hash']);
            requireAudit(value.sequence === sequence + 1 && value.previousHash === hash);
            const record = safeRecord(value.record as AuditRecord);
            requireAudit(
              this.validMac(value.hash, [
                'record',
                this.logId,
                segment,
                value.sequence,
                hash,
                record,
              ]),
            );
            sequence++;
            hash = value.hash as string;
            if (sequence === checkpoint.sequence) {
              requireAudit(hash === checkpoint.hash);
              checkpointSeen = true;
            }
          }
          requireAudit(index === files.length - 1 || sealed);
          lastSize = bytes.length;
        }
        requireAudit(
          checkpointSeen && sequence >= checkpoint.sequence && checkpoint.segment <= files.length,
        );
        this.sequence = sequence;
        this.hash = hash;
        this.segment = files.length;
        this.segmentBytes = lastSize;
        this.sealed = sealed;
        if (sequence > checkpoint.sequence || files.length > checkpoint.segment) {
          const next = await this.protectedCheckpoint({
            format: 'audit-checkpoint-v1',
            logId: this.logId,
            sequence,
            hash,
            segment: files.length,
          });
          requireAudit((await this.diskBytes()) + next.length <= this.options.maxBytes, 'quota');
          await this.replaceCheckpoint(next);
        }
        this.setHealth('healthy', 'none');
      } catch (error) {
        this.setHealth(
          'degraded',
          error instanceof AuditError && error.code === 'quota'
            ? 'quota'
            : error instanceof AuditError && error.code === 'storage'
              ? 'storage'
              : 'integrity',
        );
      }
      return this.health;
    });
  }
  async close(): Promise<void> {
    if (this.closed) return;
    this.closing = true;
    await this.tail;
    this.closed = true;
    this.#key.fill(0);
    this.setHealth('closed', 'none');
  }
  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    if (this.closed || this.closing) return Promise.reject(new AuditError('closed'));
    if (this.queued >= 64) return Promise.reject(new AuditError('busy'));
    this.queued++;
    const result = this.tail.then(operation);
    this.tail = result
      .catch(() => {})
      .finally(() => {
        this.queued--;
      });
    return result;
  }
  private setHealth(state: AuditHealth['state'], reason: AuditHealth['reason']): void {
    this.status = Object.freeze({ state, reason, sequence: this.sequence });
  }
  private mac(value: readonly unknown[]): string {
    return createHmac('sha256', this.#key).update(JSON.stringify(value)).digest('hex');
  }
  private validMac(value: unknown, expected: readonly unknown[]): boolean {
    return (
      typeof value === 'string' &&
      HEX.test(value) &&
      timingSafeEqual(Buffer.from(value, 'hex'), Buffer.from(this.mac(expected), 'hex'))
    );
  }
  private segmentName(segment: number): string {
    return `${String(segment).padStart(10, '0')}.audit`;
  }
  private header(segment: number, sequence: number, hash: string): string {
    const value: Header = {
      type: 'header',
      format: 'audit-segment-v1',
      logId: this.logId,
      segment,
      sequence,
      hash,
      mac: this.mac(['header', this.logId, segment, sequence, hash]),
    };
    return `${JSON.stringify(value)}\n`;
  }
  private seal(segment: number, sequence: number, value: { hash?: unknown }): string {
    const hash = value.hash as string;
    const seal: Seal = {
      type: 'seal',
      segment,
      sequence,
      hash,
      mac: this.mac(['seal', this.logId, segment, sequence, hash]),
    };
    return `${JSON.stringify(seal)}\n`;
  }
  private recordLine(record: AuditRecord, sequence: number, segment: number): string {
    return `${JSON.stringify({ sequence, previousHash: this.hash, record, hash: this.mac(['record', this.logId, segment, sequence, this.hash, record]) })}\n`;
  }
  private async protectedCheckpoint(checkpoint: Checkpoint): Promise<Buffer> {
    const plaintext = Buffer.from(JSON.stringify(checkpoint));
    try {
      const result = await this.options.protector.protect(plaintext);
      requireAudit(
        Buffer.isBuffer(result) &&
          result.length > 0 &&
          result.length <= 4096 &&
          !result.equals(plaintext),
        'storage',
      );
      return result;
    } finally {
      plaintext.fill(0);
    }
  }
  private async writeExclusive(name: string, bytes: Buffer): Promise<void> {
    const handle = await open(path.join(this.options.directory, name), 'wx', 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await this.syncDirectory();
  }
  private async appendDurable(name: string, line: string): Promise<void> {
    const handle = await open(path.join(this.options.directory, name), 'a');
    try {
      await handle.writeFile(line);
      await handle.sync();
    } finally {
      await handle.close();
    }
  }
  private async replaceCheckpoint(bytes: Buffer): Promise<void> {
    const temporary = `checkpoint.${randomUUID()}.tmp`;
    try {
      await this.writeExclusive(temporary, bytes);
      await rename(
        path.join(this.options.directory, temporary),
        path.join(this.options.directory, 'checkpoint.dpapi'),
      );
      await this.syncDirectory();
    } finally {
      await rm(path.join(this.options.directory, temporary), { force: true });
    }
  }
  private async syncDirectory(): Promise<void> {
    // Windows FlushFileBuffers on regular files is required above; directory fsync is Unix-only.
    if (process.platform === 'win32') return;
    const handle = await open(this.options.directory, 'r');
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  }
  private async diskBytes(): Promise<number> {
    let total = 0;
    for (const name of await readdir(this.options.directory)) {
      const stat = await lstat(path.join(this.options.directory, name));
      requireAudit(stat.isFile() && !stat.isSymbolicLink(), 'storage');
      total += stat.size;
      requireAudit(Number.isSafeInteger(total), 'quota');
    }
    return total;
  }
  private static async readBounded(directory: string, name: string, max: number): Promise<Buffer> {
    const filename = path.join(directory, name);
    const stat = await lstat(filename);
    requireAudit(stat.isFile() && !stat.isSymbolicLink() && stat.size > 0 && stat.size <= max);
    const bytes = await readFile(filename);
    requireAudit(bytes.length === stat.size && bytes.length <= max);
    return bytes;
  }
}
