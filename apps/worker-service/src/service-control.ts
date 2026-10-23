import { once } from 'node:events';
import type { Readable, Writable } from 'node:stream';

export const SERVICE_CONTROL_MAX_FRAME_BYTES = 1024 * 1024 + 1;
const READY = Buffer.from('READY', 'ascii');
const STOP = Buffer.from('STOP', 'ascii');
const STOPPED = Buffer.from('STOPPED', 'ascii');
const APPLY_SIGNED_TRUST_OPERATION = 0x10;
const APPLY_SIGNED_PAIRING_BUNDLE = 0x12;
const TRUST_OPERATION_RESULT = 0x11;
const MIN_TRUST_OPERATION_BYTES = 2;

export interface ServiceControlChannel {
  readonly input: Readable;
  readonly output: Writable;
}

export interface ClosableWorkerService {
  close(): Promise<void>;
  applyTrustOperation?(bundle: Buffer): Promise<void>;
  applyPairingBundle?(bundle: Buffer): Promise<void>;
}

function encodeFrame(payload: Buffer): Buffer {
  if (payload.length < 1 || payload.length > SERVICE_CONTROL_MAX_FRAME_BYTES) {
    throw new TypeError('invalid service control frame');
  }
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32LE(payload.length);
  return Buffer.concat([header, payload]);
}

async function writeFrame(output: Writable, payload: Buffer): Promise<void> {
  if (output.destroyed || output.writableEnded) throw new Error('service control output is closed');
  if (!output.write(encodeFrame(payload))) await once(output, 'drain');
}

async function readFrame(
  iterator: AsyncIterator<Buffer | string>,
  pending: Buffer,
): Promise<{ frame: Buffer; rest: Buffer }> {
  let bytes = pending;
  const fill = async (minimum: number): Promise<void> => {
    while (bytes.length < minimum) {
      const next = await iterator.next();
      if (next.done) throw new Error('service control input closed before STOP');
      const chunk = Buffer.isBuffer(next.value) ? next.value : Buffer.from(next.value);
      if (bytes.length + chunk.length > 4 + SERVICE_CONTROL_MAX_FRAME_BYTES) {
        chunk.fill(0);
        bytes.fill(0);
        throw new Error('service control frame exceeds its bound');
      }
      const combined = bytes.length === 0 ? chunk : Buffer.concat([bytes, chunk]);
      if (combined !== bytes) bytes.fill(0);
      if (combined !== chunk) chunk.fill(0);
      bytes = combined;
    }
  };

  try {
    await fill(4);
    const length = bytes.readUInt32LE(0);
    if (length < 1 || length > SERVICE_CONTROL_MAX_FRAME_BYTES) {
      throw new Error('service control frame length is invalid');
    }
    const frameBytes = length + 4;
    await fill(frameBytes);
    const frame = Buffer.from(bytes.subarray(4, frameBytes));
    const rest = Buffer.from(bytes.subarray(frameBytes));
    bytes.fill(0);
    return { frame, rest };
  } catch (error) {
    bytes.fill(0);
    throw error;
  }
}

/**
 * Owns the SCM stdio protocol. stdout is reserved for these bounded frames;
 * diagnostics belong on stderr, which the native host redirects to NUL.
 */
export async function runWorkerServiceControl(
  channel: ServiceControlChannel,
  start: () => Promise<ClosableWorkerService>,
): Promise<void> {
  const service = await start();
  let stopped = false;
  let closeAttempted = false;
  let pending: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  const inputIterator = channel.input[Symbol.asyncIterator]();
  try {
    await writeFrame(channel.output, READY);
    for (;;) {
      const { frame, rest } = await readFrame(inputIterator, pending);
      pending = rest;
      try {
        if (frame.equals(STOP)) {
          closeAttempted = true;
          await service.close();
          stopped = true;
          await writeFrame(channel.output, STOPPED);
          return;
        }
        if (
          (frame[0] !== APPLY_SIGNED_TRUST_OPERATION && frame[0] !== APPLY_SIGNED_PAIRING_BUNDLE) ||
          frame.length < MIN_TRUST_OPERATION_BYTES
        ) {
          throw new Error('service control command is invalid');
        }
        const bundle = Buffer.from(frame.subarray(1));
        let succeeded = false;
        try {
          const apply =
            frame[0] === APPLY_SIGNED_TRUST_OPERATION
              ? service.applyTrustOperation
              : service.applyPairingBundle;
          if (apply) await apply.call(service, bundle);
          succeeded = Boolean(apply);
        } catch {
          // The host receives only a stable status byte; exception text and bundle data stay local.
        } finally {
          bundle.fill(0);
        }
        await writeFrame(channel.output, Buffer.from([TRUST_OPERATION_RESULT, succeeded ? 0 : 1]));
      } finally {
        frame.fill(0);
      }
    }
  } finally {
    pending.fill(0);
    await inputIterator.return?.();
    if (!stopped && !closeAttempted) {
      // Best-effort cleanup never emits STOPPED, so the host cannot mistake this
      // failure path for an orderly shutdown receipt.
      await service.close().catch(() => {});
    }
  }
}
