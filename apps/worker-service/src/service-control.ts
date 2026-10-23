import { once } from 'node:events';
import type { Readable, Writable } from 'node:stream';

export const SERVICE_CONTROL_MAX_FRAME_BYTES = 64;
const READY = Buffer.from('READY', 'ascii');
const STOP = Buffer.from('STOP', 'ascii');
const STOPPED = Buffer.from('STOPPED', 'ascii');

export interface ServiceControlChannel {
  readonly input: Readable;
  readonly output: Writable;
}

export interface ClosableWorkerService {
  close(): Promise<void>;
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

async function readStop(input: Readable): Promise<void> {
  const iterator = input[Symbol.asyncIterator]();
  let pending = Buffer.alloc(0);
  const fill = async (minimum: number): Promise<void> => {
    while (pending.length < minimum) {
      const next = await iterator.next();
      if (next.done) throw new Error('service control input closed before STOP');
      const chunk = Buffer.isBuffer(next.value) ? next.value : Buffer.from(next.value);
      if (pending.length + chunk.length > 4 + SERVICE_CONTROL_MAX_FRAME_BYTES) {
        throw new Error('service control frame exceeds its bound');
      }
      pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);
    }
  };

  await fill(4);
  const length = pending.readUInt32LE(0);
  if (length < 1 || length > SERVICE_CONTROL_MAX_FRAME_BYTES) {
    throw new Error('service control frame length is invalid');
  }
  const frameBytes = length + 4;
  await fill(frameBytes);
  if (pending.length !== frameBytes || !pending.subarray(4).equals(STOP)) {
    throw new Error('service control command is invalid');
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
  try {
    await writeFrame(channel.output, READY);
    await readStop(channel.input);
    closeAttempted = true;
    await service.close();
    stopped = true;
    await writeFrame(channel.output, STOPPED);
  } finally {
    if (!stopped && !closeAttempted) {
      // Best-effort cleanup never emits STOPPED, so the host cannot mistake this
      // failure path for an orderly shutdown receipt.
      await service.close().catch(() => {});
    }
  }
}
