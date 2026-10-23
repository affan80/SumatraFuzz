import { PassThrough } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';
import { runWorkerServiceControl } from '../src/service-control.js';

function frame(token: string): Buffer {
  const payload = Buffer.from(token, 'ascii');
  const length = Buffer.alloc(4);
  length.writeUInt32LE(payload.length);
  return Buffer.concat([length, payload]);
}

function channel() {
  const input = new PassThrough();
  const output = new PassThrough();
  const written: Buffer[] = [];
  output.on('data', (chunk: Buffer) => written.push(Buffer.from(chunk)));
  return { input, output, written };
}

describe('worker service stdio control protocol', () => {
  it('reports readiness and acknowledges only after successful application drain', async () => {
    const streams = channel();
    const close = vi.fn(async () => {});
    const task = runWorkerServiceControl(streams, async () => ({ close }));
    await vi.waitFor(() => expect(streams.written).toEqual([frame('READY')]));
    streams.input.write(frame('STOP'));
    await task;
    expect(close).toHaveBeenCalledOnce();
    expect(streams.written).toEqual([frame('READY'), frame('STOPPED')]);
  });

  it('rejects malformed controls and never reports a graceful stop', async () => {
    const streams = channel();
    const close = vi.fn(async () => {});
    const task = runWorkerServiceControl(streams, async () => ({ close }));
    await vi.waitFor(() => expect(streams.written).toEqual([frame('READY')]));
    streams.input.write(frame('RESTART'));
    await expect(task).rejects.toThrow(/command is invalid/i);
    expect(close).toHaveBeenCalledOnce();
    expect(streams.written).toEqual([frame('READY')]);
  });

  it('does not report STOPPED when application teardown fails', async () => {
    const streams = channel();
    const task = runWorkerServiceControl(streams, async () => ({
      close: async () => {
        throw new Error('shutdown failed');
      },
    }));
    await vi.waitFor(() => expect(streams.written).toEqual([frame('READY')]));
    streams.input.write(frame('STOP'));
    await expect(task).rejects.toThrow('shutdown failed');
    expect(streams.written).toEqual([frame('READY')]);
  });
});
