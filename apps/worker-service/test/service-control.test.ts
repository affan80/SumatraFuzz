import { PassThrough, Readable } from 'node:stream';
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
  it('applies one bounded signed trust transaction and emits only a generic receipt', async () => {
    const streams = channel();
    const bundle = Buffer.from('{"signed":"transaction"}');
    const request = Buffer.concat([Buffer.from([0x10]), bundle]);
    const header = Buffer.alloc(4);
    header.writeUInt32LE(request.length);
    const apply = vi.fn(async (received: Buffer) => {
      expect(received).toEqual(bundle);
      received.fill(0);
    });
    const task = runWorkerServiceControl(streams, async () => ({
      close: async () => {},
      applyTrustOperation: apply,
    }));
    await vi.waitFor(() => expect(streams.written).toEqual([frame('READY')]));
    streams.input.write(Buffer.concat([header, request]));
    await vi.waitFor(() => expect(streams.written).toHaveLength(2));
    expect(streams.written[1]).toEqual(Buffer.from([2, 0, 0, 0, 0x11, 0]));
    expect(apply).toHaveBeenCalledOnce();
    streams.input.write(frame('STOP'));
    await task;
    expect(streams.written.at(-1)).toEqual(frame('STOPPED'));
  });

  it('applies a signed pairing bundle through its separate verified operation handler', async () => {
    const streams = channel();
    const bundle = Buffer.from('{"signed":"pairing"}');
    const request = Buffer.concat([Buffer.from([0x12]), bundle]);
    const header = Buffer.alloc(4);
    header.writeUInt32LE(request.length);
    const applyPairingBundle = vi.fn(async (received: Buffer) => {
      expect(received).toEqual(bundle);
      received.fill(0);
    });
    const task = runWorkerServiceControl(streams, async () => ({
      close: async () => {},
      applyPairingBundle,
    }));
    await vi.waitFor(() => expect(streams.written).toEqual([frame('READY')]));
    streams.input.write(Buffer.concat([header, request]));
    await vi.waitFor(() => expect(streams.written).toHaveLength(2));
    expect(streams.written[1]).toEqual(Buffer.from([2, 0, 0, 0, 0x11, 0]));
    expect(applyPairingBundle).toHaveBeenCalledOnce();
    streams.input.write(frame('STOP'));
    await task;
  });

  it('keeps control-channel listeners bounded across repeated trust operations', async () => {
    const streams = channel();
    const bundle = Buffer.from('{"signed":"transaction"}');
    const request = Buffer.concat([Buffer.from([0x10]), bundle]);
    const header = Buffer.alloc(4);
    header.writeUInt32LE(request.length);
    const apply = vi.fn(async () => {});
    const task = runWorkerServiceControl(streams, async () => ({
      close: async () => {},
      applyTrustOperation: apply,
    }));
    await vi.waitFor(() => expect(streams.written).toEqual([frame('READY')]));

    streams.input.write(
      Buffer.concat(Array.from({ length: 24 }, () => Buffer.concat([header, request]))),
    );
    await vi.waitFor(() => expect(apply).toHaveBeenCalledTimes(24));
    expect(streams.input.listenerCount('readable')).toBeLessThanOrEqual(1);
    expect(streams.input.listenerCount('error')).toBeLessThanOrEqual(1);
    streams.input.write(frame('STOP'));
    await task;
  });

  it('clears fragmented input chunks after processing a signed trust operation', async () => {
    const input = new Readable({ objectMode: true, read() {} });
    const output = new PassThrough();
    const written: Buffer[] = [];
    output.on('data', (chunk: Buffer) => written.push(Buffer.from(chunk)));
    const streams = { input, output, written };
    const header = Buffer.alloc(4);
    header.writeUInt32LE(6);
    const chunks = [
      Buffer.from(header.subarray(0, 2)),
      Buffer.concat([header.subarray(2), Buffer.from([0x10, 0x41])]),
      Buffer.from([0x42, 0x43, 0x44, 0x45]),
    ];
    const applyTrustOperation = vi.fn(async (received: Buffer) => {
      expect(received).toEqual(Buffer.from('ABCDE'));
      received.fill(0);
    });
    const task = runWorkerServiceControl(streams, async () => ({
      close: async () => {},
      applyTrustOperation,
    }));
    await vi.waitFor(() => expect(streams.written).toEqual([frame('READY')]));
    for (const chunk of chunks) streams.input.push(chunk);
    streams.input.push(frame('STOP'));
    await vi.waitFor(() => expect(applyTrustOperation).toHaveBeenCalledOnce());
    await task;
    expect(chunks.every((chunk) => chunk.every((byte) => byte === 0))).toBe(true);
  });

  it('rejects oversized trust operation frames before allocating the payload', async () => {
    const streams = channel();
    const task = runWorkerServiceControl(streams, async () => ({ close: async () => {} }));
    await vi.waitFor(() => expect(streams.written).toEqual([frame('READY')]));
    const header = Buffer.alloc(4);
    header.writeUInt32LE(1024 * 1024 + 2);
    streams.input.write(header);
    await expect(task).rejects.toThrow(/length is invalid/i);
    expect(streams.written).toEqual([frame('READY')]);
  });

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
