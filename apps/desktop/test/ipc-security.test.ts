import type { RunRequest } from '@sumatrafuzz/worker-protocol';
import { describe, expect, it } from 'vitest';
import { type DesktopIpcEvent, registerDesktopIpc } from '../src/main/ipc.js';
import { createSumatraFuzzApi } from '../src/preload/api.js';

const request: RunRequest = {
  request_id: '22222222-2222-4222-8222-222222222222' as RunRequest['request_id'],
  controller_id: '33333333-3333-4333-8333-333333333333' as RunRequest['controller_id'],
  input_bundle_id: 'seed-set-1',
  target_lock_sha256: 'a'.repeat(64),
  limits: {
    max_duration_s: 60,
    max_memory_bytes: 1024,
    max_disk_bytes: 1024,
    max_cpu_percent: 50,
  },
  label: 'security test',
};

function registeredIpc() {
  const handlers = new Map<string, (event: DesktopIpcEvent, ...args: unknown[]) => unknown>();
  const removed: string[] = [];
  const calls: unknown[][] = [];
  const dispose = registerDesktopIpc(
    {
      handle: (channel, handler) => handlers.set(channel, handler),
      removeHandler: (channel) => removed.push(channel),
    },
    {
      listWorkers: async () => [],
      pairWorker: async () => {
        calls.push(['pair']);
        return { cancelled: true };
      },
      unpairWorker: async () => {
        calls.push(['unpair']);
      },
      startRun: async (value) => {
        calls.push(['start', value]);
        return { accepted: true };
      },
      getRun: async (runId) => ({ runId }),
      stopRun: async (runId) => ({ runId, stopped: true }),
    },
  );
  const mainFrame = { url: 'app://renderer/index.html' };
  const event = (frame = mainFrame): DesktopIpcEvent => ({
    sender: { mainFrame },
    senderFrame: frame,
  });
  return { handlers, removed, calls, dispose, event, mainFrame };
}

describe('Electron IPC security', () => {
  it('rejects cross-origin and subframe IPC before calling application handlers', async () => {
    const ipc = registeredIpc();
    const handler = ipc.handlers.get('sf:runs:start');
    expect(handler).toBeDefined();

    await expect(
      handler?.(ipc.event({ url: 'https://attacker.invalid' }), request),
    ).rejects.toThrow(/untrusted renderer/i);
    await expect(
      handler?.(
        { sender: { mainFrame: ipc.mainFrame }, senderFrame: { url: 'app://renderer/frame.html' } },
        request,
      ),
    ).rejects.toThrow(/untrusted renderer/i);
    expect(ipc.calls).toEqual([]);
  });

  it('only opens the certificate picker from the trusted main frame with no arguments', async () => {
    const ipc = registeredIpc();
    const handler = ipc.handlers.get('sf:workers:pair');
    await expect(handler?.(ipc.event({ url: 'https://attacker.invalid' }))).rejects.toThrow(
      /untrusted renderer/i,
    );
    await expect(handler?.(ipc.event(), 'C:\\secrets\\private.pem')).rejects.toThrow(
      /argument count/i,
    );
    expect(ipc.calls).toEqual([]);
    await expect(handler?.(ipc.event())).resolves.toEqual({ cancelled: true });
    expect(ipc.calls).toEqual([['pair']]);
  });

  it('validates exact run schemas and rejects path, shell, and extra fields', async () => {
    const ipc = registeredIpc();
    const handler = ipc.handlers.get('sf:runs:start');
    await expect(
      handler?.(ipc.event(), { ...request, shell: 'calc.exe', path: '/tmp/secret' }),
    ).rejects.toThrow();
    expect(ipc.calls).toEqual([]);
    await expect(handler?.(ipc.event(), request)).resolves.toEqual({ accepted: true });
    expect(ipc.calls).toEqual([['start', request]]);
  });

  it('uses only fixed channel names and validates run identifiers', async () => {
    const ipc = registeredIpc();
    await expect(
      ipc.handlers.get('sf:runs:get')?.(ipc.event(), '../../etc/passwd'),
    ).rejects.toThrow(/UUID/i);
    await expect(
      ipc.handlers.get('sf:runs:get')?.(ipc.event(), '44444444-4444-4444-8444-444444444444'),
    ).resolves.toEqual({ runId: '44444444-4444-4444-8444-444444444444' });
    ipc.dispose();
    expect(ipc.removed).toEqual([
      'sf:workers:list',
      'sf:workers:pair',
      'sf:workers:unpair',
      'sf:runs:start',
      'sf:runs:get',
      'sf:runs:stop',
    ]);
  });

  it('exposes typed methods but no raw IPC transport to the renderer', async () => {
    const invoked: unknown[][] = [];
    const api = createSumatraFuzzApi({
      invoke: async (...args: unknown[]) => {
        invoked.push(args);
        return [];
      },
    });

    expect(Object.keys(api).sort()).toEqual([
      'getRun',
      'listWorkers',
      'pairWorker',
      'startRun',
      'stopRun',
      'unpairWorker',
    ]);
    expect('send' in api).toBe(false);
    expect('invoke' in api).toBe(false);
    await api.listWorkers();
    expect(invoked).toEqual([['sf:workers:list']]);
    await api.pairWorker();
    await api.unpairWorker();
    expect(invoked.slice(1)).toEqual([['sf:workers:pair'], ['sf:workers:unpair']]);
  });
});
