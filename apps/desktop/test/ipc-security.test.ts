import { describe, expect, it } from 'vitest';
import { type DesktopIpcEvent, registerDesktopIpc } from '../src/main/ipc.js';
import { createSumatraFuzzApi } from '../src/preload/api.js';

const draft = {
  label: 'security test',
  limits: {
    max_duration_s: 60,
    max_memory_bytes: 1024,
    max_disk_bytes: 1024,
    max_cpu_percent: 50,
  },
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
      importInputBundle: async () => ({ input_bundle_id: 'private-id' }),
      getCampaignStatus: async () => ({ connection_state: 'connected' }),
      startCampaign: async (value) => {
        calls.push(['start', value]);
        return { accepted: true } as never;
      },
      stopActiveRun: async () => ({ stopped: true }) as never,
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
    const handler = ipc.handlers.get('sf:campaigns:start');
    expect(handler).toBeDefined();

    await expect(handler?.(ipc.event({ url: 'https://attacker.invalid' }), draft)).rejects.toThrow(
      /untrusted renderer/i,
    );
    await expect(
      handler?.(
        { sender: { mainFrame: ipc.mainFrame }, senderFrame: { url: 'app://renderer/frame.html' } },
        draft,
      ),
    ).rejects.toThrow(/untrusted renderer/i);
    ipc.mainFrame.url = 'app://renderer/app.js';
    await expect(handler?.(ipc.event(), draft)).rejects.toThrow(/untrusted renderer/i);
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

  it('accepts only a label and limits for a campaign start', async () => {
    const ipc = registeredIpc();
    const handler = ipc.handlers.get('sf:campaigns:start');
    await expect(
      handler?.(ipc.event(), { ...draft, shell: 'calc.exe', path: '/tmp/secret' }),
    ).rejects.toThrow();
    await expect(handler?.(ipc.event(), draft, 'extra')).rejects.toThrow(/argument count/i);
    expect(ipc.calls).toEqual([]);
    await expect(
      handler?.(ipc.event(), {
        ...draft,
        limits: { ...draft.limits, max_disk_bytes: Number.MAX_SAFE_INTEGER },
      }),
    ).resolves.toEqual({ accepted: true });
    expect(ipc.calls).toEqual([
      ['start', { ...draft, limits: { ...draft.limits, max_disk_bytes: Number.MAX_SAFE_INTEGER } }],
    ]);
  });

  it('uses fixed channels and gives the renderer no run-ID lookup or stop authority', async () => {
    const ipc = registeredIpc();
    expect(ipc.handlers.has('sf:runs:get')).toBe(false);
    expect(ipc.handlers.has('sf:runs:stop')).toBe(false);
    await expect(
      ipc.handlers.get('sf:campaigns:stop')?.(ipc.event(), 'forged-run-id'),
    ).rejects.toThrow(/argument count/i);
    await expect(ipc.handlers.get('sf:campaigns:stop')?.(ipc.event())).resolves.toEqual({
      stopped: true,
    });
    ipc.dispose();
    expect(ipc.removed).toEqual([
      'sf:workers:list',
      'sf:workers:pair',
      'sf:workers:unpair',
      'sf:campaigns:import',
      'sf:campaigns:status',
      'sf:campaigns:start',
      'sf:campaigns:stop',
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
      'getCampaignStatus',
      'importInputBundle',
      'listWorkers',
      'pairWorker',
      'startCampaign',
      'stopActiveRun',
      'unpairWorker',
    ]);
    expect('send' in api).toBe(false);
    expect('invoke' in api).toBe(false);
    await api.listWorkers();
    expect(invoked).toEqual([['sf:workers:list']]);
    await api.pairWorker();
    await api.unpairWorker();
    await api.importInputBundle();
    await api.getCampaignStatus();
    await api.startCampaign(draft);
    await api.stopActiveRun();
    expect(invoked.slice(1)).toEqual([
      ['sf:workers:pair'],
      ['sf:workers:unpair'],
      ['sf:campaigns:import'],
      ['sf:campaigns:status'],
      ['sf:campaigns:start', draft],
      ['sf:campaigns:stop'],
    ]);
  });
});
