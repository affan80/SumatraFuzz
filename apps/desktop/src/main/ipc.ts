import type { CampaignLimits, RunStatus } from '@sumatrafuzz/worker-protocol';
import { isTrustedAppDocumentUrl } from './window-security.js';

export interface DesktopIpcEvent {
  readonly sender: { readonly mainFrame: { readonly url: string } };
  readonly senderFrame?: { readonly url: string } | null;
}

export interface DesktopIpcRegistrar {
  handle(channel: string, listener: (event: DesktopIpcEvent, ...args: unknown[]) => unknown): void;
  removeHandler(channel: string): void;
}

export interface DesktopIpcHandlers {
  listWorkers(): Promise<readonly unknown[]>;
  pairWorker(): Promise<unknown>;
  unpairWorker(): Promise<void>;
  importInputBundle(): Promise<unknown>;
  getCampaignStatus(): Promise<unknown>;
  startCampaign(draft: RunDraft): Promise<RunStatus>;
  stopActiveRun(): Promise<RunStatus | null>;
}

export interface RunDraft {
  readonly label: string;
  readonly limits: CampaignLimits;
}

const CHANNELS = [
  'sf:workers:list',
  'sf:workers:pair',
  'sf:workers:unpair',
  'sf:campaigns:import',
  'sf:campaigns:status',
  'sf:campaigns:start',
  'sf:campaigns:stop',
] as const;

function assertTrustedMainFrame(event: DesktopIpcEvent): void {
  const frame = event.senderFrame;
  if (!frame || frame !== event.sender.mainFrame || !isTrustedAppDocumentUrl(frame.url)) {
    throw new Error('IPC request rejected from an untrusted renderer');
  }
}

function expectArgumentCount(args: readonly unknown[], expected: number): void {
  if (args.length !== expected) throw new TypeError('IPC request has an invalid argument count');
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}

function validateRunDraft(value: unknown): RunDraft {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('campaign draft is invalid');
  }
  const candidate = value as Record<string, unknown>;
  if (
    !exactKeys(candidate, ['label', 'limits']) ||
    typeof candidate.label !== 'string' ||
    candidate.label.length > 128 ||
    [...candidate.label].some((character) => {
      const code = character.codePointAt(0) ?? 0;
      return code <= 0x1f || (code >= 0x7f && code <= 0x9f);
    }) ||
    typeof candidate.limits !== 'object' ||
    candidate.limits === null ||
    Array.isArray(candidate.limits)
  ) {
    throw new TypeError('campaign draft is invalid');
  }
  const limits = candidate.limits as Record<string, unknown>;
  if (
    !exactKeys(limits, [
      'max_duration_s',
      'max_memory_bytes',
      'max_disk_bytes',
      'max_cpu_percent',
    ]) ||
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
    throw new TypeError('campaign limits are invalid');
  }
  return {
    label: candidate.label,
    limits: {
      max_duration_s: limits.max_duration_s as number,
      max_memory_bytes: limits.max_memory_bytes as number,
      max_disk_bytes: limits.max_disk_bytes as number,
      max_cpu_percent: limits.max_cpu_percent as number,
    },
  };
}

export function registerDesktopIpc(
  ipcMain: DesktopIpcRegistrar,
  handlers: DesktopIpcHandlers,
): () => void {
  ipcMain.handle('sf:workers:list', async (event, ...args) => {
    assertTrustedMainFrame(event);
    expectArgumentCount(args, 0);
    return handlers.listWorkers();
  });
  ipcMain.handle('sf:workers:pair', async (event, ...args) => {
    assertTrustedMainFrame(event);
    expectArgumentCount(args, 0);
    return handlers.pairWorker();
  });
  ipcMain.handle('sf:workers:unpair', async (event, ...args) => {
    assertTrustedMainFrame(event);
    expectArgumentCount(args, 0);
    await handlers.unpairWorker();
  });
  ipcMain.handle('sf:campaigns:import', async (event, ...args) => {
    assertTrustedMainFrame(event);
    expectArgumentCount(args, 0);
    return handlers.importInputBundle();
  });
  ipcMain.handle('sf:campaigns:status', async (event, ...args) => {
    assertTrustedMainFrame(event);
    expectArgumentCount(args, 0);
    return handlers.getCampaignStatus();
  });
  ipcMain.handle('sf:campaigns:start', async (event, ...args) => {
    assertTrustedMainFrame(event);
    expectArgumentCount(args, 1);
    return handlers.startCampaign(validateRunDraft(args[0]));
  });
  ipcMain.handle('sf:campaigns:stop', async (event, ...args) => {
    assertTrustedMainFrame(event);
    expectArgumentCount(args, 0);
    return handlers.stopActiveRun();
  });

  return () => {
    for (const channel of CHANNELS) ipcMain.removeHandler(channel);
  };
}
