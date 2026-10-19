import { isNonNilUuid, type RunRequest, validateRunRequest } from '@sumatrafuzz/worker-protocol';
import { isTrustedAppUrl } from './window-security.js';

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
  startRun(request: RunRequest): Promise<unknown>;
  getRun(runId: string): Promise<unknown>;
  stopRun(runId: string): Promise<unknown>;
}

const CHANNELS = [
  'sf:workers:list',
  'sf:workers:pair',
  'sf:workers:unpair',
  'sf:runs:start',
  'sf:runs:get',
  'sf:runs:stop',
] as const;

function assertTrustedMainFrame(event: DesktopIpcEvent): void {
  const frame = event.senderFrame;
  if (!frame || frame !== event.sender.mainFrame || !isTrustedAppUrl(frame.url)) {
    throw new Error('IPC request rejected from an untrusted renderer');
  }
}

function expectArgumentCount(args: readonly unknown[], expected: number): void {
  if (args.length !== expected) throw new TypeError('IPC request has an invalid argument count');
}

function expectRunId(value: unknown): string {
  if (typeof value !== 'string' || !isNonNilUuid(value)) {
    throw new TypeError('IPC run ID must be a non-nil UUID');
  }
  return value;
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
  ipcMain.handle('sf:runs:start', async (event, ...args) => {
    assertTrustedMainFrame(event);
    expectArgumentCount(args, 1);
    return handlers.startRun(validateRunRequest(args[0]));
  });
  ipcMain.handle('sf:runs:get', async (event, ...args) => {
    assertTrustedMainFrame(event);
    expectArgumentCount(args, 1);
    return handlers.getRun(expectRunId(args[0]));
  });
  ipcMain.handle('sf:runs:stop', async (event, ...args) => {
    assertTrustedMainFrame(event);
    expectArgumentCount(args, 1);
    return handlers.stopRun(expectRunId(args[0]));
  });

  return () => {
    for (const channel of CHANNELS) ipcMain.removeHandler(channel);
  };
}
