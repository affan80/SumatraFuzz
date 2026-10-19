import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { app, ipcMain, protocol, session } from 'electron';
import { type DesktopIpcHandlers, type DesktopIpcRegistrar, registerDesktopIpc } from './ipc.js';
import { createMainWindow } from './window.js';
import { isAllowedRendererRequest, secureResponseHeaders } from './window-security.js';

protocol.registerSchemesAsPrivileged([
  {
    scheme: 'app',
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      corsEnabled: false,
      allowServiceWorkers: false,
      codeCache: false,
    },
  },
]);

function installRendererProtocol(): void {
  const rendererEntry = path.join(app.getAppPath(), 'dist', 'renderer', 'index.html');
  protocol.handle('app', async (request) => {
    if (!isAllowedRendererRequest(request.method, request.url)) {
      return new Response('Not found', { status: 404 });
    }
    return new Response(await readFile(rendererEntry), {
      headers: secureResponseHeaders({ 'content-type': 'text/html; charset=utf-8' }),
    });
  });
}

function denyPermissions(): void {
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
    callback(false);
  });
  session.defaultSession.setPermissionCheckHandler(() => false);
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: Object.fromEntries(
        Object.entries(secureResponseHeaders(details.responseHeaders ?? {})).map(
          ([name, value]) => [name, [value]],
        ),
      ),
    });
  });
}

const unavailableHandlers: DesktopIpcHandlers = {
  async listWorkers() {
    throw new Error('worker client is not configured');
  },
  async startRun() {
    throw new Error('worker client is not configured');
  },
  async getRun() {
    throw new Error('worker client is not configured');
  },
  async stopRun() {
    throw new Error('worker client is not configured');
  },
};

void app.whenReady().then(() => {
  installRendererProtocol();
  denyPermissions();
  registerDesktopIpc(ipcMain as unknown as DesktopIpcRegistrar, unavailableHandlers);
  createMainWindow(path.join(app.getAppPath(), 'dist', 'src', 'preload', 'index.js'));
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
