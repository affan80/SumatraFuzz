import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { createWorkerClient } from '@sumatrafuzz/worker-client';
import { app, dialog, ipcMain, protocol, safeStorage, session } from 'electron';
import { type DesktopIpcRegistrar, registerDesktopIpc } from './ipc.js';
import { createMainWindow } from './window.js';
import { isAllowedRendererRequest, secureResponseHeaders } from './window-security.js';
import { loadTrustedWorkerBundleSigningKey } from './worker-bundle.js';
import { readWorkerBundleFile } from './worker-bundle-file.js';
import {
  createDesktopWorkerController,
  type DesktopWorkerController,
} from './worker-controller.js';
import { createWorkerProfileStore } from './worker-profile-store.js';

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
  const rendererRoot = path.join(app.getAppPath(), 'dist', 'renderer');
  protocol.handle('app', async (request) => {
    if (!isAllowedRendererRequest(request.method, request.url)) {
      return new Response('Not found', { status: 404 });
    }
    const url = new URL(request.url);
    const isScript = url.pathname === '/app.js';
    const resourcePath = path.join(rendererRoot, isScript ? 'app.js' : 'index.html');
    return new Response(await readFile(resourcePath), {
      headers: secureResponseHeaders({
        'content-type': isScript ? 'text/javascript; charset=utf-8' : 'text/html; charset=utf-8',
      }),
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

let workerController: DesktopWorkerController | undefined;

void app
  .whenReady()
  .then(async () => {
    installRendererProtocol();
    denyPermissions();
    const profileStore = createWorkerProfileStore({
      filePath: path.join(app.getPath('userData'), 'worker-profile.v1.enc'),
      safeStorage,
    });
    workerController = createDesktopWorkerController({
      profileStore,
      loadTrustedSigningPublicKey: () =>
        loadTrustedWorkerBundleSigningKey(
          path.join(app.getAppPath(), 'dist', 'resources', 'worker-bundle-signing-key.pem'),
        ),
      selectBundle: async () => {
        const selection = await dialog.showOpenDialog({
          title: 'Import signed worker certificate bundle',
          filters: [{ name: 'SumatraFuzz pairing bundle', extensions: ['sfpair'] }],
          properties: ['openFile'],
        });
        if (selection.canceled || selection.filePaths.length !== 1) return null;
        const [selectedPath] = selection.filePaths;
        if (!selectedPath) return null;
        return readWorkerBundleFile(selectedPath);
      },
      createClient: (profile) =>
        createWorkerClient({
          baseUrl: profile.baseUrl,
          workerFingerprint: profile.workerFingerprint,
          controllerCertificate: Buffer.from(profile.controllerCertificatePem),
          controllerKey: Buffer.from(profile.controllerPrivateKeyPem),
          trustedCa: Buffer.from(profile.trustedCaPem),
        }),
    });
    await workerController.restore();
    registerDesktopIpc(ipcMain as unknown as DesktopIpcRegistrar, workerController);
    createMainWindow(path.join(app.getAppPath(), 'dist', 'src', 'preload', 'index.js'));
  })
  .catch(() => {
    dialog.showErrorBox(
      'Worker profile unavailable',
      'The encrypted worker profile could not be opened. No credentials were removed. Check Windows account encryption availability, then restart the app.',
    );
    app.quit();
  });

app.on('before-quit', () => {
  workerController?.close();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
