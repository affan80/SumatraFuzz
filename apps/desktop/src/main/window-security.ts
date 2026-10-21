import type { BrowserWindowConstructorOptions } from 'electron';

export const DESKTOP_APP_URL = 'app://renderer/index.html';
export const DESKTOP_APP_CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'none'; worker-src 'none'; media-src 'none'";
const RENDERER_PATHS = [
  '/index.html',
  '/app.js',
  '/campaign-poller.js',
  '/campaign-view-model.js',
] as const;

export interface GuardedWebContents {
  setWindowOpenHandler(handler: () => { action: 'deny' }): void;
  on(
    event: 'will-navigate' | 'will-redirect',
    listener: (event: { preventDefault(): void }, url: string) => void,
  ): void;
}

export interface ShowWhenReadyWindow {
  once(event: 'ready-to-show', callback: () => void): void;
  show(): void;
}

export function createWindowOptions(preload: string): BrowserWindowConstructorOptions {
  return {
    width: 1280,
    height: 800,
    show: false,
    webPreferences: {
      preload,
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      nodeIntegrationInSubFrames: false,
      nodeIntegrationInWorker: false,
    },
  };
}

export function showWhenReady(window: ShowWhenReadyWindow): void {
  window.once('ready-to-show', () => window.show());
}

export function isAllowedRendererRequest(method: string, value: string): boolean {
  if (method !== 'GET') return false;
  try {
    const url = new URL(value);
    return (
      isTrustedAppUrl(value) &&
      (RENDERER_PATHS as readonly string[]).includes(url.pathname) &&
      url.search === '' &&
      url.hash === ''
    );
  } catch {
    return false;
  }
}

export function isTrustedAppUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      url.protocol === 'app:' &&
      url.hostname === 'renderer' &&
      url.port === '' &&
      url.username === '' &&
      url.password === ''
    );
  } catch {
    return false;
  }
}

export function isTrustedAppDocumentUrl(value: string): boolean {
  return value === DESKTOP_APP_URL;
}

export function attachWindowGuards(webContents: GuardedWebContents): void {
  webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  const rejectUntrustedNavigation = (event: { preventDefault(): void }, url: string): void => {
    if (!isTrustedAppDocumentUrl(url)) event.preventDefault();
  };
  webContents.on('will-navigate', rejectUntrustedNavigation);
  webContents.on('will-redirect', rejectUntrustedNavigation);
}

export function secureResponseHeaders(
  existing: Record<string, string | string[]> = {},
): Record<string, string> {
  const retained = Object.fromEntries(
    Object.entries(existing)
      .filter(
        ([name]) =>
          !['content-security-policy', 'x-content-type-options', 'referrer-policy'].includes(
            name.toLowerCase(),
          ),
      )
      .map(([name, value]) => [name, Array.isArray(value) ? value.join(', ') : value]),
  );
  return {
    ...retained,
    'content-security-policy': DESKTOP_APP_CSP,
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'cache-control': 'no-store',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), usb=(), serial=()',
    'x-frame-options': 'DENY',
  };
}
