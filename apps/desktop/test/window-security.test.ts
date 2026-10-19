import { describe, expect, it } from 'vitest';
import {
  attachWindowGuards,
  createWindowOptions,
  isAllowedRendererRequest,
  isTrustedAppDocumentUrl,
  isTrustedAppUrl,
  secureResponseHeaders,
  showWhenReady,
} from '../src/main/window-security.js';

describe('Electron window security', () => {
  it('creates a sandboxed renderer with no Node integration', () => {
    const options = createWindowOptions('/app/preload.js');

    expect(options.webPreferences).toMatchObject({
      preload: '/app/preload.js',
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
    });
  });

  it('accepts only the packaged app origin without URL credentials or ports', () => {
    expect(isTrustedAppUrl('app://renderer/index.html')).toBe(true);
    for (const url of [
      'https://renderer/index.html',
      'app://attacker/index.html',
      'app://renderer:80/index.html',
      'app://user@renderer/index.html',
      'javascript:alert(1)',
      'file:///tmp/index.html',
    ]) {
      expect(isTrustedAppUrl(url)).toBe(false);
    }
  });

  it('trusts only the exact packaged HTML document for navigation and IPC', () => {
    expect(isTrustedAppDocumentUrl('app://renderer/index.html')).toBe(true);
    for (const url of [
      'app://renderer/app.js',
      'app://renderer/index.html?view=worker',
      'app://renderer/index.html#worker',
      'app://renderer/missing',
    ]) {
      expect(isTrustedAppDocumentUrl(url)).toBe(false);
    }
  });

  it('serves only exact packaged renderer resources for GET requests', () => {
    expect(isAllowedRendererRequest('GET', 'app://renderer/index.html')).toBe(true);
    expect(isAllowedRendererRequest('GET', 'app://renderer/app.js')).toBe(true);
    for (const [method, url] of [
      ['POST', 'app://renderer/index.html'],
      ['GET', 'app://renderer/../../secret'],
      ['GET', 'app://renderer/index.html?file=secret'],
      ['GET', 'app://renderer/index.html#fragment'],
      ['GET', 'app://renderer/app.js?file=secret'],
      ['GET', 'app://renderer/not-allowlisted.js'],
      ['GET', 'app://attacker/index.html'],
    ]) {
      expect(isAllowedRendererRequest(method as string, url as string)).toBe(false);
    }
  });

  it('blocks popup windows and navigation outside the packaged app origin', () => {
    let openHandler: (() => { action: 'deny' | 'allow' }) | undefined;
    const navigationHandlers = new Map<
      string,
      (event: { preventDefault(): void }, url: string) => void
    >();
    attachWindowGuards({
      setWindowOpenHandler(handler) {
        openHandler = handler;
      },
      on(event, handler) {
        navigationHandlers.set(event, handler);
      },
    });

    expect(openHandler?.()).toEqual({ action: 'deny' });
    let prevented = false;
    navigationHandlers.get('will-navigate')?.(
      { preventDefault: () => (prevented = true) },
      'https://attacker.invalid',
    );
    expect(prevented).toBe(true);
    prevented = false;
    navigationHandlers.get('will-redirect')?.(
      { preventDefault: () => (prevented = true) },
      'https://attacker.invalid',
    );
    expect(prevented).toBe(true);
    prevented = false;
    navigationHandlers.get('will-navigate')?.(
      { preventDefault: () => (prevented = true) },
      'app://renderer/index.html',
    );
    expect(prevented).toBe(false);
    navigationHandlers.get('will-navigate')?.(
      { preventDefault: () => (prevented = true) },
      'app://renderer/app.js',
    );
    expect(prevented).toBe(true);
  });

  it('applies a restrictive content security policy to app responses', () => {
    const headers = secureResponseHeaders({ 'content-type': ['text/html'] });

    expect(headers['content-type']).toBe('text/html');
    expect(headers['content-security-policy']).toContain("default-src 'self'");
    expect(headers['content-security-policy']).toContain("object-src 'none'");
    expect(headers['content-security-policy']).not.toContain("'unsafe-eval'");
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['cache-control']).toBe('no-store');
    expect(headers['permissions-policy']).toContain('camera=()');
    expect(headers['x-frame-options']).toBe('DENY');
  });

  it('shows the desktop window only after its renderer is ready', () => {
    let ready: (() => void) | undefined;
    let shows = 0;
    showWhenReady({
      once(event, callback) {
        expect(event).toBe('ready-to-show');
        ready = callback;
      },
      show() {
        shows += 1;
      },
    });

    expect(shows).toBe(0);
    ready?.();
    expect(shows).toBe(1);
  });
});
