import { BrowserWindow } from 'electron';
import {
  attachWindowGuards,
  createWindowOptions,
  DESKTOP_APP_URL,
  showWhenReady,
} from './window-security.js';

export function createMainWindow(preloadPath: string): BrowserWindow {
  const window = new BrowserWindow(createWindowOptions(preloadPath));
  attachWindowGuards(window.webContents);
  showWhenReady(window);
  void window.loadURL(DESKTOP_APP_URL).catch(() => window.destroy());
  return window;
}
