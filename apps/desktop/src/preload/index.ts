import { contextBridge, ipcRenderer } from 'electron';
import { createSumatraFuzzApi } from './api.js';

contextBridge.exposeInMainWorld('sumatraFuzz', createSumatraFuzzApi(ipcRenderer));
