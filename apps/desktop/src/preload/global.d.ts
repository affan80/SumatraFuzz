import type { SumatraFuzzApi } from './api.js';

declare global {
  interface Window {
    readonly sumatraFuzz: SumatraFuzzApi;
  }
}
