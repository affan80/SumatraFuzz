import { describe, expect, it } from 'vitest';
import { validateBindAddress } from '../src/network-policy.js';

describe('worker service bind policy', () => {
  it('permits loopback only in local mode', () => {
    expect(() => validateBindAddress('127.0.0.1', 'local')).not.toThrow();
    expect(() => validateBindAddress('::1', 'local')).not.toThrow();
    expect(() => validateBindAddress('127.0.0.1', 'remote')).toThrow(/private|VPN/i);
  });

  it('accepts private literal interfaces for remote mode and rejects public or DNS hosts', () => {
    for (const address of ['10.20.30.40', '172.20.0.2', '192.168.1.2', 'fd00::1']) {
      expect(() => validateBindAddress(address, 'remote')).not.toThrow();
    }
    for (const address of ['8.8.8.8', '2001:4860:4860::8888', 'worker.internal']) {
      expect(() => validateBindAddress(address, 'remote')).toThrow();
    }
  });

  it('does not allow DNS rebinding by resolving names at startup', () => {
    expect(() => validateBindAddress('localhost', 'local')).toThrow(/IP literal/i);
  });
});
