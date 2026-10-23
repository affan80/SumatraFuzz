import { afterEach, describe, expect, it, vi } from 'vitest';
import { monitorNetworkBinding } from '../src/network-binding-monitor.js';

afterEach(() => vi.useRealTimers());

describe('remote network binding monitor', () => {
  it('closes the listener once after adapter loss and never attempts to rebind', async () => {
    vi.useFakeTimers();
    let probeCount = 0;
    let closeCount = 0;
    const monitor = monitorNetworkBinding(
      () => {
        probeCount += 1;
        throw new Error('adapter gone');
      },
      async () => {
        closeCount += 1;
      },
      100,
    );
    await vi.advanceTimersByTimeAsync(100);
    await monitor.stop();
    await vi.advanceTimersByTimeAsync(500);
    expect(probeCount).toBe(1);
    expect(closeCount).toBe(1);
  });

  it('keeps checking while the exact adapter binding remains valid', async () => {
    vi.useFakeTimers();
    const verify = vi.fn();
    const close = vi.fn(async () => {});
    const monitor = monitorNetworkBinding(verify, close, 100);
    await vi.advanceTimersByTimeAsync(300);
    await monitor.stop();
    expect(verify).toHaveBeenCalledTimes(3);
    expect(close).not.toHaveBeenCalled();
  });
});
