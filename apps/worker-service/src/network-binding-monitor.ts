export interface NetworkBindingMonitor {
  stop(): Promise<void>;
}

/** Close admissions once on adapter loss; this deliberately has no rebind path. */
export function monitorNetworkBinding(
  verify: () => void,
  closeListener: () => Promise<void>,
  intervalMs = 5_000,
): NetworkBindingMonitor {
  if (typeof verify !== 'function' || typeof closeListener !== 'function')
    throw new TypeError('network binding monitor callbacks are required');
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 100 || intervalMs > 60_000)
    throw new RangeError('network binding monitor interval is invalid');
  let stopped = false;
  let closePromise: Promise<void> | undefined;
  let closeFailed = false;
  const timer = setInterval(() => {
    if (stopped || closePromise) return;
    try {
      verify();
    } catch {
      stopped = true;
      clearInterval(timer);
      closePromise = closeListener().catch(() => {
        closeFailed = true;
      });
    }
  }, intervalMs);
  timer.unref?.();
  return {
    async stop() {
      stopped = true;
      clearInterval(timer);
      await closePromise;
      if (closeFailed) throw new Error('worker listener shutdown after adapter loss failed');
    },
  };
}
