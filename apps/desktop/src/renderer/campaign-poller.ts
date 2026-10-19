const POLL_INTERVAL_MS = 1000;
const MAX_BACKOFF_MS = 15_000;

export interface CampaignPoller {
  start(): void;
  stop(): void;
}

/** Poll serially so a slow worker cannot accumulate overlapping status requests. */
export function createCampaignPoller<T>(
  fetchStatus: () => Promise<T>,
  onStatus: (status: T) => void,
  onError: (error: unknown) => void,
): CampaignPoller {
  let running = false;
  let inFlight = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let nextErrorDelay = POLL_INTERVAL_MS;

  const schedule = (delay: number): void => {
    if (!running) return;
    timer = setTimeout(() => {
      timer = undefined;
      void poll();
    }, delay);
  };

  const poll = async (): Promise<void> => {
    if (!running || inFlight) return;
    inFlight = true;
    try {
      const status = await fetchStatus();
      if (!running) return;
      onStatus(status);
      nextErrorDelay = POLL_INTERVAL_MS;
      schedule(POLL_INTERVAL_MS);
    } catch (error) {
      if (!running) return;
      onError(error);
      schedule(nextErrorDelay);
      nextErrorDelay = Math.min(nextErrorDelay * 2, MAX_BACKOFF_MS);
    } finally {
      inFlight = false;
    }
  };

  return {
    start() {
      if (running) return;
      running = true;
      void poll();
    },
    stop() {
      running = false;
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
    },
  };
}
