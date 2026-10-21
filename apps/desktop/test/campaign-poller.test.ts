import { afterEach, describe, expect, it, vi } from 'vitest';
import { createCampaignPoller } from '../src/renderer/campaign-poller.js';

afterEach(() => vi.useRealTimers());

describe('campaign status poller', () => {
  it('runs immediately and schedules the next poll one second after completion', async () => {
    vi.useFakeTimers();
    const fetchStatus = vi.fn(async () => ({ state: 'running' }));
    const onStatus = vi.fn();
    const poller = createCampaignPoller(fetchStatus, onStatus, vi.fn());

    poller.start();
    await vi.waitFor(() => expect(fetchStatus).toHaveBeenCalledOnce());
    expect(onStatus).toHaveBeenCalledWith({ state: 'running' });
    await vi.advanceTimersByTimeAsync(999);
    expect(fetchStatus).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => expect(fetchStatus).toHaveBeenCalledTimes(2));
    poller.stop();
  });

  it('never overlaps requests even when a status request is slow', async () => {
    vi.useFakeTimers();
    let finish!: (value: { state: string }) => void;
    const fetchStatus = vi.fn(
      () => new Promise<{ state: string }>((resolve) => (finish = resolve)),
    );
    const poller = createCampaignPoller(fetchStatus, vi.fn(), vi.fn());
    poller.start();
    await vi.waitFor(() => expect(fetchStatus).toHaveBeenCalledOnce());
    await vi.advanceTimersByTimeAsync(20_000);
    expect(fetchStatus).toHaveBeenCalledOnce();
    finish({ state: 'running' });
    await vi.waitFor(() => expect(fetchStatus).toHaveBeenCalledOnce());
    await vi.advanceTimersByTimeAsync(1000);
    await vi.waitFor(() => expect(fetchStatus).toHaveBeenCalledTimes(2));
    poller.stop();
  });

  it('backs off transient errors up to fifteen seconds', async () => {
    vi.useFakeTimers();
    const fetchStatus = vi.fn(async () => {
      throw new Error('temporary');
    });
    const poller = createCampaignPoller(fetchStatus, vi.fn(), vi.fn());
    poller.start();
    await vi.waitFor(() => expect(fetchStatus).toHaveBeenCalledTimes(1));
    for (const [delay, expected] of [
      [1000, 2],
      [2000, 3],
      [4000, 4],
      [8000, 5],
      [15000, 6],
    ] as const) {
      await vi.advanceTimersByTimeAsync(delay);
      await vi.waitFor(() => expect(fetchStatus).toHaveBeenCalledTimes(expected));
    }
    poller.stop();
    expect(fetchStatus).toHaveBeenCalledTimes(6);
  });

  it('stop cancels scheduled and in-flight follow-up polls', async () => {
    vi.useFakeTimers();
    const fetchStatus = vi.fn(async () => ({ state: 'idle' }));
    const poller = createCampaignPoller(fetchStatus, vi.fn(), vi.fn());
    poller.start();
    await vi.waitFor(() => expect(fetchStatus).toHaveBeenCalledOnce());
    poller.stop();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(fetchStatus).toHaveBeenCalledOnce();
  });
});
