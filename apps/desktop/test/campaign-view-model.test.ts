import { describe, expect, it } from 'vitest';
import {
  parseCampaignStatus,
  parseInputBundleSummary,
} from '../src/renderer/campaign-view-model.js';

const workerId = '11111111-1111-4111-8111-111111111111';
const runId = '22222222-2222-4222-8222-222222222222';
const baseStatus = {
  connection_state: 'connected',
  worker_id: workerId,
  max_limits: {
    max_duration_s: 300,
    max_memory_bytes: 64 * 1024 * 1024,
    max_disk_bytes: 2048,
    max_cpu_percent: 80,
  },
  imported_bundle: {
    archive_sha256: 'a'.repeat(64),
    file_count: 2,
    expanded_bytes: 4096,
  },
  campaign_label: 'nightly',
  active_run: {
    run_id: runId,
    worker_id: workerId,
    state: 'running',
    last_event_seq: 3n,
    stop_reason: null,
  },
};

describe('campaign renderer view mapping', () => {
  it('accepts only a validated upload summary', () => {
    expect(parseInputBundleSummary(baseStatus.imported_bundle)).toEqual({
      archiveSha256: 'a'.repeat(64),
      fileCount: 2,
      expandedBytes: 4096,
    });
    expect(
      parseInputBundleSummary({
        ...baseStatus.imported_bundle,
        input_bundle_id: 'renderer-must-not-receive-this',
      }),
    ).toBeNull();
    expect(parseInputBundleSummary({ ...baseStatus.imported_bundle, file_count: 0 })).toBeNull();
  });

  it('maps unknown run states and stop reasons to fixed safe labels', () => {
    const status = parseCampaignStatus({
      ...baseStatus,
      active_run: {
        ...baseStatus.active_run,
        state: 'worker-supplied-html',
        stop_reason: 'mystery',
      },
    });
    expect(status?.runState).toBe('Unknown state');
    expect(status?.stopReason).toBeNull();
  });

  it('rejects malformed policy limits and worker-mismatched run summaries', () => {
    expect(
      parseCampaignStatus({
        ...baseStatus,
        max_limits: { ...baseStatus.max_limits, max_memory_bytes: 16 * 1024 * 1024 - 1 },
      }),
    ).toBeNull();
    expect(
      parseCampaignStatus({
        ...baseStatus,
        max_limits: { ...baseStatus.max_limits, max_memory_bytes: Number.POSITIVE_INFINITY },
      }),
    ).toBeNull();
    expect(
      parseCampaignStatus({
        ...baseStatus,
        active_run: { ...baseStatus.active_run, worker_id: '33333333-3333-4333-8333-333333333333' },
      }),
    ).toBeNull();
  });

  it('allows only documented stop reasons and displays disconnected state safely', () => {
    expect(
      parseCampaignStatus({
        ...baseStatus,
        active_run: { ...baseStatus.active_run, stop_reason: 'memory_limit' },
      })?.stopReason,
    ).toBe('memory_limit');
    expect(
      parseCampaignStatus({
        connection_state: 'disconnected',
        worker_id: null,
        max_limits: null,
        imported_bundle: null,
        campaign_label: null,
        active_run: null,
      })?.connectionState,
    ).toBe('disconnected');
  });
});
