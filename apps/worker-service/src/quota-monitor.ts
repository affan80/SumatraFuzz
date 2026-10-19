import type { SqliteRunStore } from '@sumatrafuzz/run-store';
import type { JobHandle, ResourceSample, VerifiedRunSpec } from '@sumatrafuzz/worker-core';
import type { CampaignLimits, RunId, StopReason } from '@sumatrafuzz/worker-protocol';

export interface QuotaMonitorConfig {
  readonly store: Pick<SqliteRunStore, 'appendMetricSample'>;
  readonly sampleJob: (handle: JobHandle) => Promise<ResourceSample>;
  /** Reads usage from the provisioned worker-volume quota provider. */
  readonly measureWorkerVolumeUsedBytes: () => Promise<number>;
  readonly stopRun: (controllerId: string, runId: string, reason: StopReason) => Promise<unknown>;
  readonly intervalMs?: number;
  readonly now?: () => number;
}

interface MonitoredRun {
  readonly controllerId: string;
  readonly handle: JobHandle;
  readonly limits: CampaignLimits;
  readonly startedAt: number;
  timer?: NodeJS.Timeout;
  sampling: boolean;
  stopping: boolean;
}

export class WorkerQuotaMonitor {
  private readonly runs = new Map<string, MonitoredRun>();
  private readonly intervalMs: number;
  private readonly now: () => number;

  constructor(private readonly config: QuotaMonitorConfig) {
    this.intervalMs = config.intervalMs ?? 5_000;
    this.now = config.now ?? Date.now;
    if (
      !Number.isSafeInteger(this.intervalMs) ||
      this.intervalMs < 250 ||
      this.intervalMs > 60_000
    ) {
      throw new RangeError('quota monitor interval must be between 250 and 60000 ms');
    }
  }

  start(runId: RunId, controllerId: string, handle: JobHandle, spec: VerifiedRunSpec): void {
    if (this.runs.has(runId)) throw new Error('run already has an active quota monitor');
    const run: MonitoredRun = {
      controllerId,
      handle,
      limits: spec.limits,
      startedAt: this.now(),
      sampling: false,
      stopping: false,
    };
    this.runs.set(runId, run);
    this.schedule(runId, run);
  }

  stop(runId: RunId): void {
    const run = this.runs.get(runId);
    if (!run) return;
    run.stopping = true;
    if (run.timer) clearTimeout(run.timer);
    this.runs.delete(runId);
  }

  async sampleOnce(runId: RunId): Promise<StopReason | null> {
    const run = this.runs.get(runId);
    if (!run || run.stopping || run.sampling) return null;
    run.sampling = true;
    try {
      const [sample, diskBytes] = await Promise.all([
        this.config.sampleJob(run.handle),
        this.config.measureWorkerVolumeUsedBytes(),
      ]);
      if (!this.runs.has(runId) || run.stopping) return null;
      if (!Number.isSafeInteger(diskBytes) || diskBytes < 0) {
        throw new Error('worker-volume quota provider returned invalid usage');
      }
      const timestamp = new Date(this.now()).toISOString();
      this.config.store.appendMetricSample(runId, {
        time_utc: timestamp,
        cpu_percent: sample.cpu_percent,
        memory_bytes: sample.memory_bytes,
        disk_bytes: diskBytes,
        process_count: sample.process_count,
      });

      let reason: StopReason | null = null;
      if (sample.process_count === 0) reason = 'native_exit';
      else if (this.now() - run.startedAt >= run.limits.max_duration_s * 1_000)
        reason = 'time_limit';
      else if (sample.cpu_percent > run.limits.max_cpu_percent) reason = 'cpu_limit';
      else if (sample.memory_bytes >= run.limits.max_memory_bytes) reason = 'memory_limit';
      else if (diskBytes >= run.limits.max_disk_bytes) reason = 'disk_limit';

      if (reason) {
        run.stopping = true;
        if (run.timer) clearTimeout(run.timer);
        await this.config.stopRun(run.controllerId, runId, reason);
      }
      return reason;
    } catch (error) {
      if (!run.stopping && this.runs.has(runId)) {
        run.stopping = true;
        if (run.timer) clearTimeout(run.timer);
        await this.config.stopRun(run.controllerId, runId, 'process_failure');
      }
      throw error;
    } finally {
      run.sampling = false;
      if (this.runs.has(runId) && !run.stopping) this.schedule(runId, run);
    }
  }

  private schedule(runId: RunId, run: MonitoredRun): void {
    if (run.stopping || !this.runs.has(runId)) return;
    run.timer = setTimeout(() => {
      void this.sampleOnce(runId).catch(() => undefined);
    }, this.intervalMs);
    run.timer.unref();
  }
}
