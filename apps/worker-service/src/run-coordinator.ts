import { createHash } from 'node:crypto';
import path from 'node:path';
import type { FinalArtifact, SqliteRunStore, TeardownReceipt } from '@sumatrafuzz/run-store';
import {
  type JobHandle,
  type NativeTeardownReceipt,
  type VerifiedRunSpec,
  verifyAndBuildLaunch,
  type WindowsJobSupervisor,
  type WorkerPolicy,
} from '@sumatrafuzz/worker-core';
import {
  asControllerId,
  asRunId,
  MIN_CAMPAIGN_MEMORY_BYTES,
  type RunRequest,
  type RunState,
  type StopReason,
  WorkerError,
  WorkerProtocolError,
} from '@sumatrafuzz/worker-protocol';
import { WorkerQuotaMonitor } from './quota-monitor.js';
import type { WorkerApiHandlers, WorkerEventRecord } from './server.js';

type Supervisor = Pick<
  WindowsJobSupervisor,
  'launchSuspended' | 'stopJob' | 'sampleJob' | 'sampleVolumeUsage'
>;

export interface RunEvidence {
  finalize(runId: string, evidenceDir: string): Promise<readonly FinalArtifact[]>;
  manifest(runId: string): Promise<unknown>;
  artifactMetadata(
    runId: string,
    artifactId: string,
  ): Promise<{ etag: string; totalBytes: number }>;
  artifact(
    runId: string,
    artifactId: string,
    range: { start: number; end: number },
  ): Promise<{
    etag: string;
    totalBytes: number;
    start: number;
    end: number;
    bytes: Buffer;
  }>;
}

export interface WorkerCoordinatorConfig {
  readonly workerId: string;
  readonly store: SqliteRunStore;
  readonly policy: WorkerPolicy;
  readonly supervisor: Supervisor;
  readonly evidence: RunEvidence;
  readonly measureWorkerVolumeUsedBytes: () => Promise<number>;
  readonly quotaIntervalMs?: number;
  readonly verifyLaunch?: typeof verifyAndBuildLaunch;
}

function conflict(message: string): never {
  throw Object.assign(new Error(message), { status: 409 });
}

function requestDigest(request: RunRequest): string {
  return createHash('sha256')
    .update(
      JSON.stringify({
        request_id: request.request_id,
        controller_id: request.controller_id,
        input_bundle_id: request.input_bundle_id,
        target_lock_sha256: request.target_lock_sha256,
        limits: {
          max_duration_s: request.limits.max_duration_s,
          max_memory_bytes: request.limits.max_memory_bytes,
          max_disk_bytes: request.limits.max_disk_bytes,
          max_cpu_percent: request.limits.max_cpu_percent,
        },
        label: request.label,
      }),
    )
    .digest('hex');
}

const STOP_REASONS = new Set<StopReason>([
  'requested',
  'time_limit',
  'cpu_limit',
  'memory_limit',
  'disk_limit',
  'native_exit',
  'process_failure',
  'worker_restart',
]);

export class WorkerRunCoordinator implements WorkerApiHandlers {
  private readonly active = new Map<
    string,
    { handle: JobHandle; spec: VerifiedRunSpec; receipt?: TeardownReceipt }
  >();
  private readonly quotaMonitor: WorkerQuotaMonitor;

  constructor(private readonly config: WorkerCoordinatorConfig) {
    this.quotaMonitor = new WorkerQuotaMonitor({
      store: config.store,
      sampleJob: (handle) => config.supervisor.sampleJob(handle),
      measureWorkerVolumeUsedBytes: config.measureWorkerVolumeUsedBytes,
      ...(config.quotaIntervalMs === undefined ? {} : { intervalMs: config.quotaIntervalMs }),
      stopRun: (controllerId, runId, reason) => this.stopRun(controllerId, runId, reason),
    });
  }

  async reconcileStartup(): Promise<
    'clean' | 'finalized_after_restart' | 'lease_held_for_operator'
  > {
    const active = this.config.store.activeRunSnapshot();
    if (!active) return 'clean';
    if (active.state === 'stopping' && this.config.store.teardownReceipt(active.runId)) {
      await this.stopRun(active.controllerId, active.runId);
      return 'finalized_after_restart';
    }
    return 'lease_held_for_operator';
  }

  private requireOwnership(controllerId: string, runId: string): void {
    if (!this.config.store.ownsRun(asControllerId(controllerId), asRunId(runId))) {
      throw Object.assign(new Error('run not found'), { status: 404 });
    }
  }

  async capabilities(controllerId: string): Promise<unknown> {
    return {
      worker_id: this.config.workerId,
      controller_id: controllerId,
      protocol_version: 1,
      target_lock_sha256: this.config.policy.pinnedTargetLockSha256,
      max_limits: this.config.policy.maxLimits,
    };
  }

  async activeRun(controllerId: string): Promise<unknown> {
    const active = this.config.store.activeRunSnapshot();
    if (!active || active.controllerId.toLowerCase() !== controllerId.toLowerCase()) return null;
    return this.getRun(controllerId, active.runId);
  }

  async startRun(controllerId: string, request: RunRequest): Promise<unknown> {
    if (request.controller_id !== controllerId) {
      throw Object.assign(new Error('request controller does not match authenticated controller'), {
        status: 403,
      });
    }
    if (request.limits.max_memory_bytes < MIN_CAMPAIGN_MEMORY_BYTES) {
      throw new WorkerProtocolError(WorkerError.InvalidConfig);
    }
    if (request.limits.max_disk_bytes !== this.config.policy.maxLimits.max_disk_bytes) {
      throw new WorkerProtocolError(WorkerError.InvalidConfig);
    }
    const controller = asControllerId(controllerId);
    const digest = requestDigest(request);
    const prior = this.config.store.findRequest(controller, request.request_id);
    if (prior) {
      if (prior.payloadDigest !== digest) conflict('idempotency key reused with another request');
      return this.getRun(controllerId, prior.runId);
    }

    const policy: WorkerPolicy = {
      ...this.config.policy,
      allowedInputRoot: path.join(this.config.policy.allowedInputRoot, controllerId.toLowerCase()),
    };
    const spec = await (this.config.verifyLaunch ?? verifyAndBuildLaunch)(request, policy);
    const outcome = this.config.store.claimWorkerSlot(
      controller,
      request.request_id,
      digest,
      asRunId(spec.runId),
    );
    if (outcome.kind === 'worker_busy') conflict('worker already has an active campaign');
    if (outcome.kind === 'existing') return this.getRun(controllerId, outcome.runId);
    this.config.store.transitionState(outcome.runId, 'created', 'preparing', 'state_changed');
    let handle: JobHandle | undefined;
    try {
      handle = await this.config.supervisor.launchSuspended(spec);
      this.config.store.transitionState(outcome.runId, 'preparing', 'running', 'state_changed');
      this.active.set(outcome.runId, { handle, spec });
      this.quotaMonitor.start(outcome.runId, controllerId, handle, spec);
      return this.getRun(controllerId, outcome.runId);
    } catch (cause) {
      this.quotaMonitor.stop(outcome.runId);
      if (handle) {
        // A launched process must be torn down before the durable lease can be released.
        const receipt = await this.config.supervisor.stopJob(handle, 0);
        const state = this.config.store.runState(outcome.runId);
        if (state === 'preparing' || state === 'running')
          this.config.store.transitionState(outcome.runId, state, 'failed', 'state_changed');
        this.config.store.releaseAfterTeardown(outcome.runId, {
          ...receipt,
          stopReason: 'process_failure',
        });
      } else if (this.config.store.runState(outcome.runId) === 'preparing') {
        // Keep the slot after an ambiguous native launch failure until explicit reconciliation.
        this.config.store.transitionState(outcome.runId, 'preparing', 'failed', 'state_changed');
      }
      throw cause;
    }
  }

  async getRun(controllerId: string, runId: string): Promise<unknown> {
    this.requireOwnership(controllerId, runId);
    const snapshot = this.config.store.runSnapshot(asRunId(runId));
    const receipt = this.config.store.teardownReceipt(asRunId(runId));
    const stopReason = receipt && STOP_REASONS.has(receipt.stopReason) ? receipt.stopReason : null;
    return {
      run_id: runId,
      worker_id: this.config.workerId,
      state: snapshot.state,
      last_event_seq: snapshot.lastSequence.toString(),
      stop_reason: stopReason,
    };
  }

  async stopRun(
    controllerId: string,
    runId: string,
    reason: StopReason = 'requested',
  ): Promise<unknown> {
    this.requireOwnership(controllerId, runId);
    const active = this.active.get(runId);
    const current = this.config.store.runState(asRunId(runId));
    if (current === 'completed' || current === 'failed' || current === 'interrupted') {
      this.quotaMonitor.stop(asRunId(runId));
      return this.getRun(controllerId, runId);
    }
    if (current !== 'running' && current !== 'stopping')
      conflict('run is not in a stoppable state');
    let transitionFailed = false;
    if (current === 'running') {
      try {
        this.config.store.transitionState(asRunId(runId), 'running', 'stopping', 'state_changed');
      } catch {
        // Still terminate the native job if journaling the stopping state fails.
        transitionFailed = true;
      }
    }
    let receipt = this.config.store.teardownReceipt(asRunId(runId));
    if (!receipt) {
      if (!active) conflict('run has no durable teardown receipt or live Job Object handle');
      if (active.receipt) {
        receipt = active.receipt;
      } else {
        const nativeReceipt: NativeTeardownReceipt = await this.config.supervisor.stopJob(
          active.handle,
          1_000,
        );
        if (nativeReceipt.jobId !== active.handle.id || nativeReceipt.remainingProcesses !== 0) {
          throw new Error('native teardown receipt does not match the active process job');
        }
        receipt = { ...nativeReceipt, stopReason: reason };
        active.receipt = receipt;
      }
    }
    if (transitionFailed) {
      try {
        this.config.store.transitionState(asRunId(runId), 'running', 'stopping', 'state_changed');
      } catch {
        // A durable teardown receipt keeps the worker slot reserved for startup reconciliation.
        throw new Error('could not persist stopping state after native teardown');
      }
    }
    if (!this.config.store.teardownReceipt(asRunId(runId))) {
      this.config.store.recordTeardownReceipt(asRunId(runId), receipt);
    }
    let next: Extract<RunState, 'completed' | 'failed'> =
      reason === 'process_failure' || reason === 'native_exit' ? 'failed' : 'completed';
    let artifacts: readonly FinalArtifact[] = [];
    try {
      const evidenceDir =
        active?.spec.evidenceDir ?? path.join(this.config.policy.outputRoot, runId);
      artifacts = await this.config.evidence.finalize(runId, evidenceDir);
    } catch {
      next = 'failed';
    }
    this.config.store.finalizeAfterTeardown(asRunId(runId), next, artifacts, receipt);
    this.active.delete(runId);
    this.quotaMonitor.stop(asRunId(runId));
    return this.getRun(controllerId, runId);
  }

  async eventsAfter(
    controllerId: string,
    runId: string,
    sequence: string,
    limit: number,
  ): Promise<readonly WorkerEventRecord[]> {
    this.requireOwnership(controllerId, runId);
    return this.config.store
      .readEventsAfter(asRunId(runId), BigInt(sequence), limit)
      .map((event) => ({
        seq: event.seq.toString(),
        event: { ...event, seq: event.seq.toString() },
      }));
  }

  async manifest(controllerId: string, runId: string): Promise<unknown> {
    this.requireOwnership(controllerId, runId);
    return this.config.evidence.manifest(runId);
  }

  async artifactMetadata(controllerId: string, runId: string, artifactId: string) {
    this.requireOwnership(controllerId, runId);
    return this.config.evidence.artifactMetadata(runId, artifactId);
  }

  async artifact(
    controllerId: string,
    runId: string,
    artifactId: string,
    range: { start: number; end: number },
  ) {
    this.requireOwnership(controllerId, runId);
    return this.config.evidence.artifact(runId, artifactId, range);
  }
}
