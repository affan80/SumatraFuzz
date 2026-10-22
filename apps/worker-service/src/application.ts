import path from 'node:path';
import { SqliteRunStore } from '@sumatrafuzz/run-store';
import {
  type VolumeUsageSample,
  WindowsJobSupervisor,
  type WorkerPolicy,
} from '@sumatrafuzz/worker-core';
import { FileEvidenceRepository } from './artifacts.js';
import { type WorkerCoordinatorConfig, WorkerRunCoordinator } from './run-coordinator.js';
import { createWorkerServer, type WorkerServer, type WorkerServerConfig } from './server.js';

export interface WorkerApplicationConfig
  extends Omit<WorkerServerConfig, 'handlers' | 'store'>,
    Omit<
      WorkerCoordinatorConfig,
      'workerId' | 'store' | 'evidence' | 'policy' | 'supervisor' | 'measureWorkerVolumeUsedBytes'
    > {
  readonly databasePath: string;
  readonly policy: WorkerPolicy;
  readonly supervisor?: WorkerCoordinatorConfig['supervisor'];
  readonly readWorkerVolumeUsage?: () => Promise<VolumeUsageSample>;
}

export interface WorkerApplication {
  readonly server: WorkerServer;
  readonly store: SqliteRunStore;
  readonly coordinator: WorkerRunCoordinator;
  readonly startupRecovery: 'clean' | 'finalized_after_restart' | 'lease_held_for_operator';
  close(): Promise<void>;
}

/** Compose the authenticated API, durable journal, verified launcher and evidence repository. */
export async function createWorkerApplication(
  config: WorkerApplicationConfig,
): Promise<WorkerApplication> {
  if (path.resolve(config.inputRoot) !== path.resolve(config.policy.allowedInputRoot)) {
    throw new TypeError('input root must match the verified worker policy root');
  }
  if (config.workerId.length === 0) throw new TypeError('worker ID is required');
  const store = SqliteRunStore.open(config.databasePath);
  try {
    const supervisor = config.supervisor ?? new WindowsJobSupervisor();
    const readVolumeUsage =
      config.readWorkerVolumeUsage ?? (async () => supervisor.sampleVolumeUsage(config.inputRoot));
    const measureWorkerVolumeUsedBytes = async (): Promise<number> => {
      const usage = await readVolumeUsage();
      if (
        usage.quota_bytes !== config.policy.maxLimits.max_disk_bytes ||
        !Number.isSafeInteger(usage.used_bytes) ||
        usage.used_bytes < 0 ||
        !Number.isSafeInteger(usage.available_bytes) ||
        usage.available_bytes < 0 ||
        usage.used_bytes + usage.available_bytes !== usage.quota_bytes
      ) {
        throw new Error('provisioned worker-volume quota does not match the verified disk limit');
      }
      return usage.used_bytes;
    };
    await measureWorkerVolumeUsedBytes();
    const evidence = new FileEvidenceRepository(
      store,
      config.policy.outputRoot,
      config.policy.maxLimits.max_disk_bytes,
    );
    const coordinator = new WorkerRunCoordinator({
      workerId: config.workerId,
      store,
      policy: config.policy,
      supervisor,
      evidence,
      measureWorkerVolumeUsedBytes,
      ...(config.quotaIntervalMs === undefined ? {} : { quotaIntervalMs: config.quotaIntervalMs }),
      ...(config.verifyLaunch === undefined ? {} : { verifyLaunch: config.verifyLaunch }),
    });
    const startupRecovery = await coordinator.reconcileStartup();
    const server = await createWorkerServer({
      host: config.host,
      mode: config.mode,
      port: config.port,
      workerId: config.workerId,
      key: config.key,
      cert: config.cert,
      ca: config.ca,
      pairedControllers: config.pairedControllers,
      ...(config.revokedFingerprints === undefined
        ? {}
        : { revokedFingerprints: config.revokedFingerprints }),
      handlers: coordinator,
      store,
      inputRoot: config.inputRoot,
      ensureInputCapacity: async (bytesToWrite) => {
        const usedBytes = await measureWorkerVolumeUsedBytes();
        if (usedBytes + bytesToWrite > config.policy.maxLimits.max_disk_bytes) {
          throw Object.assign(new Error('worker disk limit would be exceeded'), { status: 507 });
        }
      },
      maxInputBundleBytes: config.policy.maxLimits.max_disk_bytes,
      ...(config.maxRequestBytes === undefined ? {} : { maxRequestBytes: config.maxRequestBytes }),
      ...(config.admissionPolicy === undefined ? {} : { admissionPolicy: config.admissionPolicy }),
      ...(config.shutdownTimeoutMs === undefined
        ? {}
        : { shutdownTimeoutMs: config.shutdownTimeoutMs }),
    });
    return {
      server,
      store,
      coordinator,
      startupRecovery,
      close: async () => {
        // A timed-out drain leaves SQLite open; the service host will force-stop this process.
        // Closing it while an admitted handler can still resume would corrupt recovery state.
        await server.close();
        store.close();
      },
    };
  } catch (error) {
    store.close();
    throw error;
  }
}
