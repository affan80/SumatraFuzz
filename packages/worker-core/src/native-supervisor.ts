import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { isIP } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { VerifiedRunSpec } from './policy.js';
import { verifyFileProofs } from './verified-launch.js';

export class ProcessError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'ProcessError';
  }
}

export interface JobHandle {
  readonly id: string;
  readonly processId: number;
}

export interface ResourceSample {
  readonly cpu_percent: number;
  readonly memory_bytes: number;
  readonly process_count: number;
}

export interface VolumeUsageSample {
  readonly quota_bytes: number;
  readonly available_bytes: number;
  readonly used_bytes: number;
  readonly volume_id: string;
}

export interface NativeTeardownReceipt {
  readonly jobId: string;
  readonly stoppedAtUtc: string;
  readonly remainingProcesses: number;
  readonly exitCode: number | null;
  readonly stopReason: 'requested' | 'timeout' | 'resource_limit' | 'worker_shutdown';
}

export interface NativeSupervisorBinding {
  assertWorkerServiceIdentity(): void;
  assertWorkerServiceNetworkBinding(adapterGuid: string, address: string): void;
  launchSuspended(spec: VerifiedRunSpec): JobHandle;
  stopJob(handle: JobHandle, graceMs: number): NativeTeardownReceipt;
  sampleJob(handle: JobHandle): ResourceSample;
  sampleVolumeUsage(path: string): VolumeUsageSample;
  protectSecret(plaintext: Buffer): Buffer;
  unprotectSecret(ciphertext: Buffer): Buffer;
}

function loadNativeBinding(): NativeSupervisorBinding {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    throw new ProcessError('Windows x64 Job Object supervisor is unsupported on this platform');
  }
  const require = createRequire(import.meta.url);
  const addonPath = resolveNativeSupervisorAddonPath(process.execPath, import.meta.url);
  try {
    return require(addonPath) as NativeSupervisorBinding;
  } catch (cause) {
    throw new ProcessError('Windows supervisor addon is missing or could not be loaded', { cause });
  }
}

/** Resolve the installed addon from the fixed package layout, then fall back to source workspaces. */
export function resolveNativeSupervisorAddonPath(
  executablePath: string,
  moduleUrl: string,
  fileExists: (candidate: string) => boolean = existsSync,
): string {
  const installedRoot = path.resolve(path.dirname(executablePath), '..');
  const installedPath = path.join(
    installedRoot,
    'native',
    'worker-supervisor',
    'build',
    'Release',
    'worker_supervisor.node',
  );
  const sourcePath = fileURLToPath(
    new URL('../../../native/worker-supervisor/build/Release/worker_supervisor.node', moduleUrl),
  );
  return fileExists(installedPath) ? installedPath : sourcePath;
}

export class WindowsJobSupervisor {
  constructor(private readonly binding: NativeSupervisorBinding = loadNativeBinding()) {}

  assertWorkerServiceIdentity(): void {
    try {
      this.binding.assertWorkerServiceIdentity();
    } catch {
      // Native token and SID details are intentionally not propagated to callers.
      throw new ProcessError('Worker service identity verification failed');
    }
  }

  assertWorkerServiceNetworkBinding(adapterGuid: string, address: string): void {
    if (
      typeof adapterGuid !== 'string' ||
      !/^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\})$/i.test(
        adapterGuid,
      ) ||
      typeof address !== 'string' ||
      address.length > 64 ||
      address.includes('%') ||
      isIP(address) === 0
    ) {
      throw new ProcessError('Worker network binding verification failed');
    }
    try {
      this.binding.assertWorkerServiceNetworkBinding(adapterGuid, address);
    } catch {
      throw new ProcessError('Worker network binding verification failed');
    }
  }

  async launchSuspended(spec: VerifiedRunSpec): Promise<JobHandle> {
    try {
      await verifyFileProofs(spec.fileProofs);
      return this.binding.launchSuspended(spec);
    } catch (cause) {
      if (cause instanceof ProcessError) throw cause;
      throw new ProcessError('Verified process launch failed closed', { cause });
    }
  }

  async stopJob(handle: JobHandle, graceMs: number): Promise<NativeTeardownReceipt> {
    try {
      const receipt = this.binding.stopJob(handle, graceMs);
      if (receipt.remainingProcesses !== 0)
        throw new Error('native supervisor reported remaining processes');
      return receipt;
    } catch (cause) {
      throw new ProcessError('Process tree teardown could not be confirmed', { cause });
    }
  }

  async sampleJob(handle: JobHandle): Promise<ResourceSample> {
    try {
      const sample = this.binding.sampleJob(handle);
      if (
        !Number.isFinite(sample.cpu_percent) ||
        !Number.isSafeInteger(sample.memory_bytes) ||
        sample.memory_bytes < 0 ||
        !Number.isSafeInteger(sample.process_count) ||
        sample.process_count < 0
      ) {
        throw new Error('native supervisor returned an invalid resource sample');
      }
      return sample;
    } catch (cause) {
      throw new ProcessError('Job Object resource sampling failed', { cause });
    }
  }

  sampleVolumeUsage(path: string): VolumeUsageSample {
    try {
      const sample = this.binding.sampleVolumeUsage(path);
      if (
        typeof sample.volume_id !== 'string' ||
        !/^\\\\\?\\Volume\{[0-9a-f-]{36}\}\\$/i.test(sample.volume_id) ||
        !Number.isSafeInteger(sample.quota_bytes) ||
        sample.quota_bytes < 1 ||
        !Number.isSafeInteger(sample.available_bytes) ||
        sample.available_bytes < 0 ||
        sample.available_bytes > sample.quota_bytes ||
        !Number.isSafeInteger(sample.used_bytes) ||
        sample.used_bytes !== sample.quota_bytes - sample.available_bytes
      ) {
        throw new Error('native supervisor returned an invalid worker-volume usage sample');
      }
      return sample;
    } catch (cause) {
      throw new ProcessError('Worker-volume quota sampling failed', { cause });
    }
  }

  protectSecret(plaintext: Buffer): Buffer {
    try {
      return this.binding.protectSecret(plaintext);
    } catch (cause) {
      throw new ProcessError('DPAPI secret protection failed', { cause });
    }
  }

  unprotectSecret(ciphertext: Buffer): Buffer {
    try {
      return this.binding.unprotectSecret(ciphertext);
    } catch (cause) {
      throw new ProcessError('DPAPI secret unprotection failed', { cause });
    }
  }
}
