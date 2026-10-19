import { createRequire } from 'node:module';
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
}

export interface NativeTeardownReceipt {
  readonly jobId: string;
  readonly stoppedAtUtc: string;
  readonly remainingProcesses: number;
  readonly exitCode: number | null;
  readonly stopReason: 'requested' | 'timeout' | 'resource_limit' | 'worker_shutdown';
}

export interface NativeSupervisorBinding {
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
  const addonPath = fileURLToPath(
    new URL(
      '../../../native/worker-supervisor/build/Release/worker_supervisor.node',
      import.meta.url,
    ),
  );
  try {
    return require(addonPath) as NativeSupervisorBinding;
  } catch (cause) {
    throw new ProcessError('Windows supervisor addon is missing or could not be loaded', { cause });
  }
}

export class WindowsJobSupervisor {
  constructor(private readonly binding: NativeSupervisorBinding = loadNativeBinding()) {}

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
