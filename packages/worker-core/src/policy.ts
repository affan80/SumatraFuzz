import type { CampaignLimits } from '@sumatrafuzz/worker-protocol';

export interface WorkerPolicy {
  readonly maxLimits: CampaignLimits;
  readonly pinnedTargetLockSha256: string;
  readonly pinnedA4ManifestSha256: string;
  readonly targetLockPath: string;
  readonly a4ManifestPath: string;
  readonly harnessPath: string;
  readonly allowedBinaryRoot: string;
  readonly allowedToolRoot: string;
  readonly allowedInputRoot: string;
  readonly outputRoot: string;
}

export interface VerifiedRunSpec {
  readonly runId: string;
  readonly executable: string;
  readonly argv: readonly string[];
  readonly workingDir: string;
  readonly limits: CampaignLimits;
  readonly evidenceDir: string;
  readonly fileProofs: readonly VerifiedFile[];
}

export interface VerifiedFile {
  readonly path: string;
  readonly root: string;
  readonly sha256: string;
}
