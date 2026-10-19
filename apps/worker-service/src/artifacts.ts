import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, opendir } from 'node:fs/promises';
import path from 'node:path';
import type { FinalArtifact, SqliteRunStore } from '@sumatrafuzz/run-store';
import { verifyPathWithinRoot } from '@sumatrafuzz/worker-core';
import { asRunId } from '@sumatrafuzz/worker-protocol';
import type { RunEvidence } from './run-coordinator.js';

const MAX_ARTIFACTS = 10_000;
const MAX_TREE_ENTRIES = 20_000;
const MAX_DEPTH = 8;
const MAX_CHUNK_BYTES = 16 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;

function missing(): never {
  throw Object.assign(new Error('artifact not found'), { status: 404 });
}

function runPath(root: string, runId: string): string {
  if (!UUID.test(runId)) missing();
  return path.join(root, runId);
}

async function readAndHash(
  file: string,
  root: string,
  maximumBytes: number,
  range?: { start: number; end: number },
): Promise<{ sha256: string; size: number; bytes?: Buffer }> {
  await verifyPathWithinRoot(file, root);
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const info = await handle.stat();
    if (!info.isFile() || !Number.isSafeInteger(info.size) || info.size > maximumBytes) {
      throw new Error('artifact is not a bounded regular file');
    }
    if (
      range &&
      (range.start < 0 ||
        range.end < range.start ||
        range.end >= info.size ||
        range.end - range.start + 1 > MAX_CHUNK_BYTES)
    ) {
      throw Object.assign(new Error('unsatisfiable artifact range'), { status: 416 });
    }
    const digest = createHash('sha256');
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, Math.max(1, info.size)));
    const output = range ? Buffer.alloc(range.end - range.start + 1) : undefined;
    let offset = 0;
    while (offset < info.size) {
      const count = Math.min(buffer.length, info.size - offset);
      const { bytesRead } = await handle.read(buffer, 0, count, offset);
      if (bytesRead !== count) throw new Error('artifact changed during read');
      digest.update(buffer.subarray(0, bytesRead));
      if (range && output) {
        const overlapStart = Math.max(offset, range.start);
        const overlapEnd = Math.min(offset + bytesRead, range.end + 1);
        if (overlapStart < overlapEnd) {
          buffer.copy(
            output,
            overlapStart - range.start,
            overlapStart - offset,
            overlapEnd - offset,
          );
        }
      }
      offset += bytesRead;
    }
    const afterward = await handle.stat();
    if (afterward.size !== info.size || afterward.mtimeMs !== info.mtimeMs) {
      throw new Error('artifact changed during read');
    }
    return { sha256: digest.digest('hex'), size: info.size, ...(output ? { bytes: output } : {}) };
  } finally {
    await handle.close();
  }
}

export class FileEvidenceRepository implements RunEvidence {
  constructor(
    private readonly store: SqliteRunStore,
    private readonly outputRoot: string,
    private readonly maxTotalBytes: number,
  ) {
    if (!Number.isSafeInteger(maxTotalBytes) || maxTotalBytes < 1) {
      throw new RangeError('invalid evidence byte limit');
    }
  }

  async finalize(runId: string, evidenceDir: string): Promise<readonly FinalArtifact[]> {
    const root = runPath(this.outputRoot, runId);
    if (path.resolve(root) !== path.resolve(evidenceDir))
      throw new Error('run evidence directory mismatch');
    await verifyPathWithinRoot(root, this.outputRoot);
    const rootInfo = await lstat(root);
    if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink())
      throw new Error('run evidence is not a real directory');
    const artifacts: FinalArtifact[] = [];
    let total = 0;
    let visited = 0;
    const visit = async (directory: string, depth: number): Promise<void> => {
      if (depth > MAX_DEPTH) throw new Error('run evidence nesting exceeds policy');
      const entries = await opendir(directory);
      for await (const entry of entries) {
        visited += 1;
        if (visited > MAX_TREE_ENTRIES) throw new Error('run evidence tree exceeds entry policy');
        const file = path.join(directory, entry.name);
        if (entry.isSymbolicLink()) throw new Error('run evidence contains a redirected path');
        await verifyPathWithinRoot(file, root);
        if (entry.isDirectory()) {
          await visit(file, depth + 1);
          continue;
        }
        if (!entry.isFile()) throw new Error('run evidence contains a non-file entry');
        if (artifacts.length >= MAX_ARTIFACTS)
          throw new Error('run evidence file count exceeds policy');
        const relativePath = path.relative(root, file).split(path.sep).join('/');
        const remaining = this.maxTotalBytes - total;
        const measured = await readAndHash(file, root, remaining);
        total += measured.size;
        artifacts.push({
          artifactId: createHash('sha256').update(relativePath).digest('hex').slice(0, 32),
          sha256: measured.sha256,
          relativePath,
          sizeBytes: measured.size,
        });
      }
    };
    await visit(root, 0);
    if (artifacts.length === 0) throw new Error('run produced no evidence files');
    return artifacts;
  }

  async manifest(runId: string): Promise<unknown> {
    const artifacts = this.store.finalArtifacts(asRunId(runId));
    const revision = createHash('sha256').update(JSON.stringify(artifacts)).digest('hex');
    return {
      run_id: runId,
      revision,
      artifacts: artifacts.map((artifact) => ({
        artifact_id: artifact.artifactId,
        relative_path: artifact.relativePath,
        sha256: artifact.sha256,
        size_bytes: artifact.sizeBytes,
      })),
    };
  }

  async artifactMetadata(
    runId: string,
    artifactId: string,
  ): Promise<{ etag: string; totalBytes: number }> {
    const artifact = this.find(runId, artifactId);
    return { etag: artifact.sha256, totalBytes: artifact.sizeBytes };
  }

  async artifact(runId: string, artifactId: string, range: { start: number; end: number }) {
    const artifact = this.find(runId, artifactId);
    const root = runPath(this.outputRoot, runId);
    const file = path.join(root, ...artifact.relativePath.split('/'));
    const measured = await readAndHash(file, root, this.maxTotalBytes, range);
    if (
      measured.sha256 !== artifact.sha256 ||
      measured.size !== artifact.sizeBytes ||
      !measured.bytes
    ) {
      throw new Error('final artifact no longer matches its indexed hash');
    }
    return {
      etag: artifact.sha256,
      totalBytes: artifact.sizeBytes,
      start: range.start,
      end: range.end,
      bytes: measured.bytes,
    };
  }

  private find(runId: string, artifactId: string): FinalArtifact {
    if (!UUID.test(runId) || !/^[A-Za-z0-9_-]{1,128}$/.test(artifactId)) missing();
    const artifact = this.store
      .finalArtifacts(asRunId(runId))
      .find((item) => item.artifactId === artifactId);
    return artifact ?? missing();
  }
}
