import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { crc32 } from 'node:zlib';
import { fromBufferPromise } from 'yauzl';

export const MAX_ARCHIVE_BYTES = 32 * 1024 * 1024;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_EXPANDED_BYTES = 64 * 1024 * 1024;
const MAX_FILES = 1024;
const MAX_RATIO = 200;
const PDF_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.pdf$/i;
const RESERVED_NAME = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i;

export interface ImportedInputBundle {
  readonly input_bundle_id: string;
  readonly archive_sha256: string;
  readonly file_count: number;
  readonly expanded_bytes: number;
}

export interface InputBundleImportOptions {
  /** Recheck the worker volume before each extracted file is created. */
  readonly ensureCapacity?: (bytesToWrite: number) => Promise<void>;
}

function reject(message: string): never {
  throw Object.assign(new Error(message), { status: 400 });
}

function validateEntryName(name: string): void {
  if (
    !PDF_NAME.test(name) ||
    name.includes('..') ||
    name.endsWith('.') ||
    RESERVED_NAME.test(name)
  ) {
    reject('input bundle contains an unsafe or non-PDF filename');
  }
}

/** The caller supplies a controller ID established from its authenticated certificate. */
export async function importInputBundle(
  inputRoot: string,
  controllerId: string,
  archive: Buffer,
  options: InputBundleImportOptions = {},
): Promise<ImportedInputBundle> {
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(controllerId)) {
    throw new TypeError('controller ID must be a UUID');
  }
  if (archive.length < 22 || archive.length > MAX_ARCHIVE_BYTES) {
    reject('input bundle archive size is outside policy');
  }
  const rootInfo = await lstat(inputRoot);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
    throw new Error('input root must be a real directory');
  }
  const root = await realpath(inputRoot);
  const controllerRoot = path.join(root, controllerId.toLowerCase());
  await mkdir(controllerRoot, { recursive: true, mode: 0o700 });
  const controllerInfo = await lstat(controllerRoot);
  if (
    !controllerInfo.isDirectory() ||
    controllerInfo.isSymbolicLink() ||
    (await realpath(controllerRoot)) !== controllerRoot
  ) {
    throw new Error('controller input root is redirected');
  }

  const bundleId = randomUUID();
  const staging = path.join(controllerRoot, `.staging-${bundleId}`);
  const destination = path.join(controllerRoot, bundleId);
  await mkdir(staging, { mode: 0o700 });
  let zip: Awaited<ReturnType<typeof fromBufferPromise>> | undefined;
  try {
    zip = await fromBufferPromise(archive, {
      lazyEntries: true,
      decodeStrings: true,
      strictFileNames: true,
      validateEntrySizes: true,
    });
    if (zip.entryCount < 1 || zip.entryCount > MAX_FILES)
      reject('input bundle file count is outside policy');
    const seen = new Set<string>();
    let count = 0;
    let expanded = 0;
    for await (const entry of zip.eachEntry()) {
      validateEntryName(entry.fileName);
      const nameKey = entry.fileName.toLowerCase();
      if (seen.has(nameKey)) reject('input bundle has duplicate filenames');
      seen.add(nameKey);
      if (entry.isEncrypted() || !entry.canDecodeFileData())
        reject('unsupported input bundle entry');
      const unixMode = entry.versionMadeBy >>> 8 === 3 ? entry.externalFileAttributes >>> 16 : 0;
      if (unixMode && (unixMode & 0o170000) !== 0o100000)
        reject('input bundle contains a non-file entry');
      const dosAttributes = entry.externalFileAttributes & 0xffff;
      if ((dosAttributes & 0x10) !== 0 || (dosAttributes & 0x400) !== 0)
        reject('input bundle contains a directory or redirected file entry');
      if (
        !Number.isSafeInteger(entry.uncompressedSize) ||
        entry.uncompressedSize < 1 ||
        entry.uncompressedSize > MAX_FILE_BYTES ||
        !Number.isSafeInteger(entry.compressedSize) ||
        entry.compressedSize < 1 ||
        entry.uncompressedSize > entry.compressedSize * MAX_RATIO
      ) {
        reject('input bundle entry exceeds expansion policy');
      }
      expanded += entry.uncompressedSize;
      if (expanded > MAX_EXPANDED_BYTES) reject('input bundle exceeds expanded-size policy');
      await options.ensureCapacity?.(entry.uncompressedSize);

      let actual = 0;
      let checksum = 0;
      const limiter = new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          actual += chunk.length;
          checksum = crc32(chunk, checksum);
          callback(
            actual <= entry.uncompressedSize && actual <= MAX_FILE_BYTES
              ? null
              : new Error('input bundle entry expanded past its declared size'),
            chunk,
          );
        },
      });
      const flags =
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0);
      const output = path.join(staging, entry.fileName);
      const handle = await open(output, flags, 0o600);
      try {
        await pipeline(await zip.openReadStreamPromise(entry), limiter, handle.createWriteStream());
      } finally {
        await handle.close();
      }
      if (actual !== entry.uncompressedSize) reject('input bundle entry size mismatch');
      if (checksum >>> 0 !== entry.crc32) reject('input bundle entry CRC mismatch');
      const syncHandle = await open(output, 'r+');
      try {
        await syncHandle.sync();
      } finally {
        await syncHandle.close();
      }
      count += 1;
    }
    if (count < 1) reject('input bundle contains no PDF files');
    await rename(staging, destination);
    return {
      input_bundle_id: bundleId,
      archive_sha256: createHash('sha256').update(archive).digest('hex'),
      file_count: count,
      expanded_bytes: expanded,
    };
  } finally {
    zip?.close();
    await rm(staging, { recursive: true, force: true });
  }
}
