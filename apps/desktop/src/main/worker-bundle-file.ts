import { lstat, open } from 'node:fs/promises';
import { MAX_BUNDLE_BYTES } from './worker-bundle.js';

/** Read only a bounded, regular bundle file selected by the main-process file picker. */
export async function readWorkerBundleFile(filePath: string): Promise<Buffer> {
  const metadata = await lstat(filePath);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size <= 0 ||
    metadata.size > MAX_BUNDLE_BYTES
  ) {
    throw new Error('worker pairing bundle file is invalid or too large');
  }
  const handle = await open(filePath, 'r');
  try {
    const openedMetadata = await handle.stat();
    if (
      !openedMetadata.isFile() ||
      openedMetadata.size !== metadata.size ||
      openedMetadata.size > MAX_BUNDLE_BYTES
    ) {
      throw new Error('worker pairing bundle file changed while opening');
    }
    const buffer = Buffer.alloc(openedMetadata.size + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
      if (offset > MAX_BUNDLE_BYTES) throw new Error('worker pairing bundle file is too large');
    }
    if (offset !== openedMetadata.size)
      throw new Error('worker pairing bundle file changed while reading');
    return buffer.subarray(0, offset);
  } finally {
    await handle.close();
  }
}
