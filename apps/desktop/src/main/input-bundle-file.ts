import { type FileHandle, lstat, open } from 'node:fs/promises';

export const MAX_INPUT_BUNDLE_BYTES = 32 * 1024 * 1024;
type OpenSelectedFile = (filePath: string, flags: 'r') => Promise<FileHandle>;

/** Read bounded bytes from a regular picker-selected file; never return its path. */
export async function readInputBundleFile(
  filePath: string,
  openSelectedFile: OpenSelectedFile = open,
): Promise<Buffer> {
  const metadata = await lstat(filePath, { bigint: true });
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size <= 0n ||
    metadata.size > BigInt(MAX_INPUT_BUNDLE_BYTES)
  ) {
    throw new Error('campaign input archive file is invalid or too large');
  }
  const handle = await openSelectedFile(filePath, 'r');
  try {
    const openedMetadata = await handle.stat({ bigint: true });
    if (
      !openedMetadata.isFile() ||
      openedMetadata.dev !== metadata.dev ||
      openedMetadata.ino !== metadata.ino ||
      openedMetadata.mtimeNs !== metadata.mtimeNs ||
      openedMetadata.size !== metadata.size ||
      openedMetadata.size > BigInt(MAX_INPUT_BUNDLE_BYTES)
    ) {
      throw new Error('campaign input archive changed while opening');
    }
    const expectedSize = Number(openedMetadata.size);
    const buffer = Buffer.alloc(expectedSize + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
      if (offset > MAX_INPUT_BUNDLE_BYTES) throw new Error('campaign input archive is too large');
    }
    const finalMetadata = await handle.stat({ bigint: true });
    if (
      finalMetadata.size !== openedMetadata.size ||
      finalMetadata.mtimeNs !== openedMetadata.mtimeNs ||
      offset !== expectedSize
    ) {
      throw new Error('campaign input archive changed while reading');
    }
    return buffer.subarray(0, offset);
  } finally {
    await handle.close();
  }
}
