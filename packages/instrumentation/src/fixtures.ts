import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const SAMPLES = {
  'page-100.pdf': [100, 100],
  'page-180.pdf': [180, 220],
  'page-300.pdf': [300, 400],
} as const;

export function buildFixturePdf(width: number, height: number): Buffer {
  if (
    !Number.isSafeInteger(width) ||
    !Number.isSafeInteger(height) ||
    width < 1 ||
    height < 1 ||
    width > 10000 ||
    height > 10000
  ) {
    throw new RangeError('page dimensions must be integers from 1 through 10000');
  }
  const chunks = [Buffer.from('%PDF-1.4\n', 'ascii')];
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${width} ${height}] >>`,
  ];
  const offsets: number[] = [];
  for (let i = 0; i < objects.length; i++) {
    offsets.push(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
    chunks.push(Buffer.from(`${i + 1} 0 obj\n${objects[i]}\nendobj\n`, 'ascii'));
  }
  const xref = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  chunks.push(Buffer.from(`xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`, 'ascii'));
  for (const offset of offsets)
    chunks.push(Buffer.from(`${offset.toString().padStart(10, '0')} 00000 n \n`, 'ascii'));
  chunks.push(
    Buffer.from(
      `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`,
      'ascii',
    ),
  );
  return Buffer.concat(chunks);
}

export async function generateFixtures(directory: string): Promise<string[]> {
  const names = Object.keys(SAMPLES);
  await mkdir(directory, { recursive: true });
  const existing = await readdir(directory);
  if (existing.some((name) => !names.includes(name)))
    throw new Error('Refusing to overwrite an unrecognized seed directory');
  const result: string[] = [];
  for (const [name, [width, height]] of Object.entries(SAMPLES)) {
    const destination = path.join(directory, name);
    const expected = buildFixturePdf(width, height);
    try {
      const current = await readFile(destination);
      if (!current.equals(expected))
        throw new Error(`Refusing to overwrite modified seed: ${destination}`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      await writeFile(destination, expected, { flag: 'wx' });
    }
    result.push(destination);
  }
  return result;
}
