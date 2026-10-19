export function generateDeterministicSeed(producer = 'SumatraFuzz Debug'): Buffer {
  if (!/^[A-Za-z0-9 ]+$/.test(producer) || !producer.trim())
    throw new TypeError('producer must be simple ASCII');
  const chunks = [Buffer.from('%PDF-1.4\n')];
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>',
    `<< /Producer (${producer}) >>`,
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
      `trailer\n<< /Root 1 0 R /Size ${objects.length + 1} >>\nstartxref\n${xref}\n%%EOF\n`,
      'ascii',
    ),
  );
  return Buffer.concat(chunks);
}

import { lstat, mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

export async function generateGateFixtures(directory: string): Promise<string[]> {
  const output = path.resolve(directory);
  await mkdir(output, { recursive: true });
  const fixtures = [
    ['page-100.pdf', 100, 100],
    ['page-180.pdf', 180, 220],
    ['page-300.pdf', 300, 400],
  ] as const;
  const allowed = new Set<string>(fixtures.map(([name]) => name));
  for (const entry of await readdir(output)) {
    if (!allowed.has(entry))
      throw new Error('Refusing to overwrite an unrecognized seed directory');
  }
  const files: string[] = [];
  for (const [name, width, height] of fixtures) {
    const file = path.join(output, name);
    const expected = buildPagePdf(width, height);
    try {
      const info = await lstat(file);
      if (!info.isFile() || info.isSymbolicLink() || !(await readFile(file)).equals(expected))
        throw new Error(`Refusing to overwrite modified seed: ${file}`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      await writeFile(file, expected, { flag: 'wx' });
    }
    files.push(file);
  }
  return files;
}

function buildPagePdf(width: number, height: number): Buffer {
  const body = Buffer.from('%PDF-1.4\n', 'ascii');
  const chunks: Buffer[] = [body];
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${width} ${height}] >>`,
  ];
  const offsets = [0];
  let length = body.length;
  for (let index = 0; index < objects.length; index++) {
    offsets.push(length);
    const chunk = Buffer.from(`${index + 1} 0 obj\n${objects[index]}\nendobj\n`, 'ascii');
    chunks.push(chunk);
    length += chunk.length;
  }
  const xref = length;
  chunks.push(Buffer.from(`xref\n0 ${offsets.length}\n0000000000 65535 f \n`, 'ascii'));
  for (const offset of offsets.slice(1))
    chunks.push(Buffer.from(`${offset.toString().padStart(10, '0')} 00000 n \n`, 'ascii'));
  chunks.push(
    Buffer.from(
      `trailer\n<< /Size ${offsets.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`,
      'ascii',
    ),
  );
  return Buffer.concat(chunks);
}
