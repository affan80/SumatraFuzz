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
