import { generateFixtures } from '@sumatrafuzz/instrumentation/fixtures';

const outIndex = process.argv.indexOf('--out');
if (outIndex < 0 || !process.argv[outIndex + 1]) throw new Error('usage: generate-fixtures.ts --out <directory>');
const output = process.argv[outIndex + 1];
if (!output) throw new Error('usage: generate-fixtures.ts --out <directory>');
for (const file of await generateFixtures(output)) process.stdout.write(`${file}\n`);
