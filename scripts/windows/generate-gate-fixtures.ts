import { generateGateFixtures } from '@sumatrafuzz/instrumentation/seed';

const index = process.argv.indexOf('--output-dir');
const directory = index < 0 ? undefined : process.argv[index + 1];
if (!directory) throw new Error('usage: generate-gate-fixtures.ts --output-dir <directory>');
for (const file of await generateGateFixtures(directory)) process.stdout.write(`${file}\n`);
