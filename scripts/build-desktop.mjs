import { cp, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const rendererOutput = path.join(repositoryRoot, 'apps', 'desktop', 'dist', 'renderer');
const resourcesOutput = path.join(repositoryRoot, 'apps', 'desktop', 'dist', 'resources');
await mkdir(rendererOutput, { recursive: true });
await mkdir(resourcesOutput, { recursive: true });
await cp(
  path.join(repositoryRoot, 'apps', 'desktop', 'src', 'renderer', 'index.html'),
  path.join(rendererOutput, 'index.html'),
);
await cp(
  path.join(repositoryRoot, 'apps', 'desktop', 'dist', 'src', 'renderer', 'app.js'),
  path.join(rendererOutput, 'app.js'),
);
for (const filename of ['campaign-poller.js', 'campaign-view-model.js']) {
  await cp(
    path.join(repositoryRoot, 'apps', 'desktop', 'dist', 'src', 'renderer', filename),
    path.join(rendererOutput, filename),
  );
}
await cp(
  path.join(repositoryRoot, 'apps', 'desktop', 'resources', 'worker-bundle-signing-key.pem'),
  path.join(resourcesOutput, 'worker-bundle-signing-key.pem'),
);
