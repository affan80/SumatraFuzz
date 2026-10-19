interface PublicWorkerIdentity {
  readonly workerId: string;
  readonly baseUrl: string;
}

function requiredElement<T extends HTMLElement>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) throw new Error('desktop renderer controls are unavailable');
  return element;
}

const status = requiredElement<HTMLElement>('#status');
const details = requiredElement<HTMLDListElement>('#worker-details');
const workerId = requiredElement<HTMLElement>('#worker-id');
const workerEndpoint = requiredElement<HTMLElement>('#worker-endpoint');
const pairButton = requiredElement<HTMLButtonElement>('#pair-worker');
const unpairButton = requiredElement<HTMLButtonElement>('#unpair-worker');

function showWorker(identity: PublicWorkerIdentity | null): void {
  details.hidden = identity === null;
  workerId.textContent = identity?.workerId ?? '';
  workerEndpoint.textContent = identity?.baseUrl ?? '';
  unpairButton.disabled = identity === null;
}

function parseWorker(value: unknown): PublicWorkerIdentity | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (typeof record.worker_id !== 'string' || typeof record.baseUrl !== 'string') return null;
  return { workerId: record.worker_id, baseUrl: record.baseUrl };
}

async function refreshWorker(): Promise<void> {
  try {
    const workers = await window.sumatraFuzz.listWorkers();
    const identity = Array.isArray(workers) ? parseWorker(workers[0]) : null;
    showWorker(identity);
    status.textContent = identity
      ? 'Worker connected and certificate-pinned.'
      : 'No worker is paired.';
  } catch {
    showWorker(null);
    status.textContent = 'No worker is paired or the worker is unavailable.';
  }
}

pairButton.addEventListener('click', async () => {
  pairButton.disabled = true;
  unpairButton.disabled = true;
  status.textContent = 'Select a signed pairing bundle…';
  try {
    const result = await window.sumatraFuzz.pairWorker();
    if (
      typeof result === 'object' &&
      result !== null &&
      'cancelled' in result &&
      result.cancelled
    ) {
      status.textContent = 'Pairing cancelled.';
    } else {
      status.textContent = 'Bundle verified and worker identity confirmed.';
      await refreshWorker();
    }
  } catch {
    status.textContent = 'Pairing failed. Check the signed bundle and worker network connection.';
  } finally {
    pairButton.disabled = false;
    await refreshWorker();
  }
});

unpairButton.addEventListener('click', async () => {
  unpairButton.disabled = true;
  pairButton.disabled = true;
  status.textContent = 'Removing the paired worker…';
  try {
    await window.sumatraFuzz.unpairWorker();
    showWorker(null);
    status.textContent = 'Worker unpaired.';
  } catch {
    status.textContent = 'Could not remove the paired worker profile.';
  } finally {
    pairButton.disabled = false;
  }
});

void refreshWorker();
