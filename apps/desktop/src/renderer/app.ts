import { createCampaignPoller } from './campaign-poller.js';
import { parseCampaignStatus, parseInputBundleSummary } from './campaign-view-model.js';

function requiredElement<T extends HTMLElement>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) throw new Error('desktop renderer controls are unavailable');
  return element;
}

const status = requiredElement<HTMLElement>('#status');
const workerDetails = requiredElement<HTMLDListElement>('#worker-details');
const workerId = requiredElement<HTMLElement>('#worker-id');
const workerConnection = requiredElement<HTMLElement>('#worker-connection');
const policyDetails = requiredElement<HTMLDListElement>('#policy-details');
const policyDuration = requiredElement<HTMLElement>('#policy-duration');
const policyMemory = requiredElement<HTMLElement>('#policy-memory');
const policyDisk = requiredElement<HTMLElement>('#policy-disk');
const policyCpu = requiredElement<HTMLElement>('#policy-cpu');
const inputSummary = requiredElement<HTMLDListElement>('#input-summary');
const inputFileCount = requiredElement<HTMLElement>('#input-file-count');
const inputHash = requiredElement<HTMLElement>('#input-hash');
const inputExpandedBytes = requiredElement<HTMLElement>('#input-expanded-bytes');
const runDetails = requiredElement<HTMLDListElement>('#run-details');
const runLabel = requiredElement<HTMLElement>('#run-label');
const runState = requiredElement<HTMLElement>('#run-state');
const runStopReason = requiredElement<HTMLElement>('#run-stop-reason');
const campaignForm = requiredElement<HTMLFormElement>('#campaign-form');
const campaignLabel = requiredElement<HTMLInputElement>('#campaign-label');
const durationInput = requiredElement<HTMLInputElement>('#limit-duration');
const memoryInput = requiredElement<HTMLInputElement>('#limit-memory');
const diskInput = requiredElement<HTMLInputElement>('#limit-disk');
const cpuInput = requiredElement<HTMLInputElement>('#limit-cpu');
const pairButton = requiredElement<HTMLButtonElement>('#pair-worker');
const unpairButton = requiredElement<HTMLButtonElement>('#unpair-worker');
const importButton = requiredElement<HTMLButtonElement>('#import-input');
const startButton = requiredElement<HTMLButtonElement>('#start-campaign');
const stopButton = requiredElement<HTMLButtonElement>('#stop-campaign');

const stopReasonLabels: Readonly<Record<string, string>> = {
  requested: 'Stopped by operator',
  time_limit: 'Time limit reached',
  cpu_limit: 'CPU limit reached',
  memory_limit: 'Memory limit reached',
  disk_limit: 'Disk limit reached',
  native_exit: 'Native process exited',
  process_failure: 'Process failed',
  worker_restart: 'Worker restarted',
};

let actionPending = false;
let currentStatus: ReturnType<typeof parseCampaignStatus> = null;
let configuredWorkerId: string | null = null;

function isRunActive(runState: string | null): boolean {
  return runState !== null && !['completed', 'failed', 'interrupted'].includes(runState);
}

function renderStatus(value: unknown): void {
  const view = parseCampaignStatus(value);
  currentStatus = view;
  if (!view) {
    status.textContent = 'Worker status could not be validated.';
    workerDetails.hidden = true;
    policyDetails.hidden = true;
    inputSummary.hidden = true;
    runDetails.hidden = true;
    importButton.disabled = true;
    startButton.disabled = true;
    stopButton.disabled = true;
    unpairButton.disabled = true;
    return;
  }

  const connected = view.connectionState === 'connected';
  status.textContent = connected
    ? 'Worker connected and certificate-pinned.'
    : 'No worker is paired.';
  workerDetails.hidden = !connected;
  workerId.textContent = view.workerId ?? '';
  workerConnection.textContent = connected ? 'Connected' : 'Disconnected';
  policyDetails.hidden = !view.policyLimits;
  if (view.policyLimits) {
    const limits = view.policyLimits;
    policyDuration.textContent = String(limits.max_duration_s);
    policyMemory.textContent = String(limits.max_memory_bytes);
    policyDisk.textContent = String(limits.max_disk_bytes);
    policyCpu.textContent = String(limits.max_cpu_percent);
    durationInput.max = String(limits.max_duration_s);
    memoryInput.max = String(limits.max_memory_bytes);
    diskInput.max = String(limits.max_disk_bytes);
    cpuInput.max = String(limits.max_cpu_percent);
    if (configuredWorkerId !== view.workerId) {
      durationInput.value = String(Math.min(60, limits.max_duration_s));
      memoryInput.value = String(limits.max_memory_bytes);
      diskInput.value = String(limits.max_disk_bytes);
      cpuInput.value = String(limits.max_cpu_percent);
      configuredWorkerId = view.workerId;
    }
  }
  inputSummary.hidden = view.inputBundle === null;
  if (view.inputBundle) {
    inputFileCount.textContent = String(view.inputBundle.fileCount);
    inputHash.textContent = view.inputBundle.archiveSha256;
    inputExpandedBytes.textContent = String(view.inputBundle.expandedBytes);
  }
  runDetails.hidden = view.runState === null;
  runLabel.textContent = view.campaignLabel ?? (view.runState ? campaignLabel.value : '');
  runState.textContent = view.runState ?? '';
  runStopReason.textContent = view.stopReason ? (stopReasonLabels[view.stopReason] ?? '') : '—';
  unpairButton.disabled = !connected || actionPending;
  importButton.disabled = !connected || actionPending;
  const runIsActive = isRunActive(view.runState);
  startButton.disabled = !connected || !view.inputBundle || runIsActive || actionPending;
  stopButton.disabled = !connected || !runIsActive || actionPending;
}

function onPollError(): void {
  status.textContent = 'Worker status is temporarily unavailable.';
  workerConnection.textContent = 'Unavailable';
  importButton.disabled = true;
  startButton.disabled = true;
}

const poller = createCampaignPoller(
  () => window.sumatraFuzz.getCampaignStatus(),
  renderStatus,
  onPollError,
);

function setActionPending(pending: boolean): void {
  actionPending = pending;
  const connected = currentStatus?.connectionState === 'connected';
  const runIsActive = isRunActive(currentStatus?.runState ?? null);
  pairButton.disabled = pending;
  unpairButton.disabled = pending || !connected;
  importButton.disabled = pending || !connected;
  startButton.disabled = pending || !connected || !currentStatus?.inputBundle || runIsActive;
  stopButton.disabled = pending || !connected || !runIsActive;
}

pairButton.addEventListener('click', async () => {
  setActionPending(true);
  status.textContent = 'Select a signed pairing bundle…';
  try {
    const result = await window.sumatraFuzz.pairWorker();
    if (
      typeof result === 'object' &&
      result !== null &&
      'cancelled' in result &&
      result.cancelled === true
    ) {
      status.textContent = 'Pairing cancelled.';
    } else {
      status.textContent = 'Bundle verified and worker identity confirmed.';
    }
  } catch {
    status.textContent = 'Pairing failed. Check the signed bundle and worker network connection.';
  } finally {
    currentStatus = null;
    setActionPending(false);
  }
});

unpairButton.addEventListener('click', async () => {
  setActionPending(true);
  status.textContent = 'Removing the paired worker…';
  try {
    await window.sumatraFuzz.unpairWorker();
    status.textContent = 'Worker unpaired.';
  } catch {
    status.textContent = 'Could not remove the paired worker profile.';
  } finally {
    currentStatus = null;
    setActionPending(false);
  }
});

importButton.addEventListener('click', async () => {
  setActionPending(true);
  status.textContent = 'Select a PDF ZIP bundle…';
  try {
    const imported = await window.sumatraFuzz.importInputBundle();
    if (imported === null) {
      status.textContent = 'Input import cancelled.';
    } else {
      const summary = parseInputBundleSummary(imported);
      if (!summary) throw new Error('invalid summary');
      inputSummary.hidden = false;
      inputFileCount.textContent = String(summary.fileCount);
      inputHash.textContent = summary.archiveSha256;
      inputExpandedBytes.textContent = String(summary.expandedBytes);
      status.textContent = 'Worker validated the PDF input bundle.';
    }
  } catch {
    status.textContent = 'Input import failed. Check that the archive contains valid PDF files.';
  } finally {
    setActionPending(false);
  }
});

campaignForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!campaignForm.reportValidity()) return;
  const limits = {
    max_duration_s: durationInput.valueAsNumber,
    max_memory_bytes: memoryInput.valueAsNumber,
    max_disk_bytes: diskInput.valueAsNumber,
    max_cpu_percent: cpuInput.valueAsNumber,
  };
  if (
    !Object.values(limits).every(Number.isSafeInteger) ||
    limits.max_duration_s < 1 ||
    limits.max_memory_bytes < 16 * 1024 * 1024 ||
    limits.max_disk_bytes < 1 ||
    limits.max_cpu_percent < 1 ||
    limits.max_cpu_percent > 100
  ) {
    status.textContent = 'Enter safe positive integer campaign limits.';
    return;
  }
  setActionPending(true);
  status.textContent = 'Starting campaign…';
  try {
    await window.sumatraFuzz.startCampaign({ label: campaignLabel.value, limits });
    status.textContent = 'Campaign accepted by the worker.';
  } catch {
    status.textContent =
      'Campaign could not start. Check the worker policy limits and input bundle.';
  } finally {
    setActionPending(false);
  }
});

stopButton.addEventListener('click', async () => {
  setActionPending(true);
  status.textContent = 'Requesting campaign stop…';
  try {
    await window.sumatraFuzz.stopActiveRun();
    renderStatus(await window.sumatraFuzz.getCampaignStatus());
    status.textContent = 'Campaign stop requested.';
  } catch {
    status.textContent = 'Campaign stop could not be confirmed.';
  } finally {
    setActionPending(false);
  }
});

poller.start();
window.addEventListener('beforeunload', () => poller.stop(), { once: true });
