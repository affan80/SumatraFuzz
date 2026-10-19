export const WorkerError = {
  WorkerBusy: 'worker_busy',
  IdempotencyConflict: 'idempotency_conflict',
  InvalidConfig: 'invalid_config',
  Unauthorized: 'unauthorized',
  UnsupportedPlatform: 'unsupported_platform',
  UnverifiedToolchain: 'unverified_toolchain',
  LimitExceeded: 'limit_exceeded',
  InvalidTransition: 'invalid_transition',
  ProcessError: 'process_error',
  StorageError: 'storage_error',
} as const;

export type WorkerErrorCode = (typeof WorkerError)[keyof typeof WorkerError];

export class WorkerProtocolError extends Error {
  constructor(
    readonly code: WorkerErrorCode,
    message: string = code,
  ) {
    super(message);
    this.name = 'WorkerProtocolError';
  }
}
