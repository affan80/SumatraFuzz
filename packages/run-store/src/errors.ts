export type StoreErrorCode =
  | 'database'
  | 'invalid_transition'
  | 'idempotency_conflict'
  | 'invalid_request'
  | 'corrupt'
  | 'unsupported_version';

export class StoreError extends Error {
  constructor(
    readonly code: StoreErrorCode,
    message: string = code,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'StoreError';
  }
}
