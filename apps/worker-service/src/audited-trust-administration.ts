import { randomUUID } from 'node:crypto';
import type { AuditAction, AuditRecord, SecurityAudit } from './security-audit.js';
import type { TrustProvisionInput, TrustRecord, WorkerTrustRepository } from './trust-store.js';

/** Async trust-mutation boundary used by signed pairing and operator workflows. */
export interface TrustProvisioner {
  provision(input: TrustProvisionInput): Promise<TrustRecord>;
}

type MutableTrustRepository = Pick<
  WorkerTrustRepository,
  'revision' | 'listActive' | 'provision' | 'rotate' | 'revoke' | 'unpair'
>;

/**
 * Emits a redacted intent before each operator trust mutation and its observed result after.
 * The underlying repository must remain private to the service so callers cannot bypass this
 * boundary. A failed intent append prevents the mutation; a failed result append reports failure
 * while leaving the already committed repository mutation intact for operator reconciliation.
 */
export class AuditedTrustAdministration implements TrustProvisioner {
  constructor(
    private readonly repository: MutableTrustRepository,
    private readonly audit: SecurityAudit,
    private readonly now: () => Date = () => new Date(),
    private readonly requestId: () => string = randomUUID,
  ) {}

  provision(input: TrustProvisionInput): Promise<TrustRecord> {
    return this.mutate('trust_provision', input.fingerprint, input.controllerId, () =>
      this.repository.provision(input),
    );
  }

  listActive(): readonly TrustRecord[] {
    return this.repository.listActive();
  }

  rotate(input: TrustProvisionInput, overlapUntil: Date, now = this.now()): Promise<TrustRecord> {
    return this.mutate('trust_rotate', input.fingerprint, input.controllerId, () =>
      this.repository.rotate(input, overlapUntil, now),
    );
  }

  revoke(fingerprint: string): Promise<TrustRecord | null> {
    return this.mutate('trust_revoke', fingerprint, undefined, () =>
      this.repository.revoke(fingerprint),
    );
  }

  unpair(controllerId: string): Promise<number> {
    return this.mutate('trust_unpair', undefined, controllerId, () =>
      this.repository.unpair(controllerId),
    );
  }

  private async mutate<T>(
    action: AuditAction,
    fingerprint: string | undefined,
    controllerId: string | undefined,
    operation: () => T,
  ): Promise<T> {
    if (this.audit.health.state !== 'healthy')
      throw new Error('Worker trust administration failed');
    const common = {
      requestId: this.requestId(),
      action,
      resource: 'trust' as const,
      ...(fingerprint === undefined ? {} : { fingerprint }),
      ...(controllerId === undefined ? {} : { controllerId }),
    };
    try {
      await this.append({ ...common, decision: 'intent', trustRevision: this.repository.revision });
      // The audit implementation can become unhealthy while serializing the intent.
      if (this.audit.health.state !== 'healthy') {
        throw new Error('Worker trust administration failed');
      }
    } catch {
      throw new Error('Worker trust administration failed');
    }

    let result: T;
    try {
      result = operation();
    } catch {
      await this.appendObservedFailure(common);
      throw new Error('Worker trust administration failed');
    }

    try {
      await this.append({
        ...common,
        decision: 'success',
        trustRevision: this.repository.revision,
      });
    } catch {
      throw new Error('Worker trust administration failed');
    }
    return result;
  }

  private async appendObservedFailure(
    common: Omit<AuditRecord, 'decision' | 'trustRevision' | 'timestamp'>,
  ): Promise<void> {
    try {
      await this.append({
        ...common,
        decision: 'failure',
        trustRevision: this.repository.revision,
        errorCode: 'operation_failed',
      });
    } catch {
      // Preserve the same generic outward error whether storage or audit failed.
    }
  }

  private append(record: Omit<AuditRecord, 'timestamp'>): Promise<number> {
    const timestamp = this.now().toISOString();
    return this.audit.append({ ...record, timestamp });
  }
}
