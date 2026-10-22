/** Candidate limits only: Windows x64 acceptance/measurement must precede release policy. */
export const PROVISIONAL_ADMISSION_POLICY = {
  maxSockets: 64,
  maxRequests: 32,
  maxRequestsPerController: 4,
  maxControllers: 16,
  requestsPerSecond: 10,
  requestBurst: 20,
  maxArtifactTransfersPerController: 2,
  maxEventReplaysPerRun: 1,
  handshakeTimeoutMs: 10_000,
  headersTimeoutMs: 15_000,
  idleTimeoutMs: 30_000,
  requestTimeoutMs: 30_000,
  uploadTimeoutMs: 120_000,
  maxHeaderBytes: 16 * 1024,
  maxTargetBytes: 4 * 1024,
} as const;
export type AdmissionPolicy = { readonly [K in keyof typeof PROVISIONAL_ADMISSION_POLICY]: number };
export type CancellationReason = 'disconnect' | 'deadline' | 'idle' | 'revoke' | 'shutdown';
export interface SocketLease {
  readonly active: boolean;
  secure(): void;
  touch(): void;
  headersReceived(): void;
  waitForHeaders(): void;
  release(): void;
}
export interface RequestLease {
  readonly active: boolean;
  readonly signal: AbortSignal;
  assertActive(): void;
  release(): void;
}
export type RequestScope =
  | { readonly kind: 'ordinary' | 'upload' | 'artifact' }
  | { readonly kind: 'replay'; readonly runId: string };
export type RequestAdmission =
  | { readonly allowed: false; readonly status: 429 | 503 }
  | { readonly allowed: true; readonly lease: RequestLease };
export interface AdmissionController {
  acquireSocket(disconnect: () => void): SocketLease | undefined;
  acquireRequest(
    socket: SocketLease,
    controllerId: string,
    scope: RequestScope,
    cancelled?: (reason: CancellationReason) => void,
  ): RequestAdmission;
  revokeController(controllerId: string): void;
  close(): void;
}
export function createAdmissionController(input: AdmissionPolicy): AdmissionController {
  const policy = { ...input };
  for (const key of Object.keys(PROVISIONAL_ADMISSION_POLICY) as (keyof AdmissionPolicy)[]) {
    if (
      !Number.isSafeInteger(policy[key]) ||
      policy[key] < 1 ||
      policy[key] > PROVISIONAL_ADMISSION_POLICY[key]
    )
      throw new TypeError(`invalid admission policy: ${key}`);
  }
  type Bucket = {
    tokens: number;
    updated: number;
    requests: number;
    artifacts: number;
    replays: Map<string, number>;
    retired: boolean;
  };
  type SocketState = {
    active: boolean;
    secure: boolean;
    headerDeadline: number | undefined;
    controllerId?: string;
    timer: ReturnType<typeof setTimeout> | undefined;
    requests: Set<RequestState>;
    disconnect: () => void;
    lease: SocketLease;
  };
  type RequestState = {
    released: boolean;
    cancelled: boolean;
    timer: ReturnType<typeof setTimeout> | undefined;
    socket: SocketState;
    bucket: Bucket;
    controllerId: string;
    scope: RequestScope;
    abort: AbortController;
    onCancel?: (reason: CancellationReason) => void;
  };
  const sockets = new Map<SocketLease, SocketState>();
  const requests = new Set<RequestState>();
  const buckets = new Map<string, Bucket>();
  let closed = false;
  const timer = (callback: () => void, milliseconds: number) => {
    const handle = setTimeout(callback, milliseconds);
    handle.unref?.();
    return handle;
  };
  const refill = (bucket: Bucket) => {
    const now = performance.now();
    bucket.tokens = Math.min(
      policy.requestBurst,
      bucket.tokens + (Math.max(0, now - bucket.updated) * policy.requestsPerSecond) / 1000,
    );
    bucket.updated = Math.max(now, bucket.updated);
  };
  const cancelRequest = (state: RequestState, reason: CancellationReason) => {
    if (state.released || state.cancelled) return;
    state.cancelled = true;
    clearTimeout(state.timer);
    state.timer = undefined;
    state.abort.abort(reason);
    state.onCancel?.(reason);
  };
  const closeSocket = (state: SocketState, reason: CancellationReason, disconnect: boolean) => {
    if (!state.active) return;
    state.active = false;
    clearTimeout(state.timer);
    state.timer = undefined;
    sockets.delete(state.lease);
    for (const request of state.requests) cancelRequest(request, reason);
    if (disconnect) state.disconnect();
  };
  const armSocket = (state: SocketState) => {
    if (!state.active) return;
    clearTimeout(state.timer);
    const remaining =
      state.headerDeadline === undefined
        ? Infinity
        : Math.max(1, state.headerDeadline - performance.now());
    state.timer = timer(
      () =>
        closeSocket(
          state,
          state.secure && state.headerDeadline === undefined ? 'idle' : 'deadline',
          true,
        ),
      state.secure ? Math.min(policy.idleTimeoutMs, remaining) : policy.handshakeTimeoutMs,
    );
  };
  return {
    acquireSocket(disconnect) {
      if (closed || sockets.size >= policy.maxSockets) return undefined;
      const state: SocketState = {
        active: true,
        secure: false,
        headerDeadline: undefined,
        timer: undefined,
        requests: new Set(),
        disconnect,
        lease: undefined as unknown as SocketLease,
      };
      const lease: SocketLease = {
        get active() {
          return state.active;
        },
        secure() {
          if (!state.active) return;
          state.secure = true;
          state.headerDeadline = performance.now() + policy.headersTimeoutMs;
          armSocket(state);
        },
        touch() {
          if (state.secure) armSocket(state);
        },
        headersReceived() {
          state.headerDeadline = undefined;
          armSocket(state);
        },
        waitForHeaders() {
          state.headerDeadline = performance.now() + policy.headersTimeoutMs;
          armSocket(state);
        },
        release() {
          closeSocket(state, 'disconnect', false);
        },
      };
      state.lease = lease;
      sockets.set(lease, state);
      armSocket(state);
      return lease;
    },
    acquireRequest(lease, controllerId, scope, onCancel) {
      const socket = sockets.get(lease);
      if (
        closed ||
        !socket?.active ||
        !socket.secure ||
        (socket.controllerId !== undefined && socket.controllerId !== controllerId)
      )
        return { allowed: false, status: 503 };
      for (const [id, bucket] of buckets) {
        refill(bucket);
        if (bucket.requests === 0 && (bucket.retired || bucket.tokens >= policy.requestBurst))
          buckets.delete(id);
      }
      let bucket = buckets.get(controllerId);
      if (!bucket) {
        if (buckets.size >= policy.maxControllers) return { allowed: false, status: 503 };
        bucket = {
          tokens: policy.requestBurst,
          updated: performance.now(),
          requests: 0,
          artifacts: 0,
          replays: new Map(),
          retired: false,
        };
        buckets.set(controllerId, bucket);
      }
      if (bucket.retired || requests.size >= policy.maxRequests)
        return { allowed: false, status: 503 };
      if (
        bucket.requests >= policy.maxRequestsPerController ||
        bucket.tokens < 1 ||
        (scope.kind === 'artifact' &&
          bucket.artifacts >= policy.maxArtifactTransfersPerController) ||
        (scope.kind === 'replay' &&
          (bucket.replays.get(scope.runId) ?? 0) >= policy.maxEventReplaysPerRun)
      )
        return { allowed: false, status: 429 };
      socket.lease.headersReceived();
      socket.controllerId = controllerId;
      bucket.tokens--;
      bucket.requests++;
      if (scope.kind === 'artifact') bucket.artifacts++;
      if (scope.kind === 'replay')
        bucket.replays.set(scope.runId, (bucket.replays.get(scope.runId) ?? 0) + 1);
      const state: RequestState = {
        released: false,
        cancelled: false,
        timer: undefined,
        socket,
        bucket,
        controllerId,
        scope,
        abort: new AbortController(),
        ...(onCancel ? { onCancel } : {}),
      };
      requests.add(state);
      socket.requests.add(state);
      state.timer = timer(
        () => closeSocket(socket, 'deadline', true),
        scope.kind === 'upload' ? policy.uploadTimeoutMs : policy.requestTimeoutMs,
      );
      return {
        allowed: true,
        lease: {
          get active() {
            return !state.released && !state.cancelled && socket.active && !closed;
          },
          signal: state.abort.signal,
          assertActive() {
            if (state.released || state.cancelled || !socket.active || closed)
              throw Object.assign(new Error('request cancelled'), { status: 408 });
          },
          release() {
            if (state.released) return;
            state.released = true;
            clearTimeout(state.timer);
            state.timer = undefined;
            requests.delete(state);
            socket.requests.delete(state);
            bucket.requests--;
            if (scope.kind === 'artifact') bucket.artifacts--;
            if (scope.kind === 'replay') {
              const remaining = (bucket.replays.get(scope.runId) ?? 1) - 1;
              if (remaining === 0) bucket.replays.delete(scope.runId);
              else bucket.replays.set(scope.runId, remaining);
            }
            if (bucket.requests === 0 && (closed || bucket.retired)) buckets.delete(controllerId);
          },
        },
      };
    },
    revokeController(controllerId) {
      const bucket = buckets.get(controllerId);
      if (bucket) {
        bucket.retired = true;
        if (bucket.requests === 0) buckets.delete(controllerId);
      }
      for (const state of sockets.values())
        if (state.controllerId === controllerId) closeSocket(state, 'revoke', true);
    },
    close() {
      if (closed) return;
      closed = true;
      for (const state of sockets.values()) closeSocket(state, 'shutdown', true);
      for (const state of requests) cancelRequest(state, 'shutdown');
      for (const [id, bucket] of buckets) if (bucket.requests === 0) buckets.delete(id);
    },
  };
}
