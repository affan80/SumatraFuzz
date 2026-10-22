import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAdmissionController, PROVISIONAL_ADMISSION_POLICY } from '../src/admission.js';

const policy = {
  ...PROVISIONAL_ADMISSION_POLICY,
  maxSockets: 2,
  maxRequests: 3,
  maxRequestsPerController: 2,
  maxControllers: 2,
  maxArtifactTransfersPerController: 1,
  maxEventReplaysPerRun: 1,
  requestBurst: 10,
  requestsPerSecond: 2,
  handshakeTimeoutMs: 100,
  idleTimeoutMs: 200,
  requestTimeoutMs: 300,
  uploadTimeoutMs: 500,
};
afterEach(() => {
  vi.useRealTimers();
});

function fixture(overrides: Partial<typeof policy> = {}) {
  const admission = createAdmissionController({ ...policy, ...overrides });
  const disconnect = vi.fn();
  const socket = admission.acquireSocket(disconnect);
  expect(socket).toBeDefined();
  if (!socket) throw new Error('expected socket permit');
  socket.secure();
  return { admission, socket, disconnect };
}

describe('provisional bounded API admission', () => {
  it('caps initial sockets and releases monotonically, including handshake deadlines', () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const { admission, socket, disconnect } = fixture();
    const second = admission.acquireSocket(vi.fn());
    expect(second).toBeDefined();
    expect(admission.acquireSocket(vi.fn())).toBeUndefined();
    socket.release();
    socket.release();
    expect(disconnect).not.toHaveBeenCalled();
    const replacementClose = vi.fn();
    const replacement = admission.acquireSocket(replacementClose);
    expect(replacement).toBeDefined();
    vi.advanceTimersByTime(100);
    expect(replacement?.active).toBe(false);
    expect(replacementClose).toHaveBeenCalledOnce();
    expect(second?.active).toBe(false);
    expect(admission.acquireSocket(vi.fn())).toBeDefined();
    admission.close();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('enforces global and per-controller request permits without duplicate release inflation', () => {
    const { admission, socket } = fixture();
    const one = admission.acquireRequest(socket, 'A', { kind: 'ordinary' });
    const two = admission.acquireRequest(socket, 'A', { kind: 'ordinary' });
    expect(one.allowed && two.allowed).toBe(true);
    expect(admission.acquireRequest(socket, 'A', { kind: 'ordinary' })).toEqual({
      allowed: false,
      status: 429,
    });
    const otherSocket = admission.acquireSocket(vi.fn());
    if (!otherSocket) throw new Error('expected second socket permit');
    otherSocket.secure();
    const three = admission.acquireRequest(otherSocket, 'B', { kind: 'ordinary' });
    expect(three.allowed).toBe(true);
    expect(admission.acquireRequest(otherSocket, 'B', { kind: 'ordinary' })).toEqual({
      allowed: false,
      status: 503,
    });
    if (one.allowed) {
      one.lease.release();
      one.lease.release();
    }
    expect(admission.acquireRequest(socket, 'A', { kind: 'ordinary' }).allowed).toBe(true);
    expect(admission.acquireRequest(otherSocket, 'B', { kind: 'ordinary' }).allowed).toBe(false);
    admission.close();
  });

  it('uses a finite token bucket and monotonic clock refill without reset on release or idle eviction', () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const { admission, socket } = fixture({ requestBurst: 2, idleTimeoutMs: 2000 });
    for (let i = 0; i < 2; i++) {
      const result = admission.acquireRequest(socket, 'A', { kind: 'ordinary' });
      expect(result.allowed).toBe(true);
      if (result.allowed) result.lease.release();
    }
    expect(admission.acquireRequest(socket, 'A', { kind: 'ordinary' }).allowed).toBe(false);
    vi.advanceTimersByTime(250);
    socket.touch();
    expect(admission.acquireRequest(socket, 'A', { kind: 'ordinary' }).allowed).toBe(false);
    vi.advanceTimersByTime(250);
    socket.touch();
    expect(admission.acquireRequest(socket, 'A', { kind: 'ordinary' }).allowed).toBe(true);
    admission.close();
  });

  it('bounds controller rate-state cardinality and reclaims fully refilled inactive entries', () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const { admission, socket } = fixture({
      maxControllers: 1,
      requestBurst: 1,
      idleTimeoutMs: 2000,
    });
    const result = admission.acquireRequest(socket, 'A', { kind: 'ordinary' });
    if (result.allowed) result.lease.release();
    const otherSocket = admission.acquireSocket(vi.fn());
    if (!otherSocket) throw new Error('expected second socket permit');
    otherSocket.secure();
    expect(admission.acquireRequest(otherSocket, 'B', { kind: 'ordinary' })).toEqual({
      allowed: false,
      status: 503,
    });
    vi.advanceTimersByTime(500);
    expect(admission.acquireRequest(otherSocket, 'B', { kind: 'ordinary' }).allowed).toBe(true);
    admission.close();
  });

  it('caps artifacts per controller and replay per controller/run without blocking distinct scopes', () => {
    const { admission, socket } = fixture({ maxRequests: 8, maxRequestsPerController: 4 });
    const artifact = admission.acquireRequest(socket, 'A', { kind: 'artifact' });
    expect(artifact.allowed).toBe(true);
    expect(admission.acquireRequest(socket, 'A', { kind: 'artifact' }).allowed).toBe(false);
    const replay = admission.acquireRequest(socket, 'A', { kind: 'replay', runId: 'run-1' });
    expect(replay.allowed).toBe(true);
    expect(admission.acquireRequest(socket, 'A', { kind: 'replay', runId: 'run-1' }).allowed).toBe(
      false,
    );
    expect(admission.acquireRequest(socket, 'A', { kind: 'replay', runId: 'run-2' }).allowed).toBe(
      true,
    );
    if (artifact.allowed) {
      artifact.lease.release();
      artifact.lease.release();
    }
    if (replay.allowed) {
      replay.lease.release();
      replay.lease.release();
    }
    expect(admission.acquireRequest(socket, 'A', { kind: 'artifact' }).allowed).toBe(true);
    expect(admission.acquireRequest(socket, 'A', { kind: 'replay', runId: 'run-1' }).allowed).toBe(
      true,
    );
    admission.close();
  });

  it.each(['disconnect', 'deadline', 'idle', 'revoke', 'shutdown'] as const)(
    'cancels on %s, retains dispatched permits until settled, and clears timers',
    (reason) => {
      vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
      const { admission, socket, disconnect } = fixture({
        maxRequests: 1,
        maxRequestsPerController: 1,
      });
      const cancelled = vi.fn();
      const result = admission.acquireRequest(socket, 'A', { kind: 'ordinary' }, cancelled);
      expect(result.allowed).toBe(true);
      if (!result.allowed) return;
      if (reason === 'disconnect') socket.release();
      if (reason === 'deadline') {
        vi.advanceTimersByTime(150);
        socket.touch();
        vi.advanceTimersByTime(150);
      }
      if (reason === 'idle') vi.advanceTimersByTime(200);
      if (reason === 'revoke') admission.revokeController('A');
      if (reason === 'shutdown') admission.close();
      expect(result.lease.active).toBe(false);
      expect(result.lease.signal.aborted).toBe(true);
      expect(cancelled).toHaveBeenCalledOnce();
      expect(() => result.lease.assertActive()).toThrow();
      expect(socket.active).toBe(false);
      if (reason !== 'disconnect') expect(disconnect).toHaveBeenCalledOnce();
      const replacement = admission.acquireSocket(vi.fn());
      if (reason === 'shutdown') expect(replacement).toBeUndefined();
      else {
        if (!replacement) throw new Error('expected replacement socket permit');
        replacement.secure();
        expect(admission.acquireRequest(replacement, 'A', { kind: 'ordinary' }).allowed).toBe(
          false,
        );
        result.lease.release();
        result.lease.release();
        expect(admission.acquireRequest(replacement, 'A', { kind: 'ordinary' }).allowed).toBe(true);
      }
      result.lease.release();
      admission.close();
      expect(vi.getTimerCount()).toBe(0);
    },
  );

  it('gives upload work a finite absolute deadline despite continued activity', () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const { admission, socket } = fixture();
    const result = admission.acquireRequest(socket, 'A', { kind: 'upload' });
    for (let i = 0; i < 4; i++) {
      vi.advanceTimersByTime(100);
      socket.touch();
    }
    expect(result.allowed && result.lease.active).toBe(true);
    vi.advanceTimersByTime(100);
    expect(result.allowed && result.lease.active).toBe(false);
    if (result.allowed) result.lease.release();
    admission.close();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('snapshots validated candidate limits and rejects unmeasured relaxation', () => {
    const mutable = { ...policy };
    const admission = createAdmissionController(mutable);
    mutable.maxSockets = 100;
    expect(admission.acquireSocket(vi.fn())).toBeDefined();
    expect(admission.acquireSocket(vi.fn())).toBeDefined();
    expect(admission.acquireSocket(vi.fn())).toBeUndefined();
    admission.close();
    expect(() => createAdmissionController({ ...policy, maxHeaderBytes: 32 * 1024 })).toThrow();
  });

  it('rejects invalid and unbounded policies before allocating timers or state', () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    for (const value of [0, -1, NaN, Infinity, 1.5, 2 ** 32]) {
      expect(() => createAdmissionController({ ...policy, idleTimeoutMs: value })).toThrow();
      expect(() => createAdmissionController({ ...policy, maxSockets: value })).toThrow();
    }
    expect(vi.getTimerCount()).toBe(0);
  });
});
