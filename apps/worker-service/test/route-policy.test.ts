import { describe, expect, it } from 'vitest';
import { type AuthenticatedPrincipal, authorizeRoute } from '../src/route-policy.js';
import type { TrustPermission } from '../src/trust-store.js';

const runId = '33333333-3333-4333-8333-333333333333';
const matrix: readonly [string, string, TrustPermission, string, object][] = [
  ['GET', '/v1/capabilities', 'capabilities:read', 'capabilities', { kind: 'controller' }],
  ['GET', '/v1/runs/active', 'runs:read', 'activeRun', { kind: 'controller' }],
  ['POST', '/v1/input-bundles', 'input-bundles:write', 'importInputBundle', { kind: 'controller' }],
  ['POST', '/v1/runs', 'runs:start', 'startRun', { kind: 'controller' }],
  ['GET', `/v1/runs/${runId}`, 'runs:read', 'getRun', { kind: 'run', runId }],
  ['POST', `/v1/runs/${runId}/stop`, 'runs:stop', 'stopRun', { kind: 'run', runId }],
  ['GET', `/v1/runs/${runId}/events`, 'events:read', 'eventsAfter', { kind: 'run', runId }],
  ['GET', `/v1/runs/${runId}/manifest`, 'artifacts:read', 'manifest', { kind: 'run', runId }],
  [
    'GET',
    `/v1/runs/${runId}/artifacts/seed_1`,
    'artifacts:read',
    'artifact',
    { kind: 'artifact', runId, artifactId: 'seed_1' },
  ],
];
const principal: AuthenticatedPrincipal = {
  controllerId: '22222222-2222-4222-8222-222222222222',
  fingerprint: 'a'.repeat(64),
  permissions: [
    'capabilities:read',
    'input-bundles:write',
    'runs:start',
    'runs:read',
    'runs:stop',
    'events:read',
    'artifacts:read',
  ],
};

describe('deny-default worker route policy', () => {
  it.each(matrix)(
    'requires the exact %s %s permission and identifies resource scope',
    (method, pathname, permission, route, scope) => {
      expect(authorizeRoute({ ...principal, permissions: [permission] }, method, pathname)).toEqual(
        { allowed: true, permission, route, scope },
      );
      expect(
        authorizeRoute(
          {
            ...principal,
            permissions: principal.permissions.filter((value) => value !== permission),
          },
          method,
          pathname,
        ),
      ).toEqual({ allowed: false });
      expect(authorizeRoute({ ...principal, permissions: [] }, method, pathname)).toEqual({
        allowed: false,
      });
    },
  );

  it('never grants unknown methods, routes, malformed resource IDs, or path aliases', () => {
    for (const [method, pathname] of matrix) {
      for (const wrongMethod of [
        'HEAD',
        'OPTIONS',
        'PUT',
        'DELETE',
        method.toLowerCase(),
        method === 'GET' ? 'POST' : 'GET',
      ]) {
        // /v1/runs has only POST; every other matrix entry also has exactly one method.
        expect(authorizeRoute(principal, wrongMethod, pathname)).toEqual({ allowed: false });
      }
      for (const alias of [
        `${pathname}/`,
        pathname.replace('/v1/', '/v1//'),
        pathname.replace('/v1/', '/v1/./'),
        `${pathname}?x=1`,
        `${pathname}#fragment`,
        pathname.replace('/v1/', '/v1/%2e%2e/v1/'),
      ]) {
        expect(authorizeRoute(principal, method, alias)).toEqual({ allowed: false });
      }
    }
    for (const pathname of [
      '/v1/unknown',
      '/v1/runs/bad',
      '/v1/runs/00000000-0000-0000-0000-000000000000',
      `/v1/runs/${runId}/artifacts/.`,
      `/v1/runs/${runId}/artifacts/${'a'.repeat(129)}`,
      '/v1/%63apabilities',
      '/v1/../v1/capabilities',
      '//v1/capabilities',
      '/v1\\capabilities',
    ]) {
      expect(authorizeRoute(principal, 'GET', pathname)).toEqual({ allowed: false });
    }
    expect(
      authorizeRoute(
        { ...principal, permissions: ['*' as TrustPermission] },
        'GET',
        '/v1/capabilities',
      ),
    ).toEqual({ allowed: false });
  });
});
