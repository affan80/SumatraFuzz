import { isNonNilUuid } from '@sumatrafuzz/worker-protocol';
import type { TrustPermission } from './trust-store.js';

/** Produced only from the verified peer and the authoritative trust source. */
export interface AuthenticatedPrincipal {
  readonly controllerId: string;
  readonly fingerprint: string;
  readonly permissions: readonly TrustPermission[];
}

export type RouteScope =
  | { readonly kind: 'controller' }
  | { readonly kind: 'run'; readonly runId: string }
  | { readonly kind: 'artifact'; readonly runId: string; readonly artifactId: string };
export type AuthorizedRoute =
  | 'capabilities'
  | 'activeRun'
  | 'importInputBundle'
  | 'startRun'
  | 'getRun'
  | 'stopRun'
  | 'eventsAfter'
  | 'manifest'
  | 'artifact';
export type RouteDecision =
  | { readonly allowed: false }
  | {
      readonly allowed: true;
      readonly route: AuthorizedRoute;
      readonly permission: TrustPermission;
      readonly scope: RouteScope;
    };

const controllerRoutes: readonly [string, string, AuthorizedRoute, TrustPermission][] = [
  ['GET', '/v1/capabilities', 'capabilities', 'capabilities:read'],
  ['GET', '/v1/runs/active', 'activeRun', 'runs:read'],
  ['POST', '/v1/input-bundles', 'importInputBundle', 'input-bundles:write'],
  ['POST', '/v1/runs', 'startRun', 'runs:start'],
];
const runRoutes: readonly [string, string | undefined, AuthorizedRoute, TrustPermission][] = [
  ['GET', undefined, 'getRun', 'runs:read'],
  ['POST', 'stop', 'stopRun', 'runs:stop'],
  ['GET', 'events', 'eventsAfter', 'events:read'],
  ['GET', 'manifest', 'manifest', 'artifacts:read'],
];

/** Match the original pathname, before any URL normalization or decoding. */
export function authorizeRoute(
  principal: AuthenticatedPrincipal,
  method: string,
  pathname: string,
): RouteDecision {
  const allow = (
    route: AuthorizedRoute,
    permission: TrustPermission,
    scope: RouteScope,
  ): RouteDecision =>
    principal.permissions.includes(permission)
      ? { allowed: true, route, permission, scope }
      : { allowed: false };
  for (const [expectedMethod, expectedPath, route, permission] of controllerRoutes) {
    if (method === expectedMethod && pathname === expectedPath)
      return allow(route, permission, { kind: 'controller' });
  }
  const match =
    /^\/v1\/runs\/([0-9a-f-]{36})(?:\/(stop|events|manifest|artifacts)(?:\/([A-Za-z0-9_-]{1,128}))?)?$/.exec(
      pathname,
    );
  if (!match || !isNonNilUuid(match[1] ?? '')) return { allowed: false };
  const runId = match[1] as string;
  if (match[2] === 'artifacts' && match[3] && method === 'GET')
    return allow('artifact', 'artifacts:read', { kind: 'artifact', runId, artifactId: match[3] });
  if (match[3]) return { allowed: false };
  for (const [expectedMethod, suffix, route, permission] of runRoutes) {
    if (method === expectedMethod && match[2] === suffix)
      return allow(route, permission, { kind: 'run', runId });
  }
  return { allowed: false };
}
