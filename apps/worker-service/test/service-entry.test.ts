import { describe, expect, it } from 'vitest';
import {
  assertServiceBindReady,
  deriveWorkerServicePaths,
  parseWorkerServiceConfig,
} from '../src/service-entry.js';

const install = 'C:\\Program Files\\SumatraFuzz';
const data = 'C:\\ProgramData\\SumatraFuzz\\Worker';
type MutableConfig = {
  bind: { adapterGuid: string; peerCidrs: unknown[] };
  storage: { diskLimitBytes: number };
  audit: { maxBytes: number };
  policy: { allowedInputRoot: string };
  [key: string]: unknown;
};
const config = () => ({
  schema: 1,
  workerId: '12345678-1234-4234-8234-123456789abc',
  bind: {
    mode: 'local',
    address: '127.0.0.1',
    port: 9443,
    adapterGuid: '{12345678-1234-4234-8234-123456789abc}',
    peerCidrs: ['192.168.1.0/24'],
  },
  storage: {
    root: data,
    volumeId: 'volume{12345678-1234-4234-8234-123456789abc}',
    diskLimitBytes: 1024 * 1024 * 1024,
  },
  trust: {
    organizationSigningPublicKeyPath: `${install}\\config\\organization-signing-public-key.pem`,
  },
  credentials: {
    protectedBundlePath: 'C:\\ProgramData\\SumatraFuzz\\Worker\\credentials.dpapi',
  },
  policy: {
    maxLimits: {
      max_duration_s: 3600,
      max_memory_bytes: 512 * 1024 * 1024,
      max_disk_bytes: 1024 * 1024 * 1024,
      max_cpu_percent: 90,
    },
    pinnedTargetLockSha256: 'a'.repeat(64),
    pinnedA4ManifestSha256: 'b'.repeat(64),
    targetLockPath: `${install}\\external\\native-tools\\locks\\target-lock.json`,
    a4ManifestPath: `${install}\\acceptance\\a4.json`,
    harnessPath: `${install}\\native\\harness.exe`,
    allowedBinaryRoot: `${install}\\external\\sumatrapdf`,
    allowedToolRoot: `${install}\\external\\native-tools`,
    allowedInputRoot: `${data}\\inputs`,
    outputRoot: `${data}\\outputs`,
  },
  audit: { maxBytes: 16 * 1024 * 1024, maxSegmentBytes: 1024 * 1024, maxSegments: 16 },
});

describe('worker service entry config', () => {
  it('accepts the exact bounded schema with a quota matching the worker policy', () => {
    expect(parseWorkerServiceConfig(config()).workerId).toBe(
      '12345678-1234-4234-8234-123456789abc',
    );
  });

  it.each([64 * 1024 * 1024 - 1, 2 ** 40 + 1])(
    'rejects a disk quota outside the installer-supported range (%s bytes)',
    (diskLimitBytes) => {
      const value = config();
      value.storage.diskLimitBytes = diskLimitBytes;
      value.policy.maxLimits.max_disk_bytes = diskLimitBytes;
      expect(() => parseWorkerServiceConfig(value)).toThrow();
    },
  );

  it.each([
    [
      'unknown top-level field',
      (value: Record<string, unknown>) => {
        value.extra = true;
      },
    ],
    [
      'malformed adapter GUID',
      (value: MutableConfig) => {
        value.bind.adapterGuid = 'adapter';
      },
    ],
    [
      'invalid CIDR',
      (value: MutableConfig) => {
        value.bind.peerCidrs = ['192.168.1.999/24'];
      },
    ],
    [
      'disk quota mismatch',
      (value: MutableConfig) => {
        value.storage.diskLimitBytes -= 1;
      },
    ],
    [
      'audit segments exceed cap',
      (value: MutableConfig) => {
        value.audit.maxBytes = 1000;
      },
    ],
    [
      'input path escapes storage root',
      (value: MutableConfig) => {
        value.policy.allowedInputRoot = 'C:\\other';
      },
    ],
  ])('rejects %s', (_description, mutate) => {
    const value = config() as MutableConfig;
    mutate(value);
    expect(() => parseWorkerServiceConfig(value)).toThrow();
  });

  it('derives packaged install and protected ProgramData locations', () => {
    expect(
      deriveWorkerServicePaths(
        `${install}\\apps\\worker-service\\dist\\src\\service-entry.js`,
        'C:\\Windows',
      ),
    ).toEqual({
      installRoot: install,
      programDataRoot: 'C:\\ProgramData\\SumatraFuzz\\Worker',
      configPath: 'C:\\ProgramData\\SumatraFuzz\\Worker\\worker-config.json',
      signingKeyPath: `${install}\\config\\organization-signing-public-key.pem`,
      stagingRoot: 'C:\\ProgramData\\SumatraFuzz\\Worker\\staging',
      credentialStagePath: 'C:\\ProgramData\\SumatraFuzz\\Worker\\staging\\worker-credentials.json',
      pairingStagePath: 'C:\\ProgramData\\SumatraFuzz\\Worker\\staging\\worker-pairing.sfpair',
      trustOperationStagePath:
        'C:\\ProgramData\\SumatraFuzz\\Worker\\staging\\worker-trust-operation.sftxn',
    });
  });

  it('fails closed on remote mode without adapter ownership verification', () => {
    expect(() => assertServiceBindReady('remote')).toThrow(
      'remote adapter ownership verification is unavailable',
    );
    expect(() => assertServiceBindReady('local')).not.toThrow();
  });

  it('delegates remote mode adapter and address to native ownership verification', () => {
    let verified = false;
    assertServiceBindReady(
      'remote',
      (adapterGuid, address) => {
        expect(adapterGuid).toBe('{12345678-1234-4234-8234-123456789abc}');
        expect(address).toBe('192.168.1.2');
        verified = true;
      },
      '{12345678-1234-4234-8234-123456789abc}',
      '192.168.1.2',
    );
    expect(verified).toBe(true);
  });
});
