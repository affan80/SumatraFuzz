import { isIP } from 'node:net';

export type BindMode = 'local' | 'remote';

function ipv4Octets(address: string): number[] {
  if (isIP(address) !== 4) throw new TypeError('bind address must be an IP literal');
  return address.split('.').map((octet) => Number(octet));
}

function isPrivateIpv4(address: string): boolean {
  const [a, b] = ipv4Octets(address);
  return (
    a === 10 ||
    (a === 172 && b !== undefined && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b !== undefined && b >= 64 && b <= 127)
  );
}

export function validateBindAddress(address: string, mode: BindMode): void {
  if (address.includes('%')) throw new TypeError('scoped bind addresses are not supported');
  const family = isIP(address);
  if (!family) throw new TypeError('bind address must be an IP literal');
  const normalized = address.toLowerCase();
  const loopback = normalized === '::1' || (family === 4 && ipv4Octets(normalized)[0] === 127);

  if (mode === 'local') {
    if (!loopback) throw new Error('local worker service must bind to a loopback address');
    return;
  }

  const privateAddress =
    family === 4 ? isPrivateIpv4(normalized) : /^f[cd][0-9a-f]{2}:/i.test(normalized);
  if (!privateAddress || loopback) {
    throw new Error('remote worker service must bind to an explicit private or VPN interface');
  }
}
