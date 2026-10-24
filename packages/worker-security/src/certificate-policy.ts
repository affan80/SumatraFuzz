import { X509Certificate } from 'node:crypto';

interface DerValue {
  readonly tag: number;
  readonly bytes: Buffer;
}

/** Read bounded DER TLVs; Node exposes extended key usage, but not X.509 keyUsage. */
function values(bytes: Buffer): DerValue[] {
  const result: DerValue[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    const tag = bytes[offset++];
    const firstLength = bytes[offset++];
    if (tag === undefined || firstLength === undefined) throw new Error('invalid certificate DER');
    let length = firstLength;
    if (firstLength & 0x80) {
      const count = firstLength & 0x7f;
      if (count < 1 || count > 4 || offset + count > bytes.length || bytes[offset] === 0)
        throw new Error('invalid certificate DER length');
      length = 0;
      for (let i = 0; i < count; i++) length = length * 256 + (bytes[offset++] as number);
      if (length < 128) throw new Error('noncanonical certificate DER length');
    }
    if (offset + length > bytes.length) throw new Error('truncated certificate DER');
    result.push({ tag, bytes: bytes.subarray(offset, offset + length) });
    offset += length;
  }
  return result;
}

function assertLeafExtensions(raw: Buffer): void {
  const certificate = values(raw)[0];
  if (certificate?.tag !== 0x30) throw new Error('invalid certificate sequence');
  const tbs = values(certificate.bytes)[0];
  if (tbs?.tag !== 0x30) throw new Error('invalid certificate body');
  const extensions = values(tbs.bytes).find((value) => value.tag === 0xa3);
  const sequence = extensions && values(extensions.bytes)[0];
  if (sequence?.tag !== 0x30) throw new Error('endpoint certificate requires key usage');
  let usage: Buffer | undefined;
  for (const extension of values(sequence.bytes)) {
    if (extension.tag !== 0x30) throw new Error('invalid certificate extension');
    const fields = values(extension.bytes);
    if (fields[0]?.tag !== 0x06) throw new Error('invalid extension identifier');
    const oid = fields[0].bytes.toString('hex');
    if (oid === '551d13') {
      const encoded = fields.at(-1);
      if (encoded?.tag !== 0x04) throw new Error('invalid basic constraints');
      const constraints = values(encoded.bytes)[0];
      if (constraints?.tag !== 0x30) throw new Error('invalid basic constraints');
      const ca = values(constraints.bytes)[0];
      // X509Certificate.ca also considers keyCertSign; inspect the signed CA flag itself.
      if (ca?.tag === 0x01 && ca.bytes.some((byte) => byte !== 0))
        throw new Error('CA certificates cannot identify endpoints');
    }
    if (oid !== '551d0f') continue;
    if (usage) throw new Error('duplicate certificate key usage');
    const encoded = fields.at(-1);
    if (encoded?.tag !== 0x04) throw new Error('invalid certificate key usage');
    const bits = values(encoded.bytes);
    if (bits.length !== 1 || bits[0]?.tag !== 0x03) throw new Error('invalid key usage bits');
    usage = bits[0].bytes;
  }
  const unused = usage?.[0];
  const signing = usage?.[1];
  if (
    unused === undefined ||
    signing === undefined ||
    unused > 7 ||
    !(signing & 0x80) ||
    signing & 0x06
  )
    throw new Error('endpoint certificate requires digital signature key usage without CA signing');
}

/** Leaf policy complements TLS chain validation; it does not establish a trust anchor. */
export function validateEndpointCertificate(
  pem: Buffer | string,
  purpose: 'client' | 'server',
  now: Date = new Date(),
): X509Certificate {
  const cert = new X509Certificate(pem);
  if (cert.ca) throw new Error('CA certificates cannot identify endpoints');
  const time = now.getTime();
  if (
    !Number.isFinite(time) ||
    time < Date.parse(cert.validFrom) ||
    time >= Date.parse(cert.validTo)
  )
    throw new Error('endpoint certificate is outside its validity period');
  const requiredEku = purpose === 'client' ? '1.3.6.1.5.5.7.3.2' : '1.3.6.1.5.5.7.3.1';
  if (!cert.keyUsage?.includes(requiredEku))
    throw new Error('endpoint certificate purpose mismatch');
  assertLeafExtensions(cert.raw);
  const key = cert.publicKey;
  const details = key.asymmetricKeyDetails;
  if (key.asymmetricKeyType === 'rsa' && (details?.modulusLength ?? 0) >= 2048) return cert;
  if (
    key.asymmetricKeyType === 'ec' &&
    ['prime256v1', 'secp384r1'].includes(details?.namedCurve ?? '')
  )
    return cert;
  throw new Error('endpoint certificate uses an unsupported or weak public key');
}
