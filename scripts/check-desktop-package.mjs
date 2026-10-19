import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractFile, listPackage, statFile } from '@electron/asar';

const ALLOWED_ROOTS = [
  'package.json',
  'dist/',
  'node_modules/@sumatrafuzz/worker-client/',
  'node_modules/@sumatrafuzz/worker-protocol/',
  'node_modules/@sinclair/typebox/',
  'node_modules/ajv/',
  'node_modules/ajv-formats/',
  'node_modules/fast-deep-equal/',
  'node_modules/fast-uri/',
  'node_modules/json-schema-traverse/',
  'node_modules/require-from-string/',
];

function normalizeEntry(entry) {
  return entry.replaceAll('\\', '/').replace(/^\/+/, '');
}

export function findForbiddenPackageEntries(entries) {
  const findings = [];
  for (const original of entries) {
    const entry = normalizeEntry(original);
    const segments = entry.split('/');
    if (path.posix.isAbsolute(entry) || segments.includes('..') || segments.includes('.')) {
      findings.push(`${original}: unsafe package path`);
      continue;
    }
    if (
      /(?:private[._-]?key|id_rsa|id_ed25519|worker-profile\.v\d+\.enc|\.sfpair|\.p12$|\.pfx$|\.key$)/i.test(
        entry,
      ) ||
      /(?:^|\/)(?:credentials?|secrets?)(?:[-_.][^/]*)?\.(?:json|ya?ml|txt|enc)$/i.test(entry) ||
      /(?:^|\/)\.env(?:\.|$)/i.test(entry)
    ) {
      findings.push(`${original}: secret or pairing credential`);
      continue;
    }
    if (
      entry.toLowerCase().endsWith('.pem') &&
      entry !== 'dist/resources/worker-bundle-signing-key.pem'
    ) {
      findings.push(`${original}: unapproved certificate or key material`);
      continue;
    }
    if (
      /(?:^|\/)(?:test|tests|__tests__|fixture|fixtures|corpus|corpora|crashes|queue|runs|test-data)(?:\/|$)/i.test(
        entry,
      )
    ) {
      findings.push(`${original}: test data or corpus`);
      continue;
    }
    if (
      /(?:winafl|dynamorio|sumatrafuzz-harness|pdffilter|libmupdf|fuzz(?:er)?[-_.].*\.(?:exe|dll)|crashpad_handler)/i.test(
        entry,
      ) ||
      /\.(?:pdf|zip|seed|exe|dll|pdb|dmp|node)$/i.test(entry)
    ) {
      findings.push(`${original}: native fuzzing or crash tooling`);
      continue;
    }
    const sourceDirectory =
      /(?:^|\/)src(?:\/|$)/i.test(entry) && !/(?:^|\/)dist\/src(?:\/|$)/i.test(entry);
    if (
      /(?:\.map$|\.ts$|\.tsx$|\.mts$|\.cts$|\.d\.(?:ts|mts|cts)$|\.pdb$|package-lock\.json$|(?:^|\/)(?:\.github|scripts|docs|\.git)(?:\/|$))/i.test(
        entry,
      ) ||
      /(?:^|\/)dist\/src\/preload(?:\/|$)/i.test(entry) ||
      sourceDirectory
    ) {
      findings.push(
        `${original}: ${/dist\/src\/preload/i.test(entry) ? 'preload source is forbidden; use the bundled CommonJS preload' : 'build-only or source file'}`,
      );
      continue;
    }
    const allowed =
      ALLOWED_ROOTS.some((root) => entry === root || entry.startsWith(root)) ||
      ALLOWED_ROOTS.some((root) => root.startsWith(`${entry}/`));
    if (!allowed) findings.push(`${original}: path is outside the desktop package allowlist`);
    else if (
      entry.startsWith('dist/') &&
      path.posix.extname(entry) !== '' &&
      !/\.(?:js|cjs|html|pem)$/i.test(entry)
    ) {
      findings.push(`${original}: unexpected desktop asset type`);
    }
  }
  return findings;
}

export function validatePackagedTrustKey(contents) {
  const key = contents.toString('utf8');
  return key.startsWith('-----BEGIN PUBLIC KEY-----') && !key.includes('PRIVATE KEY');
}

export function containsPrivateSigningKey(contents) {
  return /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i.test(contents.toString('utf8'));
}

export async function inspectDesktopAsar(asarPath) {
  if (!existsSync(asarPath)) throw new Error(`desktop ASAR was not found: ${asarPath}`);
  const entries = listPackage(asarPath, { isPack: false });
  const findings = findForbiddenPackageEntries(entries);
  for (const original of entries) {
    const entry = normalizeEntry(original);
    const metadata = statFile(asarPath, entry, false);
    if ('files' in metadata) continue;
    if ('link' in metadata) {
      findings.push(`${original}: packaged symbolic link is not allowed`);
      continue;
    }
    if (containsPrivateSigningKey(extractFile(asarPath, entry, false))) {
      findings.push(`${original}: private signing key content is forbidden`);
    }
  }
  const trustKeyPath = 'dist/resources/worker-bundle-signing-key.pem';
  if (!entries.some((entry) => normalizeEntry(entry) === trustKeyPath)) {
    findings.push(`${trustKeyPath}: required organization trust key is missing`);
  } else {
    if (!validatePackagedTrustKey(extractFile(asarPath, trustKeyPath))) {
      findings.push(`${trustKeyPath}: packaged trust key is not public-only`);
    }
  }
  if (!entries.some((entry) => normalizeEntry(entry) === 'dist/src/main/index.js')) {
    findings.push('dist/src/main/index.js: desktop main entry point is missing');
  }
  const preloadPath = 'dist/preload.cjs';
  if (!entries.some((entry) => normalizeEntry(entry) === preloadPath)) {
    findings.push(`${preloadPath}: bundled CommonJS preload is missing`);
  } else {
    const preload = extractFile(asarPath, preloadPath).toString('utf8');
    if (!/require\(["']electron["']\)/.test(preload) || /^\s*(?:import|export)\s/m.test(preload)) {
      findings.push(`${preloadPath}: sandboxed preload must be bundled as CommonJS`);
    }
  }
  if (findings.length) throw new Error(`desktop package policy failed:\n${findings.join('\n')}`);
  return entries;
}

async function findAsarPath(value) {
  const resolved = path.resolve(value);
  if (resolved.endsWith('.asar')) return resolved;
  const candidates = [
    path.join(resolved, 'resources', 'app.asar'),
    path.join(resolved, 'Contents', 'Resources', 'app.asar'),
  ];
  return candidates.find((candidate) => existsSync(candidate));
}

async function main() {
  const input = process.argv[2];
  if (!input)
    throw new Error('usage: node scripts/check-desktop-package.mjs <asar-or-unpacked-app>');
  const asarPath = await findAsarPath(input);
  if (!asarPath) throw new Error(`app.asar was not found under ${input}`);
  const entries = await inspectDesktopAsar(asarPath);
  console.log(`Desktop package policy passed for ${entries.length} ASAR entries.`);
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))
) {
  try {
    await main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'desktop package inspection failed');
    process.exitCode = 1;
  }
}
