import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

export async function createTlsFixture(root: string) {
  const caKeyPath = path.join(root, 'ca.key');
  const caCertPath = path.join(root, 'ca.crt');
  const workerKeyPath = path.join(root, 'worker.key');
  const workerCsrPath = path.join(root, 'worker.csr');
  const workerCertPath = path.join(root, 'worker.crt');
  const clientKeyPath = path.join(root, 'client.key');
  const clientCsrPath = path.join(root, 'client.csr');
  const clientCertPath = path.join(root, 'client.crt');
  const workerExtensionsPath = path.join(root, 'worker.ext');
  const clientExtensionsPath = path.join(root, 'client.ext');

  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      caKeyPath,
      '-out',
      caCertPath,
      '-days',
      '2',
      '-subj',
      '/CN=SumatraFuzz test CA',
      '-addext',
      'basicConstraints=critical,CA:TRUE',
      '-addext',
      'keyUsage=critical,keyCertSign,cRLSign',
    ],
    { stdio: 'ignore' },
  );
  for (const [name, keyPath, csrPath] of [
    ['worker', workerKeyPath, workerCsrPath],
    ['client', clientKeyPath, clientCsrPath],
  ] as const) {
    execFileSync(
      'openssl',
      [
        'req',
        '-new',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        keyPath,
        '-out',
        csrPath,
        '-subj',
        `/CN=SumatraFuzz test ${name}`,
      ],
      { stdio: 'ignore' },
    );
  }
  await writeFile(
    workerExtensionsPath,
    'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n',
  );
  await writeFile(
    clientExtensionsPath,
    'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n',
  );
  for (const [csrPath, certPath, extensionPath] of [
    [workerCsrPath, workerCertPath, workerExtensionsPath],
    [clientCsrPath, clientCertPath, clientExtensionsPath],
  ] as const) {
    execFileSync(
      'openssl',
      [
        'x509',
        '-req',
        '-in',
        csrPath,
        '-CA',
        caCertPath,
        '-CAkey',
        caKeyPath,
        '-CAcreateserial',
        '-out',
        certPath,
        '-days',
        '2',
        '-extfile',
        extensionPath,
      ],
      { stdio: 'ignore' },
    );
  }

  const [ca, workerCert, workerKey, clientCert, clientKey] = await Promise.all([
    readFile(caCertPath),
    readFile(workerCertPath),
    readFile(workerKeyPath),
    readFile(clientCertPath),
    readFile(clientKeyPath),
  ]);
  const fingerprint = new X509Certificate(clientCert).fingerprint256
    .replaceAll(':', '')
    .toLowerCase();
  return { ca, workerCert, workerKey, clientCert, clientKey, fingerprint };
}

export async function issueCertificate(
  root: string,
  name: string,
  extensions: string,
  keySpec: readonly string[] = ['-newkey', 'rsa:2048'],
  days = '2',
) {
  const file = (suffix: string) => path.join(root, `${name}.${suffix}`);
  execFileSync(
    'openssl',
    [
      'req',
      '-new',
      ...keySpec,
      '-nodes',
      '-keyout',
      file('key'),
      '-out',
      file('csr'),
      '-subj',
      `/CN=${name}`,
    ],
    { stdio: 'ignore' },
  );
  await writeFile(file('ext'), extensions);
  if (days === '-1') {
    // OpenSSL config treats backslashes as escape characters, so normalize
    // Windows paths before embedding them in the generated CA configuration.
    const configPath = (value: string) => value.replaceAll('\\', '/');
    await writeFile(file('index'), '');
    await writeFile(file('serial'), '01\n');
    await writeFile(file('ext'), `[leaf]\n${extensions}`);
    await writeFile(
      file('conf'),
      `[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=${configPath(file('index'))}\nserial=${configPath(file('serial'))}\nnew_certs_dir=${configPath(root)}\ncertificate=${configPath(path.join(root, 'ca.crt'))}\nprivate_key=${configPath(path.join(root, 'ca.key'))}\ndefault_md=sha256\npolicy=names\n[names]\ncommonName=supplied\n`,
    );
    execFileSync(
      'openssl',
      [
        'ca',
        '-batch',
        '-config',
        file('conf'),
        '-in',
        file('csr'),
        '-out',
        file('crt'),
        '-notext',
        '-startdate',
        '20200101000000Z',
        '-enddate',
        '20200102000000Z',
        '-extfile',
        file('ext'),
        '-extensions',
        'leaf',
      ],
      { stdio: 'ignore' },
    );
  } else {
    execFileSync(
      'openssl',
      [
        'x509',
        '-req',
        '-in',
        file('csr'),
        '-CA',
        path.join(root, 'ca.crt'),
        '-CAkey',
        path.join(root, 'ca.key'),
        '-CAcreateserial',
        '-out',
        file('crt'),
        '-days',
        days,
        '-extfile',
        file('ext'),
      ],
      { stdio: 'ignore' },
    );
  }
  return { cert: await readFile(file('crt')), key: await readFile(file('key')) };
}
