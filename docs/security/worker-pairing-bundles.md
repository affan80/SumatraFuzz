# Signed worker pairing bundles

The desktop accepts only `sumatrafuzz-worker-pairing-bundle-v1` files with an Ed25519 signature from the public key packaged at `apps/desktop/resources/worker-bundle-signing-key.pem`. The signed payload includes the worker UUID, HTTPS origin, SHA-256 worker certificate pin, controller certificate and private key, worker CA certificate, and an issue/expiry window. The signer creates 24-hour bundles by default; the importer rejects bundles longer than seven days or outside their validity window.

The controller opens the file picker in Electron main, reads at most 1 MiB, verifies the exact payload bytes, and checks the worker over pinned mutual TLS. It confirms the worker UUID before atomically replacing its one-slot profile. Private credentials are encrypted with Windows DPAPI and never returned through IPC. The bundle itself contains the controller private key, so protect the profile input and signed output during transfer, use a trusted private channel, and remove temporary copies after import.

The offline signing command reads one profile JSON object from standard input and writes a new `.sfpair` file without overwriting an existing path. Set `SUMATRAFUZZ_WORKER_BUNDLE_SIGNING_PRIVATE_KEY_FILE` to the encrypted Ed25519 private key. On macOS, the signing passphrase is read from the `com.sumatrafuzz.worker-bundle-signing-passphrase` Keychain item; other signing hosts must provide it through their OS-backed secret manager as `SUMATRAFUZZ_WORKER_BUNDLE_SIGNING_KEY_PASSPHRASE`.

```sh
npm run desktop:build
chmod 600 worker-profile.json
cat worker-profile.json | npm run worker:bundle:sign -- --out worker.sfpair
```

Never commit the private signing key, passphrase, profile JSON, or generated bundle. The committed PEM is public trust material. Rotating it requires a reviewed desktop release with the new public key and a controlled period where operators provision newly signed bundles.
