CREATE TABLE trust_metadata (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  revision INTEGER NOT NULL CHECK (revision BETWEEN 0 AND 9007199254740991)
) STRICT;
INSERT INTO trust_metadata VALUES (1, 0);

CREATE TABLE trust_controllers (
  controller_id TEXT PRIMARY KEY,
  paired INTEGER NOT NULL CHECK (paired IN (0, 1)),
  last_generation INTEGER NOT NULL CHECK (last_generation BETWEEN 1 AND 4096),
  revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991)
) STRICT;

-- Fingerprints are never deleted or reassigned, including after unpair.
CREATE TABLE trust_certificates (
  fingerprint TEXT PRIMARY KEY CHECK (length(fingerprint) = 64 AND fingerprint NOT GLOB '*[^0-9a-f]*'),
  controller_id TEXT NOT NULL REFERENCES trust_controllers(controller_id),
  permissions TEXT NOT NULL CHECK (length(permissions) <= 256 AND json_valid(permissions)),
  not_before TEXT NOT NULL,
  not_after TEXT NOT NULL CHECK (not_before < not_after),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  generation INTEGER NOT NULL CHECK (generation BETWEEN 1 AND 4096),
  revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
  UNIQUE (controller_id, generation)
) STRICT;
CREATE INDEX trust_controller_status ON trust_certificates(controller_id, status);
