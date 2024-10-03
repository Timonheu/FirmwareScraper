CREATE TABLE IF NOT EXISTS vendor (
  vendor_name text PRIMARY KEY,
  vendor_url text
);

CREATE TABLE IF NOT EXISTS operating_system(
  id serial PRIMARY KEY,
  family_name text NOT NULL,
  os_name text NOT NULL,
  os_version text NOT NULL
);

CREATE TABLE IF NOT EXISTS cpe(
  cpe_name text PRIMARY KEY,
  cpe_name_id text
);

CREATE TABLE IF NOT EXISTS architecture(
  id serial PRIMARY KEY,
  name text NOT NULL,
  bits smallint,
  CONSTRAINT valid_bits CHECK (bits > 0 AND bits % 2 = 0),
  endianness char(1),
  CONSTRAINT valid_endianness CHECK (
      endianness = NULL 
      OR endianness = 'l' 
      OR endianness = 'b'
  ),
  isa text NULL
);

CREATE TABLE IF NOT EXISTS firmware(
  id serial PRIMARY KEY,
  name text,
  version text,
  firmware_url text,
  firmware_location text,
  archive_url text,
  unpacked boolean DEFAULT false,
  firmware_checksum text,
  firmware_size float, -- size in bytes
  vendor text REFERENCES vendor,
  cpe_name text REFERENCES cpe NULL DEFAULT NULL,
  architecture integer REFERENCES architecture ON DELETE SET NULL DEFAULT NULL,
  operating_system integer REFERENCES operating_system ON DELETE SET NULL DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS weakness(
  cwe_id text PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS vulnerability(
  cve_id text PRIMARY KEY,
  description text,
  -- jsonb so the structure of the response from nvd can be
  -- preserved, with sources and tags.
  cve_references jsonb[] NULL,
  vendor_comments text[] NULL,
  level_of_knowledge char(1) NULL DEFAULT NULL,
  -- null, 0, p, c or l
  CONSTRAINT valid_loK CHECK (
    level_of_knowledge = NULL OR
    level_of_knowledge = '0' OR
    level_of_knowledge = 'c' OR
    level_of_knowledge = 'l'
  ),
  vulnerable_protocols text NULL,
  vulnerable_files jsonb NULL,
  stack_trace text NULL,
  proof_of_concept text NULL,
  further_notes text NULL
);

-- Need to create a many to many relationship if we want one vulnerability
-- to relate to 1 or more CPEs
CREATE TABLE IF NOT EXISTS vulnerability_firmware(
  cve_id text REFERENCES vulnerability,
  cpe_name text REFERENCES cpe,
  PRIMARY KEY (cve_id, cpe_name)
);

-- Need to create a many to many relationship if we want one vulnerability
-- to relate to zero or more CWEs.
CREATE TABLE IF NOT EXISTS vulnerability_weakness(
  cve_id text REFERENCES vulnerability,
  cwe_id text REFERENCES weakness,
  source text,
  source_type char(1),
  -- primary or secondary
  CONSTRAINT valid_source_type CHECK (source_type = 'p' OR source_type = 's'),
  PRIMARY KEY (cve_id, cwe_id)
);
