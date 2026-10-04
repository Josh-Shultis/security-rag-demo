from __future__ import annotations

SCHEMA_VERSION = 2

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY,
  vendor TEXT,
  product TEXT,
  vulnerability_track TEXT,
  title TEXT,
  status TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_file TEXT NOT NULL,
  source_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  ingestion_time TEXT NOT NULL,
  duplicate_of TEXT,
  extension TEXT,
  mime_type TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(case_id)
);

CREATE TABLE IF NOT EXISTS chunks (
  chunk_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  vendor TEXT,
  product TEXT,
  vulnerability_track TEXT,
  source_type TEXT,
  source_file TEXT,
  source_path TEXT,
  artifact_id TEXT,
  test_id TEXT,
  object_id TEXT,
  account_role TEXT,
  endpoint TEXT,
  http_method TEXT,
  operation_name TEXT,
  timestamp TEXT,
  sha256 TEXT,
  ingestion_time TEXT,
  evidence_class TEXT,
  content TEXT NOT NULL,
  byte_start INTEGER,
  byte_end INTEGER,
  line_start INTEGER,
  line_end INTEGER,
  json_path TEXT,
  har_entry_index INTEGER,
  request_response_side TEXT,
  parser_name TEXT,
  parser_version TEXT,
  provenance_json TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(case_id)
);

CREATE VIRTUAL TABLE IF NOT EXISTS chunk_fts USING fts5(
  chunk_id UNINDEXED,
  case_id UNINDEXED,
  content,
  tokenize='unicode61'
);

CREATE TABLE IF NOT EXISTS vectors (
  chunk_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  vector_json TEXT NOT NULL,
  embedding_backend TEXT,
  embedding_model TEXT,
  embedding_version TEXT,
  embedding_dimension INTEGER,
  chunk_hash TEXT,
  embedding_timestamp TEXT,
  FOREIGN KEY(chunk_id) REFERENCES chunks(chunk_id)
);

CREATE TABLE IF NOT EXISTS identifiers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL,
  chunk_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  FOREIGN KEY(chunk_id) REFERENCES chunks(chunk_id)
);

CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  source_artifact TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  timestamp TEXT,
  account_role TEXT,
  claim_supported TEXT,
  evidence_class TEXT NOT NULL,
  confidence REAL NOT NULL,
  related_ids TEXT NOT NULL,
  notes TEXT,
  chunk_id TEXT,
  state TEXT DEFAULT 'observation',
  provenance_json TEXT,
  FOREIGN KEY(chunk_id) REFERENCES chunks(chunk_id)
);

CREATE TABLE IF NOT EXISTS graph_nodes (
  node_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  evidence_id TEXT NOT NULL,
  node_type TEXT NOT NULL,
  label TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  FOREIGN KEY(evidence_id) REFERENCES evidence(evidence_id)
);

CREATE TABLE IF NOT EXISTS graph_edges (
  edge_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  from_node TEXT NOT NULL,
  relation TEXT NOT NULL,
  to_node TEXT NOT NULL,
  evidence_id TEXT NOT NULL,
  FOREIGN KEY(from_node) REFERENCES graph_nodes(node_id),
  FOREIGN KEY(to_node) REFERENCES graph_nodes(node_id)
);

CREATE TABLE IF NOT EXISTS timeline (
  event_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  timestamp TEXT,
  timezone TEXT,
  source TEXT,
  account_role TEXT,
  artifact TEXT,
  event_type TEXT,
  object_id TEXT,
  operation_name TEXT,
  related_evidence_ids TEXT NOT NULL,
  original_timestamp TEXT,
  normalized_utc TEXT,
  timestamp_confidence TEXT,
  parser_confidence REAL
);

CREATE TABLE IF NOT EXISTS ingestion_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_time TEXT NOT NULL,
  case_id TEXT,
  source_path TEXT,
  sha256 TEXT,
  status TEXT NOT NULL,
  message TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingestion_events (
  event_id TEXT PRIMARY KEY,
  event_time TEXT NOT NULL,
  case_id TEXT,
  source_path TEXT,
  sha256 TEXT,
  parser_used TEXT,
  parser_version TEXT,
  chunk_count INTEGER NOT NULL DEFAULT 0,
  redactions_applied INTEGER NOT NULL DEFAULT 0,
  duplicate_status TEXT NOT NULL,
  success INTEGER NOT NULL,
  error_message TEXT,
  source_size INTEGER,
  source_extension TEXT,
  source_type TEXT
);

CREATE TABLE IF NOT EXISTS facts (
  fact_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  statement TEXT NOT NULL,
  evidence_ids TEXT NOT NULL,
  created_at TEXT NOT NULL,
  researcher TEXT,
  status TEXT NOT NULL DEFAULT 'confirmed'
);

CREATE TABLE IF NOT EXISTS hypotheses (
  hypothesis_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  statement TEXT NOT NULL,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  reason_rejected TEXT,
  contradiction_evidence_ids TEXT,
  researcher TEXT,
  rejected_at TEXT
);

CREATE TABLE IF NOT EXISTS proof_gaps (
  gap_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  evidence_ids TEXT
);

CREATE INDEX IF NOT EXISTS idx_chunks_case ON chunks(case_id);
CREATE INDEX IF NOT EXISTS idx_chunks_endpoint ON chunks(case_id, endpoint);
CREATE INDEX IF NOT EXISTS idx_chunks_object ON chunks(case_id, object_id);
CREATE INDEX IF NOT EXISTS idx_ident_case_value ON identifiers(case_id, value);
CREATE INDEX IF NOT EXISTS idx_timeline_case_ts ON timeline(case_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_ingestion_events_case ON ingestion_events(case_id, event_time);
"""