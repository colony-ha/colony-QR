-- COLONY QR migration 002: user-owned saved QR codes.
-- Run once against the colony-qr-db D1 database.

CREATE TABLE IF NOT EXISTS qr_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  title TEXT NOT NULL,
  qr_type TEXT NOT NULL
    CHECK (qr_type IN ('url', 'text', 'wifi', 'whatsapp', 'phone', 'email', 'sms', 'contact', 'location', 'event', 'social')),
  content TEXT NOT NULL,
  design_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_qr_codes_user_created
  ON qr_codes(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_qr_codes_type
  ON qr_codes(qr_type);
