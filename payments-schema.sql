-- COLONY QR manual subscription payments
-- Safe to run more than once in Cloudflare D1.

CREATE TABLE IF NOT EXISTS payment_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  usd_to_dzd REAL,
  usd_to_eur REAL,
  ccp_account_holder TEXT NOT NULL DEFAULT '',
  ccp_account_number TEXT NOT NULL DEFAULT '',
  cpa_account_holder TEXT NOT NULL DEFAULT '',
  cpa_account_number TEXT NOT NULL DEFAULT '',
  sepa_account_holder TEXT NOT NULL DEFAULT '',
  sepa_iban TEXT NOT NULL DEFAULT '',
  sepa_bank_name TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO payment_settings (id, updated_at)
VALUES (1, CURRENT_TIMESTAMP);

CREATE TABLE IF NOT EXISTS payment_requests (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  plan_code TEXT NOT NULL CHECK (plan_code IN ('pro', 'business')),
  payment_method TEXT NOT NULL CHECK (payment_method IN ('ccp', 'cpa', 'sepa')),
  amount REAL NOT NULL,
  currency TEXT NOT NULL CHECK (currency IN ('DZD', 'EUR')),
  amount_usd REAL NOT NULL,
  exchange_rate REAL,
  receipt_file_path TEXT NOT NULL,
  receipt_file_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'rejected')),
  admin_note TEXT NOT NULL DEFAULT '',
  reviewed_by TEXT,
  reviewed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_payment_requests_status_created
ON payment_requests(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_payment_requests_user_created
ON payment_requests(user_id, created_at DESC);
