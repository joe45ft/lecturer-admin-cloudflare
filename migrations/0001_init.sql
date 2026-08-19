PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS lecturers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  subject TEXT,
  address TEXT,
  notes TEXT,
  monthly_fee REAL NOT NULL DEFAULT 0,
  student_enrollment_fee REAL NOT NULL DEFAULT 0,
  subscription_start_date TEXT,
  subscription_end_date TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','archived')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_code TEXT UNIQUE,
  full_name TEXT NOT NULL,
  phone TEXT,
  parent_phone TEXT,
  email TEXT,
  date_of_birth TEXT,
  gender TEXT,
  address TEXT,
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','archived')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enrollments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL,
  lecturer_id INTEGER NOT NULL,
  subject TEXT,
  enrollment_date TEXT NOT NULL DEFAULT (date('now')),
  original_fee REAL NOT NULL DEFAULT 0,
  required_fee REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','cancelled')),
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE RESTRICT,
  FOREIGN KEY(lecturer_id) REFERENCES lecturers(id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_active_student_lecturer
ON enrollments(student_id, lecturer_id)
WHERE status = 'active';

CREATE TABLE IF NOT EXISTS lecturer_subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lecturer_id INTEGER NOT NULL,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  months INTEGER NOT NULL DEFAULT 1,
  required_amount REAL NOT NULL DEFAULT 0,
  paid_amount REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'unpaid' CHECK(status IN ('unpaid','partial','paid','cancelled')),
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(lecturer_id) REFERENCES lecturers(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  receipt_no TEXT UNIQUE NOT NULL,
  payment_type TEXT NOT NULL CHECK(payment_type IN ('lecturer_subscription','student_enrollment')),
  lecturer_id INTEGER,
  student_id INTEGER,
  enrollment_id INTEGER,
  subscription_id INTEGER,
  amount REAL NOT NULL CHECK(amount >= 0),
  payment_method TEXT NOT NULL DEFAULT 'Cash',
  reference TEXT,
  notes TEXT,
  payment_date TEXT NOT NULL DEFAULT (datetime('now')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(lecturer_id) REFERENCES lecturers(id) ON DELETE RESTRICT,
  FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE RESTRICT,
  FOREIGN KEY(enrollment_id) REFERENCES enrollments(id) ON DELETE RESTRICT,
  FOREIGN KEY(subscription_id) REFERENCES lecturer_subscriptions(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS activity_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id INTEGER,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO settings(key, value) VALUES
('platform_name', 'Lecturer Manager'),
('currency', 'EGP'),
('default_monthly_fee', '500'),
('default_student_fee', '200'),
('subscription_warning_days', '7'),
('payment_methods', '["Cash","InstaPay","Vodafone Cash","Bank Transfer","Card","Other"]');
