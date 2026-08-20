# Lecturer Manager v2.2.0

Cloudflare Workers + D1 admin platform for lecturer subscriptions, student enrollments and payments.

## New in v2.2.0
- Lecturer and student rich profiles.
- Payment receipt view and browser print.
- Archived lecturer/student workspace with restore.
- Owner-only custom permanent delete, blocked when historical financial/enrollment links exist.
- Global search for lecturers, students and receipts.
- Filters for lecturer subscription status, student balances, enrollment payment status and payment type.
- Outstanding workspace for unpaid student enrollments and lecturer subscriptions due/expired.
- CSV export for lecturers, students, enrollments, payments and outstanding balances.
- Client-side pagination for the main tables and archive.
- Existing 30-second smart auto refresh retained.

## Upgrade safely
For an existing Cloudflare deployment, use the PATCH archive and replace only:
- `src/worker.js`
- `public/app.js`
- `public/index.html`
- `public/style.css`
- `package.json`

Do not replace your existing `wrangler.jsonc`, because it contains your real D1 `database_id`.

No new D1 migration is required for v2.2.0.

## Custom Delete behavior
- Normal delete action = Archive (soft delete).
- Archive page can Restore an item.
- Permanent Delete is Owner-only.
- Permanent Delete requires typing `DELETE`.
- If related enrollments/payments/subscriptions exist, the API refuses permanent deletion to preserve history.

## Tests performed
- `node --check src/worker.js`
- `node --check public/app.js`
- HTML duplicate/missing ID checks.
- SQLite smoke tests for new profile, receipt, outstanding and search queries.
