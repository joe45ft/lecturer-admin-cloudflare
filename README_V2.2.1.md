# Lecturer Admin v2.2.1

## Owner-only Reset All Data

A new Danger Zone is available under **Settings** for the Owner account only.

The reset action:
- Deletes lecturers, students, enrollments, payments, lecturer subscriptions, other admins, other sessions, and activity logs.
- Keeps only the current Owner account and current Owner session.
- Resets platform settings to defaults.
- Requires the Owner's current password.
- Requires typing `RESET ALL DATA` exactly.
- Is enforced on the backend; non-Owner accounts receive HTTP 403.

No database migration is required.

For an existing Cloudflare deployment, use the patch package and keep your existing `wrangler.jsonc` so your real D1 `database_id` remains unchanged.
