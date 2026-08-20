# v2.2.1 — Owner-only Reset All Data

- Added an Owner-only **Reset All Data** danger-zone action in Settings.
- Requires the current Owner password and the exact phrase `RESET ALL DATA`.
- Deletes lecturers, students, enrollments, lecturer subscriptions, payments, other admin accounts, other admin sessions, and activity logs.
- Preserves the current Owner account and current Owner session.
- Resets platform settings to safe defaults.
- Resets data-table sequences where possible.
- Backend enforces Owner-only access even if the API is called directly.
