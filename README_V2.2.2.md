# Lecturer Admin v2.2.2 — Dark Mode

This release adds a persistent Dark Mode across the full admin interface.

## Behavior
- A theme button is available before and after login.
- The first visit follows the device light/dark preference.
- Manual selection is saved in `localStorage` under `lecturer-admin:theme`.
- Dark mode covers dashboards, tables, forms, search, profiles, modals, archive, outstanding, settings, and Danger Zone.
- Receipt preview stays paper-white so printed receipts remain readable.

## Deployment
No D1 migration is required. Keep your existing `wrangler.jsonc` so the current D1 `database_id` remains unchanged.
