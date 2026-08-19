# Lecturer & Student Admin — Cloudflare (Production Upgrade)

Admin-only management platform for lecturers, students, monthly lecturer subscriptions, one-time student enrollment fees, payments, finance, and multi-admin permissions.

## Stack
- Cloudflare Workers
- Workers Static Assets
- Cloudflare D1
- Vanilla HTML/CSS/JavaScript (no frontend build step)

## Security / Admin model
The first login bootstraps the first **Super Admin** from `ADMIN_USERNAME` + the `ADMIN_PASSWORD` secret **only when the `admins` table is empty**. After that, admin accounts are stored in D1 with PBKDF2 password hashing and database-backed sessions.

Roles included:
- Super Admin
- Manager
- Finance Admin
- Data Entry
- Viewer
- Custom permissions

Only a **Super Admin** can create/edit admin accounts or reset another admin's password. Permissions are enforced on both the UI and API.

## Fresh install
```bash
npm install
npx wrangler login
npx wrangler d1 create lecturer-student-admin-db
```
Copy the returned `database_id` into `wrangler.jsonc`, then:

```bash
npx wrangler d1 migrations apply lecturer-student-admin-db --remote
npx wrangler secret put ADMIN_PASSWORD
npm run deploy
```

`ADMIN_USERNAME` defaults to `admin` in `wrangler.jsonc`.

## Upgrade an existing v1.0 database
Keep your existing D1 database ID and run:

```bash
npx wrangler d1 migrations apply lecturer-student-admin-db --remote
```

This preserves existing lecturers, students, enrollments, subscriptions, payments, settings, and activity history and adds the admin/permission tables and indexes.

If the upgraded database has no rows in `admins`, the next successful login using the original environment admin credentials creates the first Super Admin automatically.

## Local development
Create `.dev.vars` from `.dev.vars.example`, then:

```bash
npx wrangler d1 migrations apply lecturer-student-admin-db --local
npm run dev
```

## Validation
```bash
npm test
```

## Main features
- Multi-admin authentication and RBAC/permissions
- Database-backed sessions + CSRF protection
- Password hashing (PBKDF2)
- Security headers / CSP
- Dashboard KPIs
- Lecturers CRUD / suspend / archive
- Monthly lecturer subscription renewal
- Students CRUD / suspend / archive
- Student ↔ Lecturer enrollment with duplicate prevention
- One-time fee per active student/lecturer enrollment
- Partial payments and payment history
- Finance overview
- Settings
- Audited admin activity
- Responsive RTL UI
- Server-side validation and user-friendly errors

## Important
- Never commit `.dev.vars`, passwords, API tokens, or secrets.
- Keep D1 migrations under version control and apply them before deploying code that depends on them.
- Do not remove the last active Super Admin.


## v1.2.0 — Automatic D1 Schema Bootstrap

This version automatically creates/updates all required D1 tables, indexes, and default settings on the first API request. Manual migration execution is no longer required for a brand-new empty D1 database. The D1 database still must exist and be bound as `DB` with a valid `database_id` in Cloudflare.

Health check after deployment: `/api/system/health`

Required Cloudflare variables:
- `ADMIN_USERNAME` (plain variable; default project value: `admin`)
- `ADMIN_PASSWORD` (Secret)
