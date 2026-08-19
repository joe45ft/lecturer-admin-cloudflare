# Lecturer Admin Cloudflare v2.0

منصة Admin/Owner لإدارة المحاضرين والطلاب والاشتراكات والمدفوعات على Cloudflare Workers + D1.

## أول تشغيل

بعد ربط D1 ونجاح الـDeploy افتح الموقع. إذا لم يوجد أي حساب إداري ستظهر شاشة **إنشاء حساب Owner** تلقائياً. لا تحتاج إلى `ADMIN_PASSWORD` أو `ADMIN_USERNAME` في Cloudflare.

الـOwner هو أعلى صلاحية، ويمكنه بعد ذلك إنشاء Super Admin / Manager / Finance / Data Entry / Viewer / Custom من صفحة المسؤولين والصلاحيات.

## Cloudflare المطلوب

- Worker name: `lecturer-admin`
- D1 binding name: `DB`
- D1 database: `lecturer-student-admin-db`
- ضع UUID الحقيقي للقاعدة في `wrangler.jsonc` مكان `REPLACE_WITH_D1_DATABASE_ID`.

## Deploy

```bash
npm install
npx wrangler deploy
```

أو اربط المشروع بـ GitHub Workers Builds بعد وضع Database ID الحقيقي في `wrangler.jsonc`.

## Health Check

`/api/system/health`

يرجع `setup_required: true` إذا كان مطلوب إنشاء Owner.

## Security

- Password hashing PBKDF2-SHA256
- D1 server-side sessions
- CSRF protection
- Role/permission authorization on API
- Login rate lockout
- Security headers / CSP
- Server-side validation
