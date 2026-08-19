const SESSION_SECONDS = 60 * 60 * 12;
const PASSWORD_ITERATIONS = 120000;
const MAX_BODY_BYTES = 64 * 1024;

const PERMISSIONS = [
  'dashboard.view',
  'lecturers.view','lecturers.create','lecturers.edit','lecturers.archive','subscriptions.renew',
  'students.view','students.create','students.edit','students.archive',
  'enrollments.view','enrollments.create','enrollments.cancel',
  'payments.view','payments.create','finance.view',
  'settings.view','settings.manage','activity.view','admins.view','admins.manage'
];

const ROLE_PRESETS = {
  super_admin: [...PERMISSIONS],
  manager: PERMISSIONS.filter(p => !['admins.view','admins.manage','settings.manage'].includes(p)),
  finance: ['dashboard.view','lecturers.view','students.view','enrollments.view','payments.view','payments.create','finance.view','subscriptions.renew'],
  data_entry: ['dashboard.view','lecturers.view','lecturers.create','lecturers.edit','students.view','students.create','students.edit','enrollments.view','enrollments.create','payments.view','payments.create'],
  viewer: ['dashboard.view','lecturers.view','students.view','enrollments.view','payments.view'],
};

const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control':'no-store', ...headers },
});
const bad = (message, status = 400, code = 'BAD_REQUEST') => json({ ok:false, code, message }, status);
const ok = (data = {}, status = 200, headers = {}) => json({ ok:true, ...data }, status, headers);

function cookie(name, value, maxAge = SESSION_SECONDS) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}
function parseCookies(request) {
  const out = {};
  for (const part of (request.headers.get('cookie') || '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k) out[k] = v.join('=');
  }
  return out;
}
function b64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
}
function randomToken(size = 32) { const b = new Uint8Array(size); crypto.getRandomValues(b); return b64url(b); }
async function sha256(text) { return b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))); }
async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', hash:'SHA-256', salt:new TextEncoder().encode(salt), iterations:PASSWORD_ITERATIONS }, key, 256);
  return b64url(bits);
}
function constantTimeEqual(a='', b='') {
  if (a.length !== b.length) return false;
  let diff=0; for (let i=0;i<a.length;i++) diff |= a.charCodeAt(i)^b.charCodeAt(i); return diff===0;
}
async function readBody(request) {
  const len = Number(request.headers.get('content-length') || 0);
  if (len > MAX_BODY_BYTES) throw Object.assign(new Error('Request too large'), { status:413 });
  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) throw Object.assign(new Error('Request too large'), { status:413 });
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return {}; }
}
function num(v, fallback=0) { const n=Number(v); return Number.isFinite(n)?n:fallback; }
function text(v,max=500){ return String(v??'').trim().slice(0,max); }
function validEmail(v){ return !v || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function today(){ return new Date().toISOString().slice(0,10); }
function addMonths(dateString, months){ const d=new Date(`${dateString}T00:00:00Z`); d.setUTCMonth(d.getUTCMonth()+Number(months)); return d.toISOString().slice(0,10); }
function receiptNo(){ const stamp=new Date().toISOString().replace(/[-:TZ.]/g,'').slice(0,14); return `REC-${stamp}-${randomToken(5).slice(0,7).toUpperCase()}`; }
function normalizePermissions(role, raw){
  if (role !== 'custom') return ROLE_PRESETS[role] ? [...ROLE_PRESETS[role]] : [...ROLE_PRESETS.viewer];
  const list = Array.isArray(raw) ? raw : [];
  return [...new Set(list.filter(p=>PERMISSIONS.includes(p)))];
}
function parsePermissions(row){
  if (!row) return [];
  if (row.role === 'super_admin') return [...PERMISSIONS];
  try { const custom=JSON.parse(row.permissions||'[]'); return normalizePermissions(row.role, custom); } catch { return normalizePermissions(row.role, []); }
}
function publicAdmin(row){ return { id:row.id, username:row.username, full_name:row.full_name, role:row.role, permissions:parsePermissions(row), status:row.status, last_login_at:row.last_login_at, created_at:row.created_at }; }
function hasPermission(admin, permission){ if (!admin) return false; if (permission==='admins.manage') return admin.role==='super_admin'; return admin.role==='super_admin' || admin.permissions?.includes(permission); }
function forbidUnless(admin, permission){ return hasPermission(admin,permission) ? null : bad('ليس لديك صلاحية لتنفيذ هذه العملية.',403,'FORBIDDEN'); }

async function ensureBootstrapAdmin(env, username, password){
  const row = await env.DB.prepare(`SELECT COUNT(*) total FROM admins`).first();
  if (Number(row?.total||0) > 0) return;
  if (!env.ADMIN_PASSWORD || !env.ADMIN_USERNAME) return;
  if (username !== env.ADMIN_USERNAME || password !== env.ADMIN_PASSWORD) return;
  const salt=randomToken(18), passwordHash=await hashPassword(password,salt);
  await env.DB.prepare(`INSERT INTO admins(username,full_name,password_salt,password_hash,role,permissions,status) VALUES(?,?,?,?,?,?, 'active')`)
    .bind(text(username,80), 'Super Admin', salt, passwordHash, 'super_admin', JSON.stringify(PERMISSIONS)).run();
}
async function createDbSession(env, adminId){
  const token=randomToken(32), tokenHash=await sha256(token), csrf=randomToken(24);
  const expiresAt=new Date(Date.now()+SESSION_SECONDS*1000).toISOString();
  await env.DB.prepare(`DELETE FROM admin_sessions WHERE expires_at <= datetime('now')`).run();
  await env.DB.prepare(`INSERT INTO admin_sessions(admin_id,token_hash,csrf_token,expires_at) VALUES(?,?,?,?)`).bind(adminId,tokenHash,csrf,expiresAt).run();
  return {token, csrf};
}
async function getAuth(request, env){
  const token=parseCookies(request).admin_session;
  if (!token) return null;
  const tokenHash=await sha256(token);
  const row=await env.DB.prepare(`SELECT a.*,s.csrf_token,s.id session_id,s.expires_at FROM admin_sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at > datetime('now') AND a.status='active'`).bind(tokenHash).first();
  if (!row) return null;
  const admin={...publicAdmin(row), csrf_token:row.csrf_token, session_id:row.session_id};
  return admin;
}
function requireCsrf(request, admin){
  if (['GET','HEAD','OPTIONS'].includes(request.method)) return null;
  const token=request.headers.get('x-csrf-token')||'';
  return constantTimeEqual(token,admin.csrf_token) ? null : bad('انتهت صلاحية الحماية. أعد تحميل الصفحة وحاول مرة أخرى.',403,'CSRF_FAILED');
}
async function log(env, admin, action, entityType, entityId, details=''){
  await env.DB.prepare(`INSERT INTO activity_logs(action,entity_type,entity_id,details,admin_id,admin_name) VALUES(?,?,?,?,?,?)`)
    .bind(action,entityType||null,entityId||null,text(details,1000),admin?.id||null,admin?.full_name||admin?.username||'System').run();
}
async function settingsMap(env){ const {results}=await env.DB.prepare(`SELECT key,value FROM settings`).all(); return Object.fromEntries(results.map(r=>[r.key,r.value])); }

function lecturerPayload(d){
  const fullName=text(d.full_name,160); if(!fullName) return {error:'اسم المحاضر مطلوب.'};
  const email=text(d.email,180); if(!validEmail(email)) return {error:'البريد الإلكتروني غير صحيح.'};
  const monthly=num(d.monthly_fee), studentFee=num(d.student_enrollment_fee);
  if(monthly<0||studentFee<0) return {error:'الرسوم لا يمكن أن تكون سالبة.'};
  const status=['active','suspended'].includes(d.status)?d.status:'active';
  return {value:{fullName,phone:text(d.phone,40),email,subject:text(d.subject,120),address:text(d.address,300),notes:text(d.notes,1000),monthly,studentFee,status}};
}
function studentPayload(d){
  const fullName=text(d.full_name,160); if(!fullName) return {error:'اسم الطالب مطلوب.'};
  const email=text(d.email,180); if(!validEmail(email)) return {error:'البريد الإلكتروني غير صحيح.'};
  const status=['active','suspended'].includes(d.status)?d.status:'active';
  return {value:{fullName,phone:text(d.phone,40),parentPhone:text(d.parent_phone,40),email,dateOfBirth:text(d.date_of_birth,20)||null,gender:text(d.gender,30),address:text(d.address,300),notes:text(d.notes,1000),status}};
}


let schemaReady = false;
let schemaInitPromise = null;

async function ensureDatabaseSchema(env){
  if (schemaReady) return;
  if (!env?.DB || typeof env.DB.prepare !== 'function') {
    const err = new Error('D1 binding DB is not configured.');
    err.code = 'DB_NOT_CONFIGURED';
    throw err;
  }
  if (schemaInitPromise) return schemaInitPromise;

  schemaInitPromise = (async () => {
    const statements = [
      `CREATE TABLE IF NOT EXISTS lecturers (
        id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, phone TEXT, email TEXT, subject TEXT,
        address TEXT, notes TEXT, monthly_fee REAL NOT NULL DEFAULT 0, student_enrollment_fee REAL NOT NULL DEFAULT 0,
        subscription_start_date TEXT, subscription_end_date TEXT,
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','archived')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT, student_code TEXT UNIQUE, full_name TEXT NOT NULL, phone TEXT,
        parent_phone TEXT, email TEXT, date_of_birth TEXT, gender TEXT, address TEXT, notes TEXT,
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','archived')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL, lecturer_id INTEGER NOT NULL,
        subject TEXT, enrollment_date TEXT NOT NULL DEFAULT (date('now')), original_fee REAL NOT NULL DEFAULT 0,
        required_fee REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','cancelled')),
        notes TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE RESTRICT,
        FOREIGN KEY(lecturer_id) REFERENCES lecturers(id) ON DELETE RESTRICT
      )`,
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_active_student_lecturer ON enrollments(student_id, lecturer_id) WHERE status='active'`,
      `CREATE TABLE IF NOT EXISTS lecturer_subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, lecturer_id INTEGER NOT NULL, start_date TEXT NOT NULL, end_date TEXT NOT NULL,
        months INTEGER NOT NULL DEFAULT 1, required_amount REAL NOT NULL DEFAULT 0, paid_amount REAL NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'unpaid' CHECK(status IN ('unpaid','partial','paid','cancelled')), notes TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(lecturer_id) REFERENCES lecturers(id) ON DELETE RESTRICT
      )`,
      `CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT, receipt_no TEXT UNIQUE NOT NULL,
        payment_type TEXT NOT NULL CHECK(payment_type IN ('lecturer_subscription','student_enrollment')),
        lecturer_id INTEGER, student_id INTEGER, enrollment_id INTEGER, subscription_id INTEGER,
        amount REAL NOT NULL CHECK(amount >= 0), payment_method TEXT NOT NULL DEFAULT 'Cash', reference TEXT, notes TEXT,
        payment_date TEXT NOT NULL DEFAULT (datetime('now')), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(lecturer_id) REFERENCES lecturers(id) ON DELETE RESTRICT,
        FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE RESTRICT,
        FOREIGN KEY(enrollment_id) REFERENCES enrollments(id) ON DELETE RESTRICT,
        FOREIGN KEY(subscription_id) REFERENCES lecturer_subscriptions(id) ON DELETE RESTRICT
      )`,
      `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
      `CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, entity_type TEXT, entity_id INTEGER, details TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, admin_id INTEGER, admin_name TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, full_name TEXT NOT NULL,
        password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('super_admin','manager','finance','data_entry','viewer','custom')),
        permissions TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended')),
        last_login_at TEXT, failed_login_count INTEGER NOT NULL DEFAULT 0, locked_until TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS admin_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE,
        csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(admin_id) REFERENCES admins(id) ON DELETE CASCADE
      )`,
      `CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin ON admin_sessions(admin_id)`,
      `CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at)`,
      `CREATE INDEX IF NOT EXISTS idx_lecturers_phone ON lecturers(phone)`,
      `CREATE INDEX IF NOT EXISTS idx_lecturers_status ON lecturers(status)`,
      `CREATE INDEX IF NOT EXISTS idx_students_phone ON students(phone)`,
      `CREATE INDEX IF NOT EXISTS idx_students_parent_phone ON students(parent_phone)`,
      `CREATE INDEX IF NOT EXISTS idx_students_status ON students(status)`,
      `CREATE INDEX IF NOT EXISTS idx_enrollments_student ON enrollments(student_id)`,
      `CREATE INDEX IF NOT EXISTS idx_enrollments_lecturer ON enrollments(lecturer_id)`,
      `CREATE INDEX IF NOT EXISTS idx_payments_enrollment ON payments(enrollment_id)`,
      `CREATE INDEX IF NOT EXISTS idx_payments_subscription ON payments(subscription_id)`,
      `CREATE INDEX IF NOT EXISTS idx_payments_lecturer ON payments(lecturer_id)`,
      `CREATE INDEX IF NOT EXISTS idx_payments_student ON payments(student_id)`,
      `CREATE INDEX IF NOT EXISTS idx_payments_date ON payments(payment_date)`
    ];

    await env.DB.batch(statements.map(sql => env.DB.prepare(sql)));

    // Upgrade older databases safely without repeating ALTER TABLE errors.
    const { results: activityCols = [] } = await env.DB.prepare(`PRAGMA table_info(activity_logs)`).all();
    const names = new Set(activityCols.map(c => c.name));
    if (!names.has('admin_id')) await env.DB.prepare(`ALTER TABLE activity_logs ADD COLUMN admin_id INTEGER`).run();
    if (!names.has('admin_name')) await env.DB.prepare(`ALTER TABLE activity_logs ADD COLUMN admin_name TEXT`).run();

    await env.DB.batch([
      env.DB.prepare(`INSERT OR IGNORE INTO settings(key,value) VALUES('platform_name','Lecturer Manager')`),
      env.DB.prepare(`INSERT OR IGNORE INTO settings(key,value) VALUES('currency','EGP')`),
      env.DB.prepare(`INSERT OR IGNORE INTO settings(key,value) VALUES('default_monthly_fee','500')`),
      env.DB.prepare(`INSERT OR IGNORE INTO settings(key,value) VALUES('default_student_fee','200')`),
      env.DB.prepare(`INSERT OR IGNORE INTO settings(key,value) VALUES('subscription_warning_days','7')`),
      env.DB.prepare(`INSERT OR IGNORE INTO settings(key,value) VALUES('payment_methods','["Cash","InstaPay","Vodafone Cash","Bank Transfer","Card","Other"]')`)
    ]);
    schemaReady = true;
  })().catch(err => {
    schemaInitPromise = null;
    throw err;
  });

  return schemaInitPromise;
}

async function api(request, env, path){
  await ensureDatabaseSchema(env);

  if (path==='/api/system/health' && request.method==='GET') {
    const adminCount = await env.DB.prepare(`SELECT COUNT(*) total FROM admins`).first();
    return ok({ database:'ready', schema:'ready', admin_count:Number(adminCount?.total||0), admin_secret_configured:Boolean(env.ADMIN_PASSWORD), admin_username:env.ADMIN_USERNAME||'admin' });
  }

  if (path==='/api/auth/login' && request.method==='POST') {
    if (!env.ADMIN_PASSWORD) return bad('إعداد ADMIN_PASSWORD غير موجود في Cloudflare. أضفه من Settings → Variables and Secrets كـ Secret ثم أعد Deploy.',503,'ADMIN_SECRET_MISSING');
    if (!env.ADMIN_USERNAME) return bad('إعداد ADMIN_USERNAME غير موجود في Cloudflare.',503,'ADMIN_USERNAME_MISSING');
    const d=await readBody(request); const username=text(d.username,80), password=String(d.password||'');
    if (!username || !password) return bad('أدخل اسم المستخدم وكلمة المرور.');
    await ensureBootstrapAdmin(env,username,password);
    const adminRow=await env.DB.prepare(`SELECT * FROM admins WHERE username=? COLLATE NOCASE`).bind(username).first();
    if (!adminRow || adminRow.status!=='active') return bad('اسم المستخدم أو كلمة المرور غير صحيحة.',401,'INVALID_CREDENTIALS');
    if (adminRow.locked_until) {
      const lockedUntil = new Date(String(adminRow.locked_until).replace(' ','T')+'Z');
      if (!Number.isNaN(lockedUntil.getTime()) && lockedUntil.getTime() > Date.now()) return bad('تم إيقاف محاولات الدخول مؤقتًا بسبب تكرار كلمة مرور غير صحيحة. حاول لاحقًا.',429,'LOGIN_LOCKED');
    }
    const candidate=await hashPassword(password,adminRow.password_salt);
    if (!constantTimeEqual(candidate,adminRow.password_hash)) {
      await env.DB.prepare(`UPDATE admins SET failed_login_count=failed_login_count+1,locked_until=CASE WHEN failed_login_count+1>=5 THEN datetime('now','+15 minutes') ELSE locked_until END WHERE id=?`).bind(adminRow.id).run();
      return bad('اسم المستخدم أو كلمة المرور غير صحيحة.',401,'INVALID_CREDENTIALS');
    }
    const session=await createDbSession(env,adminRow.id);
    await env.DB.prepare(`UPDATE admins SET last_login_at=CURRENT_TIMESTAMP,failed_login_count=0,locked_until=NULL WHERE id=?`).bind(adminRow.id).run();
    await log(env,publicAdmin(adminRow),'Admin Login','admin',adminRow.id);
    return ok({admin:publicAdmin({...adminRow,last_login_at:new Date().toISOString()}),csrf_token:session.csrf},200,{ 'set-cookie':cookie('admin_session',session.token) });
  }

  const admin=await getAuth(request,env);
  if (path==='/api/auth/me' && request.method==='GET') return admin ? ok({admin,csrf_token:admin.csrf_token}) : bad('يجب تسجيل الدخول.',401,'UNAUTHORIZED');
  if (!admin) return bad('يجب تسجيل الدخول.',401,'UNAUTHORIZED');
  const csrfError=requireCsrf(request,admin); if(csrfError) return csrfError;

  if (path==='/api/auth/logout' && request.method==='POST') {
    await env.DB.prepare(`DELETE FROM admin_sessions WHERE id=?`).bind(admin.session_id).run();
    await log(env,admin,'Admin Logout','admin',admin.id);
    return ok({},200,{ 'set-cookie':cookie('admin_session','',0) });
  }
  if (path==='/api/auth/change-password' && request.method==='POST') {
    const d=await readBody(request), current=String(d.current_password||''), next=String(d.new_password||'');
    if(next.length<10) return bad('كلمة المرور الجديدة يجب ألا تقل عن 10 أحرف.');
    const row=await env.DB.prepare(`SELECT * FROM admins WHERE id=?`).bind(admin.id).first();
    const candidate=await hashPassword(current,row.password_salt);
    if(!constantTimeEqual(candidate,row.password_hash)) return bad('كلمة المرور الحالية غير صحيحة.',400,'INVALID_PASSWORD');
    const salt=randomToken(18), hash=await hashPassword(next,salt);
    await env.DB.batch([
      env.DB.prepare(`UPDATE admins SET password_salt=?,password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(salt,hash,admin.id),
      env.DB.prepare(`DELETE FROM admin_sessions WHERE admin_id=? AND id<>?`).bind(admin.id,admin.session_id),
      env.DB.prepare(`INSERT INTO activity_logs(action,entity_type,entity_id,details,admin_id,admin_name) VALUES('Password Changed','admin',?,'',?,?)`).bind(admin.id,admin.id,admin.full_name)
    ]);
    return ok();
  }

  if(path==='/api/dashboard' && request.method==='GET'){
    const denied=forbidUnless(admin,'dashboard.view'); if(denied)return denied;
    const warningDays=Math.max(1,Math.min(60,num((await settingsMap(env)).subscription_warning_days,7)));
    const [lect,stu,enr,pay,expiring,expired,recent,outstanding]=await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) total,SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) active FROM lecturers WHERE status!='archived'`).first(),
      env.DB.prepare(`SELECT COUNT(*) total,SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) active FROM students WHERE status!='archived'`).first(),
      env.DB.prepare(`SELECT COUNT(*) total FROM enrollments WHERE status='active'`).first(),
      env.DB.prepare(`SELECT COALESCE(SUM(CASE WHEN payment_type='lecturer_subscription' THEN amount ELSE 0 END),0) lecturer_revenue,COALESCE(SUM(CASE WHEN payment_type='student_enrollment' THEN amount ELSE 0 END),0) student_revenue,COALESCE(SUM(amount),0) total_revenue FROM payments`).first(),
      env.DB.prepare(`SELECT COUNT(*) total FROM lecturers WHERE status='active' AND subscription_end_date IS NOT NULL AND date(subscription_end_date) BETWEEN date('now') AND date('now','+'||?||' day')`).bind(warningDays).first(),
      env.DB.prepare(`SELECT COUNT(*) total FROM lecturers WHERE status='active' AND subscription_end_date IS NOT NULL AND date(subscription_end_date)<date('now')`).first(),
      hasPermission(admin,'payments.view') ? env.DB.prepare(`SELECT p.*,l.full_name lecturer_name,s.full_name student_name FROM payments p LEFT JOIN lecturers l ON l.id=p.lecturer_id LEFT JOIN students s ON s.id=p.student_id ORDER BY p.id DESC LIMIT 8`).all() : Promise.resolve({results:[]}),
      env.DB.prepare(`SELECT COUNT(*) total FROM (SELECT e.id,e.required_fee,COALESCE(SUM(p.amount),0) paid FROM enrollments e LEFT JOIN payments p ON p.enrollment_id=e.id AND p.payment_type='student_enrollment' WHERE e.status='active' GROUP BY e.id HAVING paid<e.required_fee)`).first()
    ]);
    const finance=hasPermission(admin,'finance.view');
    return ok({stats:{lecturers:lect.total||0,activeLecturers:lect.active||0,students:stu.total||0,activeStudents:stu.active||0,enrollments:enr.total||0,expiring:expiring.total||0,expired:expired.total||0,outstandingEnrollments:outstanding.total||0,lecturerRevenue:finance?(pay.lecturer_revenue||0):null,studentRevenue:finance?(pay.student_revenue||0):null,totalRevenue:finance?(pay.total_revenue||0):null},recentPayments:recent.results});
  }

  if(path==='/api/lecturers'&&request.method==='GET'){
    const denied=forbidUnless(admin,'lecturers.view');if(denied)return denied;
    const {results}=await env.DB.prepare(`SELECT l.*,(SELECT COUNT(*) FROM enrollments e WHERE e.lecturer_id=l.id AND e.status='active') student_count,CASE WHEN l.status='suspended' THEN 'suspended' WHEN l.subscription_end_date IS NULL THEN 'unpaid' WHEN date(l.subscription_end_date)<date('now') THEN 'expired' WHEN date(l.subscription_end_date)<=date('now','+7 day') THEN 'due_soon' ELSE 'active' END subscription_status FROM lecturers l WHERE l.status!='archived' ORDER BY l.id DESC`).all();
    return ok({items:results});
  }
  if(path==='/api/lecturers'&&request.method==='POST'){
    const denied=forbidUnless(admin,'lecturers.create');if(denied)return denied; const d=await readBody(request),p=lecturerPayload(d);if(p.error)return bad(p.error); const v=p.value;
    const r=await env.DB.prepare(`INSERT INTO lecturers(full_name,phone,email,subject,address,notes,monthly_fee,student_enrollment_fee,subscription_start_date,subscription_end_date,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(v.fullName,v.phone,v.email,v.subject,v.address,v.notes,v.monthly,v.studentFee,d.subscription_start_date||null,d.subscription_end_date||null,v.status).run();
    await log(env,admin,'Lecturer Created','lecturer',r.meta.last_row_id,v.fullName); return ok({id:r.meta.last_row_id},201);
  }
  const lecturerMatch=path.match(/^\/api\/lecturers\/(\d+)$/);
  if(lecturerMatch&&request.method==='PUT'){
    const denied=forbidUnless(admin,'lecturers.edit');if(denied)return denied; const id=Number(lecturerMatch[1]),d=await readBody(request),p=lecturerPayload(d);if(p.error)return bad(p.error);const v=p.value;
    const found=await env.DB.prepare(`SELECT id FROM lecturers WHERE id=? AND status!='archived'`).bind(id).first();if(!found)return bad('المحاضر غير موجود.',404,'NOT_FOUND');
    await env.DB.prepare(`UPDATE lecturers SET full_name=?,phone=?,email=?,subject=?,address=?,notes=?,monthly_fee=?,student_enrollment_fee=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(v.fullName,v.phone,v.email,v.subject,v.address,v.notes,v.monthly,v.studentFee,v.status,id).run(); await log(env,admin,'Lecturer Updated','lecturer',id,v.fullName); return ok();
  }
  if(lecturerMatch&&request.method==='DELETE'){
    const denied=forbidUnless(admin,'lecturers.archive');if(denied)return denied; const id=Number(lecturerMatch[1]); const found=await env.DB.prepare(`SELECT id FROM lecturers WHERE id=? AND status!='archived'`).bind(id).first();if(!found)return bad('المحاضر غير موجود.',404,'NOT_FOUND');
    await env.DB.prepare(`UPDATE lecturers SET status='archived',updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(id).run();await log(env,admin,'Lecturer Archived','lecturer',id);return ok();
  }
  const renewMatch=path.match(/^\/api\/lecturers\/(\d+)\/renew$/);
  if(renewMatch&&request.method==='POST'){
    const denied=forbidUnless(admin,'subscriptions.renew');if(denied)return denied; const lecturerId=Number(renewMatch[1]),d=await readBody(request);const l=await env.DB.prepare(`SELECT * FROM lecturers WHERE id=? AND status!='archived'`).bind(lecturerId).first();if(!l)return bad('المحاضر غير موجود.',404,'NOT_FOUND');
    const months=Math.max(1,Math.min(60,Math.floor(num(d.months,1)))); const start=(l.subscription_end_date&&l.subscription_end_date>=today())?l.subscription_end_date:(text(d.start_date,20)||today()); const end=addMonths(start,months); const required=num(d.required_amount,num(l.monthly_fee)*months),paid=num(d.paid_amount);if(required<0||paid<0||paid>required)return bad('المبلغ المدفوع غير صحيح أو أكبر من المطلوب.'); const status=paid>=required?'paid':paid>0?'partial':'unpaid';
    const statements=[
      env.DB.prepare(`INSERT INTO lecturer_subscriptions(lecturer_id,start_date,end_date,months,required_amount,paid_amount,status,notes) VALUES(?,?,?,?,?,?,?,?)`).bind(lecturerId,start,end,months,required,paid,status,text(d.notes,1000)),
      env.DB.prepare(`UPDATE lecturers SET subscription_start_date=?,subscription_end_date=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(start,end,lecturerId)
    ];
    if(paid>0) statements.push(env.DB.prepare(`INSERT INTO payments(receipt_no,payment_type,lecturer_id,subscription_id,amount,payment_method,reference,notes) VALUES(?,?,?,(SELECT id FROM lecturer_subscriptions WHERE lecturer_id=? ORDER BY id DESC LIMIT 1),?,?,?,?)`).bind(receiptNo(),'lecturer_subscription',lecturerId,lecturerId,paid,text(d.payment_method,40)||'Cash',text(d.reference,160),text(d.notes,1000)));
    statements.push(env.DB.prepare(`INSERT INTO activity_logs(action,entity_type,entity_id,details,admin_id,admin_name) VALUES('Subscription Renewed','lecturer',?,?,?,?)`).bind(lecturerId,`${months} month(s), ${paid}/${required}`,admin.id,admin.full_name));
    await env.DB.batch(statements); return ok({end_date:end});
  }
  const lecturerStudentsMatch=path.match(/^\/api\/lecturers\/(\d+)\/students$/);
  if(lecturerStudentsMatch&&request.method==='GET'){
    const denied=forbidUnless(admin,'enrollments.view');if(denied)return denied;const id=Number(lecturerStudentsMatch[1]);
    const {results}=await env.DB.prepare(`SELECT e.id enrollment_id,e.enrollment_date,e.required_fee,e.original_fee,e.status enrollment_status,s.id student_id,s.student_code,s.full_name,s.phone,s.parent_phone,s.status,COALESCE((SELECT SUM(p.amount) FROM payments p WHERE p.enrollment_id=e.id AND p.payment_type='student_enrollment'),0) paid_amount FROM enrollments e JOIN students s ON s.id=e.student_id WHERE e.lecturer_id=? AND e.status='active' AND s.status!='archived' ORDER BY e.id DESC`).bind(id).all();
    return ok({items:results.map(x=>({...x,remaining_amount:Math.max(0,num(x.required_fee)-num(x.paid_amount))}))});
  }

  if(path==='/api/students'&&request.method==='GET'){
    const denied=forbidUnless(admin,'students.view');if(denied)return denied; const {results}=await env.DB.prepare(`SELECT s.*,(SELECT COUNT(*) FROM enrollments e WHERE e.student_id=s.id AND e.status='active') lecturer_count,COALESCE((SELECT SUM(e.required_fee) FROM enrollments e WHERE e.student_id=s.id AND e.status='active'),0) total_required,COALESCE((SELECT SUM(p.amount) FROM payments p WHERE p.student_id=s.id AND p.payment_type='student_enrollment'),0) total_paid FROM students s WHERE s.status!='archived' ORDER BY s.id DESC`).all(); return ok({items:results.map(x=>({...x,remaining:Math.max(0,num(x.total_required)-num(x.total_paid))}))});
  }
  if(path==='/api/students'&&request.method==='POST'){
    const denied=forbidUnless(admin,'students.create');if(denied)return denied;const d=await readBody(request),p=studentPayload(d);if(p.error)return bad(p.error);const v=p.value;
    const results=await env.DB.batch([
      env.DB.prepare(`INSERT INTO students(full_name,phone,parent_phone,email,date_of_birth,gender,address,notes,status) VALUES(?,?,?,?,?,?,?,?,?)`).bind(v.fullName,v.phone,v.parentPhone,v.email,v.dateOfBirth,v.gender,v.address,v.notes,v.status),
      env.DB.prepare(`UPDATE students SET student_code='STU-'||printf('%05d',last_insert_rowid()) WHERE id=last_insert_rowid()`),
      env.DB.prepare(`INSERT INTO activity_logs(action,entity_type,entity_id,details,admin_id,admin_name) VALUES('Student Created','student',last_insert_rowid(),?,?,?)`).bind(v.fullName,admin.id,admin.full_name)
    ]);
    const id=results[0]?.meta?.last_row_id;const row=await env.DB.prepare(`SELECT student_code FROM students WHERE id=?`).bind(id).first();return ok({id,student_code:row?.student_code},201);
  }
  const studentMatch=path.match(/^\/api\/students\/(\d+)$/);
  if(studentMatch&&request.method==='PUT'){
    const denied=forbidUnless(admin,'students.edit');if(denied)return denied;const id=Number(studentMatch[1]),d=await readBody(request),p=studentPayload(d);if(p.error)return bad(p.error);const v=p.value;const found=await env.DB.prepare(`SELECT id FROM students WHERE id=? AND status!='archived'`).bind(id).first();if(!found)return bad('الطالب غير موجود.',404,'NOT_FOUND');await env.DB.prepare(`UPDATE students SET full_name=?,phone=?,parent_phone=?,email=?,date_of_birth=?,gender=?,address=?,notes=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(v.fullName,v.phone,v.parentPhone,v.email,v.dateOfBirth,v.gender,v.address,v.notes,v.status,id).run();await log(env,admin,'Student Updated','student',id,v.fullName);return ok();
  }
  if(studentMatch&&request.method==='DELETE'){
    const denied=forbidUnless(admin,'students.archive');if(denied)return denied;const id=Number(studentMatch[1]);const found=await env.DB.prepare(`SELECT id FROM students WHERE id=? AND status!='archived'`).bind(id).first();if(!found)return bad('الطالب غير موجود.',404,'NOT_FOUND');await env.DB.prepare(`UPDATE students SET status='archived',updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(id).run();await log(env,admin,'Student Archived','student',id);return ok();
  }
  const studentEnrollmentsMatch=path.match(/^\/api\/students\/(\d+)\/enrollments$/);
  if(studentEnrollmentsMatch&&request.method==='GET'){
    const denied=forbidUnless(admin,'enrollments.view');if(denied)return denied;const id=Number(studentEnrollmentsMatch[1]);
    const {results}=await env.DB.prepare(`SELECT e.*,l.full_name lecturer_name,l.subject lecturer_subject,COALESCE((SELECT SUM(p.amount) FROM payments p WHERE p.enrollment_id=e.id AND p.payment_type='student_enrollment'),0) paid_amount FROM enrollments e JOIN lecturers l ON l.id=e.lecturer_id WHERE e.student_id=? AND e.status='active' ORDER BY e.id DESC`).bind(id).all();
    return ok({items:results.map(x=>({...x,remaining_amount:Math.max(0,num(x.required_fee)-num(x.paid_amount))}))});
  }

  if(path==='/api/enrollments'&&request.method==='GET'){
    const denied=forbidUnless(admin,'enrollments.view');if(denied)return denied;const {results}=await env.DB.prepare(`SELECT e.*,s.full_name student_name,s.student_code,l.full_name lecturer_name,l.subject lecturer_subject,COALESCE((SELECT SUM(p.amount) FROM payments p WHERE p.enrollment_id=e.id AND p.payment_type='student_enrollment'),0) paid_amount FROM enrollments e JOIN students s ON s.id=e.student_id JOIN lecturers l ON l.id=e.lecturer_id WHERE e.status='active' AND s.status!='archived' AND l.status!='archived' ORDER BY e.id DESC`).all();return ok({items:results.map(x=>({...x,remaining_amount:Math.max(0,num(x.required_fee)-num(x.paid_amount)),payment_status:num(x.paid_amount)>=num(x.required_fee)?'paid':num(x.paid_amount)>0?'partial':'unpaid'}))});
  }
  if(path==='/api/enrollments'&&request.method==='POST'){
    const denied=forbidUnless(admin,'enrollments.create');if(denied)return denied;const d=await readBody(request),studentId=Number(d.student_id),lecturerId=Number(d.lecturer_id);if(!studentId||!lecturerId)return bad('اختر الطالب والمحاضر.');const [existing,lecturer,student]=await Promise.all([env.DB.prepare(`SELECT id FROM enrollments WHERE student_id=? AND lecturer_id=? AND status='active'`).bind(studentId,lecturerId).first(),env.DB.prepare(`SELECT * FROM lecturers WHERE id=? AND status='active'`).bind(lecturerId).first(),env.DB.prepare(`SELECT * FROM students WHERE id=? AND status='active'`).bind(studentId).first()]);if(existing)return bad('هذا الطالب مسجل بالفعل مع هذا المحاضر.',409,'DUPLICATE_ENROLLMENT');if(!lecturer||!student)return bad('الطالب أو المحاضر غير موجود أو غير نشط.',404,'NOT_FOUND');const original=num(lecturer.student_enrollment_fee),required=d.required_fee===''||d.required_fee==null?original:num(d.required_fee),paid=num(d.paid_amount);if(required<0||paid<0||paid>required)return bad('تأكد من قيمة الرسوم والمبلغ المدفوع.');
    const statements=[env.DB.prepare(`INSERT INTO enrollments(student_id,lecturer_id,subject,enrollment_date,original_fee,required_fee,notes) VALUES(?,?,?,?,?,?,?)`).bind(studentId,lecturerId,text(d.subject,120)||lecturer.subject||'',text(d.enrollment_date,20)||today(),original,required,text(d.notes,1000))];
    if(paid>0)statements.push(env.DB.prepare(`INSERT INTO payments(receipt_no,payment_type,lecturer_id,student_id,enrollment_id,amount,payment_method,reference,notes) VALUES(?,?,?,?, (SELECT id FROM enrollments WHERE student_id=? AND lecturer_id=? AND status='active'),?,?,?,?)`).bind(receiptNo(),'student_enrollment',lecturerId,studentId,studentId,lecturerId,paid,text(d.payment_method,40)||'Cash',text(d.reference,160),text(d.notes,1000)));
    statements.push(env.DB.prepare(`INSERT INTO activity_logs(action,entity_type,entity_id,details,admin_id,admin_name) VALUES('Enrollment Created','enrollment',(SELECT id FROM enrollments WHERE student_id=? AND lecturer_id=? AND status='active'),?,?,?)`).bind(studentId,lecturerId,`${student.full_name} -> ${lecturer.full_name}`,admin.id,admin.full_name));
    const results=await env.DB.batch(statements);const id=results[0]?.meta?.last_row_id;return ok({id},201);
  }
  const enrollmentMatch=path.match(/^\/api\/enrollments\/(\d+)$/);
  if(enrollmentMatch&&request.method==='DELETE'){
    const denied=forbidUnless(admin,'enrollments.cancel');if(denied)return denied;const id=Number(enrollmentMatch[1]);const found=await env.DB.prepare(`SELECT id FROM enrollments WHERE id=? AND status='active'`).bind(id).first();if(!found)return bad('التسجيل غير موجود.',404,'NOT_FOUND');await env.DB.prepare(`UPDATE enrollments SET status='cancelled',updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(id).run();await log(env,admin,'Enrollment Cancelled','enrollment',id);return ok();
  }

  if(path==='/api/payments'&&request.method==='GET'){
    const denied=forbidUnless(admin,'payments.view');if(denied)return denied;const {results}=await env.DB.prepare(`SELECT p.*,l.full_name lecturer_name,s.full_name student_name FROM payments p LEFT JOIN lecturers l ON l.id=p.lecturer_id LEFT JOIN students s ON s.id=p.student_id ORDER BY p.id DESC LIMIT 500`).all();return ok({items:results});
  }
  if(path==='/api/payments/enrollment'&&request.method==='POST'){
    const denied=forbidUnless(admin,'payments.create');if(denied)return denied;const d=await readBody(request),enrollmentId=Number(d.enrollment_id),amount=num(d.amount);const e=await env.DB.prepare(`SELECT e.*,s.full_name student_name,l.full_name lecturer_name FROM enrollments e JOIN students s ON s.id=e.student_id JOIN lecturers l ON l.id=e.lecturer_id WHERE e.id=? AND e.status='active'`).bind(enrollmentId).first();if(!e)return bad('التسجيل غير موجود.',404,'NOT_FOUND');const paidRow=await env.DB.prepare(`SELECT COALESCE(SUM(amount),0) paid FROM payments WHERE enrollment_id=? AND payment_type='student_enrollment'`).bind(enrollmentId).first();const remaining=Math.max(0,num(e.required_fee)-num(paidRow.paid));if(amount<=0)return bad('أدخل مبلغاً أكبر من صفر.');if(amount>remaining)return bad(`المبلغ أكبر من المتبقي (${remaining}).`);const rec=receiptNo();await env.DB.batch([env.DB.prepare(`INSERT INTO payments(receipt_no,payment_type,lecturer_id,student_id,enrollment_id,amount,payment_method,reference,notes) VALUES(?,?,?,?,?,?,?,?,?)`).bind(rec,'student_enrollment',e.lecturer_id,e.student_id,enrollmentId,amount,text(d.payment_method,40)||'Cash',text(d.reference,160),text(d.notes,1000)),env.DB.prepare(`INSERT INTO activity_logs(action,entity_type,entity_id,details,admin_id,admin_name) VALUES('Student Payment Added','enrollment',?,?,?,?)`).bind(enrollmentId,String(amount),admin.id,admin.full_name)]);return ok({receipt_no:rec});
  }

  if(path==='/api/settings'&&request.method==='GET'){
    const denied=forbidUnless(admin,'settings.view');if(denied)return denied;return ok({settings:await settingsMap(env)});
  }
  if(path==='/api/settings'&&request.method==='PUT'){
    const denied=forbidUnless(admin,'settings.manage');if(denied)return denied;const d=await readBody(request),allowed=['platform_name','currency','default_monthly_fee','default_student_fee','subscription_warning_days','payment_methods'];const statements=[];for(const [key,value] of Object.entries(d)){if(!allowed.includes(key))continue;if(['default_monthly_fee','default_student_fee'].includes(key)&&num(value)<0)return bad('القيم المالية لا يمكن أن تكون سالبة.');if(key==='subscription_warning_days'&&(num(value)<1||num(value)>60))return bad('أيام التنبيه يجب أن تكون بين 1 و60.');statements.push(env.DB.prepare(`INSERT INTO settings(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP`).bind(key,text(value,2000)));}if(statements.length)await env.DB.batch(statements);await log(env,admin,'Settings Updated','settings',null);return ok();
  }
  if(path==='/api/activity'&&request.method==='GET'){
    const denied=forbidUnless(admin,'activity.view');if(denied)return denied;const {results}=await env.DB.prepare(`SELECT * FROM activity_logs ORDER BY id DESC LIMIT 300`).all();return ok({items:results});
  }

  if(path==='/api/admins/meta'&&request.method==='GET'){
    const denied=forbidUnless(admin,'admins.view');if(denied)return denied;return ok({permissions:PERMISSIONS,role_presets:ROLE_PRESETS});
  }
  if(path==='/api/admins'&&request.method==='GET'){
    const denied=forbidUnless(admin,'admins.view');if(denied)return denied;const {results}=await env.DB.prepare(`SELECT id,username,full_name,role,permissions,status,last_login_at,created_at FROM admins ORDER BY id ASC`).all();return ok({items:results.map(publicAdmin)});
  }
  if(path==='/api/admins'&&request.method==='POST'){
    const denied=forbidUnless(admin,'admins.manage');if(denied)return denied;const d=await readBody(request),username=text(d.username,80),fullName=text(d.full_name,160),password=String(d.password||''),role=ROLE_PRESETS[d.role]?d.role:(d.role==='custom'?'custom':'viewer');if(!/^[A-Za-z0-9._-]{3,80}$/.test(username))return bad('اسم المستخدم يجب أن يكون 3 أحرف على الأقل ويحتوي على حروف أو أرقام فقط.');if(!fullName)return bad('اسم المسؤول مطلوب.');if(password.length<10)return bad('كلمة المرور يجب ألا تقل عن 10 أحرف.');const salt=randomToken(18),hash=await hashPassword(password,salt),permissions=normalizePermissions(role,d.permissions);try{const r=await env.DB.prepare(`INSERT INTO admins(username,full_name,password_salt,password_hash,role,permissions,status) VALUES(?,?,?,?,?,?,?)`).bind(username,fullName,salt,hash,role,JSON.stringify(permissions),d.status==='suspended'?'suspended':'active').run();await log(env,admin,'Admin Created','admin',r.meta.last_row_id,username);return ok({id:r.meta.last_row_id},201);}catch(err){if(String(err.message).includes('UNIQUE'))return bad('اسم المستخدم مستخدم بالفعل.',409,'DUPLICATE_USERNAME');throw err;}
  }
  const adminMatch=path.match(/^\/api\/admins\/(\d+)$/);
  if(adminMatch&&request.method==='PUT'){
    const denied=forbidUnless(admin,'admins.manage');if(denied)return denied;const id=Number(adminMatch[1]),d=await readBody(request),target=await env.DB.prepare(`SELECT * FROM admins WHERE id=?`).bind(id).first();if(!target)return bad('المسؤول غير موجود.',404,'NOT_FOUND');const username=text(d.username,80),fullName=text(d.full_name,160),role=ROLE_PRESETS[d.role]?d.role:(d.role==='custom'?'custom':target.role),status=d.status==='suspended'?'suspended':'active',permissions=normalizePermissions(role,d.permissions);if(!/^[A-Za-z0-9._-]{3,80}$/.test(username)||!fullName)return bad('بيانات المسؤول غير صحيحة.');if(id===admin.id&&status!=='active')return bad('لا يمكنك تعليق حسابك الحالي.');if(target.role==='super_admin'&&(role!=='super_admin'||status!=='active')){const c=await env.DB.prepare(`SELECT COUNT(*) total FROM admins WHERE role='super_admin' AND status='active'`).first();if(Number(c.total)<=1)return bad('يجب أن يظل هناك Super Admin نشط واحد على الأقل.');}try{await env.DB.prepare(`UPDATE admins SET username=?,full_name=?,role=?,permissions=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(username,fullName,role,JSON.stringify(permissions),status,id).run();if(status==='suspended')await env.DB.prepare(`DELETE FROM admin_sessions WHERE admin_id=?`).bind(id).run();await log(env,admin,'Admin Updated','admin',id,username);return ok();}catch(err){if(String(err.message).includes('UNIQUE'))return bad('اسم المستخدم مستخدم بالفعل.',409,'DUPLICATE_USERNAME');throw err;}
  }
  const resetMatch=path.match(/^\/api\/admins\/(\d+)\/reset-password$/);
  if(resetMatch&&request.method==='POST'){
    const denied=forbidUnless(admin,'admins.manage');if(denied)return denied;const id=Number(resetMatch[1]),d=await readBody(request),password=String(d.password||'');if(password.length<10)return bad('كلمة المرور يجب ألا تقل عن 10 أحرف.');const target=await env.DB.prepare(`SELECT id,username FROM admins WHERE id=?`).bind(id).first();if(!target)return bad('المسؤول غير موجود.',404,'NOT_FOUND');const salt=randomToken(18),hash=await hashPassword(password,salt);await env.DB.batch([env.DB.prepare(`UPDATE admins SET password_salt=?,password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(salt,hash,id),env.DB.prepare(`DELETE FROM admin_sessions WHERE admin_id=?`).bind(id)]);await log(env,admin,'Admin Password Reset','admin',id,target.username);return ok();
  }

  return bad('المسار غير موجود.',404,'NOT_FOUND');
}

function securityHeaders(response){
  const h=new Headers(response.headers);
  h.set('x-content-type-options','nosniff'); h.set('x-frame-options','DENY'); h.set('referrer-policy','no-referrer'); h.set('permissions-policy','camera=(), microphone=(), geolocation=()');
  h.set('content-security-policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
  h.set('strict-transport-security','max-age=31536000; includeSubDomains');
  return new Response(response.body,{status:response.status,statusText:response.statusText,headers:h});
}

export default {
  async fetch(request,env){
    const url=new URL(request.url);
    try{
      if(url.pathname.startsWith('/api/')) return securityHeaders(await api(request,env,url.pathname));
      return securityHeaders(await env.ASSETS.fetch(request));
    }catch(err){
      console.error('Unhandled error',err);
      if(err?.status===413)return securityHeaders(bad('حجم الطلب أكبر من المسموح.',413,'PAYLOAD_TOO_LARGE'));
      const msg=String(err?.message||err);
      if(err?.code==='DB_NOT_CONFIGURED' || msg.includes('D1 binding DB is not configured')) return securityHeaders(bad('قاعدة البيانات D1 غير مربوطة بالموقع. اربط قاعدة D1 بالـ binding باسم DB.',503,'DB_NOT_CONFIGURED'));
      if(msg.includes('no such table')) return securityHeaders(bad('تعذر تجهيز جداول قاعدة البيانات تلقائيًا. تحقق من صلاحية D1 binding باسم DB ثم أعد المحاولة.',503,'DB_SCHEMA_ERROR'));
      if(msg.includes('UNIQUE constraint failed')&&msg.includes('enrollments'))return securityHeaders(bad('هذا الطالب مسجل بالفعل مع هذا المحاضر.',409,'DUPLICATE_ENROLLMENT'));
      console.error('Internal error detail:', msg);
      return securityHeaders(bad('تعذر إكمال العملية. تحقق من إعداد قاعدة D1 وVariables and Secrets ثم حاول مرة أخرى.',500,'INTERNAL_ERROR'));
    }
  }
};
