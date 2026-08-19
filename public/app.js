const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const state={auth:null,csrf:'',settings:{currency:'EGP'},lecturers:[],students:[],enrollments:[],payments:[],admins:[],adminMeta:null,dashboard:null,currentPage:'dashboard',autoRefresh:true,refreshTimer:null,refreshing:false,lastRefresh:null};
const PAGE_INFO={dashboard:['الرئيسية','نظرة عامة على المنصة'],lecturers:['المحاضرون','إدارة المحاضرين والاشتراكات'],students:['الطلاب','إدارة بيانات الطلاب'],enrollments:['التسجيلات','ربط الطلاب بالمحاضرين'],payments:['المدفوعات','كل الحركات المالية'],finance:['المالية','ملخص الإيرادات'],admins:['المسؤولون والصلاحيات','إدارة حسابات الإدارة والتحكم في الوصول'],activity:['سجل النشاط','تتبع العمليات الإدارية'],settings:['الإعدادات','إعدادات المنصة والأسعار الافتراضية']};
const ROLE_NAMES={owner:'Owner',super_admin:'Super Admin',manager:'Manager',finance:'Finance Admin',data_entry:'Data Entry',viewer:'Viewer',custom:'Custom'};
const PERM_NAMES={'dashboard.view':'عرض الرئيسية','lecturers.view':'عرض المحاضرين','lecturers.create':'إضافة محاضر','lecturers.edit':'تعديل محاضر','lecturers.archive':'أرشفة محاضر','subscriptions.renew':'تجديد اشتراك','students.view':'عرض الطلاب','students.create':'إضافة طالب','students.edit':'تعديل طالب','students.archive':'أرشفة طالب','enrollments.view':'عرض التسجيلات','enrollments.create':'إضافة تسجيل','enrollments.cancel':'إلغاء تسجيل','payments.view':'عرض المدفوعات','payments.create':'تسجيل دفعات','finance.view':'عرض المالية','settings.view':'عرض الإعدادات','settings.manage':'تعديل الإعدادات','activity.view':'عرض سجل النشاط','admins.view':'عرض المسؤولين','admins.manage':'إدارة المسؤولين'};

function esc(v){return String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}
function has(permission){if(permission==='admins.manage')return state.auth?.role==='owner';return state.auth?.role==='owner'||!!state.auth?.permissions?.includes(permission);}
function money(v){return `${new Intl.NumberFormat('ar-EG',{maximumFractionDigits:2}).format(Number(v||0))} ${esc(state.settings.currency||'EGP')}`;}
function dateText(v){if(!v)return '-'; const d=new Date(v); return Number.isNaN(d.getTime())?esc(v):new Intl.DateTimeFormat('ar-EG',{dateStyle:'medium'}).format(d);}
function statusBadge(v){const map={active:['نشط','green'],paid:['مدفوع','green'],due_soon:['ينتهي قريبًا','orange'],partial:['جزئي','orange'],unpaid:['غير مدفوع','red'],expired:['منتهي','red'],suspended:['موقوف','gray'],archived:['مؤرشف','gray']};const [t,c]=map[v]||[v||'-','gray'];return `<span class="badge ${c}">${esc(t)}</span>`;}
function toast(msg,isError=false){const el=$('#toast');el.textContent=msg;el.className=`toast show${isError?' error':''}`;clearTimeout(toast.t);toast.t=setTimeout(()=>el.className='toast',2800);}
function formData(form){return Object.fromEntries(new FormData(form).entries());}
function setBusy(form,busy){const btn=form.querySelector('button[type="submit"],button:not([type])');if(btn){btn.disabled=busy;btn.dataset.oldText??=btn.textContent;if(busy)btn.textContent='جاري الحفظ...';else btn.textContent=btn.dataset.oldText;}}
async function api(path,options={}){const headers={'content-type':'application/json',...(options.headers||{})};if(!['GET','HEAD'].includes((options.method||'GET').toUpperCase())&&state.csrf)headers['x-csrf-token']=state.csrf;const res=await fetch(path,{credentials:'same-origin',...options,headers});let data={};try{data=await res.json();}catch{}const makeError=()=>{const err=new Error(data.message||'تعذر إتمام العملية.');err.code=data.code||'REQUEST_FAILED';err.stage=data.stage||'';err.detail=data.detail||'';err.status=res.status;return err;};if(res.status===401){showLogin();throw makeError();}if(!res.ok)throw makeError();return data;}
function openModal(id){const d=$('#'+id);if(d&&!d.open)d.showModal();}
function closeDialog(el){el.closest('dialog')?.close();}
function hideAuthViews(){$('#systemView').classList.add('hidden');$('#setupView').classList.add('hidden');$('#loginView').classList.add('hidden');$('#appView').classList.add('hidden');}
function showSetup(){stopAutoRefresh();hideAuthViews();$('#setupView').classList.remove('hidden');state.auth=null;state.csrf='';}
function showSystemError(err={}){stopAutoRefresh();hideAuthViews();$('#systemView').classList.remove('hidden');state.auth=null;state.csrf='';$('#systemMessage').textContent=err.message||'تعذر تجهيز النظام.';$('#systemCode').textContent=err.code||'UNKNOWN';$('#systemStage').textContent=err.stage||'-';$('#systemDetail').textContent=err.detail||'لا توجد تفاصيل إضافية.';}
function showLogin(){stopAutoRefresh();hideAuthViews();$('#loginView').classList.remove('hidden');state.auth=null;state.csrf='';}
function showApp(){hideAuthViews();$('#appView').classList.remove('hidden');}
function applyPermissions(){
  $$('[data-permission]').forEach(el=>{el.hidden=!has(el.dataset.permission);});
  $('#adminIdentity').textContent=`${state.auth.full_name} · ${ROLE_NAMES[state.auth.role]||state.auth.role}`;
  const first=$('#nav button:not([hidden])'); if(!$('#nav button.active:not([hidden])')&&first)navigate(first.dataset.page);
}
function navigate(page){const btn=$(`#nav [data-page="${page}"]`);if(!btn||btn.hidden)return;state.currentPage=page;$$('#nav [data-page]').forEach(x=>x.classList.toggle('active',x===btn));$$('.page').forEach(x=>x.classList.toggle('active',x.id===page));$('#pageTitle').textContent=PAGE_INFO[page][0];$('#pageSubtitle').textContent=PAGE_INFO[page][1];$('#sidebar').classList.remove('open');}


function activeDialogOpen(){return !!document.querySelector('dialog[open]');}
function refreshTimeText(date=new Date()){
  return new Intl.DateTimeFormat('ar-EG',{hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(date);
}
function updateRefreshStatus(message){
  const el=$('#refreshStatus'); if(el) el.textContent=message;
}
function syncAutoRefreshUi(){
  const toggle=$('#autoRefreshToggle');
  if(toggle) toggle.checked=state.autoRefresh;
}
function stopAutoRefresh(){
  if(state.refreshTimer){clearInterval(state.refreshTimer);state.refreshTimer=null;}
}
function startAutoRefresh(){
  stopAutoRefresh();
  if(!state.auth||!state.autoRefresh)return;
  state.refreshTimer=setInterval(()=>refreshCurrentPage({silent:true,auto:true}),30000);
}
async function refreshCurrentPage({silent=false,auto=false}={}){
  if(!state.auth||state.refreshing)return;
  if(auto&&(document.hidden||activeDialogOpen()))return;
  state.refreshing=true;
  const btn=$('#refreshBtn');
  btn?.classList.add('is-refreshing');
  if(!silent) updateRefreshStatus('جاري التحديث...');
  try{
    const page=state.currentPage||$('#nav [data-page].active')?.dataset.page||'dashboard';
    if(page==='dashboard'||page==='finance') await loadDashboard();
    else if(page==='lecturers'&&has('lecturers.view')) await loadLecturers();
    else if(page==='students'&&has('students.view')) await loadStudents();
    else if(page==='enrollments'&&has('enrollments.view')) await loadEnrollments();
    else if(page==='payments'&&has('payments.view')) await loadPayments();
    else if(page==='admins'&&has('admins.view')) await loadAdmins();
    else if(page==='activity'&&has('activity.view')) await loadActivity();
    else if(page==='settings'&&has('settings.view')) await loadSettings();

    // Keep the dashboard counters reasonably fresh without reloading every list.
    if(page!=='dashboard'&&page!=='finance'&&has('dashboard.view')) await loadDashboard();

    state.lastRefresh=new Date();
    updateRefreshStatus(`آخر تحديث ${refreshTimeText(state.lastRefresh)}`);
    if(!silent) toast('تم تحديث البيانات.');
  }catch(err){
    updateRefreshStatus('تعذر التحديث');
    if(!silent) toast(err.message||'تعذر تحديث البيانات.',true);
  }finally{
    state.refreshing=false;
    btn?.classList.remove('is-refreshing');
  }
}

async function boot(){try{const health=await api('/api/system/health');if(!health.ok)throw new Error('فشل فحص النظام.');const setup=await api('/api/setup/status');if(setup.setup_required){showSetup();return;}try{const me=await api('/api/auth/me');state.auth=me.admin;state.csrf=me.csrf_token;showApp();applyPermissions();await loadAll();state.lastRefresh=new Date();updateRefreshStatus(`آخر تحديث ${refreshTimeText(state.lastRefresh)}`);syncAutoRefreshUi();startAutoRefresh();}catch(err){if(err.status===401){showLogin();}else{showSystemError(err);}}}catch(err){showSystemError(err);}}
async function loadAll(){await loadSettings();const jobs=[loadDashboard()];if(has('lecturers.view'))jobs.push(loadLecturers());if(has('students.view'))jobs.push(loadStudents());if(has('enrollments.view'))jobs.push(loadEnrollments());if(has('payments.view'))jobs.push(loadPayments());if(has('activity.view'))jobs.push(loadActivity());if(has('admins.view'))jobs.push(loadAdmins());await Promise.allSettled(jobs);}
async function loadSettings(){if(!has('settings.view'))return;const r=await api('/api/settings');state.settings=r.settings;$('#brandName').textContent=state.settings.platform_name||'Lecturer Manager';document.title=state.settings.platform_name||'Lecturer Manager';const f=$('#settingsForm');Object.entries(state.settings).forEach(([k,v])=>{if(f.elements[k])f.elements[k].value=v;});}
async function loadDashboard(){if(!has('dashboard.view'))return;const r=await api('/api/dashboard');state.dashboard=r;renderDashboard();}
async function loadLecturers(){const r=await api('/api/lecturers');state.lecturers=r.items;renderLecturers();populateSelects();}
async function loadStudents(){const r=await api('/api/students');state.students=r.items;renderStudents();populateSelects();}
async function loadEnrollments(){const r=await api('/api/enrollments');state.enrollments=r.items;renderEnrollments();}
async function loadPayments(){const r=await api('/api/payments');state.payments=r.items;renderPayments();}
async function loadActivity(){const r=await api('/api/activity');$('#activityBody').innerHTML=r.items.map(x=>`<tr><td>${esc(x.admin_name||'System')}</td><td>${esc(x.action)}</td><td>${esc(x.entity_type||'-')}</td><td>${esc(x.details||'-')}</td><td>${dateText(x.created_at)}</td></tr>`).join('')||'<tr><td colspan="5">لا يوجد نشاط.</td></tr>';}
async function loadAdmins(){const [a,m]=await Promise.all([api('/api/admins'),api('/api/admins/meta')]);state.admins=a.items;state.adminMeta=m;renderAdmins();renderPermissionCheckboxes();}

function stat(title,value,icon='fi-rr-dashboard-monitor'){return `<div class="stat"><span class="stat-icon" aria-hidden="true"><i class="fi ${icon}"></i></span><div><small>${esc(title)}</small><strong>${value}</strong></div></div>`;}
function renderDashboard(){const s=state.dashboard.stats;const cards=[stat('المحاضرون',s.lecturers,'fi-rr-chalkboard-user'),stat('الطلاب',s.students,'fi-rr-users-class'),stat('التسجيلات',s.enrollments,'fi-rr-clipboard-list-check'),stat('اشتراكات منتهية',s.expired,'fi-rr-cross-circle'),stat('تنتهي قريبًا',s.expiring,'fi-rr-clock'),stat('تسجيلات عليها متبقي',s.outstandingEnrollments,'fi-rr-receipt')];if(has('finance.view'))cards.push(stat('إيرادات المحاضرين',money(s.lecturerRevenue),'fi-rr-coins'),stat('إيرادات الطلاب',money(s.studentRevenue),'fi-rr-coins'),stat('إجمالي الإيرادات',money(s.totalRevenue),'fi-rr-wallet'));$('#stats').innerHTML=cards.join('');$('#financeCards').innerHTML=has('finance.view')?[stat('إيرادات المحاضرين',money(s.lecturerRevenue),'fi-rr-coins'),stat('إيرادات الطلاب',money(s.studentRevenue),'fi-rr-coins'),stat('الإجمالي',money(s.totalRevenue),'fi-rr-wallet')].join(''):'';$('#recentPayments').innerHTML=state.dashboard.recentPayments.length?state.dashboard.recentPayments.map(p=>`<div class="list-row"><span>${esc(p.student_name||p.lecturer_name||'-')}<br><small class="muted">${esc(p.receipt_no)}</small></span><strong>${money(p.amount)}</strong></div>`).join(''):'<div class="empty-note">لا توجد مدفوعات حديثة.</div>';$('#alerts').innerHTML=`<div class="list-row"><span>اشتراكات منتهية</span><strong>${s.expired}</strong></div><div class="list-row"><span>تنتهي قريبًا</span><strong>${s.expiring}</strong></div><div class="list-row"><span>تسجيلات عليها متبقي</span><strong>${s.outstandingEnrollments}</strong></div>`;}
function renderLecturers(){const q=($('#lecturerSearch').value||'').toLowerCase(),rows=state.lecturers.filter(l=>`${l.full_name} ${l.phone||''} ${l.subject||''}`.toLowerCase().includes(q));$('#lecturersBody').innerHTML=rows.map(l=>`<tr><td><strong>${esc(l.full_name)}</strong></td><td>${esc(l.subject||'-')}</td><td>${esc(l.phone||'-')}</td><td>${l.student_count||0}</td><td>${money(l.monthly_fee)}</td><td>${money(l.student_enrollment_fee)}</td><td>${dateText(l.subscription_end_date)}</td><td>${statusBadge(l.subscription_status)}</td><td><div class="actions">${has('lecturers.edit')?`<button class="btn sm" data-action="edit-lecturer" data-id="${l.id}"><i class="fi fi-rr-pencil" aria-hidden="true"></i><span>تعديل</span></button>`:''}${has('subscriptions.renew')?`<button class="btn sm primary" data-action="renew-lecturer" data-id="${l.id}"><i class="fi fi-rr-refresh" aria-hidden="true"></i><span>تجديد</span></button>`:''}${has('enrollments.create')?`<button class="btn sm" data-action="enroll-lecturer" data-id="${l.id}"><i class="fi fi-rr-user-add" aria-hidden="true"></i><span>طالب</span></button>`:''}${has('lecturers.archive')?`<button class="btn sm" data-action="archive-lecturer" data-id="${l.id}"><i class="fi fi-rr-box-open-full" aria-hidden="true"></i><span>أرشفة</span></button>`:''}</div></td></tr>`).join('')||'<tr><td colspan="9">لا يوجد محاضرون.</td></tr>';}
function renderStudents(){const q=($('#studentSearch').value||'').toLowerCase(),rows=state.students.filter(s=>`${s.full_name} ${s.student_code||''} ${s.phone||''}`.toLowerCase().includes(q));$('#studentsBody').innerHTML=rows.map(s=>`<tr><td>${esc(s.student_code||'-')}</td><td><strong>${esc(s.full_name)}</strong></td><td>${esc(s.phone||'-')}</td><td>${esc(s.parent_phone||'-')}</td><td>${s.lecturer_count||0}</td><td>${money(s.total_required)}</td><td>${money(s.total_paid)}</td><td>${money(s.remaining)}</td><td><div class="actions">${has('students.edit')?`<button class="btn sm" data-action="edit-student" data-id="${s.id}"><i class="fi fi-rr-pencil" aria-hidden="true"></i><span>تعديل</span></button>`:''}${has('enrollments.create')?`<button class="btn sm primary" data-action="enroll-student" data-id="${s.id}"><i class="fi fi-rr-user-add" aria-hidden="true"></i><span>محاضر</span></button>`:''}${has('students.archive')?`<button class="btn sm" data-action="archive-student" data-id="${s.id}"><i class="fi fi-rr-box-open-full" aria-hidden="true"></i><span>أرشفة</span></button>`:''}</div></td></tr>`).join('')||'<tr><td colspan="9">لا يوجد طلاب.</td></tr>';}
function renderEnrollments(){const q=($('#enrollmentSearch').value||'').toLowerCase(),rows=state.enrollments.filter(e=>`${e.student_name} ${e.lecturer_name}`.toLowerCase().includes(q));$('#enrollmentsBody').innerHTML=rows.map(e=>`<tr><td><strong>${esc(e.student_name)}</strong><br><small>${esc(e.student_code||'')}</small></td><td>${esc(e.lecturer_name)}</td><td>${esc(e.subject||e.lecturer_subject||'-')}</td><td>${dateText(e.enrollment_date)}</td><td>${money(e.required_fee)}</td><td>${money(e.paid_amount)}</td><td>${money(e.remaining_amount)}</td><td>${statusBadge(e.payment_status)}</td><td><div class="actions">${has('payments.create')&&e.remaining_amount>0?`<button class="btn sm primary" data-action="pay-enrollment" data-id="${e.id}" data-remaining="${Number(e.remaining_amount)}"><i class="fi fi-rr-receipt" aria-hidden="true"></i><span>دفع</span></button>`:''}${has('enrollments.cancel')?`<button class="btn sm" data-action="cancel-enrollment" data-id="${e.id}"><i class="fi fi-rr-cross-circle" aria-hidden="true"></i><span>إلغاء التسجيل</span></button>`:''}</div></td></tr>`).join('')||'<tr><td colspan="9">لا توجد تسجيلات.</td></tr>';}
function renderPayments(){const q=($('#paymentSearch').value||'').toLowerCase(),rows=state.payments.filter(p=>`${p.receipt_no} ${p.student_name||''} ${p.lecturer_name||''}`.toLowerCase().includes(q));$('#paymentsBody').innerHTML=rows.map(p=>`<tr><td>${esc(p.receipt_no)}</td><td>${p.payment_type==='student_enrollment'?'رسوم طالب':'اشتراك محاضر'}</td><td>${esc(p.student_name||p.lecturer_name||'-')}</td><td>${money(p.amount)}</td><td>${esc(p.payment_method)}</td><td>${dateText(p.payment_date)}</td></tr>`).join('')||'<tr><td colspan="6">لا توجد مدفوعات.</td></tr>';}
function renderAdmins(){$('#adminsBody').innerHTML=state.admins.map(a=>`<tr><td><strong>${esc(a.full_name)}</strong>${a.id===state.auth.id?' <span class="badge green">أنت</span>':''}</td><td dir="ltr">${esc(a.username)}</td><td><span class="role-chip">${esc(ROLE_NAMES[a.role]||a.role)}</span></td><td>${statusBadge(a.status)}</td><td>${dateText(a.last_login_at)}</td><td><div class="actions">${has('admins.manage')?`<button class="btn sm" data-action="edit-admin" data-id="${a.id}"><i class="fi fi-rr-pencil" aria-hidden="true"></i><span>تعديل</span></button><button class="btn sm" data-action="reset-admin" data-id="${a.id}"><i class="fi fi-rr-key" aria-hidden="true"></i><span>كلمة المرور</span></button>`:''}</div></td></tr>`).join('')||'<tr><td colspan="6">لا يوجد مسؤولون.</td></tr>';}
function populateSelects(){const sf=$('#enrollmentForm [name=student_id]'),lf=$('#enrollmentForm [name=lecturer_id]');if(sf)sf.innerHTML='<option value="">اختر الطالب</option>'+state.students.filter(s=>s.status==='active').map(s=>`<option value="${s.id}">${esc(s.full_name)} — ${esc(s.student_code||'')}</option>`).join('');if(lf)lf.innerHTML='<option value="">اختر المحاضر</option>'+state.lecturers.filter(l=>l.status==='active').map(l=>`<option value="${l.id}">${esc(l.full_name)} — ${esc(l.subject||'بدون مادة')}</option>`).join('');}
function renderPermissionCheckboxes(){if(!state.adminMeta)return;$('#permissionsGrid').innerHTML=state.adminMeta.permissions.map(p=>`<label class="perm-item"><input type="checkbox" name="permissions" value="${esc(p)}" /><span>${esc(PERM_NAMES[p]||p)}</span></label>`).join('');}
function syncRolePermissions(role){if(!state.adminMeta)return;const preset=state.adminMeta.role_presets[role]||[];$$('#permissionsGrid input').forEach(c=>{c.checked=preset.includes(c.value);c.disabled=role!=='custom';});}

$('#setupForm').addEventListener('submit',async e=>{e.preventDefault();const d=formData(e.target);$('#setupError').textContent='';if(d.password!==d.password_confirm){$('#setupError').textContent='كلمتا المرور غير متطابقتين.';return;}delete d.password_confirm;setBusy(e.target,true);try{const r=await api('/api/setup/owner',{method:'POST',body:JSON.stringify(d)});state.auth=r.admin;state.csrf=r.csrf_token;showApp();applyPermissions();await loadAll();state.lastRefresh=new Date();updateRefreshStatus(`آخر تحديث ${refreshTimeText(state.lastRefresh)}`);syncAutoRefreshUi();startAutoRefresh();toast('تم إنشاء حساب الـOwner بنجاح.');}catch(err){if(err.message.includes('بالفعل')){showLogin();$('#loginError').textContent='تم إنشاء حساب الـOwner بالفعل. سجّل الدخول.';}else if(String(err.code||'').startsWith('DB_')||String(err.code||'').startsWith('SETUP_')){showSystemError(err);}else{$('#setupError').textContent=err.message;}}finally{setBusy(e.target,false);}});
$('#loginForm').addEventListener('submit',async e=>{e.preventDefault();setBusy(e.target,true);$('#loginError').textContent='';try{const r=await api('/api/auth/login',{method:'POST',body:JSON.stringify(formData(e.target))});state.auth=r.admin;state.csrf=r.csrf_token;showApp();applyPermissions();await loadAll();state.lastRefresh=new Date();updateRefreshStatus(`آخر تحديث ${refreshTimeText(state.lastRefresh)}`);syncAutoRefreshUi();startAutoRefresh();}catch(err){$('#loginError').textContent=err.message;}finally{setBusy(e.target,false);}});
$('#logoutBtn').onclick=async()=>{try{await api('/api/auth/logout',{method:'POST',body:'{}'});}catch{}showLogin();};
$('#changePasswordBtn').onclick=()=>{$('#changePasswordForm').reset();openModal('changePasswordModal');};
$('#menuBtn').onclick=()=>$('#sidebar').classList.toggle('open');
$('#nav').addEventListener('click',e=>{const b=e.target.closest('[data-page]');if(b)navigate(b.dataset.page);});
$('#refreshBtn').addEventListener('click',()=>refreshCurrentPage({silent:false}));
$('#autoRefreshToggle').addEventListener('change',e=>{
  state.autoRefresh=!!e.target.checked;
  try{localStorage.setItem('lecturer-admin:auto-refresh',state.autoRefresh?'on':'off');}catch{}
  if(state.autoRefresh){startAutoRefresh();updateRefreshStatus(state.lastRefresh?`آخر تحديث ${refreshTimeText(state.lastRefresh)}`:'التحديث التلقائي مفعل');}
  else{stopAutoRefresh();updateRefreshStatus('التحديث التلقائي متوقف');}
});
document.addEventListener('visibilitychange',()=>{
  if(!document.hidden&&state.auth&&state.autoRefresh){
    const elapsed=state.lastRefresh?Date.now()-state.lastRefresh.getTime():Infinity;
    if(elapsed>30000) refreshCurrentPage({silent:true,auto:true});
  }
});

$$('[data-open]').forEach(b=>b.onclick=()=>{if(b.hidden)return;if(b.dataset.open==='lecturerModal'){const f=$('#lecturerForm');f.reset();f.elements.id.value='';f.elements.monthly_fee.value=state.settings.default_monthly_fee||500;f.elements.student_enrollment_fee.value=state.settings.default_student_fee||200;}if(b.dataset.open==='studentModal'){const f=$('#studentForm');f.reset();f.elements.id.value='';}if(b.dataset.open==='enrollmentModal'){const f=$('#enrollmentForm');f.reset();f.elements.enrollment_date.value=new Date().toISOString().slice(0,10);populateSelects();}openModal(b.dataset.open);});
$$('[data-close]').forEach(b=>b.onclick=()=>closeDialog(b));
['lecturerSearch','studentSearch','enrollmentSearch','paymentSearch'].forEach(id=>$('#'+id).addEventListener('input',()=>({lecturerSearch:renderLecturers,studentSearch:renderStudents,enrollmentSearch:renderEnrollments,paymentSearch:renderPayments}[id])()));

async function submitForm(e,path,method,success,after){e.preventDefault();setBusy(e.target,true);try{await api(path,{method,body:JSON.stringify(formData(e.target))});e.target.closest('dialog')?.close();toast(success);await after?.();}catch(err){toast(err.message,true);}finally{setBusy(e.target,false);}}
$('#lecturerForm').addEventListener('submit',async e=>{const d=formData(e.target),id=d.id;delete d.id;e.preventDefault();setBusy(e.target,true);try{await api(id?`/api/lecturers/${id}`:'/api/lecturers',{method:id?'PUT':'POST',body:JSON.stringify(d)});e.target.closest('dialog').close();toast(id?'تم تحديث المحاضر.':'تم إضافة المحاضر.');await Promise.all([loadLecturers(),loadDashboard()]);}catch(err){toast(err.message,true);}finally{setBusy(e.target,false);}});
$('#studentForm').addEventListener('submit',async e=>{const d=formData(e.target),id=d.id;delete d.id;e.preventDefault();setBusy(e.target,true);try{await api(id?`/api/students/${id}`:'/api/students',{method:id?'PUT':'POST',body:JSON.stringify(d)});e.target.closest('dialog').close();toast(id?'تم تحديث الطالب.':'تم إضافة الطالب.');await Promise.all([loadStudents(),loadDashboard()]);}catch(err){toast(err.message,true);}finally{setBusy(e.target,false);}});
$('#enrollmentForm [name=lecturer_id]').addEventListener('change',e=>{const l=state.lecturers.find(x=>x.id===Number(e.target.value));$('#enrollmentForm [name=required_fee]').value=l?.student_enrollment_fee??'';});
$('#enrollmentForm').addEventListener('submit',e=>submitForm(e,'/api/enrollments','POST','تم تسجيل الطالب مع المحاضر.',()=>Promise.all([loadEnrollments(),loadStudents(),loadLecturers(),loadPayments(),loadDashboard()])));
$('#renewForm').addEventListener('submit',async e=>{e.preventDefault();const d=formData(e.target),id=d.lecturer_id;delete d.lecturer_id;setBusy(e.target,true);try{await api(`/api/lecturers/${id}/renew`,{method:'POST',body:JSON.stringify(d)});e.target.closest('dialog').close();toast('تم تجديد الاشتراك.');await Promise.all([loadLecturers(),loadPayments(),loadDashboard()]);}catch(err){toast(err.message,true);}finally{setBusy(e.target,false);}});
$('#paymentForm').addEventListener('submit',e=>submitForm(e,'/api/payments/enrollment','POST','تم تسجيل الدفعة.',()=>Promise.all([loadEnrollments(),loadStudents(),loadPayments(),loadDashboard()])));
$('#settingsForm').addEventListener('submit',async e=>{e.preventDefault();if(!has('settings.manage'))return;setBusy(e.target,true);try{await api('/api/settings',{method:'PUT',body:JSON.stringify(formData(e.target))});toast('تم حفظ الإعدادات.');await Promise.all([loadSettings(),loadDashboard()]);}catch(err){toast(err.message,true);}finally{setBusy(e.target,false);}});
$('#changePasswordForm').addEventListener('submit',e=>submitForm(e,'/api/auth/change-password','POST','تم تغيير كلمة المرور.',null));

$('#addAdminBtn').onclick=()=>{const f=$('#adminForm');f.reset();f.elements.id.value='';$('#adminPasswordField').hidden=false;f.elements.password.required=true;f.elements.role.value='viewer';syncRolePermissions('viewer');openModal('adminModal');};
$('#adminForm [name=role]').addEventListener('change',e=>syncRolePermissions(e.target.value));
$('#adminForm').addEventListener('submit',async e=>{e.preventDefault();const d=formData(e.target),id=d.id;d.permissions=$$('#permissionsGrid input:checked').map(x=>x.value);delete d.id;if(id&&!d.password)delete d.password;setBusy(e.target,true);try{await api(id?`/api/admins/${id}`:'/api/admins',{method:id?'PUT':'POST',body:JSON.stringify(d)});e.target.closest('dialog').close();toast(id?'تم تحديث المسؤول.':'تم إضافة المسؤول.');await loadAdmins();}catch(err){toast(err.message,true);}finally{setBusy(e.target,false);}});
$('#resetPasswordForm').addEventListener('submit',async e=>{e.preventDefault();const d=formData(e.target),id=d.admin_id;setBusy(e.target,true);try{await api(`/api/admins/${id}/reset-password`,{method:'POST',body:JSON.stringify({password:d.password})});e.target.closest('dialog').close();toast('تم تغيير كلمة مرور المسؤول.');}catch(err){toast(err.message,true);}finally{setBusy(e.target,false);}});

$('#renewForm [name=months]').addEventListener('input',e=>{const id=Number($('#renewForm [name=lecturer_id]').value),l=state.lecturers.find(x=>x.id===id),total=(Number(e.target.value)||1)*Number(l?.monthly_fee||0);$('#renewForm [name=required_amount]').value=total;$('#renewForm [name=paid_amount]').value=total;});

document.body.addEventListener('click',async e=>{const b=e.target.closest('[data-action]');if(!b)return;const id=Number(b.dataset.id);try{switch(b.dataset.action){case'edit-lecturer':{const l=state.lecturers.find(x=>x.id===id),f=$('#lecturerForm');f.reset();Object.entries(l||{}).forEach(([k,v])=>{if(f.elements[k])f.elements[k].value=v??'';});f.elements.id.value=id;openModal('lecturerModal');break;}case'renew-lecturer':{const l=state.lecturers.find(x=>x.id===id),f=$('#renewForm');f.reset();f.elements.lecturer_id.value=id;f.elements.months.value=1;f.elements.required_amount.value=l?.monthly_fee||0;f.elements.paid_amount.value=l?.monthly_fee||0;openModal('renewModal');break;}case'enroll-lecturer':{const f=$('#enrollmentForm');f.reset();populateSelects();f.elements.lecturer_id.value=id;f.elements.enrollment_date.value=new Date().toISOString().slice(0,10);const l=state.lecturers.find(x=>x.id===id);f.elements.required_fee.value=l?.student_enrollment_fee||0;openModal('enrollmentModal');break;}case'archive-lecturer':if(confirm('هل تريد أرشفة هذا المحاضر؟ لن يتم حذف السجلات المالية.')){await api(`/api/lecturers/${id}`,{method:'DELETE',body:'{}'});toast('تمت أرشفة المحاضر.');await Promise.all([loadLecturers(),loadDashboard()]);}break;case'edit-student':{const s=state.students.find(x=>x.id===id),f=$('#studentForm');f.reset();Object.entries(s||{}).forEach(([k,v])=>{if(f.elements[k])f.elements[k].value=v??'';});f.elements.id.value=id;openModal('studentModal');break;}case'enroll-student':{const f=$('#enrollmentForm');f.reset();populateSelects();f.elements.student_id.value=id;f.elements.enrollment_date.value=new Date().toISOString().slice(0,10);openModal('enrollmentModal');break;}case'archive-student':if(confirm('هل تريد أرشفة هذا الطالب؟ لن يتم حذف السجلات المالية.')){await api(`/api/students/${id}`,{method:'DELETE',body:'{}'});toast('تمت أرشفة الطالب.');await Promise.all([loadStudents(),loadDashboard()]);}break;case'pay-enrollment':{const f=$('#paymentForm');f.reset();f.elements.enrollment_id.value=id;f.elements.amount.value=b.dataset.remaining;openModal('paymentModal');break;}case'cancel-enrollment':if(confirm('هل تريد إلغاء تسجيل الطالب مع هذا المحاضر؟ المدفوعات القديمة ستظل محفوظة.')){await api(`/api/enrollments/${id}`,{method:'DELETE',body:'{}'});toast('تم إلغاء التسجيل.');await Promise.all([loadEnrollments(),loadStudents(),loadLecturers(),loadDashboard()]);}break;case'edit-admin':{const a=state.admins.find(x=>x.id===id),f=$('#adminForm');f.reset();f.elements.id.value=id;f.elements.full_name.value=a.full_name;f.elements.username.value=a.username;f.elements.role.value=a.role;f.elements.status.value=a.status;$('#adminPasswordField').hidden=true;f.elements.password.required=false;renderPermissionCheckboxes();$$('#permissionsGrid input').forEach(c=>{c.checked=a.permissions.includes(c.value);c.disabled=a.role!=='custom';});openModal('adminModal');break;}case'reset-admin':{const f=$('#resetPasswordForm');f.reset();f.elements.admin_id.value=id;openModal('resetPasswordModal');break;}}}catch(err){toast(err.message,true);}});

$('#retrySystemBtn').addEventListener('click',()=>boot());
$$('[data-system-check]').forEach(btn=>btn.addEventListener('click',async()=>{
  try{
    const r=await api('/api/system/diagnostics');
    const failed=Object.entries(r.checks||{}).filter(([,v])=>!v.ok);
    if(!failed.length){showSystemError({message:'فحص النظام ناجح. قاعدة D1 والتشفير يعملان بشكل صحيح.',code:'SYSTEM_OK',stage:'ready',detail:'كل اختبارات D1 وCrypto نجحت.'});}
    else{const [name,v]=failed[0];showSystemError({message:'اكتشف فحص النظام مشكلة.',code:'DIAGNOSTIC_FAILED',stage:name,detail:v.detail||'Unknown'});}
  }catch(err){showSystemError(err);}
}));
try{state.autoRefresh=localStorage.getItem('lecturer-admin:auto-refresh')!=='off';}catch{state.autoRefresh=true;}
syncAutoRefreshUi();
boot();
