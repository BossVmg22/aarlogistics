// ─────────────────────────────────────────────────────────────────────────────
// functions/api/admin.js — Cloudflare Pages Function
// Upload this file to: functions/api/admin.js in your GitHub repo
// ─────────────────────────────────────────────────────────────────────────────

const SUPABASE_URL         = 'https://etohixhdxyxwlbeypsll.supabase.co';
const SUPABASE_SERVICE_KEY = 'PASTE_YOUR_SERVICE_ROLE_KEY_HERE'; // ← paste service_role key
const ALLOWED_ORIGINS      = ['https://aarlogistics.pages.dev'];

const _rateLimitMap = new Map();
function corsHeaders(origin) {
  const safe = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return { 'Access-Control-Allow-Origin': safe, 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, X-Session-Token', 'Vary': 'Origin' };
}
function json(data, status = 200, origin = '') {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) } });
}
function isRateLimited(ip) {
  const now = Date.now();
  const e = _rateLimitMap.get(ip) || { count: 0, windowStart: now };
  if (now - e.windowStart > 60000) { _rateLimitMap.set(ip, { count: 1, windowStart: now }); return false; }
  e.count++; _rateLimitMap.set(ip, e);
  return e.count > 60;
}
async function sbFetch(path, options = {}) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`, 'Prefer': 'return=representation', ...(options.headers || {}) }
  });
  const text = await res.text();
  try { return { ok: res.ok, status: res.status, data: JSON.parse(text) }; }
  catch { return { ok: res.ok, status: res.status, data: text }; }
}
async function getSession(token) {
  if (!token) return null;
  const r = await sbFetch(`/sessions?token=eq.${encodeURIComponent(token)}&select=username,level,expires_at&limit=1`);
  if (!r.ok || !Array.isArray(r.data) || !r.data.length) return null;
  const s = r.data[0];
  if (new Date(s.expires_at) < new Date()) { await sbFetch(`/sessions?token=eq.${encodeURIComponent(token)}`, { method: 'DELETE' }); return null; }
  return s;
}

export async function onRequest(context) {
  const { request } = context;
  const origin = request.headers.get('Origin') || '';
  const ip     = request.headers.get('CF-Connecting-IP') || 'unknown';

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(origin) });
  if (request.method !== 'POST')   return json({ status: 'error', message: 'Method not allowed.' }, 405, origin);
  if (isRateLimited(ip))           return json({ status: 'error', message: 'Rate limit exceeded.' }, 429, origin);

  let parsed;
  try { parsed = await request.json(); }
  catch { return json({ status: 'error', message: 'Invalid request.' }, 400, origin); }

  const session = await getSession(parsed.token);
  if (!session) return json({ status: 'error', message: 'Not authenticated.' }, 401, origin);
  if (session.level < 4) return json({ status: 'error', message: 'Regiment HC access required.' }, 403, origin);

  const { action } = parsed;

  // ── List accounts ──────────────────────────────────────────────────────────
  if (action === 'listAccounts') {
    const r = await sbFetch('/accounts?select=id,username,level,created_at&order=level.asc');
    if (!r.ok) return json({ status: 'error', message: 'Failed to fetch accounts.' }, 500, origin);
    return json({ status: 'success', data: r.data }, 200, origin);
  }

  // ── Create account ─────────────────────────────────────────────────────────
  if (action === 'createAccount') {
    const { newUsername, newPassword, level } = parsed;
    if (!newUsername || !newPassword || !level) return json({ status: 'error', message: 'All fields required.' }, 400, origin);
    if (![1,2,3,4].includes(parseInt(level)))   return json({ status: 'error', message: 'Level must be 1–4.' }, 400, origin);
    if (newPassword.length < 8)                 return json({ status: 'error', message: 'Password must be at least 8 characters.' }, 400, origin);
    const hashRes = await sbFetch('/rpc/hash_password', { method: 'POST', body: JSON.stringify({ plain: newPassword }) });
    if (!hashRes.ok) return json({ status: 'error', message: 'Failed to hash password.' }, 500, origin);
    const r = await sbFetch('/accounts', { method: 'POST', body: JSON.stringify({ username: newUsername.trim(), password_hash: hashRes.data, level: parseInt(level) }) });
    if (!r.ok) {
      const msg = typeof r.data === 'object' ? (r.data?.message || r.data?.details || '') : String(r.data);
      if (msg.includes('unique') || msg.includes('duplicate') || r.status === 409)
        return json({ status: 'error', message: `Username "${newUsername}" already exists.` }, 409, origin);
      return json({ status: 'error', message: 'Failed to create account.' }, 500, origin);
    }
    return json({ status: 'success', message: `Account "${newUsername}" created at Level ${level}.` }, 200, origin);
  }

  // ── Update username ────────────────────────────────────────────────────────
  if (action === 'updateUsername') {
    const { targetUsername, newUsername } = parsed;
    if (!targetUsername || !newUsername) return json({ status: 'error', message: 'Both fields required.' }, 400, origin);
    const r = await sbFetch(`/accounts?username=eq.${encodeURIComponent(targetUsername)}`, { method: 'PATCH', body: JSON.stringify({ username: newUsername.trim() }) });
    if (!r.ok) return json({ status: 'error', message: 'Failed to update username.' }, 500, origin);
    return json({ status: 'success', message: `Username updated to "${newUsername}".` }, 200, origin);
  }

  // ── Update password ────────────────────────────────────────────────────────
  if (action === 'updatePassword') {
    const { targetUsername, newPassword } = parsed;
    if (!targetUsername || !newPassword) return json({ status: 'error', message: 'Both fields required.' }, 400, origin);
    if (newPassword.length < 8)          return json({ status: 'error', message: 'Password must be at least 8 characters.' }, 400, origin);
    const hashRes = await sbFetch('/rpc/hash_password', { method: 'POST', body: JSON.stringify({ plain: newPassword }) });
    if (!hashRes.ok) return json({ status: 'error', message: 'Failed to hash password.' }, 500, origin);
    const r = await sbFetch(`/accounts?username=eq.${encodeURIComponent(targetUsername)}`, { method: 'PATCH', body: JSON.stringify({ password_hash: hashRes.data }) });
    if (!r.ok) return json({ status: 'error', message: 'Failed to update password.' }, 500, origin);
    return json({ status: 'success', message: `Password updated for "${targetUsername}".` }, 200, origin);
  }

  // ── Delete account ─────────────────────────────────────────────────────────
  if (action === 'deleteAccount') {
    const { targetUsername } = parsed;
    if (!targetUsername) return json({ status: 'error', message: 'Username required.' }, 400, origin);
    if (targetUsername === session.username) return json({ status: 'error', message: 'You cannot delete your own account.' }, 400, origin);
    const r = await sbFetch(`/accounts?username=eq.${encodeURIComponent(targetUsername)}`, { method: 'DELETE' });
    if (!r.ok) return json({ status: 'error', message: 'Failed to delete account.' }, 500, origin);
    return json({ status: 'success', message: `Account "${targetUsername}" deleted.` }, 200, origin);
  }

  return json({ status: 'error', message: 'Unknown action.' }, 400, origin);
}
