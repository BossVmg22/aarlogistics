// ─────────────────────────────────────────────────────────────────────────────
// functions/api/auth.js — Cloudflare Pages Function
// Upload this file to: functions/api/auth.js in your GitHub repo
// ─────────────────────────────────────────────────────────────────────────────

const SUPABASE_URL         = 'https://etohixhdxyxwlbeypsll.supabase.co';
const SUPABASE_SERVICE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV0b2hpeGhkeHl4d2xiZXlwc2xsIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4MDMwNjIwNCwiZXhwIjoyMDk1ODgyMjA0fQ.6sSZuBTer_j6hIwRcftwFHWNJMbaFiuhwYcDgwMsPfk
'; // ← paste service_role key
const ALLOWED_ORIGINS      = ['https://aarlogistics.pages.dev'];
const SESSION_TTL_MS       = 8 * 60 * 60 * 1000; // 8 hours

// Shared in-memory session store
// Note: In Cloudflare Pages, each file is its own worker instance.
// Sessions created in auth.js are checked in proxy.js and admin.js
// by re-validating against Supabase. See getSession() below.
const _rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQS  = 20; // stricter for auth endpoint

function corsHeaders(origin) {
  const safe = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin':  safe,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Session-Token',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}
function json(data, status = 200, origin = '') {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) }
  });
}
function isRateLimited(ip) {
  const now = Date.now();
  const e = _rateLimitMap.get(ip) || { count: 0, windowStart: now };
  if (now - e.windowStart > RATE_LIMIT_WINDOW_MS) { _rateLimitMap.set(ip, { count: 1, windowStart: now }); return false; }
  e.count++; _rateLimitMap.set(ip, e);
  return e.count > RATE_LIMIT_MAX_REQS;
}
function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(x => x.toString(16).padStart(2,'0')).join('');
}
async function sbFetch(path, options = {}) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Prefer': 'return=representation',
      ...(options.headers || {})
    }
  });
  const text = await res.text();
  try { return { ok: res.ok, status: res.status, data: JSON.parse(text) }; }
  catch { return { ok: res.ok, status: res.status, data: text }; }
}

// We store sessions in Supabase so all 3 worker files can share them
async function createSession(username, level) {
  const token   = generateToken();
  const expires = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  await sbFetch('/sessions', {
    method: 'POST',
    body: JSON.stringify({ token, username, level, expires_at: expires })
  });
  return token;
}

export async function onRequest(context) {
  const { request } = context;
  const origin = request.headers.get('Origin') || '';
  const ip     = request.headers.get('CF-Connecting-IP') || 'unknown';

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(origin) });
  if (request.method !== 'POST')   return json({ status: 'error', message: 'Method not allowed.' }, 405, origin);
  if (isRateLimited(ip))           return json({ status: 'error', message: 'Too many attempts. Try again in 60s.' }, 429, origin);

  let parsed;
  try { parsed = await request.json(); }
  catch { return json({ status: 'error', message: 'Invalid request.' }, 400, origin); }

  const { action, username, password, token } = parsed;

  // ── Login ──────────────────────────────────────────────────────────────────
  if (action === 'login') {
    if (!username || !password)
      return json({ status: 'error', message: 'Username and password required.' }, 400, origin);

    const r = await sbFetch(`/accounts?username=eq.${encodeURIComponent(username.trim())}&select=id,username,password_hash,level&limit=1`);
    if (!r.ok || !Array.isArray(r.data) || !r.data.length)
      return json({ status: 'error', message: 'Invalid username or password.' }, 401, origin);

    const account = r.data[0];
    const verifyRes = await sbFetch('/rpc/verify_password', {
      method: 'POST',
      body: JSON.stringify({ plain: password, hashed: account.password_hash })
    });
    if (!verifyRes.ok || verifyRes.data !== true)
      return json({ status: 'error', message: 'Invalid username or password.' }, 401, origin);

    const sessionToken = await createSession(account.username, account.level);
    return json({ status: 'success', token: sessionToken, level: account.level, username: account.username }, 200, origin);
  }

  // ── Logout ─────────────────────────────────────────────────────────────────
  if (action === 'logout') {
    if (token) await sbFetch(`/sessions?token=eq.${encodeURIComponent(token)}`, { method: 'DELETE' });
    return json({ status: 'success' }, 200, origin);
  }

  // ── Validate ───────────────────────────────────────────────────────────────
  if (action === 'validate') {
    if (!token) return json({ status: 'error', message: 'No token.' }, 401, origin);
    const r = await sbFetch(`/sessions?token=eq.${encodeURIComponent(token)}&select=username,level,expires_at&limit=1`);
    if (!r.ok || !Array.isArray(r.data) || !r.data.length)
      return json({ status: 'error', message: 'Session expired.' }, 401, origin);
    const s = r.data[0];
    if (new Date(s.expires_at) < new Date()) {
      await sbFetch(`/sessions?token=eq.${encodeURIComponent(token)}`, { method: 'DELETE' });
      return json({ status: 'error', message: 'Session expired.' }, 401, origin);
    }
    return json({ status: 'success', level: s.level, username: s.username }, 200, origin);
  }

  return json({ status: 'error', message: 'Unknown action.' }, 400, origin);
}
