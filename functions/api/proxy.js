// ─────────────────────────────────────────────────────────────────────────────
// proxy.js — Cloudflare Pages Functions
// AAR Logistics Management System v4.0
// Multi-account auth via Supabase + bcrypt
// ─────────────────────────────────────────────────────────────────────────────

// ── CONFIGURE THESE ──────────────────────────────────────────────────────────
const SUPABASE_URL     = 'https://etohixhdxyxwlbeypsll.supabase.co';
const SUPABASE_SERVICE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV0b2hpeGhkeHl4d2xiZXlwc2xsIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4MDMwNjIwNCwiZXhwIjoyMDk1ODgyMjA0fQ.6sSZuBTer_j6hIwRcftwFHWNJMbaFiuhwYcDgwMsPfk
'; 
const GAS_URL          = 'https://script.google.com/macros/s/AKfycbxXpcDus7WSGZdzO9j3YgshTXouEkgMLFRgMLdePHS9rL_8eSnmJcmrJ77auoOoeeMxmA/exec';
const ALLOWED_ORIGINS  = [
  'https://aarlogistics.pages.dev/', // ← update to your real domain
];
// ─────────────────────────────────────────────────────────────────────────────

const ALLOWED_ACTIONS = new Set([
  'addHighCommand','addBatteryCommand','addPersonnel',
  'logEvent','issueStrike','removeStrike','getPersonnelInfo',
  'updatePersonnelInfo','removePersonnel','sendLog',
  'setLoA','resetLoA','reassignPersonnel','weeklyReset',
  'getAllPersonnel','getStaffInfo'
]);

const ALLOWED_WEBHOOK_HOSTS = ['discord.com','discordapp.com'];
const MAX_BODY_SIZE = 65536;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQS  = 60;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

// In-memory stores (reset on worker restart — fine for Cloudflare Pages)
const _rateLimitMap = new Map();
const _sessionStore = new Map(); // token → { username, level, expires }

// ── Helpers ───────────────────────────────────────────────────────────────────
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
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) }
  });
}

function isRateLimited(ip) {
  const now = Date.now();
  const e   = _rateLimitMap.get(ip) || { count: 0, windowStart: now };
  if (now - e.windowStart > RATE_LIMIT_WINDOW_MS) {
    _rateLimitMap.set(ip, { count: 1, windowStart: now }); return false;
  }
  e.count++;
  _rateLimitMap.set(ip, e);
  return e.count > RATE_LIMIT_MAX_REQS;
}

function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(x => x.toString(16).padStart(2,'0')).join('');
}

// ── bcrypt via Supabase RPC ───────────────────────────────────────────────────
// We use Supabase's built-in pgcrypto for bcrypt — no npm needed in CF Pages
async function supabaseQuery(query, params = []) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/run_query`, {
    method: 'POST',
    headers: {
      'Content-Type':  'application/json',
      'apikey':        SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
    },
    body: JSON.stringify({ query, params })
  });
  return res.json();
}

// Direct Supabase table access
async function sbFetch(path, options = {}) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1${path}`, {
    ...options,
    headers: {
      'Content-Type':  'application/json',
      'apikey':        SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Prefer':        'return=representation',
      ...(options.headers || {})
    }
  });
  const text = await res.text();
  try { return { ok: res.ok, status: res.status, data: JSON.parse(text) }; }
  catch { return { ok: res.ok, status: res.status, data: text }; }
}

// ── Session helpers ───────────────────────────────────────────────────────────
function createSession(username, level) {
  const token = generateToken();
  _sessionStore.set(token, { username, level, expires: Date.now() + SESSION_TTL_MS });
  return token;
}

function getSession(token) {
  if (!token) return null;
  const s = _sessionStore.get(token);
  if (!s) return null;
  if (Date.now() > s.expires) { _sessionStore.delete(token); return null; }
  return s;
}

function deleteSession(token) {
  _sessionStore.delete(token);
}

// ── Route: POST /api/auth ─────────────────────────────────────────────────────
async function handleAuth(parsed, origin) {
  const { action, username, password, token, newUsername, newPassword } = parsed;

  // ── Login ──
  if (action === 'login') {
    if (!username || !password)
      return json({ status: 'error', message: 'Username and password required.' }, 400, origin);

    // Fetch account from Supabase
    const r = await sbFetch(`/accounts?username=eq.${encodeURIComponent(username.trim())}&select=id,username,password_hash,level&limit=1`);
    if (!r.ok || !Array.isArray(r.data) || r.data.length === 0)
      return json({ status: 'error', message: 'Invalid username or password.' }, 401, origin);

    const account = r.data[0];

    // Verify password using Supabase pgcrypto bcrypt check
    const verifyRes = await sbFetch('/rpc/verify_password', {
      method: 'POST',
      body: JSON.stringify({ plain: password, hashed: account.password_hash })
    });

    if (!verifyRes.ok || verifyRes.data !== true)
      return json({ status: 'error', message: 'Invalid username or password.' }, 401, origin);

    const sessionToken = createSession(account.username, account.level);
    return json({ status: 'success', token: sessionToken, level: account.level, username: account.username }, 200, origin);
  }

  // ── Logout ──
  if (action === 'logout') {
    if (token) deleteSession(token);
    return json({ status: 'success' }, 200, origin);
  }

  // ── Validate session ──
  if (action === 'validate') {
    const s = getSession(token);
    if (!s) return json({ status: 'error', message: 'Session expired.' }, 401, origin);
    return json({ status: 'success', level: s.level, username: s.username }, 200, origin);
  }

  return json({ status: 'error', message: 'Unknown auth action.' }, 400, origin);
}

// ── Route: POST /api/admin ────────────────────────────────────────────────────
async function handleAdmin(parsed, origin) {
  const { token, action } = parsed;
  const session = getSession(token);
  if (!session) return json({ status: 'error', message: 'Not authenticated.' }, 401, origin);
  if (session.level < 4) return json({ status: 'error', message: 'Insufficient permissions.' }, 403, origin);

  // ── List accounts ──
  if (action === 'listAccounts') {
    const r = await sbFetch('/accounts?select=id,username,level,created_at&order=level.asc');
    if (!r.ok) return json({ status: 'error', message: 'Failed to fetch accounts.' }, 500, origin);
    return json({ status: 'success', data: r.data }, 200, origin);
  }

  // ── Create account ──
  if (action === 'createAccount') {
    const { newUsername, newPassword, level } = parsed;
    if (!newUsername || !newPassword || !level)
      return json({ status: 'error', message: 'Username, password, and level required.' }, 400, origin);
    if (![1,2,3,4].includes(parseInt(level)))
      return json({ status: 'error', message: 'Level must be 1–4.' }, 400, origin);
    if (newPassword.length < 8)
      return json({ status: 'error', message: 'Password must be at least 8 characters.' }, 400, origin);

    // Hash password via Supabase pgcrypto
    const hashRes = await sbFetch('/rpc/hash_password', {
      method: 'POST',
      body: JSON.stringify({ plain: newPassword })
    });
    if (!hashRes.ok) return json({ status: 'error', message: 'Failed to hash password.' }, 500, origin);

    const r = await sbFetch('/accounts', {
      method: 'POST',
      body: JSON.stringify({ username: newUsername.trim(), password_hash: hashRes.data, level: parseInt(level) })
    });
    if (!r.ok) {
      const msg = r.data?.message || '';
      if (msg.includes('unique') || msg.includes('duplicate'))
        return json({ status: 'error', message: `Username "${newUsername}" already exists.` }, 409, origin);
      return json({ status: 'error', message: 'Failed to create account.' }, 500, origin);
    }
    return json({ status: 'success', message: `Account "${newUsername}" created at Level ${level}.` }, 200, origin);
  }

  // ── Update username ──
  if (action === 'updateUsername') {
    const { targetUsername, newUsername } = parsed;
    if (!targetUsername || !newUsername)
      return json({ status: 'error', message: 'Target and new username required.' }, 400, origin);

    const r = await sbFetch(`/accounts?username=eq.${encodeURIComponent(targetUsername)}`, {
      method: 'PATCH',
      body: JSON.stringify({ username: newUsername.trim() })
    });
    if (!r.ok) return json({ status: 'error', message: 'Failed to update username.' }, 500, origin);
    return json({ status: 'success', message: `Username updated to "${newUsername}".` }, 200, origin);
  }

  // ── Update password ──
  if (action === 'updatePassword') {
    const { targetUsername, newPassword } = parsed;
    if (!targetUsername || !newPassword)
      return json({ status: 'error', message: 'Target username and new password required.' }, 400, origin);
    if (newPassword.length < 8)
      return json({ status: 'error', message: 'Password must be at least 8 characters.' }, 400, origin);

    const hashRes = await sbFetch('/rpc/hash_password', {
      method: 'POST',
      body: JSON.stringify({ plain: newPassword })
    });
    if (!hashRes.ok) return json({ status: 'error', message: 'Failed to hash password.' }, 500, origin);

    const r = await sbFetch(`/accounts?username=eq.${encodeURIComponent(targetUsername)}`, {
      method: 'PATCH',
      body: JSON.stringify({ password_hash: hashRes.data })
    });
    if (!r.ok) return json({ status: 'error', message: 'Failed to update password.' }, 500, origin);
    return json({ status: 'success', message: `Password updated for "${targetUsername}".` }, 200, origin);
  }

  // ── Delete account ──
  if (action === 'deleteAccount') {
    const { targetUsername } = parsed;
    if (!targetUsername) return json({ status: 'error', message: 'Target username required.' }, 400, origin);
    if (targetUsername === session.username)
      return json({ status: 'error', message: 'You cannot delete your own account.' }, 400, origin);

    const r = await sbFetch(`/accounts?username=eq.${encodeURIComponent(targetUsername)}`, { method: 'DELETE' });
    if (!r.ok) return json({ status: 'error', message: 'Failed to delete account.' }, 500, origin);
    return json({ status: 'success', message: `Account "${targetUsername}" deleted.` }, 200, origin);
  }

  return json({ status: 'error', message: 'Unknown admin action.' }, 400, origin);
}

// ── Route: POST /api/proxy ────────────────────────────────────────────────────
async function handleProxy(parsed, origin, sessionToken) {
  const session = getSession(sessionToken);
  if (!session) return json({ status: 'error', message: 'Not authenticated. Please log in.' }, 401, origin);

  // Level-based action guards
  const level = session.level;
  const action = parsed.action;
  const LV1_ACTIONS = new Set(['logEvent']);
  const LV2_ACTIONS = new Set(['addPersonnel','removePersonnel','logEvent']);
  const LV3_ACTIONS = new Set([...LV2_ACTIONS,'addBatteryCommand','issueStrike','removeStrike','updatePersonnelInfo','setLoA','resetLoA','weeklyReset','reassignPersonnel','getAllPersonnel','getStaffInfo']);
  const LV4_ACTIONS = new Set([...LV3_ACTIONS,'addHighCommand']);
  const READ_ACTIONS = new Set(['getPersonnelInfo','getAllPersonnel','getStaffInfo']);

  // Everyone can read
  if (!READ_ACTIONS.has(action)) {
    const allowed = level >= 4 ? LV4_ACTIONS : level >= 3 ? LV3_ACTIONS : level >= 2 ? LV2_ACTIONS : LV1_ACTIONS;
    if (!allowed.has(action))
      return json({ status: 'error', message: `Your account level does not have permission for this action.` }, 403, origin);
  }

  if (!ALLOWED_ACTIONS.has(action))
    return json({ status: 'error', message: 'Unknown action.' }, 400, origin);

  // sendLog SSRF protection
  if (action === 'sendLog') {
    let host;
    try { host = new URL(parsed.webhookUrl).hostname; } catch { return json({ status: 'error', message: 'Invalid webhook URL.' }, 400, origin); }
    if (!ALLOWED_WEBHOOK_HOSTS.some(h => host === h || host.endsWith('.'+h)))
      return json({ status: 'error', message: 'Webhook host not allowed.' }, 403, origin);
    try {
      await fetch(parsed.webhookUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(parsed.payload) });
      return json({ status: 'ok' }, 200, origin);
    } catch { return json({ status: 'error', message: 'Webhook delivery failed.' }, 502, origin); }
  }

  // Forward to GAS
  try {
    const gasRes = await fetch(GAS_URL, {
      method: 'POST',
      body: JSON.stringify(parsed),
      redirect: 'follow',
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(30000)
    });
    const data = await gasRes.text();
    return new Response(data, {
      status: gasRes.ok ? 200 : 502,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) }
    });
  } catch {
    return json({ status: 'error', message: 'Upstream service unavailable.' }, 503, origin);
  }
}

// ── Main handler ──────────────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request } = context;
  const origin = request.headers.get('Origin') || '';
  const ip     = request.headers.get('CF-Connecting-IP') || 'unknown';
  const url    = new URL(request.url);

  if (request.method === 'OPTIONS')
    return new Response(null, { status: 204, headers: corsHeaders(origin) });

  if (request.method !== 'POST')
    return json({ status: 'error', message: 'Method not allowed.' }, 405, origin);

  if (isRateLimited(ip))
    return json({ status: 'error', message: 'Rate limit exceeded.' }, 429, origin);

  const contentLength = parseInt(request.headers.get('Content-Length') || '0');
  if (contentLength > MAX_BODY_SIZE)
    return json({ status: 'error', message: 'Request too large.' }, 413, origin);

  let parsed;
  try {
    const body = await request.text();
    if (body.length > MAX_BODY_SIZE) throw new Error();
    parsed = JSON.parse(body);
  } catch {
    return json({ status: 'error', message: 'Invalid request body.' }, 400, origin);
  }

  const sessionToken = request.headers.get('X-Session-Token') || parsed._token || null;
  const path = url.pathname;

  if (path.endsWith('/api/auth'))  return handleAuth(parsed, origin);
  if (path.endsWith('/api/admin')) return handleAdmin(parsed, origin);
  if (path.endsWith('/api/proxy')) return handleProxy(parsed, origin, sessionToken);

  return json({ status: 'error', message: 'Not found.' }, 404, origin);
}
