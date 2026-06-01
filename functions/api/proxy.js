// ─────────────────────────────────────────────────────────────────────────────
// functions/api/proxy.js — Cloudflare Pages Function
// Upload this file to: functions/api/proxy.js in your GitHub repo
// ─────────────────────────────────────────────────────────────────────────────

const SUPABASE_URL         = 'https://etohixhdxyxwlbeypsll.supabase.co';
const SUPABASE_SERVICE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV0b2hpeGhkeHl4d2xiZXlwc2xsIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4MDMwNjIwNCwiZXhwIjoyMDk1ODgyMjA0fQ.6sSZuBTer_j6hIwRcftwFHWNJMbaFiuhwYcDgwMsPfk'; // ← paste service_role key
const GAS_URL              = 'https://script.google.com/macros/s/AKfycbxXpcDus7WSGZdzO9j3YgshTXouEkgMLFRgMLdePHS9rL_8eSnmJcmrJ77auoOoeeMxmA/exec';
const ALLOWED_ORIGINS      = ['https://aarlogistics.pages.dev'];

const ALLOWED_ACTIONS = new Set([
  'addHighCommand','addBatteryCommand','addPersonnel',
  'logEvent','issueStrike','removeStrike','getPersonnelInfo',
  'updatePersonnelInfo','removePersonnel','sendLog',
  'setLoA','resetLoA','reassignPersonnel','weeklyReset',
  'getAllPersonnel','getStaffInfo'
]);
const ALLOWED_WEBHOOK_HOSTS = ['discord.com','discordapp.com'];
const MAX_BODY_SIZE = 65536;

// Level-based action permissions
const LV1 = new Set(['logEvent','getPersonnelInfo','getAllPersonnel','getStaffInfo','sendLog']);
const LV2 = new Set([...LV1,'addPersonnel','removePersonnel']);
const LV3 = new Set([...LV2,'addBatteryCommand','issueStrike','removeStrike','updatePersonnelInfo','setLoA','resetLoA','weeklyReset','reassignPersonnel']);
const LV4 = new Set([...LV3,'addHighCommand']);

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
function sanitize(v) { return typeof v === 'string' ? v.trim().substring(0, 500) : v; }

async function sbFetch(path, options = {}) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`, 'Prefer': 'return=representation', ...(options.headers || {}) }
  });
  const text = await res.text();
  try { return { ok: res.ok, data: JSON.parse(text) }; }
  catch { return { ok: res.ok, data: text }; }
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
  const BOT_API_KEY = context.env.BOT_API_KEY || 'aar-bot-secret-key-2024';

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(origin) });
  if (request.method !== 'POST')   return json({ status: 'error', message: 'Method not allowed.' }, 405, origin);
  if (isRateLimited(ip))           return json({ status: 'error', message: 'Rate limit exceeded.' }, 429, origin);

  const contentLength = parseInt(request.headers.get('Content-Length') || '0');
  if (contentLength > MAX_BODY_SIZE) return json({ status: 'error', message: 'Request too large.' }, 413, origin);

  let parsed;
  try {
    const body = await request.text();
    if (body.length > MAX_BODY_SIZE) throw new Error();
    parsed = JSON.parse(body);
  } catch { return json({ status: 'error', message: 'Invalid request body.' }, 400, origin); }

  // ── Auth check ─────────────────────────────────────────────────────────────
  const isBot = parsed._apiKey && parsed._apiKey === BOT_API_KEY;
  let level = 0;

  if (isBot) {
    level = 4; // Bot requests have full access
  } else {
    const sessionToken = request.headers.get('X-Session-Token') || parsed._token || null;
    const session = await getSession(sessionToken);
    if (!session) return json({ status: 'error', message: 'Not authenticated. Please log in.' }, 401, origin);
    level = session.level;
  }

  // ── Permission check ───────────────────────────────────────────────────────
  const action  = parsed.action;
  if (!ALLOWED_ACTIONS.has(action)) return json({ status: 'error', message: 'Unknown action.' }, 400, origin);
  const allowed = level >= 4 ? LV4 : level >= 3 ? LV3 : level >= 2 ? LV2 : LV1;
  if (!allowed.has(action)) return json({ status: 'error', message: 'Your account does not have permission for this action.' }, 403, origin);

  // ── Sanitize payload ───────────────────────────────────────────────────────
  const safePayload = {};
  for (const [k, v] of Object.entries(parsed)) {
    if (k === '_token' || k === '_apiKey') continue;
    if (Array.isArray(v)) safePayload[k] = v.map(i => typeof i === 'object' ? Object.fromEntries(Object.entries(i).map(([ik,iv])=>[ik,sanitize(iv)])) : sanitize(i));
    else safePayload[k] = sanitize(v);
  }

  // ── sendLog SSRF protection ────────────────────────────────────────────────
  if (action === 'sendLog') {
    let host;
    try { host = new URL(parsed.webhookUrl).hostname; } catch { return json({ status: 'error', message: 'Invalid webhook URL.' }, 400, origin); }
    if (!ALLOWED_WEBHOOK_HOSTS.some(h => host === h || host.endsWith('.'+h))) return json({ status: 'error', message: 'Webhook host not allowed.' }, 403, origin);
    try {
      await fetch(parsed.webhookUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(parsed.payload) });
      return json({ status: 'ok' }, 200, origin);
    } catch { return json({ status: 'error', message: 'Webhook delivery failed.' }, 502, origin); }
  }

  // ── Forward to Google Apps Script ──────────────────────────────────────────
  try {
    const gasRes = await fetch(GAS_URL, {
      method: 'POST',
      body: JSON.stringify(safePayload),
      redirect: 'follow',
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(30000)
    });
    const data = await gasRes.text();
    return new Response(data, { status: gasRes.ok ? 200 : 502, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) } });
  } catch {
    return json({ status: 'error', message: 'Upstream service unavailable.' }, 503, origin);
  }
}
