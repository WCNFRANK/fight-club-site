import { createClient } from '@supabase/supabase-js';
import crypto from 'node:crypto';

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  ADMIN_PASSWORD,
  GROUP_CODE,
  SESSION_SECRET,
} = process.env;

const REQUIRED = { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, ADMIN_PASSWORD, GROUP_CODE, SESSION_SECRET };

const ADMIN_COOKIE = 'fc_admin';
const MEMBER_COOKIE = 'fc_member';
const ADMIN_MAX_AGE = 60 * 60 * 12;        // admin stays logged in 12 hours
const MEMBER_MAX_AGE = 60 * 60 * 24 * 180; // group code remembered 180 days

const FIELDS = {
  members: ['name', 'phone', 'sobriety_date'],
  meetings: ['title', 'day_of_week', 'meeting_time', 'location', 'details', 'sort_order'],
  events: ['title', 'event_date', 'event_time', 'location', 'description'],
};

let client;
function db() {
  if (!client) {
    client = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
  }
  return client;
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- sessions ----------
// Tokens are tied to the current password / group code, so changing either
// one in Vercel automatically logs everyone out.
function roleSecret(role) {
  return role === 'admin' ? ADMIN_PASSWORD : GROUP_CODE.trim().toLowerCase();
}

function sign(payload, role) {
  return crypto
    .createHmac('sha256', SESSION_SECRET + '|' + roleSecret(role))
    .update(payload)
    .digest('base64url');
}

function makeToken(role, maxAge) {
  const exp = Math.floor(Date.now() / 1000) + maxAge;
  const payload = `${role}.${exp}`;
  return `${payload}.${sign(payload, role)}`;
}

function checkToken(token, role) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== role) return false;
  const expected = Buffer.from(sign(`${parts[0]}.${parts[1]}`, role));
  const given = Buffer.from(parts[2]);
  if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) return false;
  return Number(parts[1]) > Date.now() / 1000;
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

function cookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

// ---------- validation ----------
const digitsOf = (s) => {
  const d = String(s || '').replace(/\D/g, '');
  return d.length === 11 && d.startsWith('1') ? d.slice(1) : d;
};

function cleanMember(b) {
  const name = String(b.name || '').trim().replace(/\s+/g, ' ');
  if (name.length < 2 || name.length > 80) return { error: 'Please enter your name.' };

  const d = digitsOf(b.phone);
  if (d.length < 10 || d.length > 15) return { error: 'Please enter a valid phone number.' };
  const phone = d.length === 10 ? `(${d.slice(0, 3)}) ${d.slice(3, 6)}-${d.slice(6)}` : '+' + d;

  let sobriety_date = null;
  if (b.sobriety_date) {
    const s = String(b.sobriety_date);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(s) || isNaN(Date.parse(s))) {
      return { error: 'Please enter a valid sobriety date.' };
    }
    if (Date.parse(s) > Date.now() + 86400000) {
      return { error: "Sobriety date can't be in the future." };
    }
    sobriety_date = s;
  }
  return { data: { name, phone, sobriety_date } };
}

function cleanGeneric(table, b, isCreate) {
  const out = {};
  for (const f of FIELDS[table]) {
    if (!(f in b)) continue;
    let v = b[f];
    if (f === 'sort_order') {
      v = parseInt(v, 10);
      out[f] = Number.isFinite(v) ? v : 0;
      continue;
    }
    v = v == null ? '' : String(v).trim().slice(0, 2000);
    if (f === 'event_date' && v && !/^\d{4}-\d{2}-\d{2}$/.test(v)) return { error: 'Invalid date.' };
    out[f] = v || null;
  }
  if ((isCreate || 'title' in out) && !out.title) return { error: 'Title is required.' };
  return { data: out };
}

async function phoneTaken(phone, excludeId) {
  const { data, error } = await db().from('members').select('id, phone');
  if (error) throw error;
  const target = digitsOf(phone);
  return data.some((m) => m.id !== excludeId && digitsOf(m.phone) === target);
}

// ---------- vCard (phone contacts file) ----------
function vEsc(s) {
  return String(s || '')
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/([,;])/g, '\\$1');
}

function niceDate(iso) {
  const [y, m, d] = iso.split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString('en-US', {
    month: 'long', day: 'numeric', year: 'numeric', timeZone: 'UTC',
  });
}

function toVcard(m) {
  const parts = m.name.split(' ');
  const first = parts.shift();
  const last = parts.join(' ');
  const d = digitsOf(m.phone);
  const tel = d.length === 10 ? '+1' + d : '+' + d;
  const lines = [
    'BEGIN:VCARD',
    'VERSION:3.0',
    `N:${vEsc(last)};${vEsc(first)};;;`,
    `FN:${vEsc(m.name)}`,
    `TEL;TYPE=CELL:${tel}`,
    'ORG:Fight Club',
  ];
  if (m.sobriety_date) lines.push(`NOTE:${vEsc('Sobriety date: ' + niceDate(m.sobriety_date))}`);
  lines.push('END:VCARD');
  return lines.join('\r\n');
}

// ---------- handler ----------
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  const missing = Object.keys(REQUIRED).filter((k) => !REQUIRED[k]);
  if (missing.length) {
    return res.status(500).json({ error: 'Server not configured. Missing: ' + missing.join(', ') });
  }

  const r = String(req.query.r || '');
  const id = req.query.id ? String(req.query.id) : null;
  const method = req.method;

  let body = req.body || {};
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = {}; }
  }

  const cookies = parseCookies(req);
  const isAdmin = checkToken(cookies[ADMIN_COOKIE], 'admin');
  const isMember = isAdmin || checkToken(cookies[MEMBER_COOKIE], 'member');

  try {
    // --- session status ---
    if (r === 'session') return res.json({ admin: isAdmin, member: isMember });

    // --- admin login ---
    if (r === 'login' && method === 'POST') {
      if (!body.password || !safeEqual(body.password, ADMIN_PASSWORD)) {
        await delay(700);
        return res.status(401).json({ error: 'Wrong password.' });
      }
      res.setHeader('Set-Cookie', cookie(ADMIN_COOKIE, makeToken('admin', ADMIN_MAX_AGE), ADMIN_MAX_AGE));
      return res.json({ ok: true });
    }

    // --- group code unlock ---
    if (r === 'unlock' && method === 'POST') {
      const code = String(body.code || '').trim().toLowerCase();
      if (!code || !safeEqual(code, GROUP_CODE.trim().toLowerCase())) {
        await delay(700);
        return res.status(401).json({ error: "That code isn't right." });
      }
      res.setHeader('Set-Cookie', cookie(MEMBER_COOKIE, makeToken('member', MEMBER_MAX_AGE), MEMBER_MAX_AGE));
      return res.json({ ok: true });
    }

    // --- admin logout ---
    if (r === 'logout' && method === 'POST') {
      res.setHeader('Set-Cookie', cookie(ADMIN_COOKIE, '', 0));
      return res.json({ ok: true });
    }

    // --- contacts download ---
    if (r === 'vcf' && method === 'GET') {
      if (!isMember) return res.status(401).send('Group code required.');
      let q = db().from('members').select('*').order('name', { ascending: true });
      if (id) q = q.eq('id', id);
      const { data, error } = await q;
      if (error) throw error;
      if (!data.length) return res.status(404).send('No contacts found.');
      const filename = id
        ? 'fight-club-' + data[0].name.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '.vcf'
        : 'fight-club-phone-list.vcf';
      res.setHeader('Content-Type', 'text/vcard; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      return res.send(data.map(toVcard).join('\r\n') + '\r\n');
    }

    if (!FIELDS[r]) return res.status(404).json({ error: 'Not found.' });
    const table = r;

    // --- reads ---
    if (method === 'GET') {
      if (table === 'members' && !isMember) return res.status(401).json({ error: 'Group code required.' });
      let q = db().from(table).select('*');
      if (table === 'members') q = q.order('name', { ascending: true });
      if (table === 'meetings') q = q.order('sort_order', { ascending: true }).order('created_at', { ascending: true });
      if (table === 'events') q = q.order('event_date', { ascending: true, nullsFirst: false });
      const { data, error } = await q;
      if (error) throw error;
      return res.json(data);
    }

    // --- public: add yourself to the phone list ---
    if (table === 'members' && method === 'POST' && !isAdmin) {
      if (body.website) return res.json({ ok: true }); // spam-bot trap
      const c = cleanMember(body);
      if (c.error) return res.status(400).json({ error: c.error });
      if (await phoneTaken(c.data.phone)) {
        return res.status(409).json({ error: 'That number is already on the list.' });
      }
      const { error } = await db().from('members').insert(c.data);
      if (error) throw error;
      return res.json({ ok: true });
    }

    // --- everything below is admin only ---
    if (!isAdmin) return res.status(401).json({ error: 'Admin login required.' });

    if (method === 'POST' || method === 'PUT') {
      if (method === 'PUT' && !id) return res.status(400).json({ error: 'Missing id.' });

      let c;
      if (table === 'members') {
        c = cleanMember(body);
        if (!c.error && (await phoneTaken(c.data.phone, id))) {
          return res.status(409).json({ error: 'That number is already on the list.' });
        }
      } else {
        c = cleanGeneric(table, body, method === 'POST');
      }
      if (c.error) return res.status(400).json({ error: c.error });

      const q = method === 'POST'
        ? db().from(table).insert(c.data)
        : db().from(table).update(c.data).eq('id', id);
      const { data, error } = await q.select().single();
      if (error) throw error;
      return res.json(data);
    }

    if (method === 'DELETE') {
      if (!id) return res.status(400).json({ error: 'Missing id.' });
      const { error } = await db().from(table).delete().eq('id', id);
      if (error) throw error;
      return res.json({ ok: true });
    }

    return res.status(405).json({ error: 'Method not allowed.' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
}
