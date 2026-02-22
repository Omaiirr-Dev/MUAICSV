const http = require('http');
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── UK TIMEZONE HELPER ───────────────────────────────────────────────────────
const UK_TZ = 'Europe/London';

function ukTimeToUTC(dateInUK, timeStr) {
  const [h, m] = timeStr.split(':').map(Number);
  const y  = dateInUK.getFullYear();
  const mo = dateInUK.getMonth() + 1;
  const d  = dateInUK.getDate();

  const guessUTC = Date.UTC(y, mo - 1, d, h, m, 0, 0);

  const londonParts = new Intl.DateTimeFormat('en-GB', {
    timeZone: UK_TZ,
    hour: 'numeric', minute: 'numeric', hour12: false,
  }).formatToParts(new Date(guessUTC));

  const londonH = parseInt(londonParts.find(p => p.type === 'hour').value);
  const londonM = parseInt(londonParts.find(p => p.type === 'minute').value);

  const offsetMins = (londonH * 60 + londonM) - (h * 60 + m);
  return new Date(guessUTC - offsetMins * 60 * 1000);
}

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const PORT           = process.env.PORT || 3000;
const PASSWORD       = process.env.PASSWORD || 'qaws';
const ALLOWED_IPS    = (process.env.ALLOWED_IPS || '78.150.44.100,88.97.208.41')
                         .split(',').map(s => s.trim());
const NTFY_CHANNEL   = process.env.NTFY_CHANNEL || 'CSVMUAITEST';
const NTFY_SERVER    = process.env.NTFY_SERVER   || 'https://ntfy.sh';

// Session tokens: token -> expiry timestamp
const sessions = new Map();
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress?.replace(/^::ffff:/, '') || '';
}

function isIPAllowed(ip) {
  return ALLOWED_IPS.includes(ip);
}

function getSessionToken(req) {
  const cookie = req.headers.cookie || '';
  const match  = cookie.match(/(?:^|;\s*)muai_session=([a-f0-9]{64})/);
  return match ? match[1] : null;
}

function isValidSession(token) {
  if (!token) return false;
  const expiry = sessions.get(token);
  if (!expiry) return false;
  if (Date.now() > expiry) { sessions.delete(token); return false; }
  return true;
}

function setCookieHeader(token) {
  const expires = new Date(Date.now() + SESSION_TTL_MS).toUTCString();
  return `muai_session=${token}; Path=/; HttpOnly; SameSite=Strict; Expires=${expires}`;
}

// ─── QUEUE PERSISTENCE ────────────────────────────────────────────────────────
const QUEUE_FILE = path.join(__dirname, 'queue.json');

function loadQueue() {
  try {
    return JSON.parse(fs.readFileSync(QUEUE_FILE, 'utf8'));
  } catch {
    return [];
  }
}

function saveQueue(queue) {
  fs.writeFileSync(QUEUE_FILE, JSON.stringify(queue, null, 2), 'utf8');
}

// ─── NTFY SCHEDULING HELPERS ─────────────────────────────────────────────────
const NTFY_WINDOW_MS = 72 * 60 * 60 * 1000; // 3 days — ntfy.sh free tier limit

function isWithinNtfyWindow(fireUTC) {
  const fireMs = new Date(fireUTC).getTime();
  const now    = Date.now();
  return fireMs > now && fireMs <= now + NTFY_WINDOW_MS;
}

// ─── NTFY PUSH ────────────────────────────────────────────────────────────────
// Posts JSON to the ntfy ROOT endpoint (not the topic URL) — posting JSON to
// the topic URL causes ntfy to treat the body as a file attachment.
// Uses Unix timestamps for 'delay' — ntfy rejects ISO 8601 in scheduled delivery.
const EMOJI_TO_TAG = {
  '🕋': 'kaaba',
  '☀️': 'sunny',
  '⛅': 'partly_sunny',
  '🌅': 'sunrise',
  '🌙': 'crescent_moon',
};

async function pushToNtfy(notification) {
  const url = NTFY_SERVER;   // root endpoint — topic goes inside JSON body
  const message = [notification.details, notification.countdown].filter(Boolean).join('\n') || notification.title;
  const tag = EMOJI_TO_TAG[notification.icon] || 'bell';

  const payload = {
    topic:    NTFY_CHANNEL,
    title:    notification.title,
    message,
    priority: 5,
    tags:     [tag],
  };
  if (notification.fireUTC) {
    // ntfy JSON API uses 'delay' (not 'at') — accepts Unix timestamp as string
    payload.delay = String(Math.floor(new Date(notification.fireUTC).getTime() / 1000));
  }

  const body = JSON.stringify(payload);

  try {
    if (typeof fetch !== 'undefined') {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      if (!resp.ok) {
        const err = await resp.text().catch(() => '');
        console.error(`[NTFY] ${resp.status}: ${err}`);
      }
      return resp.ok;
    } else {
      return await new Promise((resolve) => {
        const mod = url.startsWith('https') ? require('https') : require('http');
        const parsed  = new URL(url);
        const bodyBuf = Buffer.from(body, 'utf8');
        const req = mod.request({
          hostname: parsed.hostname,
          port:     parsed.port || (url.startsWith('https') ? 443 : 80),
          path:     parsed.pathname,
          method:   'POST',
          headers:  { 'Content-Type': 'application/json', 'Content-Length': bodyBuf.length },
        }, res => {
          if (res.statusCode >= 300) {
            let errBody = '';
            res.on('data', d => errBody += d);
            res.on('end', () => console.error(`[NTFY] ${res.statusCode}: ${errBody}`));
          }
          resolve(res.statusCode < 300);
        });
        req.on('error', () => resolve(false));
        req.write(bodyBuf);
        req.end();
      });
    }
  } catch (e) {
    console.error('[NTFY] push error:', e.message);
    return false;
  }
}

// ─── HTML PAGES ───────────────────────────────────────────────────────────────

const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>MUAI · Login</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#0d0d0d;color:#e8e8e8;font-family:'Segoe UI',system-ui,sans-serif;
         min-height:100vh;display:flex;align-items:center;justify-content:center}
    .card{background:#161616;border:1px solid #2a2a2a;border-radius:12px;
          padding:40px 36px;width:100%;max-width:360px;text-align:center}
    .logo{font-size:2rem;margin-bottom:8px}
    h1{font-size:1.1rem;color:#c9a84c;margin-bottom:4px}
    p{font-size:0.8rem;color:#666;margin-bottom:28px}
    input{width:100%;background:#0d0d0d;border:1px solid #2a2a2a;border-radius:6px;
          color:#e8e8e8;font-size:1rem;padding:11px 14px;outline:none;
          letter-spacing:0.15em;text-align:center;margin-bottom:14px;
          transition:border-color 0.15s}
    input:focus{border-color:#c9a84c}
    button{width:100%;background:#c9a84c;color:#111;border:none;border-radius:6px;
           font-size:0.95rem;font-weight:700;padding:12px;cursor:pointer;
           transition:opacity 0.15s}
    button:hover{opacity:0.85}
    .err{background:#2a1010;border:1px solid #7a2020;color:#f0a0a0;
         border-radius:6px;padding:9px 12px;font-size:0.82rem;margin-bottom:14px;display:none}
  </style>
</head>
<body>
<div class="card">
  <div class="logo">🕌</div>
  <h1>MUAI Prayer Times</h1>
  <p>Birmingham Islamic Notification System</p>
  <div class="err" id="err">Incorrect password</div>
  <form method="POST" action="/login">
    <input type="password" name="password" placeholder="Password" autofocus autocomplete="current-password"/>
    <button type="submit">Enter</button>
  </form>
</div>
<script>
  const u = new URLSearchParams(location.search);
  if (u.get('err')) document.getElementById('err').style.display = 'block';
</script>
</body>
</html>`;

const BLOCKED_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>403</title>
  <style>
    body{background:#0d0d0d;color:#666;font-family:monospace;
         display:flex;align-items:center;justify-content:center;min-height:100vh;flex-direction:column;gap:8px}
  </style>
</head>
<body><div style="font-size:2rem">🚫</div><div>403 — Access denied</div></body>
</html>`;

// ─── REQUEST HANDLER ──────────────────────────────────────────────────────────

function parseBody(req) {
  return new Promise(resolve => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 512 * 1024) body = body.slice(0, 512 * 1024); });
    req.on('end', () => resolve(body));
  });
}

function parseFormBody(body) {
  return Object.fromEntries(
    body.split('&').map(pair => pair.split('=').map(s => decodeURIComponent(s.replace(/\+/g, ' '))))
  );
}

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const ip  = getClientIP(req);
  const url = req.url.split('?')[0];

  // ── IP check (always first) ──────────────────────────────────────────────
  if (!isIPAllowed(ip)) {
    console.log(`[BLOCKED] ${ip} → ${req.url}`);
    res.writeHead(403, { 'Content-Type': 'text/html' });
    res.end(BLOCKED_PAGE);
    return;
  }

  // ── Login POST ───────────────────────────────────────────────────────────
  if (url === '/login' && req.method === 'POST') {
    const raw    = await parseBody(req);
    const fields = parseFormBody(raw);
    if (fields.password === PASSWORD) {
      const token = makeToken();
      sessions.set(token, Date.now() + SESSION_TTL_MS);
      console.log(`[AUTH OK] ${ip}`);
      res.writeHead(302, {
        'Set-Cookie': setCookieHeader(token),
        'Location':   '/',
      });
      res.end();
    } else {
      console.log(`[AUTH FAIL] ${ip}`);
      res.writeHead(302, { 'Location': '/login?err=1' });
      res.end();
    }
    return;
  }

  // ── Login GET ────────────────────────────────────────────────────────────
  if (url === '/login') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(LOGIN_PAGE);
    return;
  }

  // ── Logout ───────────────────────────────────────────────────────────────
  if (url === '/logout') {
    const token = getSessionToken(req);
    if (token) sessions.delete(token);
    res.writeHead(302, {
      'Set-Cookie': 'muai_session=; Path=/; HttpOnly; Max-Age=0',
      'Location':   '/login',
    });
    res.end();
    return;
  }

  // ── Session check ────────────────────────────────────────────────────────
  const token = getSessionToken(req);
  if (!isValidSession(token)) {
    res.writeHead(302, { 'Location': '/login' });
    res.end();
    return;
  }

  // ── API: GET /api/queue — return current queue ───────────────────────────
  if (url === '/api/queue' && req.method === 'GET') {
    json(res, 200, loadQueue());
    return;
  }

  // ── API: POST /api/queue — merge new notifications into queue ────────────
  if (url === '/api/queue' && req.method === 'POST') {
    const raw = await parseBody(req);
    let incoming;
    try { incoming = JSON.parse(raw); } catch { json(res, 400, { error: 'invalid json' }); return; }
    if (!Array.isArray(incoming)) { json(res, 400, { error: 'expected array' }); return; }

    const queue = loadQueue();

    // Deduplicate: key by fireUTC. New entries overwrite old for same timestamp.
    const map = new Map(queue.map(n => [n.fireUTC, n]));
    for (const n of incoming) {
      if (n.fireUTC) map.set(n.fireUTC, n);
    }
    const merged = Array.from(map.values()).sort((a, b) => a.fireUTC.localeCompare(b.fireUTC));
    saveQueue(merged);
    json(res, 200, { saved: merged.length, queue: merged });
    return;
  }

  // ── API: DELETE /api/queue/future — remove future notifications ──────────
  if (url === '/api/queue/future' && req.method === 'DELETE') {
    const now = new Date().toISOString();
    const queue = loadQueue();
    const kept = queue.filter(n => n.fireUTC <= now);
    saveQueue(kept);
    json(res, 200, { deleted: queue.length - kept.length, queue: kept });
    return;
  }

  // ── API: POST /api/push — push notifications to NTFY ────────────────────
  if (url === '/api/push' && req.method === 'POST') {
    const raw = await parseBody(req);
    let incoming;
    try { incoming = JSON.parse(raw); } catch { json(res, 400, { error: 'invalid json' }); return; }
    if (!Array.isArray(incoming)) { json(res, 400, { error: 'expected array' }); return; }

    // 1. Merge into queue — preserve pushedToNtfy flag if content unchanged
    const queue = loadQueue();
    const map = new Map(queue.map(n => [n.fireUTC, n]));
    for (const n of incoming) {
      if (!n.fireUTC) continue;
      const existing = map.get(n.fireUTC);
      // Keep pushedToNtfy if title+message unchanged (same notification re-uploaded)
      if (existing && existing.pushedToNtfy &&
          existing.title === n.title && existing.details === n.details) {
        n.pushedToNtfy = true;
      }
      map.set(n.fireUTC, n);
    }
    const merged = Array.from(map.values()).sort((a, b) => (a.fireUTC || '').localeCompare(b.fireUTC || ''));
    saveQueue(merged);

    // 2. Push only notifications within the 3-day ntfy window that haven't been pushed yet
    const nowISO = new Date().toISOString();
    const pastCount = incoming.filter(n => !n.fireUTC || n.fireUTC <= nowISO).length;
    const toPush = incoming.filter(n => n.fireUTC && isWithinNtfyWindow(n.fireUTC) && !n.pushedToNtfy);
    const deferred = incoming.length - pastCount - toPush.length
                     - incoming.filter(n => n.pushedToNtfy).length;

    let pushed = 0;
    let failed = 0;
    for (const n of toPush) {
      const ok = await pushToNtfy(n);
      if (ok) { pushed++; n.pushedToNtfy = true; }
      else    { failed++; }
    }
    saveQueue(merged);   // save again with updated pushedToNtfy flags

    console.log(`[PUSH] ${pushed} pushed, ${failed} failed, ${deferred} deferred, ${pastCount} past`);
    json(res, 200, { pushed, failed, deferred, skipped: pastCount, queued: merged.length });
    return;
  }

  // ── Serve static files ───────────────────────────────────────────────────
  const safePath = url === '/' ? '/index.html' : url;
  const filePath = path.join(__dirname, safePath.replace(/\.\./g, ''));

  if (!filePath.startsWith(__dirname)) {
    res.writeHead(403); res.end(); return;
  }

  const ext = path.extname(filePath);
  const mime = {
    '.html': 'text/html',
    '.css':  'text/css',
    '.js':   'application/javascript',
    '.json': 'application/json',
    '.csv':  'text/csv',
    '.ico':  'image/x-icon',
  }[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
      return;
    }
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log(`MUAI Prayer Times server running on http://localhost:${PORT}`);
  console.log(`Allowed IPs: ${ALLOWED_IPS.join(', ')}`);
  console.log(`Password: ${PASSWORD}`);
  console.log(`Session TTL: 8 hours`);
  console.log(`NTFY: ${NTFY_SERVER}/${NTFY_CHANNEL}`);
});

// ─── AUTO-DRIP: push upcoming notifications to ntfy every hour ───────────────
const DRIP_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

async function dripPush() {
  const queue = loadQueue();
  const toPush = queue.filter(n => n.fireUTC && !n.pushedToNtfy && isWithinNtfyWindow(n.fireUTC));

  if (toPush.length === 0) return;

  let pushed = 0;
  let failed = 0;
  for (const n of toPush) {
    const ok = await pushToNtfy(n);
    if (ok) { pushed++; n.pushedToNtfy = true; }
    else    { failed++; }
  }
  saveQueue(queue);
  console.log(`[DRIP] Pushed ${pushed}, failed ${failed} — next check in 1h`);
}

// Run once on boot, then every hour
dripPush();
setInterval(dripPush, DRIP_INTERVAL_MS);
