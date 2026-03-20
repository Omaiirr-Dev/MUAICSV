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
const NTFY_CHANNEL   = process.env.NTFY_CHANNEL || 'muaiprayer';
const NTFY_SERVER    = process.env.NTFY_SERVER   || 'https://ntfy.sh';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';

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
const DATA_DIR = process.env.DATA_DIR || __dirname;
const QUEUE_FILE = path.join(DATA_DIR, 'queue.json');

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

// ─── NTFY PUSH (instant, no scheduling) ──────────────────────────────────────
// Server is the scheduler. ntfy is just the delivery pipe — fires immediately.
const EMOJI_TO_TAG = {
  '🕋': 'kaaba',
  '🌅': 'sunrise',
  '☀️': 'sunny',
  '⛅': 'partly_sunny',
  '🌇': 'city_sunset',
  '🌙': 'crescent_moon',
};

async function pushToNtfy(notification) {
  const url = NTFY_SERVER;
  const message = [notification.details, notification.countdown].filter(Boolean).join('\n') || notification.title;
  const tag = EMOJI_TO_TAG[notification.icon];

  const payload = {
    topic:    NTFY_CHANNEL,
    title:    notification.title,
    message,
    priority: 5,
    tags:     tag ? [tag] : [],
  };
  // No delay — fire immediately

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

  // ── PUBLIC ROUTES (no IP check, no auth) ────────────────────────────────
  const host = (req.headers.host || '').toLowerCase();
  const isPublicDomain = host.includes('muaiprayertimes');

  // If visiting from the public domain, serve times.html at root
  if (url === '/times' || (isPublicDomain && url === '/')) {
    fs.readFile(path.join(__dirname, 'times.html'), (err, data) => {
      if (err) { res.writeHead(404); res.end('Not found'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
    return;
  }

  // PWA static files (public, no auth)
  const pwaFiles = {
    '/manifest.json': { file: 'manifest.json', type: 'application/manifest+json' },
    '/sw.js': { file: 'sw.js', type: 'application/javascript' },
    '/icon-192.svg': { file: 'icon.svg', type: 'image/svg+xml' },
    '/icon-512.svg': { file: 'icon.svg', type: 'image/svg+xml' },
  };
  if (pwaFiles[url]) {
    const { file, type } = pwaFiles[url];
    fs.readFile(path.join(__dirname, file), (err, data) => {
      if (err) { res.writeHead(404); res.end('Not found'); return; }
      res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'public, max-age=86400' });
      res.end(data);
    });
    return;
  }

  if (url === '/api/times' && req.method === 'GET') {
    const queue = loadQueue();
    const now = new Date();
    // Get today's date in UK timezone
    const ukDate = new Intl.DateTimeFormat('en-GB', {
      timeZone: UK_TZ, weekday: 'short', year: 'numeric', month: 'short', day: 'numeric',
    }).format(now);
    // Also get tomorrow for finding next prayer across midnight
    const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    const ukTomorrow = new Intl.DateTimeFormat('en-GB', {
      timeZone: UK_TZ, weekday: 'short', year: 'numeric', month: 'short', day: 'numeric',
    }).format(tomorrow);

    const nowISO = now.toISOString();

    // Get today's date parts for matching gregFull (e.g. "Wed, 26 Feb 2026")
    const ukParts = new Intl.DateTimeFormat('en-GB', {
      timeZone: UK_TZ, day: 'numeric', month: 'short', year: 'numeric',
    }).formatToParts(now);
    const ukDay = ukParts.find(p => p.type === 'day').value;
    const ukMonth = ukParts.find(p => p.type === 'month').value;
    const ukYear = ukParts.find(p => p.type === 'year').value;
    const todayMatch = `, ${parseInt(ukDay)} ${ukMonth} ${ukYear}`;

    const tomorrowParts = new Intl.DateTimeFormat('en-GB', {
      timeZone: UK_TZ, day: 'numeric', month: 'short', year: 'numeric',
    }).formatToParts(tomorrow);
    const tmDay = tomorrowParts.find(p => p.type === 'day').value;
    const tmMonth = tomorrowParts.find(p => p.type === 'month').value;
    const tmYear = tomorrowParts.find(p => p.type === 'year').value;
    const tomorrowMatch = `, ${parseInt(tmDay)} ${tmMonth} ${tmYear}`;

    const todayPrayers = queue.filter(n => n.gregFull && n.gregFull.includes(todayMatch));
    const tomorrowPrayers = queue.filter(n => n.gregFull && n.gregFull.includes(tomorrowMatch));

    // Find next upcoming prayer (first unfired or future)
    const allUpcoming = queue.filter(n => n.fireUTC && n.fireUTC > nowISO);
    const nextPrayer = allUpcoming.length > 0 ? allUpcoming[0] : null;

    json(res, 200, {
      today: todayPrayers,
      tomorrow: tomorrowPrayers,
      nextPrayer,
      serverTime: nowISO,
      todayLabel: ukDate,
    });
    return;
  }

  // ── API: GET /api/calendar — return all future queue days for calendar browsing ──
  if (url === '/api/calendar' && req.method === 'GET') {
    const queue = loadQueue();
    const nowISO = new Date().toISOString();
    // Group by gregFull, only include days with future or today's prayers
    const dayMap = new Map();
    for (const n of queue) {
      const key = n.gregFull || 'Unknown';
      if (!dayMap.has(key)) dayMap.set(key, []);
      dayMap.get(key).push(n);
    }
    const days = Array.from(dayMap.entries())
      .map(([label, prayers]) => ({ label, prayers }))
      .filter(d => d.prayers.some(p => p.fireUTC && p.fireUTC >= nowISO.slice(0, 10)));
    json(res, 200, { days });
    return;
  }

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

  // ── API: GET /api/ai-available — check if OpenAI key is configured ──────
  if (url === '/api/ai-available' && req.method === 'GET') {
    json(res, 200, { available: !!GEMINI_API_KEY });
    return;
  }

  // ── API: POST /api/ai-parse — use Gemini to extract prayer times ──────
  if (url === '/api/ai-parse' && req.method === 'POST') {
    if (!GEMINI_API_KEY) { json(res, 501, { error: 'Gemini API key not configured' }); return; }

    const raw = await parseBody(req);
    let body;
    try { body = JSON.parse(raw); } catch { json(res, 400, { error: 'invalid json' }); return; }
    if (!body.csv || typeof body.csv !== 'string') { json(res, 400, { error: 'missing csv field' }); return; }

    // Inject current date so the AI knows the real-world context
    const now = new Date();
    const todayStr = now.toLocaleDateString('en-GB', {
      timeZone: UK_TZ, weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
    });
    const currentYear = now.toLocaleDateString('en-GB', { timeZone: UK_TZ, year: 'numeric' });

    const systemPrompt = `You extract prayer times from CSV/spreadsheet data into JSON. Today is ${todayStr}. Year: ${currentYear}.

Output format — return a JSON object with "title" (string) and "days" (array). Each day object:
{"day":"Mon","hijriDate":"1","gregDate":"3","gregFull":"Mon, 3 Mar 2025","gregYear":2025,"gregMonth":2,"gregDay":3,"fajrStart":"5:23","fajrJamat":"5:38","sunrise":"6:45","zuhrStart":"12:30","zuhrJamat":"13:00","asrStart":"15:45","asrJamat":"16:15","maghribAdhan":"17:27","maghribJamat":"17:27","ishaStart":"19:45","ishaJamat":"20:15"}

CRITICAL RULES — READ CAREFULLY:

1. OUTPUT EVERY DAY. You MUST output EVERY SINGLE DAY from the data. If it spans March 20 to April 30, output ALL 42 days. Do NOT stop at end of a month. Do NOT skip any days. Your output row count MUST match the input row count exactly.

2. EXACT TIMES. Copy times EXACTLY as they appear. Do NOT round, adjust, or estimate. If the data says "5:08", output "5:08" — not "5:10". Every minute matters for prayer times.

3. 24H FORMAT. Convert PM times: Fajr/Sunrise are AM (keep as-is). Zuhr onward are PM — add 12: "3:36" Asr → "15:36", "5:27" sunset → "17:27", "6:59" Isha → "18:59". If a time is already ≥12 (like "12:30" Zuhr), keep it.

4. COLUMN IDENTIFICATION. The spreadsheet typically has these columns in order:
   - Day name (Mon/Tue/etc.)
   - Hijri date (Islamic calendar number) → hijriDate
   - Gregorian date (day number within the Gregorian month, e.g. "20", "21") → gregDate
   - Then prayer time columns: Fajr Start, Fajr Jamat, Sunrise, Zuhr Start, Zuhr Jamat, Asr Start, Asr Jamat, Maghrib/Sunset, Maghrib Jamat, Isha Start, Isha Jamat
   The Hijri date is NOT the Gregorian date. They are separate columns. Use the Gregorian column for gregDate/gregDay/gregFull.

5. MONTH HEADERS. The spreadsheet has separate month header rows for Hijri months (e.g. "Shawwal", "Dhul-Qadah") and Gregorian months (e.g. "March", "April", "May"). Use Gregorian month names for gregFull and gregMonth. When you see a new Gregorian month header (like "Apr" or "April"), the following rows' gregDate resets to 1 and gregMonth increments.

6. Sunset = Maghrib. Any column called Sunset/Sun Set/Iftar/Maghrib → maghribAdhan.

7. Extract BOTH start times AND jamat/congregation/iqamah times.

8. Ditto marks (") mean "same as the row above" — repeat the previous value.

9. If a jamat column has text instructions:
   - "15 minutes after fajr beginning" → fajrJamat = fajrStart + 15 minutes
   - "straight after breaking fast/iftar" → maghribJamat = same as maghribAdhan
   - "X minutes after [prayer]" → add X minutes to that prayer's start time
   Apply computed time to ALL rows.

10. If no jamat time exists, set to empty string "".

11. gregMonth is 0-indexed (Jan=0, Feb=1, Mar=2, Apr=3, etc.). Day names: Mon,Tue,Wed,Thu,Fri,Sat,Sun.

12. IGNORE non-data rows: "CLOCK CHANGE", "BST", "GMT", "*CC", notes. The times ALREADY account for clock changes — just copy them exactly.

13. title: Islamic month if identifiable (e.g. "Ramadan 1447 AH"). If it spans months, use the primary one.

14. The input may be raw spreadsheet data (XLS/binary) — extract the prayer data from whatever readable text you find. Focus on rows that have a day name and time values.

Return ONLY valid JSON. No markdown, no backticks, no explanation.`;

    const GEMINI_MODEL = 'gemini-3.0-flash';
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`;

    try {
      const geminiResp = await fetch(geminiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: [{
            role: 'user',
            parts: [{ text: `IMPORTANT: Count the data rows below carefully. You must output the EXACT same number of day objects.\n\n${body.csv}` }],
          }],
          generationConfig: {
            temperature: 0,
            maxOutputTokens: 65536,
            responseMimeType: 'application/json',
          },
        }),
      });

      if (!geminiResp.ok) {
        const errText = await geminiResp.text().catch(() => '');
        console.error(`[AI] Gemini ${geminiResp.status}: ${errText}`);
        let detail = `Gemini ${geminiResp.status}`;
        try { detail = JSON.parse(errText).error?.message || detail; } catch {}
        json(res, 502, { error: detail });
        return;
      }

      const result = await geminiResp.json();
      const content = result.candidates?.[0]?.content?.parts?.[0]?.text || '';

      // Strip markdown fences if present
      const cleaned = content.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();

      let parsed;
      try { parsed = JSON.parse(cleaned); } catch {
        console.error('[AI] Failed to parse Gemini response:', content.slice(0, 500));
        json(res, 502, { error: 'AI returned invalid JSON' });
        return;
      }

      if (!parsed.days || !Array.isArray(parsed.days)) {
        json(res, 502, { error: 'AI response missing days array' });
        return;
      }

      console.log(`[AI] Parsed ${parsed.days.length} days from CSV (model: ${GEMINI_MODEL})`);
      json(res, 200, parsed);
    } catch (e) {
      console.error('[AI] Error:', e.message);
      json(res, 500, { error: 'AI parse failed: ' + e.message });
    }
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

  // ── API: DELETE /api/queue/fired — remove already-fired notifications ────
  if (url === '/api/queue/fired' && req.method === 'DELETE') {
    const queue = loadQueue();
    const kept = queue.filter(n => !n.firedToNtfy);
    const removed = queue.length - kept.length;
    saveQueue(kept);
    json(res, 200, { removed, remaining: kept.length });
    return;
  }

  // ── API: POST /api/message — send a custom message via ntfy ─────────────
  if (url === '/api/message' && req.method === 'POST') {
    const raw = await parseBody(req);
    let body;
    try { body = JSON.parse(raw); } catch { json(res, 400, { error: 'invalid json' }); return; }

    const { title, message, schedule } = body;
    if (!title || !message) { json(res, 400, { error: 'title and message required' }); return; }

    if (schedule) {
      // Schedule for later — add to queue
      const fireUTC = new Date(schedule).toISOString();
      const notification = {
        icon: '📢', title, details: message, fireUTC,
        fireTimeFmt: new Date(schedule).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: true, timeZone: 'Europe/London' }),
        gregFull: new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/London', weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(schedule)),
        priority: 'default',
      };
      const queue = loadQueue();
      queue.push(notification);
      queue.sort((a, b) => (a.fireUTC || '').localeCompare(b.fireUTC || ''));
      saveQueue(queue);
      console.log(`[MESSAGE] Scheduled "${title}" for ${fireUTC}`);
      json(res, 200, { status: 'scheduled', fireUTC });
    } else {
      // Send immediately
      const ok = await pushToNtfy({ icon: '📢', title, details: message, priority: 'default' });
      console.log(`[MESSAGE] Sent "${title}" immediately — ${ok ? 'OK' : 'FAILED'}`);
      json(res, 200, { status: ok ? 'sent' : 'failed' });
    }
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

  // ── API: POST /api/push — queue notifications (server fires them at the right time) ──
  if (url === '/api/push' && req.method === 'POST') {
    const raw = await parseBody(req);
    let incoming;
    try { incoming = JSON.parse(raw); } catch { json(res, 400, { error: 'invalid json' }); return; }
    if (!Array.isArray(incoming)) { json(res, 400, { error: 'expected array' }); return; }

    const nowISO = new Date().toISOString();
    const queue = loadQueue();
    const map = new Map(queue.map(n => [n.fireUTC, n]));

    let queued = 0;
    let skipped = 0;
    for (const n of incoming) {
      if (!n.fireUTC) continue;
      if (n.fireUTC <= nowISO) { skipped++; continue; }
      // Don't overwrite already-fired notifications
      const existing = map.get(n.fireUTC);
      if (existing && existing.firedToNtfy) continue;
      map.set(n.fireUTC, n);
      queued++;
    }
    const merged = Array.from(map.values()).sort((a, b) => (a.fireUTC || '').localeCompare(b.fireUTC || ''));
    saveQueue(merged);

    const future = merged.filter(n => n.fireUTC > nowISO && !n.firedToNtfy).length;
    console.log(`[QUEUE] ${queued} queued, ${skipped} past skipped, ${future} pending`);
    json(res, 200, { queued, skipped, total: merged.length, pending: future });
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

// ─── SCHEDULER: check every 30s, fire notifications whose time has arrived ───
const TICK_INTERVAL_MS = 30 * 1000; // 30 seconds

async function schedulerTick() {
  const queue = loadQueue();
  const nowISO = new Date().toISOString();

  // Find notifications that are due (fireUTC <= now) and haven't been fired yet
  // Only fire if less than 5 minutes old — prevents mass-firing after server restart
  const GRACE_MS = 5 * 60 * 1000;
  const graceISO = new Date(Date.now() - GRACE_MS).toISOString();
  const due = queue.filter(n => n.fireUTC && !n.firedToNtfy && n.fireUTC <= nowISO && n.fireUTC >= graceISO);

  // Mark old missed notifications as fired so they never re-fire
  const stale = queue.filter(n => n.fireUTC && !n.firedToNtfy && n.fireUTC < graceISO);
  if (stale.length > 0) {
    for (const n of stale) n.firedToNtfy = true;
    console.log(`[SCHEDULER] Marked ${stale.length} stale notifications as fired (missed)`);
  }

  if (due.length === 0 && stale.length > 0) { saveQueue(queue); return; }
  if (due.length === 0) return;

  let pushed = 0;
  let failed = 0;
  for (const n of due) {
    const ok = await pushToNtfy(n);
    if (ok) { pushed++; n.firedToNtfy = true; }
    else    { failed++; }
  }
  saveQueue(queue);
  if (pushed > 0 || failed > 0) {
    console.log(`[SCHEDULER] Fired ${pushed}, failed ${failed}`);
  }
}

// Run every 30 seconds
setInterval(schedulerTick, TICK_INTERVAL_MS);
console.log('[SCHEDULER] Running — checking every 30s for due notifications');

// ─── ERROR/ALERT CHANNEL ─────────────────────────────────────────────────────
const ALERT_CHANNEL = process.env.ALERT_CHANNEL || 'muaierror';

async function sendAlert(title, message) {
  const payload = {
    topic: ALERT_CHANNEL,
    title,
    message,
    priority: 5,
    tags: ['warning'],
  };
  try {
    if (typeof fetch !== 'undefined') {
      await fetch(NTFY_SERVER, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
    }
    console.log(`[ALERT] ${title}: ${message}`);
  } catch (e) {
    console.error('[ALERT] Failed to send:', e.message);
  }
}

// Alert on boot (catches redeploys)
sendAlert('Server restarted', `MUAI Prayer Times server just booted at ${new Date().toISOString()}. Queue may have been wiped — check scheduled notifications.`);

// Every 12 hours, check if queue has future notifications
const HEALTH_CHECK_MS = 12 * 60 * 60 * 1000;
setInterval(() => {
  const queue = loadQueue();
  const nowISO = new Date().toISOString();
  const future = queue.filter(n => n.fireUTC && n.fireUTC > nowISO && !n.firedToNtfy);
  if (future.length === 0) {
    sendAlert('No notifications scheduled', 'The queue is empty — no upcoming prayer notifications. Upload a schedule.');
  }
}, HEALTH_CHECK_MS);
