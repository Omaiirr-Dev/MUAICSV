// MUAI Prayer Times — Scriptable Widget (Jama'ah version)
// Fetches once per day, runs from cache. Always live timer.
// Counts down: prayer → jama'ah → next prayer. Switches 10 min early.

const API = 'https://muaiprayertimes.xyz/api/times';
const SKIP_MS = 10 * 60 * 1000; // switch 10 min early

const PRAYER_MAP = {
  'Fajr has begun': 'Fajr',
  'Sunrise': 'Sunrise',
  'Zuhr has begun': 'Zuhr',
  "Zuhr has begun \u00b7 Jumu'ah": "Jumu'ah",
  'Asr has begun': 'Asr',
  'Maghrib has begun': 'Maghrib',
  'Isha has begun': 'Isha',
};

function getName(title) {
  if (PRAYER_MAP[title]) return PRAYER_MAP[title];
  if (title && title.startsWith('Fajr')) return 'Fajr';
  return title || '—';
}

// ── Cache ──
const fm = FileManager.local();
const cacheDir = fm.joinPath(fm.documentsDirectory(), 'muai-cache');
if (!fm.fileExists(cacheDir)) fm.createDirectory(cacheDir);
const cachePath = fm.joinPath(cacheDir, 'times.json');

function saveCache(data) {
  fm.writeString(cachePath, JSON.stringify({ fetchedDate: new Date().toDateString(), data }));
}
function loadCache() {
  if (fm.fileExists(cachePath)) {
    try { return JSON.parse(fm.readString(cachePath)); } catch (e) {}
  }
  return null;
}
async function getData() {
  const cache = loadCache();
  const today = new Date().toDateString();
  if (cache && cache.fetchedDate === today && cache.data) return cache.data;
  try {
    const req = new Request(API);
    req.timeoutInterval = 15;
    const data = await req.loadJSON();
    saveCache(data);
    return data;
  } catch (e) {
    return cache ? cache.data : null;
  }
}

// Build sorted event list: prayer starts + jama'ah times
function buildEvents(data) {
  const prayers = (data.today || [])
    .concat(data.tomorrow || [])
    .filter(p => p.fireUTC)
    .sort((a, b) => new Date(a.fireUTC).getTime() - new Date(b.fireUTC).getTime());

  const events = [];
  for (const p of prayers) {
    const name = getName(p.title);
    const fireMs = new Date(p.fireUTC).getTime();
    events.push({ ms: fireMs, label: name, sublabel: p.fireTimeFmt || '' });
    if (p.jamatUTC) {
      const jamatMs = new Date(p.jamatUTC).getTime();
      if (jamatMs > fireMs) {
        events.push({ ms: jamatMs, label: `${name} - Jama'ah`, sublabel: p.jamatTimeFmt || '' });
      }
    }
  }
  events.sort((a, b) => a.ms - b.ms);
  return events;
}

// Find what to display: pick the first event > 10 min away
// This guarantees the live timer NEVER reaches zero
function getDisplay(data) {
  if (!data) return null;
  const now = Date.now();
  const events = buildEvents(data);

  for (const ev of events) {
    if (ev.ms - now > SKIP_MS) {
      return ev;
    }
  }

  // Fallback
  if (data.nextPrayer && data.nextPrayer.fireUTC) {
    const ms = new Date(data.nextPrayer.fireUTC).getTime();
    return { ms, label: getName(data.nextPrayer.title), sublabel: data.nextPrayer.fireTimeFmt || '' };
  }
  return null;
}

// ── Run ──
const data = await getData();
const ev = getDisplay(data);
const family = config.widgetFamily;
const refreshDate = new Date(Date.now() + 2 * 60 * 1000);

// ── Build widget ──
const w = new ListWidget();
w.url = 'https://muaiprayertimes.xyz';
w.refreshAfterDate = refreshDate;

if (family === 'accessoryRectangular') {
  // Lock screen
  w.setPadding(4, 4, 4, 4);
  if (ev) {
    const t = w.addText(ev.label);
    t.font = Font.boldSystemFont(14);
    t.minimumScaleFactor = 0.7;
    w.addSpacer(1);
    const s = w.addText(ev.sublabel);
    s.font = Font.mediumSystemFont(10);
    s.textOpacity = 0.6;
    w.addSpacer(2);
    const cd = w.addDate(new Date(ev.ms));
    cd.applyTimerStyle();
    cd.font = Font.semiboldMonospacedSystemFont(13);
  } else {
    const t = w.addText('No prayers');
    t.font = Font.mediumSystemFont(12);
  }
  w.addSpacer();

} else {
  // Home screen
  w.backgroundColor = new Color('#1a2744');
  const isMedium = family === 'medium' || family === 'large';
  w.setPadding(14, 16, 14, 16);

  if (ev) {
    if (isMedium) {
      const row = w.addStack();
      row.layoutHorizontally();
      row.centerAlignContent();
      const left = row.addStack();
      left.layoutVertically();

      const n = left.addText(ev.label);
      n.font = Font.boldSystemFont(20);
      n.textColor = Color.white();
      n.minimumScaleFactor = 0.7;
      left.addSpacer(2);
      const s = left.addText(ev.sublabel);
      s.font = Font.mediumSystemFont(13);
      s.textColor = new Color('#8899aa');
      left.addSpacer(8);
      const cd = left.addDate(new Date(ev.ms));
      cd.applyTimerStyle();
      cd.font = Font.semiboldMonospacedSystemFont(28);
      cd.textColor = new Color('#d4af37');

      row.addSpacer();
      const lbl = row.addText('MUAI');
      lbl.font = Font.boldSystemFont(12);
      lbl.textColor = new Color('#8899aa');

    } else {
      const n = w.addText(ev.label);
      n.font = Font.boldSystemFont(16);
      n.textColor = Color.white();
      n.minimumScaleFactor = 0.7;
      w.addSpacer(2);
      const s = w.addText(ev.sublabel);
      s.font = Font.mediumSystemFont(11);
      s.textColor = new Color('#8899aa');
      w.addSpacer(6);
      const cd = w.addDate(new Date(ev.ms));
      cd.applyTimerStyle();
      cd.font = Font.semiboldMonospacedSystemFont(18);
      cd.textColor = new Color('#d4af37');
    }
  } else {
    const t = w.addText('No prayers');
    t.font = Font.mediumSystemFont(14);
    t.textColor = new Color('#8899aa');
  }
  w.addSpacer();
}

if (config.runsInWidget) {
  Script.setWidget(w);
} else {
  w.presentMedium();
}
Script.complete();
