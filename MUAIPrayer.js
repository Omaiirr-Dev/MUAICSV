// MUAI Prayer Times — Scriptable Widget
// Contextual countdown: prayer → jama'ah → next prayer
// Live timer via applyTimerStyle(), refreshes at phase transitions

const API = 'https://muaiprayertimes.xyz/api/times';

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

// Build a sorted timeline of all phase transitions for today
// Each entry: { time (ms), label (string shown on widget), countdownTo (Date) }
function buildTimeline(prayers) {
  const entries = [];

  for (let i = 0; i < prayers.length; i++) {
    const p = prayers[i];
    const fireMs = new Date(p.fireUTC).getTime();
    const jamatMs = p.jamatUTC ? new Date(p.jamatUTC).getTime() : null;
    const name = getName(p.title);

    // Phase: before this prayer starts → count down to prayer
    entries.push({
      from: 0,
      until: fireMs,
      label: name,
      sublabel: p.fireTimeFmt || '',
      countdownTo: new Date(p.fireUTC),
      nextTransition: fireMs,
    });

    if (jamatMs && jamatMs > fireMs) {
      // Phase: prayer started, before jama'ah → count down to jama'ah
      entries.push({
        from: fireMs,
        until: jamatMs,
        label: `${name} - Jama'ah`,
        sublabel: p.jamatTimeFmt || '',
        countdownTo: new Date(p.jamatUTC),
        nextTransition: jamatMs,
      });
    }
  }

  // Sort by 'until' so we can search through them
  entries.sort((a, b) => a.until - b.until);
  return entries;
}

function getWidgetState(data) {
  const now = Date.now();

  // Get all prayers sorted by fire time
  const prayers = (data.today || [])
    .concat(data.tomorrow || [])
    .filter(p => p.fireUTC)
    .sort((a, b) => new Date(a.fireUTC).getTime() - new Date(b.fireUTC).getTime());

  if (prayers.length === 0) return null;

  const timeline = buildTimeline(prayers);

  // Find the current phase: the first entry where now < until
  for (const entry of timeline) {
    if (now < entry.until) {
      return entry;
    }
  }

  // All phases passed — show the very last prayer's countdown (will show elapsed)
  // Or use nextPrayer from API as fallback
  if (data.nextPrayer && data.nextPrayer.fireUTC) {
    const np = data.nextPrayer;
    return {
      label: getName(np.title),
      sublabel: np.fireTimeFmt || '',
      countdownTo: new Date(np.fireUTC),
      nextTransition: new Date(np.fireUTC).getTime(),
    };
  }

  return null;
}

async function fetchData() {
  const req = new Request(API);
  req.timeoutInterval = 10;
  return await req.loadJSON();
}

let data;
try {
  data = await fetchData();
} catch (e) {
  data = null;
}

const state = data ? getWidgetState(data) : null;
const family = config.widgetFamily;

// Calculate when to refresh: at the next phase transition, or 5 min, whichever is sooner
let refreshMs = 5 * 60 * 1000; // default 5 min
if (state && state.nextTransition) {
  const untilTransition = state.nextTransition - Date.now();
  if (untilTransition > 0 && untilTransition < refreshMs) {
    // Refresh 2 seconds after the transition to ensure we're past it
    refreshMs = untilTransition + 2000;
  }
}
const refreshDate = new Date(Date.now() + refreshMs);

// ── Lock screen widget (accessoryRectangular) ──
if (family === 'accessoryRectangular') {
  const w = new ListWidget();
  w.url = 'https://muaiprayertimes.xyz';
  w.setPadding(4, 4, 4, 4);
  w.refreshAfterDate = refreshDate;

  if (state) {
    const row1 = w.addText(state.label);
    row1.font = Font.boldSystemFont(14);
    row1.minimumScaleFactor = 0.7;

    w.addSpacer(1);

    const sub = w.addText(state.sublabel);
    sub.font = Font.mediumSystemFont(10);
    sub.textOpacity = 0.6;

    w.addSpacer(2);

    const cd = w.addDate(state.countdownTo);
    cd.applyTimerStyle();
    cd.font = Font.semiboldMonospacedSystemFont(13);
  } else {
    const t = w.addText('No prayers');
    t.font = Font.mediumSystemFont(12);
  }

  w.addSpacer();
  Script.setWidget(w);

// ── Home screen widget ──
} else {
  const w = new ListWidget();
  w.backgroundColor = new Color('#1a2744');
  w.url = 'https://muaiprayertimes.xyz';
  w.refreshAfterDate = refreshDate;

  const isMedium = family === 'medium' || family === 'large';
  w.setPadding(14, 16, 14, 16);

  if (state) {
    if (isMedium) {
      const row = w.addStack();
      row.layoutHorizontally();
      row.centerAlignContent();

      const left = row.addStack();
      left.layoutVertically();

      const nameText = left.addText(state.label);
      nameText.font = Font.boldSystemFont(20);
      nameText.textColor = Color.white();
      nameText.minimumScaleFactor = 0.7;

      left.addSpacer(2);

      const sub = left.addText(state.sublabel);
      sub.font = Font.mediumSystemFont(13);
      sub.textColor = new Color('#8899aa');

      left.addSpacer(8);

      const cd = left.addDate(state.countdownTo);
      cd.applyTimerStyle();
      cd.font = Font.semiboldMonospacedSystemFont(28);
      cd.textColor = new Color('#d4af37');

      row.addSpacer();

      const label = row.addText('MUAI');
      label.font = Font.boldSystemFont(12);
      label.textColor = new Color('#8899aa');

    } else {
      const nameText = w.addText(state.label);
      nameText.font = Font.boldSystemFont(16);
      nameText.textColor = Color.white();
      nameText.minimumScaleFactor = 0.7;

      w.addSpacer(2);

      const sub = w.addText(state.sublabel);
      sub.font = Font.mediumSystemFont(11);
      sub.textColor = new Color('#8899aa');

      w.addSpacer(6);

      const cd = w.addDate(state.countdownTo);
      cd.applyTimerStyle();
      cd.font = Font.semiboldMonospacedSystemFont(18);
      cd.textColor = new Color('#d4af37');
    }
  } else {
    const noData = w.addText('No prayers');
    noData.font = Font.mediumSystemFont(14);
    noData.textColor = new Color('#8899aa');
  }

  w.addSpacer();

  if (config.runsInWidget) {
    Script.setWidget(w);
  } else {
    w.presentMedium();
  }
}

Script.complete();
