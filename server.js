// ─────────────────────────────────────────────────────────────────────────────
//  AppTrust Backend — server.js
//  Connects to Google Play Store via google-play-scraper (no API key needed)
//  Performs NLP sentiment analysis + fraud scoring
// ─────────────────────────────────────────────────────────────────────────────

require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const path       = require('path');
const gplay      = require('google-play-scraper');
const Sentiment  = require('sentiment');
const NodeCache  = require('node-cache');

const app       = express();
const sentiment = new Sentiment();
const cache     = new NodeCache({ stdTTL: parseInt(process.env.CACHE_TTL) || 3600 });

const PORT     = process.env.PORT || 5000;
const COUNTRY  = process.env.PLAY_STORE_COUNTRY || 'in';
const LANG     = process.env.PLAY_STORE_LANG || 'en';
const MAX_REV  = parseInt(process.env.MAX_REVIEWS) || 100;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// Serve the frontend HTML from the same folder
app.use(express.static(path.join(__dirname, 'public')));

// ─── Helper: Calculate Trust Score ───────────────────────────────────────────
function calculateTrustScore(appData, reviews, avgPolarity) {
  let score = 10;
  const reasons = [];

  // 1. Play Store Rating (max impact: -3)
  const rating = parseFloat(appData.score) || 0;
  if (rating < 2.0) {
    score -= 3;
    reasons.push(`⚠ Very low rating: ${rating.toFixed(1)} stars — critical red flag`);
  } else if (rating < 3.0) {
    score -= 2;
    reasons.push(`⚠ Low rating: ${rating.toFixed(1)} stars`);
  } else if (rating < 3.8) {
    score -= 1;
    reasons.push(`Rating is below average: ${rating.toFixed(1)} stars`);
  } else {
    reasons.push(`✓ Good Play Store rating: ${rating.toFixed(1)} stars`);
  }

  // 2. Number of ratings (credibility check)
  const ratingCount = parseInt(appData.ratings) || 0;
  if (ratingCount < 100) {
    score -= 2;
    reasons.push(`⚠ Very few ratings (${ratingCount}) — insufficient data`);
  } else if (ratingCount < 1000) {
    score -= 1;
    reasons.push(`Limited rating count: ${ratingCount.toLocaleString()}`);
  } else {
    reasons.push(`✓ ${ratingCount.toLocaleString()} ratings — good credibility`);
  }

  // 3. Sentiment Analysis (max impact: -3)
  if (avgPolarity < -0.3) {
    score -= 3;
    reasons.push(`⚠ Strongly negative review sentiment (${avgPolarity.toFixed(2)})`);
  } else if (avgPolarity < 0) {
    score -= 2;
    reasons.push(`⚠ Negative review sentiment score: ${avgPolarity.toFixed(2)}`);
  } else if (avgPolarity < 0.2) {
    score -= 1;
    reasons.push(`Mixed sentiment detected: ${avgPolarity.toFixed(2)}`);
  } else {
    reasons.push(`✓ Positive review sentiment: ${avgPolarity.toFixed(2)}`);
  }

  // 4. Fake Review Detection — pattern analysis
  const fakeResult = detectFakeReviews(reviews);
  if (fakeResult.fakePct > 60) {
    score -= 2;
    reasons.push(`⚠ High fake/bot review probability: ~${fakeResult.fakePct}%`);
  } else if (fakeResult.fakePct > 30) {
    score -= 1;
    reasons.push(`⚠ Moderate fake review patterns: ~${fakeResult.fakePct}%`);
  } else {
    reasons.push(`✓ Low fake review probability: ~${fakeResult.fakePct}%`);
  }

  // 5. App age check
  const released = new Date(appData.released || appData.updated);
  const ageMonths = (Date.now() - released) / (1000 * 60 * 60 * 24 * 30);
  if (ageMonths < 1) {
    score -= 2;
    reasons.push(`⚠ Very new app — less than 1 month old`);
  } else if (ageMonths < 3) {
    score -= 1;
    reasons.push(`⚠ New app — only ${Math.round(ageMonths)} months old`);
  } else {
    reasons.push(`✓ Established app — ${Math.round(ageMonths)} months on Play Store`);
  }

  // 6. Install count
  const installs = appData.installs || '0';
  const installNum = parseInt(installs.replace(/[^0-9]/g, '')) || 0;
  if (installNum < 1000) {
    score -= 1;
    reasons.push(`⚠ Very low installs: ${installs}`);
  } else if (installNum >= 1000000) {
    reasons.push(`✓ High install count: ${installs}`);
  } else {
    reasons.push(`Moderate install count: ${installs}`);
  }

  // 7. Permissions check
  const dangerousPerms = checkDangerousPermissions(appData.permissions || []);
  if (dangerousPerms.count > 4) {
    score -= 1;
    reasons.push(`⚠ ${dangerousPerms.count} high-risk permissions requested`);
  } else if (dangerousPerms.count > 0) {
    reasons.push(`${dangerousPerms.count} standard permissions requested`);
  } else {
    reasons.push(`✓ Minimal permissions — no high-risk access`);
  }

  // Clamp score
  score = Math.max(1, Math.min(10, score));

  // Label
  const label = score >= 7 ? 'Safe' : score >= 4 ? 'Suspicious' : 'Scam';

  return { score, label, reasons, fakeResult };
}

// ─── Helper: Detect Fake Reviews ─────────────────────────────────────────────
function detectFakeReviews(reviews) {
  if (!reviews || reviews.length === 0) return { fakePct: 0, signals: [] };

  let fakeCount  = 0;
  const signals  = [];
  const textMap  = {};

  // Check for duplicate/near-duplicate review texts
  reviews.forEach(r => {
    const key = (r.text || '').toLowerCase().trim().substring(0, 40);
    if (key.length > 5) {
      textMap[key] = (textMap[key] || 0) + 1;
    }
  });
  const dupCount = Object.values(textMap).filter(v => v > 1).reduce((a, b) => a + b, 0);
  if (dupCount > 0) {
    fakeCount += dupCount;
    signals.push(`${dupCount} duplicate or near-duplicate reviews found`);
  }

  // Check for suspiciously short positive reviews
  const shortPositive = reviews.filter(r =>
    (r.scoreText === '5' || r.score === 5) &&
    (r.text || '').trim().split(' ').length <= 3
  );
  if (shortPositive.length > reviews.length * 0.2) {
    fakeCount += shortPositive.length;
    signals.push(`${shortPositive.length} suspiciously short 5-star reviews`);
  }

  // Check for excessive exclamation marks (bot pattern)
  const exclamReviews = reviews.filter(r => (r.text || '').split('!').length - 1 >= 3);
  if (exclamReviews.length > reviews.length * 0.15) {
    fakeCount += Math.floor(exclamReviews.length * 0.5);
    signals.push(`Abnormal punctuation patterns in ${exclamReviews.length} reviews`);
  }

  // All 5-star reviews with no critical reviews at all
  const fiveStarPct = reviews.filter(r => r.score === 5).length / reviews.length;
  if (fiveStarPct > 0.9 && reviews.length > 20) {
    fakeCount += Math.floor(reviews.length * 0.2);
    signals.push(`Unnaturally high 5-star ratio (${(fiveStarPct * 100).toFixed(0)}%)`);
  }

  if (signals.length === 0) signals.push('No significant bot patterns detected');

  const fakePct = Math.min(95, Math.round((fakeCount / Math.max(reviews.length, 1)) * 100));
  return { fakePct, signals };
}

// ─── Helper: Permission Risk ──────────────────────────────────────────────────
function checkDangerousPermissions(permissions) {
  const HIGH_RISK = ['READ_CONTACTS','READ_SMS','SEND_SMS','READ_CALL_LOG',
                     'RECORD_AUDIO','ACCESS_FINE_LOCATION','READ_EXTERNAL_STORAGE',
                     'CAMERA','PROCESS_OUTGOING_CALLS','RECEIVE_SMS'];
  const flagged = permissions.filter(p =>
    HIGH_RISK.some(hr => (p || '').toUpperCase().includes(hr))
  );
  return { count: flagged.length, list: flagged };
}

// ─── Helper: Format Permissions for UI ───────────────────────────────────────
function formatPermissions(rawPerms) {
  const permMap = {
    'CAMERA':                 { icon:'📷', name:'Camera',          risk:'med' },
    'RECORD_AUDIO':           { icon:'🎤', name:'Microphone',      risk:'med' },
    'ACCESS_FINE_LOCATION':   { icon:'📍', name:'Precise Location',risk:'high'},
    'ACCESS_COARSE_LOCATION': { icon:'📍', name:'Location',        risk:'med' },
    'READ_CONTACTS':          { icon:'📇', name:'Read Contacts',   risk:'high'},
    'WRITE_CONTACTS':         { icon:'📇', name:'Write Contacts',  risk:'high'},
    'READ_SMS':               { icon:'💬', name:'Read SMS',        risk:'high'},
    'SEND_SMS':               { icon:'💬', name:'Send SMS',        risk:'high'},
    'READ_CALL_LOG':          { icon:'📞', name:'Call Logs',       risk:'high'},
    'READ_EXTERNAL_STORAGE':  { icon:'💾', name:'Storage Read',    risk:'low' },
    'WRITE_EXTERNAL_STORAGE': { icon:'💾', name:'Storage Write',   risk:'med' },
    'INTERNET':               { icon:'📶', name:'Internet',        risk:'low' },
    'RECEIVE_BOOT_COMPLETED': { icon:'🔔', name:'Auto-Start',      risk:'med' },
    'VIBRATE':                { icon:'📳', name:'Vibrate',         risk:'low' },
    'BILLING':                { icon:'💳', name:'In-App Purchase', risk:'high'},
    'USE_BIOMETRIC':          { icon:'🔐', name:'Biometrics',      risk:'med' },
  };

  const riskLabel = { high:'High', med:'Medium', low:'Low' };
  const seen = new Set();
  const result = [];

  (rawPerms || []).forEach(p => {
    const key = Object.keys(permMap).find(k => (p || '').toUpperCase().includes(k));
    if (key && !seen.has(key)) {
      seen.add(key);
      const m = permMap[key];
      result.push({ icon: m.icon, name: m.name, risk: m.risk, label: riskLabel[m.risk] });
    }
  });

  return result.slice(0, 8); // max 8 permissions shown
}

// ─── Helper: Format Reviews for UI ───────────────────────────────────────────
function formatReviews(rawReviews) {
  return rawReviews.slice(0, 5).map(r => {
    const result = sentiment.analyze(r.text || '');
    const polarity = result.score;
    let sentimentLabel, color;

    // Simple bot heuristic for display
    const text = (r.text || '').trim();
    const isLikelyBot = text.split(' ').length <= 4 && r.score === 5 &&
                        (text.split('!').length - 1 >= 2);

    if (isLikelyBot) {
      sentimentLabel = 'Suspicious';
      color = '#9b59b6';
    } else if (polarity > 1) {
      sentimentLabel = 'Positive';
      color = '#1dbd7a';
    } else if (polarity < -1) {
      sentimentLabel = 'Negative';
      color = '#e74c3c';
    } else {
      sentimentLabel = 'Neutral';
      color = '#3498db';
    }

    return {
      score:     r.score || 0,
      text:      r.text  || 'No review text',
      sentiment: sentimentLabel,
      color,
      bot:       isLikelyBot,
      author:    r.userName || 'Anonymous',
      date:      r.date || ''
    };
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  ROUTE: POST /search
//  Body: { query: "WhatsApp" }
//  Returns: list of matching apps from Play Store
// ─────────────────────────────────────────────────────────────────────────────
app.post('/search', async (req, res) => {
  const { query } = req.body;
  if (!query || query.trim().length < 2) {
    return res.json({ success: false, results: [] });
  }

  const cacheKey = `search_${query.toLowerCase().trim()}`;
  const cached = cache.get(cacheKey);
  if (cached) return res.json({ success: true, results: cached });

  try {
    const results = await gplay.search({
      term:     query,
      num:      8,
      country:  COUNTRY,
      lang:     LANG,
      fullDetail: false
    });

    const formatted = results.map(r => ({
      appId: r.appId,
      title: r.title,
      icon:  r.icon,
      score: r.score,
      developer: r.developer
    }));

    cache.set(cacheKey, formatted);
    res.json({ success: true, results: formatted });

  } catch (err) {
    console.error('[SEARCH ERROR]', err.message);
    res.json({ success: false, results: [], error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  ROUTE: POST /analyze
//  Body: { package_id: "com.whatsapp" }
//  Returns: full analysis — trust score, permissions, reviews, sentiment
// ─────────────────────────────────────────────────────────────────────────────
app.post('/analyze', async (req, res) => {
  const { package_id } = req.body;
  if (!package_id) {
    return res.json({ success: false, error: 'package_id is required' });
  }

  const cacheKey = `analyze_${package_id}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    console.log(`[CACHE HIT] ${package_id}`);
    return res.json(cached);
  }

  try {
    console.log(`[ANALYZING] ${package_id}`);

    // ── Step 1: Fetch app details from Play Store ──────────────────────────
    const appData = await gplay.app({
      appId:   package_id,
      country: COUNTRY,
      lang:    LANG
    });

    // ── Step 2: Fetch reviews ──────────────────────────────────────────────
    let rawReviews = [];
    try {
      const reviewResult = await gplay.reviews({
        appId:   package_id,
        country: COUNTRY,
        lang:    LANG,
        sort:    gplay.sort.NEWEST,
        num:     MAX_REV
      });
      rawReviews = reviewResult.data || [];
    } catch (revErr) {
      console.warn('[REVIEWS WARNING] Could not fetch reviews:', revErr.message);
    }

    // ── Step 3: Sentiment Analysis ─────────────────────────────────────────
    let totalPolarity = 0;
    rawReviews.forEach(r => {
      if (r.text) {
        const result = sentiment.analyze(r.text);
        // Normalize: sentiment library score / text word count
        const words = r.text.split(' ').length || 1;
        totalPolarity += result.score / words;
      }
    });
    const avgPolarity = rawReviews.length > 0
      ? parseFloat((totalPolarity / rawReviews.length).toFixed(2))
      : 0;

    // ── Step 4: Trust Score Calculation ───────────────────────────────────
    const { score, label, reasons, fakeResult } = calculateTrustScore(
      appData, rawReviews, avgPolarity
    );

    // ── Step 5: Format Permissions ─────────────────────────────────────────
    const permissions = formatPermissions(appData.permissions || []);

    // ── Step 6: Format Reviews for UI ─────────────────────────────────────
    const reviews = formatReviews(rawReviews);

    // ── Step 7: Developer info ─────────────────────────────────────────────
    const devScore = score >= 7 ? 8 : score >= 4 ? 5 : 2; // derive from app score

    // ── Build Response ─────────────────────────────────────────────────────
    const response = {
      success:       true,
      title:         appData.title,
      icon:          appData.icon,
      package_id:    appData.appId,
      developer:     appData.developer,
      developer_url: appData.developerWebsite || '',
      rating:        (parseFloat(appData.score) || 0).toFixed(1),
      installs:      appData.installs || 'Unknown',
      reviews_count: (appData.ratings || 0).toLocaleString(),
      version:       appData.version || 'N/A',
      updated:       appData.updated || 'N/A',
      released:      appData.released || 'N/A',
      genre:         appData.genre || 'Unknown',

      // Scores
      trust_score:   score,
      label:         label,
      avg_polarity:  avgPolarity,

      // Analysis
      reasons,
      permissions,

      // Fake review analysis
      fake_pct:      fakeResult.fakePct,
      fake_signals:  fakeResult.signals,

      // Developer
      dev_score:     devScore,
      dev_apps:      1, // Play scraper doesn't give this directly

      // Reviews
      reviews,

      // Safe alternatives placeholder (you can expand this)
      alts: []
    };

    cache.set(cacheKey, response);
    console.log(`[DONE] ${appData.title} → ${label} (${score}/10)`);
    res.json(response);

  } catch (err) {
    console.error('[ANALYZE ERROR]', err.message);
    res.json({ success: false, error: 'App not found or Play Store fetch failed.' });
  }
});

// ─── Serve Frontend ───────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ AppTrust Backend running at http://localhost:${PORT}`);
  console.log(`   Play Store Region : ${COUNTRY.toUpperCase()}`);
  console.log(`   Cache TTL         : ${process.env.CACHE_TTL || 3600}s`);
  console.log(`   Max Reviews       : ${MAX_REV}`);
  console.log(`   Frontend          : http://localhost:${PORT}\n`);
});
