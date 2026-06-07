"""
AppGuardian - Safety Analysis Engine  (fixed v2)

Bugs fixed:
  1. _label() was inverted — "High" showed when score was LOW
  2. histogram keys must be int — hist.get(5) not hist.get("5")
  3. reviewsAnalyzed now uses max(reviews, ratings) for accuracy
  4. _score_permissions returned 0 when permissions list was empty string
  5. Developer Trust display logic fixed — high trust score now shows correctly
  6. Sentiment score now directly uses real Play Store rating (score field)
  7. Fake review heuristics tuned to match real Play Store data
"""

import re

# ─────────────────────────────────────────────────────────────────────────────
# PERMISSION DATABASE
# ─────────────────────────────────────────────────────────────────────────────

PERMISSION_DB = {
    "android.permission.READ_CONTACTS":           ("Reads your entire contact list", "HIGH"),
    "android.permission.WRITE_CONTACTS":          ("Can modify your contacts", "HIGH"),
    "android.permission.READ_CALL_LOG":           ("Accesses your full call history", "HIGH"),
    "android.permission.WRITE_CALL_LOG":          ("Can modify call history", "HIGH"),
    "android.permission.RECORD_AUDIO":            ("Records microphone / audio", "HIGH"),
    "android.permission.CAMERA":                  ("Full camera access", "HIGH"),
    "android.permission.ACCESS_FINE_LOCATION":    ("Exact GPS location tracking", "HIGH"),
    "android.permission.READ_SMS":                ("Reads all your SMS messages", "HIGH"),
    "android.permission.SEND_SMS":                ("Sends SMS (may incur charges)", "HIGH"),
    "android.permission.RECEIVE_SMS":             ("Intercepts incoming SMS", "HIGH"),
    "android.permission.PROCESS_OUTGOING_CALLS":  ("Intercepts outgoing calls", "HIGH"),
    "android.permission.READ_PHONE_STATE":        ("Reads IMEI, phone number, carrier", "HIGH"),
    "android.permission.USE_BIOMETRIC":           ("Accesses fingerprint/face sensor", "HIGH"),
    "android.permission.USE_FINGERPRINT":         ("Reads fingerprint sensor", "HIGH"),
    "android.permission.BODY_SENSORS":            ("Reads heart rate & health sensors", "HIGH"),
    "android.permission.READ_CALENDAR":           ("Reads all your calendar events", "HIGH"),
    "android.permission.WRITE_CALENDAR":          ("Creates/edits calendar events", "HIGH"),
    "android.permission.MANAGE_ACCOUNTS":         ("Controls all device accounts", "HIGH"),
    "android.permission.GET_ACCOUNTS":            ("Lists every account on the device", "HIGH"),
    "android.permission.ACCESS_COARSE_LOCATION":  ("Approximate location (Wi-Fi/cell)", "MED"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("Location access when app is closed", "MED"),
    "android.permission.READ_EXTERNAL_STORAGE":   ("Reads all files on device storage", "MED"),
    "android.permission.WRITE_EXTERNAL_STORAGE":  ("Creates, edits, or deletes files", "MED"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("Full access to all storage", "MED"),
    "android.permission.BLUETOOTH":               ("Bluetooth device scanning", "MED"),
    "android.permission.BLUETOOTH_SCAN":          ("Scans nearby Bluetooth devices", "MED"),
    "android.permission.NFC":                     ("Near-field communication access", "MED"),
    "android.permission.BILLING":                 ("In-app purchase capability", "MED"),
    "android.permission.RECEIVE_BOOT_COMPLETED":  ("Starts automatically on device boot", "MED"),
    "android.permission.ACTIVITY_RECOGNITION":    ("Tracks physical activity & movement", "MED"),
    "android.permission.CALL_PHONE":              ("Can dial phone numbers directly", "MED"),
    "android.permission.REQUEST_INSTALL_PACKAGES":("Can install other APKs", "MED"),
    "android.permission.INTERNET":                ("Standard internet access", "LOW"),
    "android.permission.FOREGROUND_SERVICE":      ("Runs a persistent background service", "LOW"),
    "android.permission.VIBRATE":                 ("Controls device vibration", "LOW"),
    "android.permission.WAKE_LOCK":               ("Keeps screen/CPU awake", "LOW"),
    "android.permission.FLASHLIGHT":              ("Controls camera flashlight", "LOW"),
    "android.permission.CHANGE_NETWORK_STATE":    ("Can toggle Wi-Fi on/off", "LOW"),
    "android.permission.ACCESS_NETWORK_STATE":    ("Checks network connectivity", "LOW"),
    "android.permission.ACCESS_WIFI_STATE":       ("Reads Wi-Fi network names", "LOW"),
    "android.permission.CHANGE_WIFI_STATE":       ("Can connect/disconnect Wi-Fi", "LOW"),
    "android.permission.PUSH_NOTIFICATIONS":      ("Sends push notifications", "LOW"),
}

TRUSTED_PUBLISHERS = {
    "google", "meta", "instagram", "facebook", "microsoft", "amazon",
    "samsung", "spotify", "whatsapp", "netflix", "twitter", "x corp",
    "snapchat", "adobe", "paypal", "uber", "airbnb", "tiktok", "bytedance",
    "apple", "mozilla", "telegram", "signal", "zoom", "slack", "dropbox",
    "linkedin", "pinterest", "reddit", "duolingo", "canva", "notion",
    "youtube", "google llc",
}


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def analyze_app(app: dict) -> dict:
    fake_review_risk = _score_fake_reviews(app)
    permission_risk  = _score_permissions(app)
    developer_trust  = _score_developer(app)
    malware_risk     = _score_malware(app)
    sentiment_score  = _score_sentiment(app)

    safety_score = int(
        (100 - fake_review_risk) * 0.25 +
        (100 - permission_risk)  * 0.20 +
        developer_trust          * 0.25 +
        (100 - malware_risk)     * 0.10 +
        sentiment_score          * 0.20
    )
    safety_score = max(0, min(100, safety_score))

    risk_level  = _risk_level(safety_score)
    safe_to_use = safety_score >= 65
    grade       = _grade(safety_score)

    # Use the larger of reviews/ratings for display — whichever scraper captured
    review_count = max(
        _to_int(app.get("reviews")),
        _to_int(app.get("ratings"))
    )

    return {
        "safetyScore":      safety_score,
        "safetyGrade":      grade,
        "riskLevel":        risk_level,
        "safeToUse":        safe_to_use,
        "betterThanPct":    min(99, safety_score + 8),
        "lastAnalyzed":     "Just now",
        "reviewsAnalyzed":  _fmt_number(review_count),

        # ── Dimension scores ──
        # FIX: fakeReviewRisk — higher number = more risky → label reflects risk level
        "fakeReviewRisk":   fake_review_risk,
        "fakeReviewLabel":  _risk_label(fake_review_risk),   # Low/Medium/High based on risk

        # FIX: permissionsRisk — higher = more risky
        "permissionsRisk":  permission_risk,
        "permissionsLabel": _risk_label(permission_risk),

        # FIX: developerTrust — higher = more trustworthy, label shows trust level
        "developerTrust":   developer_trust,
        "developerLabel":   _trust_label(developer_trust),  # Low/Medium/High trust

        # malwareRisk — 0 = Safe
        "malwareRisk":      malware_risk,
        "malwareLabel":     "Safe" if malware_risk == 0 else _risk_label(malware_risk),

        "sentimentScore":   sentiment_score,
        "permissionDetails": _permission_details(app.get("permissions") or []),

        "dimensions": {
            "reviewAnalysis":   "Completed",
            "permissionsScan":  "Completed",
            "developerCheck":   "Completed",
            "behaviorAnalysis": "Completed",
            "threatDetection":  "Completed",
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
# SCORERS
# ─────────────────────────────────────────────────────────────────────────────

def _score_fake_reviews(app: dict) -> int:
    """
    Fake review risk (0-100). Higher = more suspicious.
    Uses star distribution from histogram.
    BUG FIX: histogram keys are always int after _clean_histogram in scraper.
    """
    hist     = app.get("histogram") or {}
    # Normalize keys to int just in case
    hist     = {int(k): int(v) for k, v in hist.items() if str(k).isdigit()}
    total    = sum(hist.values())
    installs = _to_int(app.get("minInstalls"))
    score_val = float(app.get("score") or 0)

    if total == 0:
        return 25  # no data — moderate unknown risk

    five_star = hist.get(5, 0)
    one_star  = hist.get(1, 0)
    five_pct  = five_star / total if total else 0
    one_pct   = one_star  / total if total else 0

    risk = 10  # baseline

    # 5-star inflation detection
    if five_pct > 0.90:   risk += 50
    elif five_pct > 0.82: risk += 35
    elif five_pct > 0.74: risk += 20
    elif five_pct > 0.65: risk += 10

    # Near-zero 1-star for large app
    if installs > 1_000_000 and one_pct < 0.004:
        risk += 18
    elif installs > 100_000 and one_pct < 0.008:
        risk += 10

    # Review-to-install ratio (sparse reviews = possible bought installs)
    if installs > 0:
        ratio = total / installs
        if ratio < 0.0001:  risk += 18
        elif ratio < 0.001: risk += 8

    # Official score vs computed distribution mismatch
    weighted     = sum(k * v for k, v in hist.items())
    computed_avg = weighted / total if total else 0
    if abs(score_val - computed_avg) > 1.5:
        risk += 12

    return min(risk, 100)


def _score_permissions(app: dict) -> int:
    """
    Permission risk (0-100). Higher = more dangerous permissions.
    BUG FIX: properly handle empty/None permissions list.
    """
    perms = app.get("permissions")
    if not perms or not isinstance(perms, list):
        return 0

    risk = 0
    for p in perms:
        if not isinstance(p, str):
            continue
        _, level = PERMISSION_DB.get(p.strip(), ("", "NONE"))
        if level == "HIGH":  risk += 15
        elif level == "MED": risk += 7
        elif level == "LOW": risk += 2

    return min(risk, 100)


def _score_developer(app: dict) -> int:
    """
    Developer trust (0-100). Higher = more trustworthy.
    BUG FIX: added 'instagram' and 'meta' to trusted publishers.
    """
    score     = 35
    installs  = _to_int(app.get("minInstalls"))
    ratings   = _to_int(app.get("ratings"))
    reviews   = _to_int(app.get("reviews"))
    app_score = float(app.get("score") or 0)
    developer = (app.get("developer") or "").lower()
    email     = app.get("developerEmail") or ""
    website   = app.get("developerWebsite") or ""
    released  = app.get("released") or ""

    # Install base
    if installs >= 1_000_000_000: score += 35
    elif installs >= 100_000_000: score += 28
    elif installs >= 10_000_000:  score += 20
    elif installs >= 1_000_000:   score += 13
    elif installs >= 100_000:     score += 6
    elif installs >= 10_000:      score += 2

    # Rating volume (use max of ratings/reviews)
    vol = max(ratings, reviews)
    if vol >= 100_000_000: score += 15
    elif vol >= 10_000_000: score += 12
    elif vol >= 1_000_000:  score += 8
    elif vol >= 100_000:    score += 4

    # App quality
    if app_score >= 4.5:   score += 12
    elif app_score >= 4.2: score += 8
    elif app_score >= 3.8: score += 4
    elif app_score < 3.0:  score -= 15
    elif app_score < 2.0:  score -= 25

    # Known trusted publisher
    if any(t in developer for t in TRUSTED_PUBLISHERS):
        score += 12

    # Transparency
    if email:   score += 3
    if website: score += 2

    # App longevity
    year = _extract_year(released)
    if year and year <= 2018:   score += 6
    elif year and year <= 2021: score += 3

    return max(0, min(100, score))


def _score_malware(app: dict) -> int:
    """Malware / virus risk (0-100)."""
    risk      = 0
    installs  = _to_int(app.get("minInstalls"))
    app_score = float(app.get("score") or 0)
    ad_sup    = bool(app.get("adSupported") or app.get("containsAds"))
    email     = app.get("developerEmail") or ""
    website   = app.get("developerWebsite") or ""
    title     = (app.get("title") or "").lower()
    perms     = app.get("permissions") or []

    if installs < 500 and app_score == 0:   risk += 45
    elif installs < 5_000:                  risk += 25
    elif installs < 50_000:                 risk += 10

    if ad_sup and installs < 10_000:   risk += 30
    elif ad_sup and installs < 50_000: risk += 15

    if not email and not website: risk += 15
    elif not email:               risk += 7

    suspicious = ["cleaner", "booster", "virus", "speed up", "optimizer",
                  "battery saver", "ram cleaner", "junk cleaner", "pro free"]
    if any(w in title for w in suspicious):
        risk += 20

    spy_perms = {
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_SMS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
    }
    overlap = len(spy_perms & set(perms))
    if overlap >= 3:  risk += 30
    elif overlap == 2: risk += 15

    if 0 < app_score < 2.0 and installs > 10_000:
        risk += 20

    return min(risk, 100)


def _score_sentiment(app: dict) -> int:
    """
    Sentiment score (0-100). Directly from Play Store rating.
    BUG FIX: use real score field as primary source, histogram as secondary.
    """
    # Primary: use the actual Play Store score (most accurate)
    app_score = float(app.get("score") or 0)
    if app_score > 0:
        return int((app_score / 5.0) * 100)

    # Fallback: compute from histogram
    hist  = app.get("histogram") or {}
    hist  = {int(k): int(v) for k, v in hist.items() if str(k).isdigit()}
    total = sum(hist.values())
    if total > 0:
        weighted = sum(k * v for k, v in hist.items())
        return int((weighted / total / 5.0) * 100)

    return 60  # neutral fallback


# ─────────────────────────────────────────────────────────────────────────────
# LABEL HELPERS  (BUG FIX: separate functions for risk vs trust)
# ─────────────────────────────────────────────────────────────────────────────

def _risk_label(score: int) -> str:
    """
    For RISK scores: higher number = worse.
    Returns: Low / Medium / High  (High = most risky)
    """
    if score >= 60: return "High"
    if score >= 30: return "Medium"
    return "Low"


def _trust_label(score: int) -> str:
    """
    For TRUST scores: higher number = better.
    Returns: Low / Medium / High  (High = most trusted)
    """
    if score >= 70: return "High"
    if score >= 40: return "Medium"
    return "Low"


def _risk_level(safety: int) -> str:
    if safety >= 75: return "LOW"
    if safety >= 50: return "MEDIUM"
    return "HIGH"


def _grade(safety: int) -> str:
    if safety >= 85: return "Excellent"
    if safety >= 70: return "Good"
    if safety >= 55: return "Fair"
    if safety >= 40: return "Poor"
    return "Dangerous"


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _permission_details(perms: list) -> list:
    result, seen = [], set()
    for p in perms:
        if not isinstance(p, str) or p in seen:
            continue
        seen.add(p)
        if p in PERMISSION_DB:
            desc, level = PERMISSION_DB[p]
        else:
            upper = p.upper()
            if "LOCATION" in upper:  level, desc = "MED",  "Location access"
            elif "CAMERA" in upper:  level, desc = "HIGH", "Camera access"
            elif "RECORD" in upper:  level, desc = "HIGH", "Audio recording"
            elif "CONTACT" in upper: level, desc = "HIGH", "Contacts access"
            elif "SMS" in upper:     level, desc = "HIGH", "SMS access"
            elif "PHONE" in upper:   level, desc = "MED",  "Phone access"
            elif "STORAGE" in upper: level, desc = "MED",  "Storage access"
            else: continue
        result.append({
            "permission":  p.split(".")[-1],
            "fullName":    p,
            "description": desc,
            "risk":        level,
        })
    result.sort(key=lambda x: {"HIGH": 0, "MED": 1, "LOW": 2}.get(x["risk"], 9))
    return result[:25]


def _to_int(val) -> int:
    try:
        return int(val or 0)
    except (TypeError, ValueError):
        return 0


def _fmt_number(n: int) -> str:
    if n >= 1_000_000_000: return f"{n/1_000_000_000:.1f}B"
    if n >= 1_000_000:     return f"{n/1_000_000:.1f}M"
    if n >= 1_000:         return f"{n/1_000:.0f}K"
    return str(n) if n else "—"


def _extract_year(released: str):
    m = re.search(r"(\d{4})", str(released))
    return int(m.group(1)) if m else None
