# AppTrust — Scam App Detector
## Full Setup Guide

---

## 📁 Folder Structure

```
apptrust/
│
├── server.js           ← Backend (Node.js + Express)
├── package.json        ← Dependencies
├── .env                ← Configuration
│
└── public/
    └── index.html      ← Frontend (your HTML file goes here)
```

---

## ⚙️ Step-by-Step Setup

### Step 1 — Install Node.js
Download from: https://nodejs.org  (choose LTS version)

### Step 2 — Create Project Folder
```bash
mkdir apptrust
cd apptrust
```

### Step 3 — Copy All Files
```
apptrust/server.js       ← paste server.js content
apptrust/package.json    ← paste package.json content
apptrust/.env            ← paste .env content
apptrust/public/index.html  ← paste index.html content
```

### Step 4 — Install Dependencies
```bash
npm install
```
This installs:
- express           → web server
- google-play-scraper → Play Store data (NO API KEY NEEDED)
- sentiment         → NLP review analysis
- node-cache        → caching to avoid rate limits
- cors              → cross-origin support
- dotenv            → environment variables

### Step 5 — Configure .env
```
PORT=5000
PLAY_STORE_COUNTRY=in     # in=India, us=USA, gb=UK
PLAY_STORE_LANG=en
MAX_REVIEWS=100
CACHE_TTL=3600
```

### Step 6 — Run the App
```bash
node server.js
```

### Step 7 — Open in Browser
```
http://localhost:5000
```

---

## 🔑 About Google Play Store API

**No API key is needed.**

This app uses `google-play-scraper` which scrapes public Play Store data directly.
Google does NOT provide an official public API for app reviews/ratings.

What the scraper fetches:
- App name, icon, rating, install count
- App description, developer, version, release date
- User reviews (up to 150 latest)
- App permissions
- Genre / category

---

## 🧠 How Trust Score is Calculated

| Factor              | Weight  |
|---------------------|---------|
| Play Store Rating   | -3 max  |
| Number of Ratings   | -2 max  |
| Review Sentiment    | -3 max  |
| Fake Review %       | -2 max  |
| App Age             | -2 max  |
| Install Count       | -1 max  |
| Permissions         | -1 max  |

Score 7-10 → ✅ Safe  
Score 4-6  → ⚠ Suspicious  
Score 1-3  → ❌ Scam  

---

## 🤖 Fake Review Detection

Checks for:
- Duplicate or near-duplicate review text
- Suspiciously short 5-star reviews (≤3 words)
- Excessive punctuation (!!! patterns)
- Unnaturally high 5-star ratio (>90%)

---

## 🚀 Deploy to Cloud (Optional)

### Render.com (Free)
1. Push to GitHub
2. Go to render.com → New Web Service
3. Connect repo → set start command: `node server.js`
4. Add environment variables from .env

### Railway.app (Free)
1. Push to GitHub
2. railway.app → New Project → Deploy from GitHub
3. Set env vars

### Heroku
```bash
heroku create apptrust-app
git push heroku main
```

---

## 📦 NPM Packages Used

| Package               | Version  | Purpose                          |
|-----------------------|----------|----------------------------------|
| express               | ^4.18.2  | HTTP server                      |
| google-play-scraper   | ^9.1.0   | Scrape Play Store (no key needed)|
| sentiment             | ^5.0.2   | NLP sentiment analysis           |
| node-cache            | ^5.1.2   | In-memory caching                |
| cors                  | ^2.8.5   | Cross-origin requests            |
| dotenv                | ^16.3.1  | Environment variables            |
