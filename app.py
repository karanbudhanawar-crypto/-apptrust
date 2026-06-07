"""
AppGuardian - Python Backend Server
Run: python app.py
API: http://localhost:5000
"""

import os
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from scraper import search_apps, get_app_details
from analyzer import analyze_app

app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)


# ── Serve frontend ────────────────────────────────────────────────────────────
@app.route('/')
def serve_frontend():
    """Serve the frontend index.html directly from /"""
    return send_from_directory('frontend', 'index.html')


# ── API routes ────────────────────────────────────────────────────────────────
@app.route('/api/status')
def status():
    return jsonify({
        "name": "AppGuardian API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": [
            "GET /api/search?q=<query>",
            "GET /api/scan/<app_id>",
            "GET /api/sample-scans",
        ]
    })


@app.route('/api/search')
def search():
    q = request.args.get('q', '').strip()
    if len(q) < 2:
        return jsonify({"error": "Query must be at least 2 characters"}), 400
    try:
        results = search_apps(q)
        return jsonify({"query": q, "results": results, "count": len(results)})
    except Exception as e:
        return jsonify({"error": str(e), "results": []}), 500


@app.route('/api/scan/<app_id>')
def scan(app_id):
    if not app_id or len(app_id) < 3:
        return jsonify({"error": "Invalid app ID"}), 400
    try:
        app_data = get_app_details(app_id)
        analysis = analyze_app(app_data)
        return jsonify({"app": app_data, "analysis": analysis})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/sample-scans')
def sample_scans():
    samples = [
        {"appId": "com.google.android.calculator", "title": "Calculator",
         "developer": "Google LLC", "letter": "=", "color": "#1565c0"},
        {"appId": "com.whatsapp", "title": "WhatsApp Messenger",
         "developer": "WhatsApp LLC", "letter": "W", "color": "#25d366"},
        {"appId": "com.spotify.music", "title": "Spotify: Music and Podcasts",
         "developer": "Spotify AB", "letter": "♪", "color": "#1db954"},
        {"appId": "com.bfs.flashcleanerpro", "title": "Flash Cleaner Pro",
         "developer": "BrightCleanLabs", "letter": "F", "color": "#ff6f00"},
    ]
    return jsonify({"samples": samples})


# ── Start ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"\n  AppGuardian running → http://localhost:{port}\n")
    app.run(host='0.0.0.0', port=port, debug=False)
