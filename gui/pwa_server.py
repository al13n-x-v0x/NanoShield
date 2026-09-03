"""
NanoShield Service Worker — Offline PWA Support
Enables full offline functionality for the web app.
"""
import os, sys, json, re, time
from flask import Flask, render_template_string, request, jsonify, send_from_directory

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Import the award GUI app
from award_gui import app, scan_code, VULN_PATTERNS

# Service Worker JavaScript
SW_JS = """
const CACHE_NAME = 'nanoshield-v1';
const urlsToCache = ['/'];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
  );
  self.skipWaiting();
});

self.addEventListener('fetch', e => {
  e.respondWith(
    caches.match(e.request).then(r => r || fetch(e.request))
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});
"""

@app.route("/sw.js")
def service_worker():
    return SW_JS, 200, {"Content-Type": "application/javascript", "Service-Worker-Allowed": "/"}

if __name__ == "__main__":
    print("\n  🛡️  NanoShield — Award-Winning GUI (PWA)")
    print("  → http://localhost:5000\n")
    app.run(debug=True, port=5000)
