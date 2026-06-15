import os
import json
import re
import urllib.parse
from flask import Flask, render_template, request, jsonify, redirect
import requests

app = Flask(__name__)

STATS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_stats.json")
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dpi_log.txt")
BLOCKLIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocklist.txt")

def get_dns_stats():
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"total_queries": 0, "blocked_queries": 0}

def get_dpi_logs():
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                # Get last 20 block logs
                for line in reversed(lines):
                    line = line.strip()
                    if not line:
                        continue
                    # Parse format: [2026-06-13 15:30:00] BLOCKED SNI: googleads.g.doubleclick.net (IP: 172.217.16.142)
                    match = re.match(r"\[(.*?)\] BLOCKED SNI:\s*(.*?)\s*\(IP:\s*(.*?)\)", line)
                    if match:
                        logs.append({
                            "timestamp": match.group(1),
                            "sni": match.group(2),
                            "ip": match.group(3)
                        })
                    if len(logs) >= 20:
                        break
        except Exception:
            pass
    return logs

def extract_and_block(url):
    domains = set()
    print(f"[Dashboard] Fetching YouTube URL: {url}")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            # Extract googlevideo stream domains
            matches = re.findall(r'[a-zA-Z0-9\-]+\.googlevideo\.com', response.text)
            for match in matches:
                domains.add(match.lower())
                
            # Scan general URLs for ad servers
            urls = re.findall(r'https?://[a-zA-Z0-9\-\.]+', response.text)
            for u in urls:
                hostname = urllib.parse.urlparse(u).hostname
                if hostname:
                    hostname = hostname.lower()
                    if any(x in hostname for x in ["googlevideo", "doubleclick", "googlesyndication", "googleads"]):
                        domains.add(hostname)
                        
            # Write new domains to blocklist
            existing = set()
            if os.path.exists(BLOCKLIST_FILE):
                with open(BLOCKLIST_FILE, "r") as f:
                    existing = {line.strip().lower() for line in f if line.strip() and not line.strip().startswith("#")}
            new_domains = domains - existing
            if new_domains:
                with open(BLOCKLIST_FILE, "a") as f:
                    for d in sorted(new_domains):
                        f.write(f"\n{d}")
                return f"Successfully added {len(new_domains)} domains to blocklist.txt"
            return "No new domains found on page. Blocklist is already up to date."
    except Exception as e:
        return f"Error resolving domains: {e}"
    return "Failed to parse YouTube page content."

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "*"
    return response

@app.route("/", methods=["GET", "POST"])
def index():
    message = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            extract_and_block(url)
            return redirect(url)
            
    stats = get_dns_stats()
    dpi_logs = get_dpi_logs()
    
    return render_template("index.html", stats=stats, dpi_logs=dpi_logs, message=message)

@app.route("/api/stats")
def api_stats():
    return jsonify({
        "stats": get_dns_stats(),
        "dpi_logs": get_dpi_logs()
    })

if __name__ == "__main__":
    print("[Dashboard] Running Flask dashboard on http://127.0.0.1:5000...")
    app.run(host="127.0.0.1", port=5000, debug=False)
