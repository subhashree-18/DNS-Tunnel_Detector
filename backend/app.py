from flask import Flask, jsonify, Response
from flask_cors import CORS
from threading import Thread
from analyze_dns import dns_sniffer, domain_count, suspicious_queries
import json
import time

app = Flask(__name__)
CORS(app)

interface = "Wi-Fi"  # Change if needed (e.g., wlan0, eth0)

# 🧠 Start sniffer thread in background
def start_sniffer():
    sniff_thread = Thread(target=dns_sniffer, args=(interface,))
    sniff_thread.daemon = True
    sniff_thread.start()

# ⚙️ Endpoint to return ONLY suspicious domains
@app.route('/api/suspicious', methods=['GET'])
def get_suspicious():
    # Extract only suspicious ones (score >= 3)
    data = [
        {"domain": d, "count": domain_count[d]}
        for d in suspicious_queries.keys()
    ]
    # Sort descending by count
    data.sort(key=lambda x: x["count"], reverse=True)
    return jsonify(data[:15])  # Limit to top 15 suspicious domains

# 🧩 Live stream endpoint (if frontend needs continuous feed)
@app.route('/api/live')
def stream_live():
    def generate():
        last_snapshot = {}
        while True:
            # Capture only suspicious ones
            snapshot = {d: domain_count[d] for d in suspicious_queries.keys()}
            if snapshot != last_snapshot:
                payload = [
                    {"domain": d, "count": domain_count[d]}
                    for d in suspicious_queries.keys()
                ]
                payload.sort(key=lambda x: x["count"], reverse=True)
                yield f"data: {json.dumps(payload[:15])}\n\n"
                last_snapshot = snapshot
            time.sleep(2)
    return Response(generate(), mimetype="text/event-stream")

@app.route('/')
def home():
    return "✅ DNS Tunneling Detection Backend Running (Suspicious-only Mode)"

if __name__ == '__main__':
    start_sniffer()
    app.run(host='0.0.0.0', port=5000, debug=True)
