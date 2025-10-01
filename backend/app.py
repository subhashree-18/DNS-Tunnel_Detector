from flask import Flask, jsonify
from threading import Thread
from analyze_dns import dns_sniffer, domain_count, suspicious_queries
import time

app = Flask(__name__)
interface = "Wi-Fi"  

# Start sniffer in background
def start_sniffer():
    sniff_thread = Thread(target=dns_sniffer, args=(interface,))
    sniff_thread.daemon = True
    sniff_thread.start()

@app.route('/api/suspicious', methods=['GET'])
def get_suspicious():
    data = [
        {"domain": d, "count": domain_count[d]}
        for d in suspicious_queries.keys()
    ]
    return jsonify(data)

@app.route('/')
def home():
    return "DNS Tunneling Detection Backend Running"

if __name__ == '__main__':
    start_sniffer()
    app.run(debug=True)
