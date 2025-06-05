import pyshark
import math
import csv
import threading
import time
import matplotlib.pyplot as plt
import asyncio
from collections import defaultdict, deque

# ---------- Entropy Calculation ----------
def calculate_entropy(string):
    if not string:
        return 0
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

# ---------- Suspicious Scoring Function ----------
def score_query(length, entropy, freq):
    score = 0
    if length > 40:
        score += 1
    if entropy > 4.2:
        score += 1
    if freq > 1:
        score += 1
    return score

# ---------- Global Data Stores ----------
domain_count = defaultdict(int)
suspicious_queries = {}
recent_domains = deque(maxlen=100)

# ---------- CSV Logging Setup ----------
csv_file = open('suspicious_dns_live.csv', 'w', newline='', encoding='utf-8')
csv_writer = csv.writer(csv_file)
csv_writer.writerow(['Domain', 'Length', 'Entropy', 'Frequency', 'Score'])

# ---------- Live DNS Sniffer ----------
def dns_sniffer(interface='eth0'):
    print(f"🔍 Starting DNS packet sniffing on interface '{interface}'...\n")

    asyncio.set_event_loop(asyncio.new_event_loop())

    try:
        cap = pyshark.LiveCapture(interface=interface, display_filter='dns')

        for pkt in cap.sniff_continuously():
            try:
                query_name = pkt.dns.qry_name
                domain = str(query_name).lower()

                # Optional: skip local domains
                if domain.endswith('.lan') or domain.endswith('.local'):
                    continue

                length = len(domain)
                entropy = calculate_entropy(domain)

                domain_count[domain] += 1
                freq = domain_count[domain]

                score = score_query(length, entropy, freq)

                # Debug log
                print(f"🔎 {domain} | Len: {length} | Entropy: {round(entropy,2)} | Freq: {freq} | Score: {score}")

                if score >= 2 and domain not in suspicious_queries:
                    suspicious_queries[domain] = {
                        'length': length,
                        'entropy': round(entropy, 2),
                        'freq': freq,
                        'score': score
                    }
                    print(f"⚠️ Suspicious: {domain} | Len: {length} | Entropy: {round(entropy,2)} | Freq: {freq} | Score: {score}")
                    csv_writer.writerow([domain, length, round(entropy, 2), freq, score])
                    csv_file.flush()

                recent_domains.append(domain)

            except AttributeError:
                continue

    except Exception as e:
        print(f"❌ Error starting capture on interface '{interface}': {e}")
        csv_file.close()
        return

# ---------- Visualization ----------
def plot_top_domains(interval=60):
    while True:
        time.sleep(interval)
        if not domain_count:
            continue

        top_domains = sorted(domain_count.items(), key=lambda x: x[1], reverse=True)[:10]
        labels, values = zip(*top_domains)

        plt.figure(figsize=(10, 6))
        plt.barh(labels, values, color='skyblue')
        plt.xlabel('Query Count')
        plt.title('Top 10 Queried Domains (Live)')
        plt.gca().invert_yaxis()
        plt.tight_layout()
        filename = "top_domains_live.png"
        plt.savefig(filename)
        plt.close()
        print(f"\n📊 Chart updated: {filename}")

# ---------- Start Threads ----------
if __name__ == '__main__':
    interface = input("Enter network interface (e.g., eth0, wlan0, Wi-Fi): ").strip()

    sniff_thread = threading.Thread(target=dns_sniffer, args=(interface,))
    plot_thread = threading.Thread(target=plot_top_domains, args=(60,))

    sniff_thread.daemon = True
    plot_thread.daemon = True

    sniff_thread.start()
    plot_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n⛔ Stopping real-time DNS analysis.")
        csv_file.close()
        sniff_thread.join()
        plot_thread.join()
