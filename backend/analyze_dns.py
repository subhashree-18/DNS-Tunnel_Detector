import pyshark
import math
import csv
import threading
import time
import matplotlib.pyplot as plt
import asyncio
import re
from collections import defaultdict, deque

# ---------- Helper Functions ----------
def calculate_entropy(string):
    if not string:
        return 0
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(string)]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def count_subdomain_levels(domain):
    return domain.count('.') - 1  # Exclude TLD

def digit_ratio(domain):
    return sum(c.isdigit() for c in domain) / len(domain)

def special_char_ratio(domain):
    return sum(not c.isalnum() and c != '.' for c in domain) / len(domain)

# ---------- Suspicious Scoring Function ----------
def score_query(length, entropy, freq, qtype, depth, digit_ratio_val, special_ratio, time_gap):
    score = 0

    if length > 40:
        score += 1
    if entropy > 4.2:
        score += 1
    if freq > 1:
        score += 1
    if qtype in ['TXT', 'NULL', 'CNAME']:
        score += 1
    if depth >= 5:
        score += 1
    if digit_ratio_val > 0.3:
        score += 1
    if special_ratio > 0.1:
        score += 1
    if time_gap is not None and time_gap < 0.5:  # too frequent
        score += 1

    return score

# ---------- Global Data Stores ----------
domain_count = defaultdict(int)
suspicious_queries = {}
recent_domains = deque(maxlen=100)
last_seen = {}
whitelist_domains = ['google.com', 'microsoft.com', 'windowsupdate.com', 'cloudflare.com', 'akamai.net', 'github.com']

# ---------- CSV Logging ----------
csv_file = open('suspicious_dns_live.csv', 'w', newline='', encoding='utf-8')
csv_writer = csv.writer(csv_file)
csv_writer.writerow(['Domain', 'Length', 'Entropy', 'Frequency', 'Score', 'QueryType', 'Depth', 'Digits', 'SpecialChars', 'TimeGap'])

# ---------- Live Capture ----------
def dns_sniffer(interface='eth0'):
    print(f"🔍 Starting DNS packet sniffing on interface '{interface}'...\n")
    asyncio.set_event_loop(asyncio.new_event_loop())

    try:
        cap = pyshark.LiveCapture(interface=interface, display_filter='dns')

        for pkt in cap.sniff_continuously():
            try:
                domain = str(pkt.dns.qry_name).lower()
                qtype = str(pkt.dns.qry_type).upper()  # Numeric type, convert to readable form if needed

                if domain.endswith(('.lan', '.local')):
                    continue
                if any(w in domain for w in whitelist_domains):
                    continue

                length = len(domain)
                entropy = calculate_entropy(domain)
                depth = count_subdomain_levels(domain)
                digit_ratio_val = digit_ratio(domain)
                special_ratio = special_char_ratio(domain)

                # Inter-arrival timing
                now = time.time()
                time_gap = now - last_seen.get(domain, now)
                last_seen[domain] = now

                domain_count[domain] += 1
                freq = domain_count[domain]

                score = score_query(length, entropy, freq, qtype, depth, digit_ratio_val, special_ratio, time_gap)

                print(f"🔎 {domain} | Len:{length} | Ent:{round(entropy,2)} | Freq:{freq} | Type:{qtype} | D:{depth} | DgR:{digit_ratio_val:.2f} | SpR:{special_ratio:.2f} | Gap:{round(time_gap,2)} | Score:{score}")

                if score >= 3 and domain not in suspicious_queries:
                    suspicious_queries[domain] = True
                    print(f"⚠️ Suspicious: {domain}")
                    csv_writer.writerow([domain, length, round(entropy, 2), freq, score, qtype, depth, round(digit_ratio_val, 2), round(special_ratio, 2), round(time_gap, 2)])
                    csv_file.flush()

                recent_domains.append(domain)

            except AttributeError:
                continue

    except Exception as e:
        print(f"❌ Error: {e}")
        csv_file.close()

# ---------- Visualization ----------
def plot_top_domains(interval=60):
    while True:
        time.sleep(interval)
        if not domain_count:
            continue

        top = sorted(domain_count.items(), key=lambda x: x[1], reverse=True)[:10]
        labels, values = zip(*top)

        plt.figure(figsize=(10, 6))
        plt.barh(labels, values, color='skyblue')
        plt.xlabel('Query Count')
        plt.title('Top 10 Queried Domains (Live)')
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plt.savefig("top_domains_live.png")
        plt.close()
        print("📊 Chart updated: top_domains_live.png")

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
