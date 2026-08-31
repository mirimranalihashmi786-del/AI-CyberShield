"""
generate_dataset.py
--------------------
Generates a labeled, NSL-KDD-style synthetic network traffic dataset for
training AI CyberShield's detection model.

Why synthetic instead of downloading CIC-IDS2017 / UNSW-NB15 / NSL-KDD?
These are multi-GB datasets distributed by third parties and can't be
fetched automatically in every environment. This script builds a dataset
with the *same feature families* those datasets use (connection stats,
byte counts, error rates, host-based counts) so you can swap in the real
CSVs later with minimal code changes -- see README.md "Using a real
dataset" section.

Output: data/traffic_dataset.csv
"""

import numpy as np
import pandas as pd

RNG = np.random.default_rng(42)
N_PER_CLASS = 2500

PROTOCOLS = ["tcp", "udp", "icmp"]
SERVICES = ["http", "https", "ssh", "ftp", "dns", "smtp", "telnet", "other"]
FLAGS = ["SF", "S0", "REJ", "RSTR", "SH"]

CLASSES = ["normal", "ddos", "portscan", "bruteforce", "sqli", "phishing", "malware"]


def base_row():
    return {
        "duration": max(0, RNG.exponential(2)),
        "protocol_type": RNG.choice(PROTOCOLS, p=[0.75, 0.2, 0.05]),
        "service": RNG.choice(SERVICES),
        "flag": "SF",
        "src_bytes": max(0, RNG.normal(500, 200)),
        "dst_bytes": max(0, RNG.normal(1200, 400)),
        "count": RNG.integers(1, 10),
        "srv_count": RNG.integers(1, 10),
        "serror_rate": np.clip(RNG.normal(0.02, 0.02), 0, 1),
        "rerror_rate": np.clip(RNG.normal(0.02, 0.02), 0, 1),
        "same_srv_rate": np.clip(RNG.normal(0.9, 0.05), 0, 1),
        "diff_srv_rate": np.clip(RNG.normal(0.05, 0.03), 0, 1),
        "dst_host_count": RNG.integers(1, 50),
        "dst_host_srv_count": RNG.integers(1, 50),
        "dst_host_same_srv_rate": np.clip(RNG.normal(0.8, 0.1), 0, 1),
        "dst_host_diff_srv_rate": np.clip(RNG.normal(0.1, 0.05), 0, 1),
        "unique_ports_touched": RNG.integers(1, 3),
        "conn_rate_per_sec": np.clip(RNG.normal(1.5, 0.8), 0.1, None),
        "payload_entropy": np.clip(RNG.normal(4.2, 0.6), 0, 8),
        "failed_logins": 0,
    }


def make_class(label, n):
    rows = []
    for _ in range(n):
        r = base_row()

        if label == "normal":
            pass  # baseline profile as-is

        elif label == "ddos":
            r["count"] = RNG.integers(400, 5000)
            r["srv_count"] = RNG.integers(400, 5000)
            r["conn_rate_per_sec"] = RNG.uniform(200, 4000)
            r["serror_rate"] = np.clip(RNG.normal(0.7, 0.15), 0, 1)
            r["src_bytes"] = max(0, RNG.normal(60, 30))
            r["flag"] = RNG.choice(["S0", "REJ"])
            r["dst_host_same_srv_rate"] = np.clip(RNG.normal(0.98, 0.02), 0, 1)

        elif label == "portscan":
            r["unique_ports_touched"] = RNG.integers(15, 200)
            r["count"] = RNG.integers(20, 300)
            r["diff_srv_rate"] = np.clip(RNG.normal(0.85, 0.1), 0, 1)
            r["same_srv_rate"] = np.clip(RNG.normal(0.1, 0.05), 0, 1)
            r["src_bytes"] = max(0, RNG.normal(40, 15))
            r["dst_bytes"] = 0
            r["flag"] = RNG.choice(["S0", "REJ"])
            r["conn_rate_per_sec"] = RNG.uniform(10, 150)

        elif label == "bruteforce":
            r["service"] = RNG.choice(["ssh", "ftp", "telnet"])
            r["failed_logins"] = RNG.integers(5, 50)
            r["count"] = RNG.integers(20, 200)
            r["conn_rate_per_sec"] = RNG.uniform(3, 40)
            r["duration"] = RNG.exponential(0.3)
            r["rerror_rate"] = np.clip(RNG.normal(0.6, 0.2), 0, 1)

        elif label == "sqli":
            r["service"] = RNG.choice(["http", "https"])
            r["payload_entropy"] = np.clip(RNG.normal(6.3, 0.5), 0, 8)
            r["src_bytes"] = max(0, RNG.normal(900, 300))
            r["duration"] = RNG.exponential(0.5)
            r["dst_host_diff_srv_rate"] = np.clip(RNG.normal(0.4, 0.15), 0, 1)

        elif label == "phishing":
            r["service"] = RNG.choice(["http", "https", "smtp"])
            r["payload_entropy"] = np.clip(RNG.normal(5.6, 0.4), 0, 8)
            r["dst_bytes"] = max(0, RNG.normal(300, 150))
            r["diff_srv_rate"] = np.clip(RNG.normal(0.5, 0.2), 0, 1)

        elif label == "malware":
            r["service"] = RNG.choice(["other", "https", "dns"])
            r["duration"] = RNG.uniform(0.05, 0.2)
            r["conn_rate_per_sec"] = RNG.uniform(0.05, 0.3)  # low & slow beaconing
            r["payload_entropy"] = np.clip(RNG.normal(7.2, 0.4), 0, 8)  # encrypted-looking
            r["dst_host_count"] = RNG.integers(1, 3)
            r["same_srv_rate"] = np.clip(RNG.normal(0.95, 0.03), 0, 1)

        r["label"] = label
        rows.append(r)
    return rows


def main():
    all_rows = []
    for c in CLASSES:
        all_rows.extend(make_class(c, N_PER_CLASS))

    df = pd.DataFrame(all_rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle
    df.to_csv("data/traffic_dataset.csv", index=False)
    print(f"Wrote {len(df)} rows to data/traffic_dataset.csv")
    print(df["label"].value_counts())


if __name__ == "__main__":
    main()
