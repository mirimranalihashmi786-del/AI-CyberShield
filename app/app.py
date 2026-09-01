"""
AI CyberShield - Flask application
-----------------------------------
Serves the dashboard and a small REST API backed by a real scikit-learn
model (trained via model/train_model.py). Includes a background thread
that simulates network traffic for demo purposes -- swap `simulate_event()`
for real packet features (see packet_capture/scapy_sniffer.py) to run
this against live traffic.

Run:
    python app/app.py
Then open http://localhost:5000
"""

import json
import os
import random
import sqlite3
import string
import threading
import time
from datetime import datetime

import joblib
import numpy as np
from flask import Flask, g, jsonify, render_template, request

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACT_DIR = os.path.join(BASE_DIR, "model", "artifacts")
DB_PATH = os.path.join(BASE_DIR, "app", "cybershield.db")

app = Flask(__name__)

# ---------------------------------------------------------------- model ---
clf = joblib.load(os.path.join(ARTIFACT_DIR, "classifier.joblib"))
iso = joblib.load(os.path.join(ARTIFACT_DIR, "anomaly_detector.joblib"))
encoders = joblib.load(os.path.join(ARTIFACT_DIR, "encoders.joblib"))
with open(os.path.join(ARTIFACT_DIR, "feature_columns.json")) as f:
    FEATURE_COLS = json.load(f)
TARGET_LE = encoders["__target__"]
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

ATTACK_META = {
    "ddos": {"label": "DDoS Flood", "severity": "critical"},
    "portscan": {"label": "Port Scan", "severity": "warning"},
    "bruteforce": {"label": "Brute Force", "severity": "warning"},
    "sqli": {"label": "SQL Injection", "severity": "critical"},
    "phishing": {"label": "Phishing Indicator", "severity": "warning"},
    "malware": {"label": "Malware C2 Traffic", "severity": "critical"},
    "normal": {"label": "Normal Traffic", "severity": "none"},
}

AUTO_RESPONSE = {"enabled": True, "threshold": 0.90}


# ------------------------------------------------------------- database ---
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(_exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            port INTEGER,
            protocol TEXT,
            classification TEXT NOT NULL,
            confidence REAL NOT NULL,
            anomaly_score REAL,
            status TEXT NOT NULL,
            features_json TEXT
        );
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            blocked_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        """
    )
    conn.commit()
    conn.close()


# --------------------------------------------------------- ML inference ---
def classify(features: dict):
    """features: dict of raw feature values (categoricals as strings)."""
    row = features.copy()
    for col in CATEGORICAL_COLS:
        le = encoders[col]
        val = row.get(col, le.classes_[0])
        if val not in le.classes_:
            val = le.classes_[0]
        row[col] = le.transform([val])[0]

    import pandas as pd
    X = pd.DataFrame([[row[c] for c in FEATURE_COLS]], columns=FEATURE_COLS)
    proba = clf.predict_proba(X)[0]
    pred_idx = int(np.argmax(proba))
    pred_label = TARGET_LE.inverse_transform([pred_idx])[0]
    confidence = float(proba[pred_idx])

    anomaly_raw = iso.decision_function(X)[0]  # higher = more normal
    anomaly_score = float(np.clip(1 - (anomaly_raw + 0.5), 0, 1))  # ~0..1, higher = more anomalous

    return pred_label, confidence, anomaly_score


# ----------------------------------------------------- traffic simulator --
PROTOCOLS = ["tcp", "udp", "icmp"]
SERVICES = ["http", "https", "ssh", "ftp", "dns", "smtp", "telnet", "other"]


def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def simulate_features(force_label=None):
    """Generate a synthetic feature vector, optionally biased toward a label,
    for demo purposes. Mirrors the distributions in data/generate_dataset.py."""
    label = force_label or random.choices(
        list(ATTACK_META.keys()), weights=[55, 8, 8, 8, 7, 7, 7], k=1
    )[0]

    base = {
        "duration": max(0, random.gauss(2, 1)),
        "protocol_type": random.choices(PROTOCOLS, weights=[0.75, 0.2, 0.05])[0],
        "service": random.choice(SERVICES),
        "flag": "SF",
        "src_bytes": max(0, random.gauss(500, 200)),
        "dst_bytes": max(0, random.gauss(1200, 400)),
        "count": random.randint(1, 10),
        "srv_count": random.randint(1, 10),
        "serror_rate": min(max(random.gauss(0.02, 0.02), 0), 1),
        "rerror_rate": min(max(random.gauss(0.02, 0.02), 0), 1),
        "same_srv_rate": min(max(random.gauss(0.9, 0.05), 0), 1),
        "diff_srv_rate": min(max(random.gauss(0.05, 0.03), 0), 1),
        "dst_host_count": random.randint(1, 50),
        "dst_host_srv_count": random.randint(1, 50),
        "dst_host_same_srv_rate": min(max(random.gauss(0.8, 0.1), 0), 1),
        "dst_host_diff_srv_rate": min(max(random.gauss(0.1, 0.05), 0), 1),
        "unique_ports_touched": random.randint(1, 3),
        "conn_rate_per_sec": max(random.gauss(1.5, 0.8), 0.1),
        "payload_entropy": min(max(random.gauss(4.2, 0.6), 0), 8),
        "failed_logins": 0,
    }

    if label == "ddos":
        base.update(count=random.randint(400, 5000), srv_count=random.randint(400, 5000),
                    conn_rate_per_sec=random.uniform(200, 4000),
                    serror_rate=min(max(random.gauss(0.7, 0.15), 0), 1),
                    src_bytes=max(0, random.gauss(60, 30)), flag=random.choice(["S0", "REJ"]))
    elif label == "portscan":
        base.update(unique_ports_touched=random.randint(15, 200), count=random.randint(20, 300),
                    diff_srv_rate=min(max(random.gauss(0.85, 0.1), 0), 1),
                    same_srv_rate=min(max(random.gauss(0.1, 0.05), 0), 1),
                    dst_bytes=0, flag=random.choice(["S0", "REJ"]))
    elif label == "bruteforce":
        base.update(service=random.choice(["ssh", "ftp", "telnet"]),
                    failed_logins=random.randint(5, 50), count=random.randint(20, 200),
                    conn_rate_per_sec=random.uniform(3, 40),
                    rerror_rate=min(max(random.gauss(0.6, 0.2), 0), 1))
    elif label == "sqli":
        base.update(service=random.choice(["http", "https"]),
                    payload_entropy=min(max(random.gauss(6.3, 0.5), 0), 8),
                    src_bytes=max(0, random.gauss(900, 300)))
    elif label == "phishing":
        base.update(service=random.choice(["http", "https", "smtp"]),
                    payload_entropy=min(max(random.gauss(5.6, 0.4), 0), 8),
                    dst_bytes=max(0, random.gauss(300, 150)))
    elif label == "malware":
        base.update(service=random.choice(["other", "https", "dns"]),
                    conn_rate_per_sec=random.uniform(0.05, 0.3),
                    payload_entropy=min(max(random.gauss(7.2, 0.4), 0), 8),
                    dst_host_count=random.randint(1, 3))

    return base, label


def gen_port():
    common = [22, 80, 443, 3389, 21, 3306, 8080, 445]
    return random.choice(common) if random.random() < 0.5 else random.randint(1024, 65535)


def is_blocked(ip):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT 1 FROM blocked_ips WHERE ip=?", (ip,)).fetchone()
    conn.close()
    return row is not None


def block_ip(ip, reason):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at) VALUES (?, ?, ?)",
        (ip, reason, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()
    # --- Real firewall integration point ---
    # Uncomment on Linux with appropriate privileges to actually block traffic:
    # import subprocess
    # subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])


def simulate_and_store():
    features, true_label = simulate_features()
    src_ip = rand_ip()
    pred_label, confidence, anomaly_score = classify(features)

    status = "allowed"
    if pred_label != "normal":
        if is_blocked(src_ip) or (AUTO_RESPONSE["enabled"] and confidence >= AUTO_RESPONSE["threshold"]):
            status = "blocked"
            block_ip(src_ip, ATTACK_META[pred_label]["label"])
        else:
            status = "flagged"

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO events (ts, src_ip, dst_ip, port, protocol, classification,
           confidence, anomaly_score, status, features_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.utcnow().isoformat(),
            src_ip,
            f"10.0.{random.randint(0,10)}.{random.randint(1,255)}",
            gen_port(),
            features["protocol_type"],
            pred_label,
            round(confidence, 4),
            round(anomaly_score, 4),
            status,
            json.dumps(features),
        ),
    )
    conn.commit()
    conn.close()


def background_traffic_loop():
    while True:
        simulate_and_store()
        time.sleep(0.8)


# ------------------------------------------------------------- routes -----
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/events")
def api_events():
    limit = int(request.args.get("limit", 60))
    db = get_db()
    rows = db.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    events = []
    for r in rows:
        events.append(
            {
                "id": r["id"],
                "ts": r["ts"],
                "src_ip": r["src_ip"],
                "dst_ip": r["dst_ip"],
                "port": r["port"],
                "protocol": r["protocol"],
                "classification": r["classification"],
                "label": ATTACK_META.get(r["classification"], {}).get("label", r["classification"]),
                "severity": ATTACK_META.get(r["classification"], {}).get("severity", "none"),
                "confidence": r["confidence"],
                "anomaly_score": r["anomaly_score"],
                "status": r["status"],
            }
        )
    return jsonify(events)


@app.route("/api/stats")
def api_stats():
    db = get_db()
    total = db.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    attacks = db.execute("SELECT COUNT(*) c FROM events WHERE classification != 'normal'").fetchone()["c"]
    blocked = db.execute("SELECT COUNT(*) c FROM blocked_ips").fetchone()["c"]
    by_type = db.execute(
        "SELECT classification, COUNT(*) c FROM events WHERE classification != 'normal' GROUP BY classification"
    ).fetchall()
    timeline = db.execute(
        """SELECT substr(ts, 1, 16) as minute,
                  SUM(CASE WHEN classification='normal' THEN 1 ELSE 0 END) as normal,
                  SUM(CASE WHEN classification!='normal' THEN 1 ELSE 0 END) as attacks
           FROM events GROUP BY minute ORDER BY minute DESC LIMIT 15"""
    ).fetchall()
    return jsonify(
        {
            "total_packets": total,
            "total_attacks": attacks,
            "blocked_ips": blocked,
            "by_type": {r["classification"]: r["c"] for r in by_type},
            "timeline": [dict(r) for r in reversed(timeline)],
            "auto_response": AUTO_RESPONSE,
        }
    )


@app.route("/api/blocked")
def api_blocked():
    db = get_db()
    rows = db.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/block", methods=["POST"])
def api_block():
    ip = request.json.get("ip")
    reason = request.json.get("reason", "Manual block")
    block_ip(ip, reason)
    return jsonify({"ok": True})


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    ip = request.json.get("ip")
    db = get_db()
    db.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/auto-response", methods=["POST"])
def api_auto_response():
    AUTO_RESPONSE["enabled"] = bool(request.json.get("enabled", True))
    return jsonify(AUTO_RESPONSE)


@app.route("/api/predict", methods=["POST"])
def api_predict():
    """Classify an arbitrary feature vector -- use this to feed real
    packet-derived features (e.g. from packet_capture/scapy_sniffer.py)."""
    features = request.json
    pred_label, confidence, anomaly_score = classify(features)
    return jsonify(
        {
            "classification": pred_label,
            "label": ATTACK_META.get(pred_label, {}).get("label", pred_label),
            "confidence": round(confidence, 4),
            "anomaly_score": round(anomaly_score, 4),
        }
    )


@app.route("/api/report/<int:event_id>")
def api_report(event_id):
    db = get_db()
    r = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if not r:
        return jsonify({"error": "not found"}), 404
    meta = ATTACK_META.get(r["classification"], {})
    report_id = "INC-" + "".join(random.choices(string.digits, k=6))
    text = f"""AI CYBERSHIELD - INCIDENT REPORT {report_id}
==================================================
Generated: {datetime.utcnow().isoformat()}Z

CLASSIFICATION : {meta.get('label', r['classification'])}
SEVERITY       : {meta.get('severity', 'unknown').upper()}
CONFIDENCE     : {r['confidence']*100:.1f}%
ANOMALY SCORE  : {r['anomaly_score']}

SOURCE IP      : {r['src_ip']}
DESTINATION    : {r['dst_ip']}:{r['port']}
PROTOCOL       : {r['protocol']}
TIMESTAMP (UTC): {r['ts']}
RESPONSE       : {r['status'].upper()}

FEATURE SNAPSHOT
-----------------
{json.dumps(json.loads(r['features_json']), indent=2)}

RECOMMENDED ACTIONS
--------------------
{recommend_actions(r['classification'])}
"""
    return jsonify({"report_id": report_id, "text": text})


def recommend_actions(classification):
    actions = {
        "ddos": "- Block/rate-limit source IP at edge firewall\n- Enable SYN cookies\n- Notify upstream ISP/CDN if volumetric",
        "portscan": "- Block source IP\n- Review exposed services on scanned ports\n- Enable port-scan alerting on IDS",
        "bruteforce": "- Block source IP\n- Enforce account lockout / rate limiting\n- Require MFA on affected service",
        "sqli": "- Block source IP\n- Review WAF rules for the affected endpoint\n- Audit application input validation",
        "phishing": "- Block destination domain at DNS/proxy\n- Notify affected user(s)\n- Add indicator to threat intel feed",
        "malware": "- Isolate affected host from network\n- Block C2 destination\n- Run full AV/EDR scan on source host",
        "normal": "- No action required",
    }
    return actions.get(classification, "- Investigate manually")


init_db()
_traffic_thread = threading.Thread(target=background_traffic_loop, daemon=True)
_traffic_thread.start()

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, port=5000)
    
    


