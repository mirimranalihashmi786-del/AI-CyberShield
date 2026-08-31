# AI CyberShield

Autonomous cyber-attack detection and response system. A Flask web app backed
by a real scikit-learn model classifies traffic in real time as normal or as
one of six attack types, shows results on a live SOC-style dashboard, and can
automatically block malicious source IPs.

## Architecture

```
Network Traffic (simulated, or real via packet_capture/)
        │
        ▼
Feature Extraction (connection stats, byte counts, error rates, entropy...)
        │
        ▼
AI Detection Model  ── RandomForestClassifier (attack type)
        │            └ IsolationForest (anomaly score, novel-behavior signal)
        │
        ├── Normal ──────────────► logged, allowed
        │
        └── Attack ──────────────► classified (DDoS / Port Scan / Brute
                                     Force / SQL Injection / Phishing /
                                     Malware C2)
                                          │
                                          ▼
                                   Alert Engine (confidence threshold)
                                          │
                                          ▼
                          Dashboard (SQLite) + Auto-Response (IP block)
```

## Quick start

```bash
python3 -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 1. Generate the training dataset
python data/generate_dataset.py

# 2. Train the model (RandomForest classifier + IsolationForest)
python model/train_model.py

# 3. Run the app
python app/app.py
```

Open **http://localhost:5000**. The app starts a background thread that
generates simulated traffic (~1.3 events/sec) and classifies each one live,
so the dashboard is populated immediately.

## What's real vs. simulated

- **Real**: the ML model (RandomForest + IsolationForest), trained and
  evaluated with scikit-learn; the Flask REST API; SQLite persistence;
  the auto-response/blocking logic; incident report generation.
- **Simulated for the demo**: the traffic itself. `app/app.py` generates
  synthetic feature vectors with the same distributions as the training
  data (see `simulate_features()`), rather than reading real packets,
  since capturing live network traffic requires root privileges and a
  suitable network interface that a hosted demo can't assume.

## Feeding it real traffic

`packet_capture/scapy_sniffer.py` is a reference implementation that:
1. Sniffs live packets with [Scapy](https://scapy.net/) (requires root).
2. Aggregates them into 2-second, per-source-IP windows (connection count,
   unique ports touched, SYN ratio, byte volume).
3. POSTs the resulting feature vector to `POST /api/predict` on the running
   Flask app and prints an alert if it's classified as an attack.

```bash
sudo python3 packet_capture/scapy_sniffer.py --iface eth0 --api http://localhost:5000
```

Wire its alerts into the dashboard's blocking flow by calling
`POST /api/block` (see `app/app.py`) when an attack is detected.

## Using a real dataset (CIC-IDS2017 / UNSW-NB15 / NSL-KDD)

`data/generate_dataset.py` builds a synthetic dataset with the same feature
families (connection stats, byte counts, error rates, host-based counts)
used by these public IDS datasets, so the training pipeline is a drop-in.
To use a real dataset instead:

1. Download the dataset CSV(s) (e.g. NSL-KDD's `KDDTrain+.csv`).
2. Rename/select columns so they match `data/traffic_dataset.csv`'s schema
   (or edit `CATEGORICAL_COLS` / feature list in `model/train_model.py` to
   match the dataset's own columns).
3. Map the dataset's attack labels onto this project's six classes
   (`ddos`, `portscan`, `bruteforce`, `sqli`, `phishing`, `malware`) plus
   `normal` — most IDS datasets group many attack subtypes (e.g. `neptune`,
   `smurf` → `ddos`; `satan`, `ipsweep` → `portscan`).
4. Re-run `python model/train_model.py`.

## Real firewall integration

`block_ip()` in `app/app.py` has a commented-out `iptables` call. Uncomment
it (Linux, requires sudo) to actually drop traffic from blocked IPs instead
of just simulating the block in the dashboard/database.

## Project layout

```
cybershield/
├── data/
│   ├── generate_dataset.py     # synthetic NSL-KDD-style dataset generator
│   └── traffic_dataset.csv     # generated dataset (after running the script)
├── model/
│   ├── train_model.py          # trains RandomForest + IsolationForest
│   └── artifacts/              # saved model, encoders, metrics (after training)
├── app/
│   ├── app.py                  # Flask app: API + background traffic simulator
│   ├── templates/dashboard.html
│   └── static/{style.css, dashboard.js}
├── packet_capture/
│   └── scapy_sniffer.py        # optional: feed real live traffic
└── requirements.txt
```

## REST API

| Endpoint                  | Method | Description                                  |
|----------------------------|--------|----------------------------------------------|
| `/api/events?limit=60`     | GET    | Recent classified traffic events             |
| `/api/stats`                | GET    | Aggregate stats + timeline for charts        |
| `/api/blocked`              | GET    | Currently blocked source IPs                 |
| `/api/block`                 | POST   | `{ "ip": "...", "reason": "..." }`           |
| `/api/unblock`               | POST   | `{ "ip": "..." }`                             |
| `/api/auto-response`         | POST   | `{ "enabled": true/false }`                   |
| `/api/predict`               | POST   | Classify an arbitrary feature vector          |
| `/api/report/<event_id>`     | GET    | Generate a text incident report               |

## Model performance

On the bundled synthetic dataset, the RandomForest classifier reaches
~99.9% accuracy / macro F1 — this is expected since the synthetic classes
are cleanly separated by design. Real-world traffic is noisier; treat
`model/artifacts/metrics.json` (written after training) as a baseline to
compare against once you swap in a real dataset.
