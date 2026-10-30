# NetMon: Smart Network Security Monitoring System

A web application that reads network flow records, runs rule-based, statistical and
Isolation Forest detectors over them, and shows prioritised security alerts on a
dashboard. Reports are generated as PDF and CSV and stored in the cloud.

Built with Python, Pandas, scikit-learn, Flask and Plotly. Runs locally with SQLite,
or on Vercel (Hobby plan, free) with Neon Postgres and a private Vercel Blob store.

## Run it locally

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python app.py                                           # http://127.0.0.1:5000
```

Sign in with the password in `ADMIN_PASSWORD` (default `netmon-admin`; change it).
On the "Analyse traffic" page, pick one of the three CIC-IDS2017 samples, or upload
your own flow CSV.

## What it detects

| Rule | Detects | How |
|---|---|---|
| R1 | Port scan | 30+ distinct service ports from one source in a minute (client-initiated flows only) |
| R2 | Brute force on FTP, SSH, Telnet, RDP | 20+ connections to one login port on one host in a minute |
| R3 | DoS / DDoS traffic spike | Flows per minute to a host more than 5 standard deviations above its benign baseline and above its busiest benign minute |
| R4 | Blacklisted IP | Source or destination listed in `data/blacklist.csv` |
| R5 | Unusual flow size | \|z\| > 3 on log(1 + bytes) against the benign baseline |
| R6 | Unusual flow size | Above Q3 + 3 × IQR on log(1 + bytes) |
| ML | Anomalous flows | Isolation Forest trained on benign traffic only |

Thresholds are in `config.yaml` and can be changed on the Settings page. The
baseline (`data/baseline.json`) and model (`data/iforest.pkl`) were learned from
the benign Monday of CIC-IDS2017.

## Reproduce the evaluation

1. Download `GeneratedLabelledFlows.zip` from the CIC-IDS2017 page
   (https://www.unb.ca/cic/datasets/ids-2017.html). Use this version, not
   `MachineLearningCSV`, because it keeps the IP addresses and timestamps.
2. Extract it into a folder, for example `data_raw/`.
3. Run:

```bash
python scripts/build_baseline.py "data_raw/Monday-WorkingHours.pcap_ISCX.csv"
python scripts/evaluate.py data_raw
```

Results go to `results/` (metrics.json, CSV tables, figures). Main results from our
run on 2,180,651 flows:

| Detector | Scored against | Recall | Precision | False-positive rate |
|---|---|---|---|---|
| R1 Port scan | PortScan | 0.998 | 1.000 | 0.0000 |
| R2 Brute force | FTP/SSH-Patator | 1.000 | 1.000 | 0.0000 |
| R3 Traffic spike | DoS + DDoS | 0.999 | 0.903 | 0.0756 |
| Rules R1–R4 combined | All attacks | 0.998 | 0.916 | 0.0461 |
| Isolation Forest | All attacks | 0.095 | 0.442 | 0.0607 |

R5 and R6 found no attacks in this dataset: the attacks consist of many small flows,
not unusually large ones.

## Capture your own traffic

```bash
pip install scapy
sudo python scripts/capture.py --iface eth0 --seconds 300 --out capture.csv
```

Upload `capture.csv` on the "Analyse traffic" page. To demonstrate detection, run
`nmap -sS <your-own-VM>` during the capture. Only capture on networks you own or have
written permission to monitor.

## Deploy to the cloud (Vercel + Neon + Vercel Blob)

1. Push this folder to a GitHub repository.
2. On vercel.com choose Add New > Project, import the repository and press Deploy.
   Vercel detects the Flask `app` in `app.py`; `vercel.json` sets the function limits.
3. In the project, open Storage:
   - Create > Blob, set access to **Private**, and connect it to all environments.
     This adds `BLOB_STORE_ID` (and the per-request OIDC token) to the project.
   - Create > Neon (Marketplace, free plan) and connect it. This adds `DATABASE_URL`.
4. Under Settings > Environment Variables add `ADMIN_PASSWORD` and a long random
   `SECRET_KEY`.
5. Redeploy (Deployments > ... > Redeploy). Open `https://<project>.vercel.app/healthz`:
   it should report `"storage": "vercel-blob"` and `"database": "Neon Postgres"`. The
   sidebar footer shows the same.

Limits on Vercel: a request can carry at most 4.5 MB, so uploads are capped at 4.4 MB.
Gzip larger captures first (`gzip capture.csv`), which shrinks them about 5-8 times; the
built-in CIC-IDS2017 samples are on the server and are not affected. Each analysis runs
in a function with up to 2 GB of memory and a 60-second limit; the 300,000-flow cap
(about one busy hour) stays. The first request after a quiet period starts a cold
function and takes a few seconds longer, so open the site before a demo.

## Project layout

```
app.py                 Flask routes (Vercel entry point)
vercel.json            Vercel function settings
public/static/         CSS, JS, Plotly (served from Vercel's CDN)
config.yaml            detection thresholds
netmon/preprocess.py   loading, cleaning, CIC timestamp fix, derived fields
netmon/features.py     window aggregates, benign baseline
netmon/rules.py        R1-R4
netmon/stats_detect.py R5-R6
netmon/ml_detect.py    Isolation Forest
netmon/alerts.py       alert merging, severity, firewall suggestions
netmon/pipeline.py     runs all detectors
netmon/summary.py      dashboard chart data
netmon/reports.py      PDF and CSV reports
netmon/db.py           SQLAlchemy models
netmon/storage.py      Vercel Blob (private) or local folder
scripts/               baseline builder, evaluation, live capture
data/                  baseline, model, blacklist, demo samples
tests/                 unit tests (python -m pytest tests)
```
