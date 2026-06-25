# ☁️ Cloud Security & Monitoring Dashboard

> A real-time cloud security operations dashboard built as a **Summer Internship Project** under the **Cloud Computing Specialization**. Features live threat detection, multi-region resource health tracking, network anomaly visualization, IAM policy compliance scanning, and a **C++ Z-score anomaly detection engine** wired to a Python Flask backend.

<div align="center">

### 🔗 Quick Links

| 🖥️ Landing Page | 📊 Live Dashboard | 💻 Source Code |
|:---:|:---:|:---:|
| [**View Site**](https://manavgupta0657.github.io/Cloud-Security-Monitoring-Dashboard) | [**Open Dashboard →**](https://manavgupta0657.github.io/Cloud-Security-Monitoring-Dashboard/dashboard.html) | [**GitHub Repo**](https://github.com/ManavGupta0657/Cloud-Security-Monitoring-Dashboard) |

</div>

---

## 📸 Preview

| Security Events | Threat Breakdown | IAM Compliance | C++ Engine |
|---|---|---|---|
| Stacked 24h bar chart | Donut by attack type | Policy pass/fail scores | Z-score anomaly output |

---

## 🚀 Features

- **Live Threat Counter** — Active threat count auto-refreshes every second
- **Security Events Chart** — Stacked bar chart showing 24-hour event volume across Critical, High, Medium, and Low severities
- **Threat Category Breakdown** — Donut chart categorizing attack types: Unauthorized Access, DDoS, Malware, Data Exfiltration, and Other
- **Incident Log Table** — Filterable table with severity badges and live status (Open / Investigating / Resolved / Mitigated)
- **Network Traffic Anomaly** — Scrolling line chart visualizing inbound traffic vs baseline
- **Multi-Region Resource Health** — Uptime bars for 5 AWS regions with incident flags
- **IAM Policy Compliance Scanner** — Policy audit scores for MFA enforcement, least privilege, root key usage, and password policy
- **C++ Engine Page** — Dedicated view showing Z-score anomaly findings from `threat_engine.cpp`, connected to Flask via `/api/engine`
- **Flask Backend** — Real AWS boto3 integration (GuardDuty, CloudWatch, IAM Access Analyzer) with graceful simulation fallback
- **Live/Demo Mode Toggle** — Mode badge in header shows `live AWS`, `flask sim`, or `sim` depending on what's available
- **Dark Theme** — Neon accent colors, responsive CSS Grid layout

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Charts | [Chart.js v4.4.1](https://www.chartjs.org/) |
| Icons | [Tabler Icons](https://tabler-icons.io/) |
| Hosting | GitHub Pages |
| Backend | Python 3.10+, Flask, Flask-CORS, python-dotenv |
| AWS SDK | boto3 (GuardDuty, CloudWatch, IAM Access Analyzer) |
| Detection Engine | C++17 (sliding-window Z-score, compiled binary) |

---

## 📁 Project Structure

```
cloud-security-dashboard/
│
├── index.html            # Landing page
├── dashboard.html        # 🔴 Main SOC dashboard — 9-page interface
├── backend.py            # Flask REST API with boto3 + AWS integration
├── threat_engine.cpp     # C++ anomaly detection engine (Z-score)
└── README.md             # This file
```

---

## ⚙️ How to Run Locally

### Frontend only (no dependencies)

```bash
git clone https://github.com/ManavGupta0657/Cloud-Security-Monitoring-Dashboard.git
cd Cloud-Security-Monitoring-Dashboard
open dashboard.html   # or just drag into your browser
```

### With Flask backend (enables /api/* endpoints)

```bash
# Install Python deps
pip install flask boto3 python-dotenv flask-cors

# Optional: copy .env.example and fill in AWS credentials
cp .env.example .env

# Start the API
python backend.py
# → runs at http://localhost:5000
```

The dashboard auto-detects the backend. The header badge shows `flask sim` (running, no AWS creds) or `live AWS` (full GuardDuty integration).

### C++ Engine (wires real detection output into the dashboard)

```bash
# Compile
g++ -std=c++17 -O2 -o threat_engine threat_engine.cpp

# Run in simulation mode
./threat_engine --simulate --threshold 3.0 --window 60 --output threats_output.json

# The Flask backend reads this file at /api/engine
# The dashboard's "C++ Engine" page displays the findings live
```

---

## ☁️ AWS Architecture

```
AWS GuardDuty          ─┐
AWS CloudWatch          ├──▶  backend.py (Flask + boto3)  ──▶  dashboard.html
AWS IAM Access Analyzer─┘          │
                                   └──▶ reads threats_output.json
                                            ▲
                                   threat_engine.cpp (C++)
```

**Backend endpoints:**

| Endpoint | Description |
|---|---|
| `GET /api/health` | Liveness check + mode (live/simulation) |
| `GET /api/threats` | GuardDuty findings (real or simulated) |
| `GET /api/metrics` | CloudWatch CPU, network, errors |
| `GET /api/compliance/iam` | IAM Access Analyzer scores |
| `GET /api/regions` | Per-region uptime data |
| `GET /api/events/timeline` | 24h event counts by severity |
| `GET /api/network/traffic` | Inbound traffic with DDoS spike |
| `GET /api/engine` | C++ engine output (reads threats_output.json) |

---

## 📊 Dashboard Pages

| Page | What it shows |
|---|---|
| Dashboard | Overview — stats, event chart, attack type donut, incident feed, network traffic |
| Incidents | Full incident table with Open / Investigating / Mitigated / Resolved breakdown |
| Network | Live scrolling traffic, blocked IPs, protocol distribution |
| IAM Compliance | Policy audit scores, violation detail, 30-day compliance trend |
| Resources | EC2 / S3 / Lambda / RDS health and risk status |
| Regions | Per-region uptime bars and comparison chart |
| Audit Logs | CloudTrail IAM events feed |
| Analytics | 7-day threat trends, severity split, resolve rate |
| **C++ Engine** | **Z-score findings from threat_engine.cpp, algorithm explanation, compile commands** |

---

## 🔬 C++ Engine — Algorithm Detail

`threat_engine.cpp` implements a **sliding-window Z-score anomaly detector**:

```
Z = |value − μ| / σ
```

- **Window size:** 60 samples (last 60 log entries)
- **Threshold:** Z > 3.0 → anomaly flagged
- **Multi-signal classification:** root access, brute-force login count, port scan count, and Z-score all independently contribute to severity (Critical / High / Medium / Low)
- **Output:** structured JSON (`threats_output.json`) consumed by Flask `/api/engine` and rendered in the C++ Engine dashboard page

---

## 🔒 Security Note

Never commit AWS credentials. Use environment variables or a `.env` file (gitignored):

```env
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_key_here
AWS_SECRET_ACCESS_KEY=your_secret_here
GUARDDUTY_DETECTOR_ID=your_detector_id
```

---

## 📝 What I Learned

- Integrating boto3 with real AWS security services (GuardDuty, CloudWatch, IAM Access Analyzer)
- Designing graceful fallback from live → simulation mode without breaking the UI
- Implementing a sliding-window Z-score anomaly detector in C++ and piping its output to a Python API
- Building a multi-page SPA with vanilla JS (no framework overhead)
- GitHub Pages deployment and managing static vs dynamic data

---

## 🔮 Future Work

- WebSocket-based real-time push instead of polling
- Add SNS/SQS alert forwarding when engine detects Critical threats  
- Docker Compose setup (Flask + C++ engine as sidecar)
- Unit tests for the Z-score detector edge cases (flat traffic, burst normalization)

---

**Manav Gupta · Summer Internship 2026 · Cloud Computing Specialization**
