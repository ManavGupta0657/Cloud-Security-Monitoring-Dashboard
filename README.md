# ☁️ Cloud Security & Monitoring Dashboard

> A real-time cloud security operations dashboard built as a **Summer Internship Project** under the **Cloud Computing Specialization**. It simulates a production-grade Security Operations Center (SOC) with live threat detection, multi-region resource health tracking, network anomaly visualization, and IAM policy compliance scanning.

<div align="center">

### 🔗 Quick Links

| 🖥️ Landing Page | 📊 Live Dashboard | 💻 Source Code |
|:---:|:---:|:---:|
| [**View Site**](https://ManavGupta0657.github.io/cloud-security-dashboard) | [**Open Dashboard →**](https://ManavGupta0657.github.io/cloud-security-dashboard/dashboard.html) | [**GitHub Repo**](https://github.com/ManavGupta0657/cloud-security-dashboard) |

</div>

> 📊 **Direct dashboard link:** https://ManavGupta0657.github.io/cloud-security-dashboard/dashboard.html

---

## 📸 Preview

| Security Events | Threat Breakdown | IAM Compliance |
|---|---|---|
| Stacked 24h bar chart | Donut by attack type | Policy pass/fail scores |

---

## 🚀 Features

- **Live Threat Counter** — Active threat count auto-refreshes every 4 seconds to simulate real-time SOC monitoring
- **Security Events Chart** — Stacked bar chart showing 24-hour event volume across Critical, High, Medium, and Low severities
- **Threat Category Breakdown** — Donut chart categorizing attack types: Unauthorized Access, DDoS, Malware, Data Exfiltration, and Other
- **Incident Log Table** — Filterable table of security events with severity badges and live investigation status (Open / Investigating / Resolved / Mitigated)
- **Network Traffic Anomaly Chart** — Line chart visualizing inbound traffic vs baseline, highlighting a 3.4× DDoS spike at 14:00
- **Multi-Region Resource Health** — Uptime bars for 5 global cloud regions (US East, EU West, AP South, US West, SA East) with incident flags
- **IAM Policy Compliance Scanner** — Simulated policy audit scores for MFA enforcement, least privilege, root key usage, and password policy — switchable by scan scope
- **Dark Mode Support** — Automatically adapts to system dark/light preference via CSS `prefers-color-scheme`
- **Fully Responsive** — Mobile-friendly layout using CSS Grid

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Charts | [Chart.js v4.4.1](https://www.chartjs.org/) |
| Icons | [Tabler Icons](https://tabler-icons.io/) |
| Hosting | GitHub Pages |
| Backend (conceptual) | Python, boto3, Flask, AWS CloudWatch / Security Hub |

> **Note:** This is a frontend simulation dashboard. In a real-world deployment, the data would be fed by a Python backend using `boto3` to pull logs from **AWS CloudWatch**, **AWS Security Hub**, **AWS GuardDuty**, and **IAM Access Analyzer**.

---

## 📁 Project Structure

```
cloud-security-dashboard/
│
├── index.html           # Landing page (hero + embedded dashboard preview)
├── dashboard.html       # 🔴 Live SOC dashboard — full interactive interface
├── backend.py           # Python Flask API (boto3 + AWS integration)
├── threat_engine.cpp    # C++ anomaly detection engine (Z-score)
└── README.md            # Project documentation

> **Direct dashboard URL:**
> ```
> https://ManavGupta0657.github.io/cloud-security-dashboard/dashboard.html
> ```
```

---

## ⚙️ How to Run Locally

No build tools or dependencies required — it's a pure HTML file.

```bash
# Clone the repository
git clone https://github.com/ManavGupta0657/cloud-security-dashboard.git

# Navigate into the folder
cd cloud-security-dashboard

# Open in browser
open index.html        # macOS
start index.html       # Windows
xdg-open index.html    # Linux
```

Or simply drag `index.html` into any modern browser.

---

## ☁️ Real-World Cloud Architecture (Conceptual)

This dashboard simulates the frontend layer of a cloud security pipeline. The full architecture would look like:

```
AWS CloudWatch Logs
AWS GuardDuty          ──▶  Python (boto3 / Flask API)  ──▶  This Dashboard
AWS Security Hub
AWS IAM Access Analyzer
```

**Python backend responsibilities:**
- Poll `boto3` for GuardDuty findings and CloudWatch metric alarms
- Aggregate IAM policy violations via Access Analyzer
- Expose a REST API (`/api/threats`, `/api/health`, `/api/compliance`)
- Feed live data to the frontend via polling or WebSockets

---

## 📊 Dashboard Panels Explained

### 1. Metrics Bar
| Metric | Description |
|---|---|
| Active Threats | Live count of open security findings |
| Monitored Resources | Total cloud assets under observation |
| Mean Time to Detect (MTTD) | Average detection latency in minutes |
| Compliance Score | Aggregate SOC2 + ISO27001 policy score |

### 2. Security Events (24h)
Stacked bar chart grouped by hour showing event distribution across four severity levels. Peaks indicate attack bursts or scanning activity.

### 3. Threat Category Breakdown
Donut chart of attack vectors based on simulated GuardDuty findings:
- **Unauthorized Access** (34%) — brute-force, credential stuffing
- **DDoS** (22%) — volumetric and application-layer attacks
- **Malware** (18%) — Lambda/EC2 compromise indicators
- **Data Exfiltration** (14%) — anomalous S3 download patterns
- **Other** (12%) — misconfiguration, policy drift

### 4. Incident Log
Real-time filterable event log with four status types:
- 🔴 **Open** — unacknowledged, needs triage
- 🟠 **Investigating** — SOC analyst assigned
- 🟢 **Resolved** — root cause identified, patched
- 🟢 **Mitigated** — impact contained, monitoring continues

### 5. Network Traffic Anomaly
Compares inbound traffic (GB/h) against a 3.0 GB/h baseline. The spike to 11.8 GB/h at 14:00 represents a simulated DDoS event.

### 6. Regional Resource Health
| Region | Resources | Uptime |
|---|---|---|
| US East (N. Virginia) | 84 | 99.7% |
| EU West (Ireland) | 67 | 98.1% |
| AP South (Mumbai) | 59 | 97.4% |
| US West (Oregon) | 38 | 100% |
| SA East (São Paulo) | 21 | 94.8% ⚠️ |

### 7. IAM Compliance Scanner
Audit results for four critical IAM policies, switchable by scope (All accounts / Production / Dev+Staging):
- MFA enforcement
- Least privilege principle
- No root access key usage
- Password complexity policy

---

## 🔒 Security Concepts Covered

- **Threat Intelligence** — categorization and prioritization of security events
- **SIEM principles** — aggregating logs from multiple cloud services
- **Zero Trust** — IAM least-privilege and MFA enforcement scanning
- **Incident Response lifecycle** — Open → Investigating → Resolved/Mitigated
- **Cloud Compliance** — SOC2 and ISO27001 policy mapping
- **DDoS detection** — baseline deviation analysis on network traffic
- **Multi-region resilience** — uptime and incident tracking across geographies

---

## 📚 Learning Outcomes

Through this project, the following cloud security skills were applied and demonstrated:

1. Designing a Security Operations Center (SOC) dashboard UI
2. Understanding AWS security services: GuardDuty, CloudWatch, Security Hub, IAM Access Analyzer
3. Visualizing time-series security data using Chart.js
4. Mapping real-world IAM policies to compliance frameworks (SOC2, ISO27001)
5. Simulating multi-region cloud infrastructure monitoring
6. Building responsive, production-grade web interfaces without a framework

---

## 🤝 Acknowledgements

- **Internship Organization** — Cloud Computing Specialization Program
- **Chart.js** — open-source charting library
- **Tabler Icons** — open-source icon set
- **AWS Documentation** — reference for GuardDuty, CloudWatch, IAM concepts

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).

---

<p align="center">Made with ❤️ by <a href="https://github.com/ManavGupta0657">Manav Gupta</a> · Summer Internship 2025 · Cloud Computing Specialization</p>
