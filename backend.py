"""
Cloud Security & Monitoring Dashboard — Python Backend
=======================================================
Summer Internship Project | Cloud Computing Specialization
Author: Manav Gupta | GitHub: ManavGupta0657

Description:
    Flask REST API backend that aggregates security findings from AWS services
    (GuardDuty, CloudWatch, Security Hub, IAM Access Analyzer) using boto3.
    Exposes endpoints consumed by the frontend dashboard.

Requirements:
    pip install flask boto3 python-dotenv flask-cors

Usage:
    python backend.py
    API runs at http://localhost:5000
"""

import os
import json
import random
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv

# ── Optional: boto3 for real AWS integration ──────────────────────────────────
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    AWS_ENABLED = True
except ImportError:
    AWS_ENABLED = False
    print("[WARN] boto3 not installed. Running in simulation mode.")

# ─────────────────────────────────────────────────────────────────────────────
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# ── AWS Configuration ─────────────────────────────────────────────────────────
AWS_REGION       = os.getenv("AWS_REGION", "us-east-1")
AWS_ACCESS_KEY   = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_KEY   = os.getenv("AWS_SECRET_ACCESS_KEY", "")
DETECTOR_ID      = os.getenv("GUARDDUTY_DETECTOR_ID", "")

REGIONS = ["us-east-1", "eu-west-1", "ap-south-1", "us-west-2", "sa-east-1"]
REGION_LABELS = {
    "us-east-1":  "US East (N. Virginia)",
    "eu-west-1":  "EU West (Ireland)",
    "ap-south-1": "AP South (Mumbai)",
    "us-west-2":  "US West (Oregon)",
    "sa-east-1":  "SA East (São Paulo)",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_boto3_client(service: str, region: str = AWS_REGION):
    """Return a boto3 client, or None in simulation mode."""
    if not AWS_ENABLED or not AWS_ACCESS_KEY:
        return None
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
    )


def simulate_threats() -> list[dict]:
    """Generate realistic mock threat findings when AWS is unavailable."""
    events = [
        {"type": "UnauthorizedAccess:EC2/SSHBruteForce",   "severity": "Critical", "region": "us-east-1",  "resource": "i-0a1b2c3d4e5f"},
        {"type": "Recon:IAMUser/MaliciousIPCaller",         "severity": "High",     "region": "eu-west-1",  "resource": "arn:aws:iam::123456789:user/admin"},
        {"type": "Trojan:EC2/BlackholeTraffic",             "severity": "Critical", "region": "ap-south-1", "resource": "i-0f9e8d7c6b5a"},
        {"type": "Policy:S3/BucketPublicAccessGranted",     "severity": "High",     "region": "us-east-1",  "resource": "arn:aws:s3:::sensitive-data-bucket"},
        {"type": "PortProbeUnprotectedPort",                "severity": "Medium",   "region": "us-west-2",  "resource": "i-0b1c2d3e4f5a"},
        {"type": "UnauthorizedAccess:IAMUser/ConsoleLogin", "severity": "High",     "region": "sa-east-1",  "resource": "arn:aws:iam::123456789:user/root"},
        {"type": "CryptoCurrency:EC2/BitcoinTool",          "severity": "Medium",   "region": "eu-west-1",  "resource": "i-0c2d3e4f5a6b"},
        {"type": "Behavior:EC2/NetworkPortUnusual",         "severity": "Low",      "region": "us-east-1",  "resource": "i-0d3e4f5a6b7c"},
    ]
    selected = random.sample(events, k=random.randint(4, 8))
    for e in selected:
        e["id"]        = f"finding-{random.randint(100000, 999999)}"
        e["timestamp"] = (datetime.utcnow() - timedelta(minutes=random.randint(1, 120))).isoformat() + "Z"
        e["status"]    = random.choice(["Open", "Investigating", "Mitigated"])
    return selected


def fetch_guardduty_findings(region: str = AWS_REGION) -> list[dict]:
    """Pull real GuardDuty findings, falling back to simulation."""
    client = get_boto3_client("guardduty", region)
    if not client or not DETECTOR_ID:
        logger.info("GuardDuty: simulation mode")
        return simulate_threats()

    try:
        response  = client.list_findings(DetectorId=DETECTOR_ID, MaxResults=50)
        ids       = response.get("FindingIds", [])
        if not ids:
            return []
        details   = client.get_findings(DetectorId=DETECTOR_ID, FindingIds=ids)
        findings  = []
        for f in details.get("Findings", []):
            findings.append({
                "id":        f["Id"],
                "type":      f["Type"],
                "severity":  _map_severity(f["Severity"]),
                "region":    f["Region"],
                "resource":  f.get("Resource", {}).get("ResourceType", "Unknown"),
                "timestamp": f["CreatedAt"],
                "status":    "Open",
            })
        return findings
    except (BotoCoreError, ClientError) as exc:
        logger.error("GuardDuty error: %s", exc)
        return simulate_threats()


def _map_severity(score: float) -> str:
    if score >= 7.0: return "Critical"
    if score >= 4.0: return "High"
    if score >= 1.0: return "Medium"
    return "Low"


def fetch_cloudwatch_metrics(region: str = AWS_REGION) -> dict:
    """Return CPU, network, and error metrics from CloudWatch (or simulated)."""
    client = get_boto3_client("cloudwatch", region)
    if not client:
        return {
            "cpu_utilization":    round(random.uniform(20, 85), 1),
            "network_in_gbh":     round(random.uniform(1.5, 12.0), 2),
            "error_rate_pct":     round(random.uniform(0.1, 4.5), 2),
            "lambda_errors":      random.randint(0, 30),
        }

    try:
        end   = datetime.utcnow()
        start = end - timedelta(hours=1)
        def get_stat(namespace, metric, dimensions, stat="Average"):
            resp = client.get_metric_statistics(
                Namespace=namespace, MetricName=metric,
                Dimensions=dimensions, StartTime=start, EndTime=end,
                Period=3600, Statistics=[stat],
            )
            pts = resp.get("Datapoints", [])
            return round(pts[0][stat], 2) if pts else 0.0

        return {
            "cpu_utilization":  get_stat("AWS/EC2", "CPUUtilization",
                                         [{"Name": "InstanceId", "Value": "ALL"}]),
            "network_in_gbh":   get_stat("AWS/EC2", "NetworkIn",
                                         [{"Name": "InstanceId", "Value": "ALL"}]),
            "error_rate_pct":   0.0,
            "lambda_errors":    int(get_stat("AWS/Lambda", "Errors",
                                             [{"Name": "FunctionName", "Value": "ALL"}], "Sum")),
        }
    except (BotoCoreError, ClientError) as exc:
        logger.error("CloudWatch error: %s", exc)
        return {"cpu_utilization": 0, "network_in_gbh": 0, "error_rate_pct": 0, "lambda_errors": 0}


def fetch_iam_compliance() -> list[dict]:
    """Audit IAM policies via Access Analyzer (or simulated)."""
    client = get_boto3_client("accessanalyzer")
    if not client:
        return [
            {"rule": "MFA enforcement",   "pass": 241, "fail": 7,  "pct": 97},
            {"rule": "Least privilege",   "pass": 188, "fail": 60, "pct": 76},
            {"rule": "No root key usage", "pass": 248, "fail": 0,  "pct": 100},
            {"rule": "Password policy",   "pass": 230, "fail": 18, "pct": 93},
        ]

    try:
        analyzers = client.list_analyzers().get("analyzers", [])
        if not analyzers:
            raise ValueError("No analyzers configured")
        findings = client.list_findings(analyzerArn=analyzers[0]["arn"]).get("findings", [])
        total    = max(len(findings), 1)
        passed   = sum(1 for f in findings if f["status"] == "RESOLVED")
        failed   = total - passed
        pct      = round((passed / total) * 100)
        return [{"rule": "Access Analyzer", "pass": passed, "fail": failed, "pct": pct}]
    except Exception as exc:
        logger.warning("IAM Access Analyzer: %s — using simulation", exc)
        return [
            {"rule": "MFA enforcement",   "pass": 241, "fail": 7,  "pct": 97},
            {"rule": "Least privilege",   "pass": 188, "fail": 60, "pct": 76},
            {"rule": "No root key usage", "pass": 248, "fail": 0,  "pct": 100},
            {"rule": "Password policy",   "pass": 230, "fail": 18, "pct": 93},
        ]


def get_region_health() -> list[dict]:
    """Return simulated uptime data per region."""
    base = {
        "us-east-1":  {"uptime": 99.7, "resources": 84, "incidents": 0},
        "eu-west-1":  {"uptime": 98.1, "resources": 67, "incidents": 1},
        "ap-south-1": {"uptime": 97.4, "resources": 59, "incidents": 1},
        "us-west-2":  {"uptime": 100.0,"resources": 38, "incidents": 0},
        "sa-east-1":  {"uptime": 94.8, "resources": 21, "incidents": 2},
    }
    return [
        {
            "region":    r,
            "label":     REGION_LABELS[r],
            "uptime":    base[r]["uptime"],
            "resources": base[r]["resources"],
            "incidents": base[r]["incidents"],
        }
        for r in REGIONS
    ]

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat() + "Z"})


@app.route("/api/threats")
def threats():
    region   = request.args.get("region", AWS_REGION)
    findings = fetch_guardduty_findings(region)
    counts   = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return jsonify({
        "total":    len(findings),
        "counts":   counts,
        "findings": findings,
    })


@app.route("/api/metrics")
def metrics():
    region = request.args.get("region", AWS_REGION)
    data   = fetch_cloudwatch_metrics(region)
    data["mttd_minutes"] = round(random.uniform(3.0, 6.5), 1)
    data["compliance_score"] = 94
    return jsonify(data)


@app.route("/api/compliance/iam")
def iam_compliance():
    return jsonify({"policies": fetch_iam_compliance()})


@app.route("/api/regions")
def regions():
    return jsonify({"regions": get_region_health()})


@app.route("/api/events/timeline")
def event_timeline():
    """24-hour event counts bucketed by hour and severity."""
    hours   = [f"{h}:00" for h in range(24)]
    data    = {
        "labels":   hours,
        "critical": [random.randint(0, 5) for _ in range(24)],
        "high":     [random.randint(0, 7) for _ in range(24)],
        "medium":   [random.randint(1, 9) for _ in range(24)],
        "low":      [random.randint(2,10) for _ in range(24)],
    }
    return jsonify(data)


@app.route("/api/network/traffic")
def network_traffic():
    """Simulated inbound traffic with injected DDoS spike."""
    baseline = 3.0
    traffic  = [round(baseline + random.uniform(-0.5, 0.8), 2) for _ in range(24)]
    traffic[13] = round(baseline * random.uniform(3.0, 4.2), 2)   # DDoS spike
    return jsonify({
        "labels":   [f"{h}:00" for h in range(24)],
        "traffic":  traffic,
        "baseline": baseline,
        "spike_hour": 13,
    })

# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("Starting Cloud Security API on http://localhost:5000")
    logger.info("AWS mode: %s", "ENABLED" if AWS_ENABLED and AWS_ACCESS_KEY else "SIMULATION")
    app.run(debug=True, host="0.0.0.0", port=5000)
