"""
Cloud Security & Monitoring Dashboard — Python Backend
=======================================================
Summer Internship Project | Cloud Computing Specialization
Author: Manav Gupta | GitHub: ManavGupta0657

Description:
    Flask REST API that pulls real security findings from AWS (GuardDuty,
    CloudWatch, IAM Access Analyzer) via boto3, falls back gracefully to
    simulation mode when credentials aren't configured, and also reads
    JSON output from the C++ threat detection engine when available.

Requirements:
    pip install flask boto3 python-dotenv flask-cors

Run:
    python backend.py
    API at http://localhost:5000

    # optional: run C++ engine first so /api/engine has real data
    ./threat_engine --simulate --output threats_output.json
"""

import os
import json
import random
import logging
from datetime import datetime, timedelta

from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv

# boto3 is optional — fall back to simulation if not installed
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    AWS_ENABLED = True
except ImportError:
    AWS_ENABLED = False
    print("[WARN] boto3 not installed — running in full simulation mode")

# --------------------------------------------------------------------------- #
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)   # allow the GitHub Pages frontend to hit this API

# --------------------------------------------------------------------------- #
# AWS config — pulled from .env file (never hardcode keys!)
# --------------------------------------------------------------------------- #
AWS_REGION     = os.getenv("AWS_REGION", "us-east-1")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
DETECTOR_ID    = os.getenv("GUARDDUTY_DETECTOR_ID", "")

# path where the C++ engine writes its JSON report
ENGINE_OUTPUT  = os.getenv("ENGINE_OUTPUT_PATH", "threats_output.json")

REGIONS = ["us-east-1", "eu-west-1", "ap-south-1", "us-west-2", "sa-east-1"]
REGION_LABELS = {
    "us-east-1":  "US East (N. Virginia)",
    "eu-west-1":  "EU West (Ireland)",
    "ap-south-1": "AP South (Mumbai)",
    "us-west-2":  "US West (Oregon)",
    "sa-east-1":  "SA East (São Paulo)",
}

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def live_mode() -> bool:
    """True only when we actually have AWS credentials configured."""
    return AWS_ENABLED and bool(AWS_ACCESS_KEY) and bool(AWS_SECRET_KEY)


def boto3_client(service: str, region: str = AWS_REGION):
    """Return a boto3 client, or None in simulation mode."""
    if not live_mode():
        return None
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
    )


def _map_severity(score: float) -> str:
    """Convert GuardDuty numeric severity to string label."""
    if score >= 7.0: return "Critical"
    if score >= 4.0: return "High"
    if score >= 1.0: return "Medium"
    return "Low"


# --------------------------------------------------------------------------- #
# Data fetchers
# --------------------------------------------------------------------------- #

def _simulate_threats() -> list[dict]:
    """Realistic mock findings used when AWS creds aren't available."""
    pool = [
        {"type": "UnauthorizedAccess:EC2/SSHBruteForce",   "severity": "Critical", "region": "us-east-1",  "resource": "i-0a1b2c3d4e5f"},
        {"type": "Recon:IAMUser/MaliciousIPCaller",         "severity": "High",     "region": "eu-west-1",  "resource": "arn:aws:iam::123456789:user/admin"},
        {"type": "Trojan:EC2/BlackholeTraffic",             "severity": "Critical", "region": "ap-south-1", "resource": "i-0f9e8d7c6b5a"},
        {"type": "Policy:S3/BucketPublicAccessGranted",     "severity": "High",     "region": "us-east-1",  "resource": "arn:aws:s3:::sensitive-data-bucket"},
        {"type": "PortProbeUnprotectedPort",                "severity": "Medium",   "region": "us-west-2",  "resource": "i-0b1c2d3e4f5a"},
        {"type": "UnauthorizedAccess:IAMUser/ConsoleLogin", "severity": "High",     "region": "sa-east-1",  "resource": "arn:aws:iam::123456789:user/root"},
        {"type": "CryptoCurrency:EC2/BitcoinTool",          "severity": "Medium",   "region": "eu-west-1",  "resource": "i-0c2d3e4f5a6b"},
        {"type": "Behavior:EC2/NetworkPortUnusual",         "severity": "Low",      "region": "us-east-1",  "resource": "i-0d3e4f5a6b7c"},
    ]
    selected = random.sample(pool, k=random.randint(4, 8))
    for i, e in enumerate(selected):
        e["id"]        = f"sim-finding-{random.randint(100000, 999999)}"
        e["timestamp"] = (datetime.utcnow() - timedelta(minutes=random.randint(1, 120))).isoformat() + "Z"
        e["status"]    = random.choice(["Open", "Investigating", "Mitigated"])
        e["source"]    = "simulation"
    return selected


def fetch_guardduty_findings(region: str = AWS_REGION) -> tuple[list[dict], str]:
    """
    Returns (findings, data_source) where data_source is 'live' or 'simulation'.
    Falls back gracefully if GuardDuty isn't configured or credentials are missing.
    """
    client = boto3_client("guardduty", region)
    if not client or not DETECTOR_ID:
        logger.info("GuardDuty: no credentials/detector → simulation mode")
        return _simulate_threats(), "simulation"

    try:
        ids = client.list_findings(DetectorId=DETECTOR_ID, MaxResults=50).get("FindingIds", [])
        if not ids:
            return [], "live"
        details  = client.get_findings(DetectorId=DETECTOR_ID, FindingIds=ids)
        findings = []
        for f in details.get("Findings", []):
            findings.append({
                "id":        f["Id"],
                "type":      f["Type"],
                "severity":  _map_severity(f["Severity"]),
                "region":    f["Region"],
                "resource":  f.get("Resource", {}).get("ResourceType", "Unknown"),
                "timestamp": f["CreatedAt"],
                "status":    "Open",
                "source":    "guardduty",
            })
        return findings, "live"
    except (BotoCoreError, ClientError) as exc:
        logger.error("GuardDuty error: %s — falling back to simulation", exc)
        return _simulate_threats(), "simulation"


def fetch_cloudwatch_metrics(region: str = AWS_REGION) -> tuple[dict, str]:
    client = boto3_client("cloudwatch", region)
    if not client:
        return {
            "cpu_utilization":  round(random.uniform(20, 85), 1),
            "network_in_gbh":   round(random.uniform(1.5, 12.0), 2),
            "error_rate_pct":   round(random.uniform(0.1, 4.5), 2),
            "lambda_errors":    random.randint(0, 30),
            "mttd_minutes":     round(random.uniform(3.0, 6.5), 1),
            "compliance_score": 94,
        }, "simulation"

    try:
        end, start = datetime.utcnow(), datetime.utcnow() - timedelta(hours=1)
        def stat(ns, metric, dims, s="Average"):
            pts = client.get_metric_statistics(
                Namespace=ns, MetricName=metric,
                Dimensions=dims, StartTime=start, EndTime=end,
                Period=3600, Statistics=[s],
            ).get("Datapoints", [])
            return round(pts[0][s], 2) if pts else 0.0

        return {
            "cpu_utilization":  stat("AWS/EC2", "CPUUtilization", []),
            "network_in_gbh":   stat("AWS/EC2", "NetworkIn", []),
            "error_rate_pct":   0.0,
            "lambda_errors":    int(stat("AWS/Lambda", "Errors", [], "Sum")),
            "mttd_minutes":     round(random.uniform(3.0, 6.5), 1),
            "compliance_score": 94,
        }, "live"
    except (BotoCoreError, ClientError) as exc:
        logger.error("CloudWatch error: %s", exc)
        return {"cpu_utilization": 0, "network_in_gbh": 0,
                "error_rate_pct": 0, "lambda_errors": 0,
                "mttd_minutes": 4.2, "compliance_score": 94}, "error"


def fetch_iam_compliance() -> tuple[list[dict], str]:
    client = boto3_client("accessanalyzer")
    if not client:
        return [
            {"rule": "MFA enforcement",   "pass": 241, "fail": 7,  "pct": 97},
            {"rule": "Least privilege",   "pass": 188, "fail": 60, "pct": 76},
            {"rule": "No root key usage", "pass": 248, "fail": 0,  "pct": 100},
            {"rule": "Password policy",   "pass": 230, "fail": 18, "pct": 93},
        ], "simulation"

    try:
        analyzers = client.list_analyzers().get("analyzers", [])
        if not analyzers:
            raise ValueError("No IAM Access Analyzers configured in this account")
        findings = client.list_findings(analyzerArn=analyzers[0]["arn"]).get("findings", [])
        total    = max(len(findings), 1)
        passed   = sum(1 for f in findings if f["status"] == "RESOLVED")
        failed   = total - passed
        return [{"rule": "Access Analyzer", "pass": passed, "fail": failed,
                 "pct": round(passed / total * 100)}], "live"
    except Exception as exc:
        logger.warning("IAM Access Analyzer fallback: %s", exc)
        return [
            {"rule": "MFA enforcement",   "pass": 241, "fail": 7,  "pct": 97},
            {"rule": "Least privilege",   "pass": 188, "fail": 60, "pct": 76},
            {"rule": "No root key usage", "pass": 248, "fail": 0,  "pct": 100},
            {"rule": "Password policy",   "pass": 230, "fail": 18, "pct": 93},
        ], "simulation"


def read_engine_output() -> dict | None:
    """
    Try to read the JSON report produced by threat_engine.cpp.
    Returns None if the file doesn't exist yet (engine hasn't been run).
    """
    if not os.path.exists(ENGINE_OUTPUT):
        return None
    try:
        with open(ENGINE_OUTPUT, "r") as f:
            data = json.load(f)
        # tag each finding with its source
        for finding in data.get("findings", []):
            finding["source"] = "cpp_engine"
        data["engine_file"] = ENGINE_OUTPUT
        data["read_at"]     = datetime.utcnow().isoformat() + "Z"
        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Could not read engine output: %s", exc)
        return None


def region_health() -> list[dict]:
    base = {
        "us-east-1":  {"uptime": 99.7, "resources": 84, "incidents": 0},
        "eu-west-1":  {"uptime": 98.1, "resources": 67, "incidents": 1},
        "ap-south-1": {"uptime": 97.4, "resources": 59, "incidents": 1},
        "us-west-2":  {"uptime": 100.0,"resources": 38, "incidents": 0},
        "sa-east-1":  {"uptime": 94.8, "resources": 21, "incidents": 2},
    }
    return [
        {"region": r, "label": REGION_LABELS[r], **base[r]}
        for r in REGIONS
    ]


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

@app.route("/api/health")
def health():
    """Simple liveness check. Also reports whether AWS creds are configured."""
    return jsonify({
        "status":     "ok",
        "timestamp":  datetime.utcnow().isoformat() + "Z",
        "mode":       "live" if live_mode() else "simulation",
        "aws_region": AWS_REGION,
        "engine_output_exists": os.path.exists(ENGINE_OUTPUT),
    })


@app.route("/api/threats")
def threats():
    """GuardDuty findings (real or simulated)."""
    region = request.args.get("region", AWS_REGION)
    findings, source = fetch_guardduty_findings(region)
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return jsonify({
        "total":       len(findings),
        "counts":      counts,
        "findings":    findings,
        "data_source": source,
    })


@app.route("/api/metrics")
def metrics():
    """CloudWatch metrics (real or simulated)."""
    region = request.args.get("region", AWS_REGION)
    data, source = fetch_cloudwatch_metrics(region)
    data["data_source"] = source
    return jsonify(data)


@app.route("/api/compliance/iam")
def iam():
    """IAM Access Analyzer compliance scores."""
    policies, source = fetch_iam_compliance()
    return jsonify({"policies": policies, "data_source": source})


@app.route("/api/regions")
def regions():
    """Per-region uptime and resource counts."""
    return jsonify({"regions": region_health()})


@app.route("/api/events/timeline")
def event_timeline():
    """24h event counts by severity bucket."""
    hours = [f"{h}:00" for h in range(24)]
    return jsonify({
        "labels":   hours,
        "critical": [random.randint(0, 5) for _ in range(24)],
        "high":     [random.randint(0, 7) for _ in range(24)],
        "medium":   [random.randint(1, 9) for _ in range(24)],
        "low":      [random.randint(2, 10) for _ in range(24)],
    })


@app.route("/api/network/traffic")
def network_traffic():
    """Simulated inbound traffic with injected DDoS spike at hour 13."""
    baseline = 3.0
    traffic  = [round(baseline + random.uniform(-0.5, 0.8), 2) for _ in range(24)]
    traffic[13] = round(baseline * random.uniform(3.0, 4.2), 2)  # simulated DDoS
    return jsonify({
        "labels":     [f"{h}:00" for h in range(24)],
        "traffic":    traffic,
        "baseline":   baseline,
        "spike_hour": 13,
    })


@app.route("/api/engine")
def engine():
    """
    Read the JSON report produced by the C++ threat_engine.
    Returns a 'not_run' status if the engine hasn't been executed yet.

    Usage:
        # compile and run engine first:
        g++ -std=c++17 -O2 -o threat_engine threat_engine.cpp
        ./threat_engine --simulate --output threats_output.json
        # then call this endpoint to load the results
    """
    data = read_engine_output()
    if data is None:
        return jsonify({
            "status": "not_run",
            "message": (
                "C++ engine output not found. "
                "Compile with: g++ -std=c++17 -O2 -o threat_engine threat_engine.cpp  "
                "Then run: ./threat_engine --simulate --output threats_output.json"
            ),
            "engine_file": ENGINE_OUTPUT,
        }), 200   # 200 so the frontend can handle it gracefully

    return jsonify({"status": "ok", **data})


# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("  Cloud Security Dashboard API — backend.py")
    logger.info("  Author: Manav Gupta | Summer Internship 2025")
    logger.info("=" * 60)
    logger.info("  Mode   : %s", "LIVE (AWS)" if live_mode() else "SIMULATION")
    logger.info("  Region : %s", AWS_REGION)
    logger.info("  Engine : %s", ENGINE_OUTPUT)
    logger.info("  URL    : http://localhost:5000")
    logger.info("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
