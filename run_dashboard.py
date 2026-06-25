#!/usr/bin/env python3
"""
run_dashboard.py — Local Development Server
============================================
Cloud Security Monitoring Dashboard
Author: Manav Gupta | Summer Internship 2025

Starts a local HTTP server that:
  1. Serves dashboard.html at http://localhost:8787/
  2. Serves index.html at http://localhost:8787/index
  3. Exposes all /api/* endpoints with live simulated data
  4. Tries real boto3/AWS calls if credentials are configured in .env
  5. Reads C++ engine output from threats_output.json if it exists

Run:
    python run_dashboard.py

Then open: http://localhost:8787/
"""

import os, json, random, logging, threading, time
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ── optional dependencies ─────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s")
log = logging.getLogger()

# ── config ────────────────────────────────────────────────────────────────────
HOST           = "127.0.0.1"
PORT           = 8787
AWS_REGION     = os.getenv("AWS_REGION", "us-east-1")
AWS_KEY        = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET     = os.getenv("AWS_SECRET_ACCESS_KEY", "")
DETECTOR_ID    = os.getenv("GUARDDUTY_DETECTOR_ID", "")
ENGINE_OUTPUT  = os.getenv("ENGINE_OUTPUT_PATH", "threats_output.json")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── helpers ───────────────────────────────────────────────────────────────────

def live_aws():
    return AWS_AVAILABLE and bool(AWS_KEY) and bool(AWS_SECRET)

def aws_client(service, region=AWS_REGION):
    if not live_aws(): return None
    return boto3.client(service, region_name=region,
                        aws_access_key_id=AWS_KEY,
                        aws_secret_access_key=AWS_SECRET)

def severity(score):
    if score >= 7: return "Critical"
    if score >= 4: return "High"
    if score >= 1: return "Medium"
    return "Low"

# ── data generators ───────────────────────────────────────────────────────────

def gen_threats():
    pool = [
        {"type":"UnauthorizedAccess:EC2/SSHBruteForce","severity":"Critical","region":"us-east-1","resource":"i-0a1b2c3d4e5f"},
        {"type":"Recon:IAMUser/MaliciousIPCaller","severity":"High","region":"eu-west-1","resource":"arn:aws:iam::123456789:user/admin"},
        {"type":"Trojan:EC2/BlackholeTraffic","severity":"Critical","region":"ap-south-1","resource":"i-0f9e8d7c6b5a"},
        {"type":"Policy:S3/BucketPublicAccessGranted","severity":"High","region":"us-east-1","resource":"arn:aws:s3:::sensitive-data"},
        {"type":"PortProbeUnprotectedPort","severity":"Medium","region":"us-west-2","resource":"i-0b1c2d3e4f5a"},
        {"type":"UnauthorizedAccess:IAMUser/ConsoleLogin","severity":"High","region":"sa-east-1","resource":"arn:aws:iam::123:user/root"},
        {"type":"CryptoCurrency:EC2/BitcoinTool","severity":"Medium","region":"eu-west-1","resource":"i-0c2d3e4f5a6b"},
        {"type":"Behavior:EC2/NetworkPortUnusual","severity":"Low","region":"us-east-1","resource":"i-0d3e4f5a6b7c"},
    ]
    items = random.sample(pool, k=random.randint(4, 8))
    for i, e in enumerate(items):
        e["id"] = f"sim-{random.randint(100000,999999)}"
        e["timestamp"] = (datetime.utcnow() - timedelta(minutes=random.randint(1,120))).isoformat()+"Z"
        e["status"] = random.choice(["Open","Investigating","Mitigated"])
        e["source"] = "simulation"
    return items

def get_threats():
    client = aws_client("guardduty")
    if not client or not DETECTOR_ID:
        findings = gen_threats()
        return findings, "simulation"
    try:
        ids = client.list_findings(DetectorId=DETECTOR_ID, MaxResults=50).get("FindingIds",[])
        if not ids: return [], "live"
        details = client.get_findings(DetectorId=DETECTOR_ID, FindingIds=ids)
        out = []
        for f in details.get("Findings",[]):
            out.append({"id":f["Id"],"type":f["Type"],"severity":severity(f["Severity"]),
                        "region":f["Region"],"resource":f.get("Resource",{}).get("ResourceType","?"),
                        "timestamp":f["CreatedAt"],"status":"Open","source":"guardduty"})
        return out, "live"
    except Exception as e:
        log.warning("GuardDuty error: %s", e)
        return gen_threats(), "simulation"

def get_metrics():
    client = aws_client("cloudwatch")
    if not client:
        return {"cpu_utilization":round(random.uniform(20,85),1),
                "network_in_gbh":round(random.uniform(1.5,12),2),
                "error_rate_pct":round(random.uniform(0.1,4.5),2),
                "lambda_errors":random.randint(0,30),
                "mttd_minutes":round(random.uniform(3,6.5),1),
                "compliance_score":94}, "simulation"
    try:
        end, start = datetime.utcnow(), datetime.utcnow()-timedelta(hours=1)
        def stat(ns,m,dims,s="Average"):
            pts = client.get_metric_statistics(Namespace=ns,MetricName=m,Dimensions=dims,
                                               StartTime=start,EndTime=end,Period=3600,Statistics=[s]).get("Datapoints",[])
            return round(pts[0][s],2) if pts else 0.0
        return {"cpu_utilization":stat("AWS/EC2","CPUUtilization",[]),
                "network_in_gbh":stat("AWS/EC2","NetworkIn",[]),
                "error_rate_pct":0.0,"lambda_errors":0,
                "mttd_minutes":round(random.uniform(3,6.5),1),
                "compliance_score":94}, "live"
    except Exception as e:
        log.warning("CloudWatch: %s", e)
        return {"cpu_utilization":0,"network_in_gbh":0,"error_rate_pct":0,
                "lambda_errors":0,"mttd_minutes":4.2,"compliance_score":94}, "error"

def get_iam():
    client = aws_client("accessanalyzer")
    if not client:
        return [{"rule":"MFA enforcement","pass":241,"fail":7,"pct":97},
                {"rule":"Least privilege","pass":188,"fail":60,"pct":76},
                {"rule":"No root key usage","pass":248,"fail":0,"pct":100},
                {"rule":"Password policy","pass":230,"fail":18,"pct":93}], "simulation"
    try:
        analyzers = client.list_analyzers().get("analyzers",[])
        if not analyzers: raise ValueError("no analyzers")
        findings = client.list_findings(analyzerArn=analyzers[0]["arn"]).get("findings",[])
        total = max(len(findings),1)
        passed = sum(1 for f in findings if f["status"]=="RESOLVED")
        return [{"rule":"Access Analyzer","pass":passed,"fail":total-passed,
                 "pct":round(passed/total*100)}], "live"
    except Exception as e:
        log.warning("IAM Analyzer: %s", e)
        return [{"rule":"MFA enforcement","pass":241,"fail":7,"pct":97},
                {"rule":"Least privilege","pass":188,"fail":60,"pct":76},
                {"rule":"No root key usage","pass":248,"fail":0,"pct":100},
                {"rule":"Password policy","pass":230,"fail":18,"pct":93}], "simulation"

def get_engine():
    path = os.path.join(SCRIPT_DIR, ENGINE_OUTPUT)
    if not os.path.exists(path):
        return {"status":"not_run","message":"Run threat_engine first: ./threat_engine --simulate"}
    try:
        with open(path) as f:
            data = json.load(f)
        for finding in data.get("findings",[]):
            finding["source"] = "cpp_engine"
        data["status"] = "ok"
        data["read_at"] = datetime.utcnow().isoformat()+"Z"
        return data
    except Exception as e:
        return {"status":"error","message":str(e)}

REGION_LABELS = {
    "us-east-1":"US East (N. Virginia)","eu-west-1":"EU West (Ireland)",
    "ap-south-1":"AP South (Mumbai)","us-west-2":"US West (Oregon)","sa-east-1":"SA East (São Paulo)"
}
REGIONS = list(REGION_LABELS)

def get_regions():
    base = {"us-east-1":{"uptime":99.7,"resources":84,"incidents":0},
            "eu-west-1":{"uptime":98.1,"resources":67,"incidents":1},
            "ap-south-1":{"uptime":97.4,"resources":59,"incidents":1},
            "us-west-2":{"uptime":100.0,"resources":38,"incidents":0},
            "sa-east-1":{"uptime":94.8,"resources":21,"incidents":2}}
    return [{"region":r,"label":REGION_LABELS[r],**base[r]} for r in REGIONS]

def get_timeline():
    return {"labels":[f"{h}:00" for h in range(24)],
            "critical":[random.randint(0,5) for _ in range(24)],
            "high":[random.randint(0,7) for _ in range(24)],
            "medium":[random.randint(1,9) for _ in range(24)],
            "low":[random.randint(2,10) for _ in range(24)]}

def get_traffic():
    t = [round(3+random.uniform(-0.5,0.8),2) for _ in range(24)]
    t[13] = round(3*random.uniform(3,4.2),2)
    return {"labels":[f"{h}:00" for h in range(24)],"traffic":t,"baseline":3.0,"spike_hour":13}

# ── HTTP handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        log.info("  %s %s", self.address_string(), fmt % args)

    def send_json(self, data, code=200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, filepath, ctype="text/html"):
        try:
            with open(filepath, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"

        # ── static pages ──────────────────────────────────────────────────
        if path in ("/", "/dashboard", "/dashboard.html"):
            f = os.path.join(SCRIPT_DIR, "dashboard.html")
            self.send_file(f)
            return

        if path in ("/index", "/index.html"):
            f = os.path.join(SCRIPT_DIR, "index.html")
            self.send_file(f)
            return

        # ── API routes ────────────────────────────────────────────────────
        if path == "/api/health":
            self.send_json({"status":"ok",
                            "timestamp":datetime.utcnow().isoformat()+"Z",
                            "mode":"live" if live_aws() else "simulation",
                            "aws_region":AWS_REGION,
                            "server":"run_dashboard.py",
                            "port":PORT,
                            "engine_output_exists":os.path.exists(os.path.join(SCRIPT_DIR,ENGINE_OUTPUT))})

        elif path == "/api/threats":
            findings, src = get_threats()
            counts = {"Critical":0,"High":0,"Medium":0,"Low":0}
            for f in findings: counts[f["severity"]] = counts.get(f["severity"],0)+1
            self.send_json({"total":len(findings),"counts":counts,"findings":findings,"data_source":src})

        elif path == "/api/metrics":
            data, src = get_metrics()
            data["data_source"] = src
            self.send_json(data)

        elif path == "/api/compliance/iam":
            policies, src = get_iam()
            self.send_json({"policies":policies,"data_source":src})

        elif path == "/api/regions":
            self.send_json({"regions":get_regions()})

        elif path == "/api/events/timeline":
            self.send_json(get_timeline())

        elif path == "/api/network/traffic":
            self.send_json(get_traffic())

        elif path == "/api/engine":
            self.send_json(get_engine())

        else:
            self.send_response(404)
            self.end_headers()

# ── startup banner ────────────────────────────────────────────────────────────

def banner():
    mode = "LIVE (AWS)" if live_aws() else "SIMULATION"
    print(f"""
╔══════════════════════════════════════════════════════════╗
║   Cloud Security Monitoring Dashboard                   ║
║   Manav Gupta · Summer Internship 2025                  ║
╠══════════════════════════════════════════════════════════╣
║   Dashboard  →  http://{HOST}:{PORT}/              ║
║   API health →  http://{HOST}:{PORT}/api/health    ║
║   Mode       →  {mode:<36} ║
╚══════════════════════════════════════════════════════════╝
""")

if __name__ == "__main__":
    banner()
    server = HTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
