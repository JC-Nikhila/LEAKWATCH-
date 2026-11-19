import datetime, json, os, socket, threading, uuid, webbrowser
from flask import Flask, jsonify, render_template, request
from scanner import scan, LEVELS
from judge import judge_all
import remediation as rem
from samples import build as build_samples

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
SCANS = {}
os.makedirs(os.path.join(BASE, "reports"), exist_ok=True)


def public(f):
    return {k: v for k, v in f.items() if k != "raw"}  # raw secrets never reach the browser


def run_scan(named_contents):
    findings = []
    for name, content in named_contents:
        findings += scan(name, content)
    findings = judge_all(findings)
    for i, f in enumerate(findings):
        f["id"] = i
        f["checklist"] = rem.checklist(f)
        f["status"] = "open" if f["verdict"] == "real" else "dismissed"
        f["remediation"] = []
    alerts = [rem.alert_owner(f) for f in findings if f["verdict"] == "real" and f["severity"] in ("high", "critical")]
    with open(os.path.join(BASE, "reports", "alerts.log"), "a") as fh:
        fh.write("\n".join(alerts) + ("\n" if alerts else ""))
    sid = uuid.uuid4().hex[:8]
    SCANS[sid] = {"id": sid, "time": datetime.datetime.now().isoformat(timespec="seconds"),
                  "files": [n for n, _ in named_contents], "findings": findings, "alerts": alerts,
                  "judge": "Claude" if os.getenv("ANTHROPIC_API_KEY") else "Built-in heuristic"}
    return report(sid)


def report(sid):
    s = SCANS[sid]
    real = [f for f in s["findings"] if f["verdict"] == "real"]
    counts = {l: sum(1 for f in real if f["severity"] == l) for l in LEVELS}
    return {"id": sid, "time": s["time"], "files": s["files"], "alerts": s["alerts"], "judge": s["judge"],
            "summary": {"total_hits": len(s["findings"]), "real": len(real),
                        "placeholders": len(s["findings"]) - len(real),
                        "remediated": sum(1 for f in real if f["status"].startswith("remediated")), **counts},
            "findings": [public(f) for f in s["findings"]]}


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def api_scan():
    files = request.files.getlist("files")
    if not files:
        return jsonify(error="Choose at least one file."), 400
    return jsonify(run_scan([(f.filename, f.read().decode("utf-8", errors="ignore")) for f in files]))


@app.post("/api/sample")
def api_sample():
    return jsonify(run_scan(list(build_samples().items())))


@app.post("/api/approve/<sid>")
def approve(sid):
    s = SCANS.get(sid)
    if not s:
        return jsonify(error="Unknown scan. Run a new scan."), 404
    ids = set(request.json.get("ids", []))
    for f in s["findings"]:
        if f["id"] in ids and f["verdict"] == "real" and f["status"] == "open":
            f["remediation"] = rem.simulate(f)
            f["status"] = "remediated (simulated)"
    return jsonify(report(sid))


def free_port(start=5000):
    for p in range(start, start + 20):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p
    return start


if __name__ == "__main__":
    port = free_port()
    url = f"http://127.0.0.1:{port}"
    print("\n  LeakWatch is running ->", url)
    print("  Judge:", "Claude" if os.getenv("ANTHROPIC_API_KEY") else "built-in heuristic (set ANTHROPIC_API_KEY to use Claude)")
    print("  Press Ctrl+C to stop.\n")
    threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=port, debug=False)
