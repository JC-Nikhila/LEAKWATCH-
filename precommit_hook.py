#!/usr/bin/env python3
"""Optional pre-commit hook. Install:  cp precommit_hook.py .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
Blocks commits whose staged additions contain high/critical secrets that don't look like placeholders."""
import subprocess, sys
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.realpath(__file__)))
from scanner import scan_line
from judge import heuristic

diff = subprocess.run(["git", "diff", "--cached", "-U0"], capture_output=True, text=True).stdout
bad, path = [], ""
for ln in diff.splitlines():
    if ln.startswith("+++ b/"): path = ln[6:]
    elif ln.startswith("+") and not ln.startswith("+++"):
        for f in scan_line(ln[1:], "file", {"file": path, "location": path}):
            if f["kind"] == "secret" and f["severity"] in ("high", "critical") and heuristic(f)["verdict"] == "real":
                bad.append(f"  {path}: {f['type']} ({f['masked']})")
if bad:
    print("LeakWatch blocked this commit - possible secrets:\n" + "\n".join(bad))
    sys.exit(1)
