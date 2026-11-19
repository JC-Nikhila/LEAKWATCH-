"""Rule-based detection: secret patterns + personal-data rules."""
import json, math, re

# name, regex, kind, base severity
RULES = [
    ("AWS Access Key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "secret", "critical"),
    ("AWS Secret Key", r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}", "secret", "critical"),
    ("GitHub Token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "secret", "critical"),
    ("Slack Token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "secret", "high"),
    ("Stripe Live Key", r"\bsk_live_[0-9a-zA-Z]{16,}\b", "secret", "critical"),
    ("Google API Key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "secret", "high"),
    ("Private Key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "secret", "critical"),
    ("DB Connection String", r"\b(?:postgres|postgresql|mysql|mongodb)(?:\+srv)?://[^\s:/@]+:[^\s@]+@[^\s]+", "secret", "high"),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "secret", "medium"),
    ("Hardcoded Password", r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\b\s*[=:]\s*['\"]([^'\"\s]{6,})['\"]", "secret", "high"),
    ("Credit Card Number", r"\b(?:\d[ -]?){13,16}\b", "pii", "critical"),
    ("Aadhaar Number", r"\b\d{4}\s\d{4}\s\d{4}\b", "pii", "high"),
    ("PAN Number", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", "pii", "high"),
    ("US SSN", r"\b\d{3}-\d{2}-\d{4}\b", "pii", "high"),
    ("Email Address", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "pii", "low"),
    ("Phone Number", r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)", "pii", "medium"),
]
COMPILED = [(n, re.compile(p), k, s) for n, p, k, s in RULES]
LEVELS = ["low", "medium", "high", "critical"]


def luhn(num):
    d = [int(c) for c in re.sub(r"\D", "", num)]
    if not 13 <= len(d) <= 16: return False
    s = 0
    for i, x in enumerate(reversed(d)):
        if i % 2: x = x * 2 - 9 if x * 2 > 9 else x * 2
        s += x
    return s % 10 == 0


def entropy(s):
    if not s: return 0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def mask(v):
    v = v.strip()
    return v[:4] + "•" * 6 + v[-2:] if len(v) > 8 else "•" * len(v)


def bump(sev, n):
    return LEVELS[min(LEVELS.index(sev) + n, 3)]


def exposure_bump(source, ctx):
    """Higher severity when the leak is more widely visible."""
    if source == "chat":
        ch = ctx.get("channel", "")
        return (2 if ch in ("general", "random", "public", "all-hands") else 1), \
               f"posted in #{ch or 'chat'} (readable by many people)"
    if source == "repo":
        return 1, "committed to repository history (persists until purged)"
    return 0, "found in uploaded file"


def scan_line(line, source, ctx):
    out, taken = [], []
    for name, rx, kind, sev in COMPILED:
        for m in rx.finditer(line):
            val = m.group(0)
            if any(m.start() < e and m.end() > b for b, e in taken): continue  # overlaps a higher-priority match
            if name == "Credit Card Number" and not luhn(val): continue
            if name == "Email Address" and source == "repo" and "noreply" in val: continue
            taken.append((m.start(), m.end()))
            b, why = exposure_bump(source, ctx)
            # PII only bumps when it is clearly sensitive; emails stay low
            final = bump(sev, b) if sev != "low" else sev
            out.append({"type": name, "kind": kind, "base_severity": sev, "severity": final,
                        "exposure": why, "raw": val, "masked": mask(val),
                        "line": line.strip()[:200], **ctx})
    return out


def parse(filename, content):
    """Yield (line, source, ctx) from repo history, chat JSON, or plain text."""
    name = filename.lower()
    if name.endswith(".json"):
        try:
            data = json.loads(content)
            msgs = data.get("messages", data) if isinstance(data, dict) else data
            for i, m in enumerate(msgs):
                text = m.get("text", "") if isinstance(m, dict) else str(m)
                ctx = {"file": filename, "channel": (m.get("channel", "") if isinstance(m, dict) else "").lstrip("#"),
                       "author": m.get("user", "") if isinstance(m, dict) else "", "location": f"message {i+1}"}
                for ln in text.splitlines() or [text]:
                    yield ln, "chat", ctx
            return
        except Exception:
            pass
    is_history = bool(re.search(r"^commit [0-9a-f]{7,40}", content, re.M))
    commit = path = author = None
    for n, ln in enumerate(content.splitlines(), 1):
        if is_history:
            if m := re.match(r"commit ([0-9a-f]{7,40})", ln): commit, path = m.group(1)[:8], None; continue
            if m := re.match(r"Author:\s*(.*)", ln): author = m.group(1); continue
            if m := re.match(r"\+\+\+ b/(.*)", ln): path = m.group(1); continue
            if ln.startswith("-") : continue
            yield ln, "repo", {"file": path or filename, "commit": commit, "author": author,
                               "location": f"commit {commit}, line {n}"}
        else:
            yield ln, "file", {"file": filename, "location": f"line {n}"}


def scan(filename, content):
    findings = []
    for line, source, ctx in parse(filename, content):
        findings += scan_line(line, source, {**ctx, "source": source})
    return findings
