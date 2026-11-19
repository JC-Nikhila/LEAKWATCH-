"""Remediation checklists. Steps are SIMULATED only, and only after approval."""
import datetime

CHECKLISTS = {
    "AWS Access Key": ["Deactivate and rotate the key in IAM", "Review CloudTrail for unauthorized use", "Purge from git history (git filter-repo)", "Notify security team"],
    "AWS Secret Key": ["Rotate the key pair in IAM", "Review CloudTrail for misuse", "Purge from history", "Notify security team"],
    "GitHub Token": ["Revoke the token in GitHub settings", "Check audit log for activity", "Purge from history", "Issue a new token with least privilege"],
    "Slack Token": ["Revoke the token in the Slack admin console", "Delete the chat message", "Issue a new token"],
    "Stripe Live Key": ["Roll the key in the Stripe dashboard", "Review recent charges and payouts", "Purge from history", "Notify finance and security"],
    "Google API Key": ["Regenerate key in Google Cloud Console", "Add API/IP restrictions", "Purge from history"],
    "Private Key": ["Revoke and replace the key pair", "Remove old public key from servers", "Purge from history", "Notify security team"],
    "DB Connection String": ["Rotate the database password", "Check DB access logs", "Move credentials to a secrets manager", "Purge from history"],
    "JWT": ["Invalidate the session/token", "Rotate signing key if it is long-lived"],
    "Hardcoded Password": ["Change the password", "Move to environment variable or secrets manager", "Purge from history"],
}
PII = ["Delete the message / redact the file", "Assess whether a data-breach notification is required", "Notify the data protection officer and affected customers if needed"]


def checklist(f):
    return CHECKLISTS.get(f["type"], PII if f["kind"] == "pii" else ["Review and remove"])


def alert_owner(f):
    owner = f.get("author") or "repo-owner"
    return f"[ALERT {datetime.datetime.now():%Y-%m-%d %H:%M}] to={owner} severity={f['severity'].upper()} type={f['type']} at={f['location']}"


def simulate(f):
    """Pretend to run each step. Nothing real is touched."""
    return [{"step": s, "status": "simulated-done"} for s in checklist(f)]
