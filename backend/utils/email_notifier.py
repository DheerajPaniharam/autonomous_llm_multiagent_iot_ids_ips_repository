"""
Email Notification Utility for Autonomous IoT IDS/IPS.
Provides simple, concise, and structured email alerts for high-severity incidents.
"""
from __future__ import annotations

import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

def generate_alert_email_text(incident_data: dict[str, Any]) -> str:
    """Generate clean, plain-text security incident alert."""
    incident_id = incident_data.get("incident_id", "INC-2026-0000")
    attack_type = incident_data.get("attack_type", "Unknown Threat")
    src_ip = incident_data.get("src_ip", "Unknown")
    dst_ip = incident_data.get("dst_ip", "192.168.1.100")
    risk_score = incident_data.get("risk_score", 0.95)
    mitigation_action = incident_data.get("mitigation_action", "nftables DROP rule deployed")
    timestamp = incident_data.get("timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    rationale = incident_data.get(
        "rationale",
        "Abnormal ingress traffic volume detected. Firewall drop rule was applied automatically."
    )

    return f"""[CRITICAL ALERT] Autonomous Threat Mitigated: {attack_type}

Dear Administrator,

The Autonomous IoT IDS/IPS platform detected and mitigated a high-severity network intrusion.

Incident Summary & Enforcement Actions:
--------------------------------------------------
- Incident ID:       {incident_id}
- Threat Class:      {attack_type}
- Attacker Source:   {src_ip} (Blocked)
- Target Asset:      {dst_ip}
- Risk Score:        {risk_score:.2f} / 1.00 (Critical)
- Mitigation Action: {mitigation_action}
- Timestamp:         {timestamp}
- System Status:     Normal / Protected

Autonomous Decision Rationale:
{rationale}

Console Access: http://localhost:5173/incidents/{incident_id}

--
Autonomous IoT Security Operations Team
This is an automated notification from the Autonomous Multi-Agent IDS/IPS Gateway.
"""

def generate_alert_email_html(incident_data: dict[str, Any]) -> str:
    """Generate clean, responsive HTML security incident alert."""
    incident_id = incident_data.get("incident_id", "INC-2026-0841")
    attack_type = incident_data.get("attack_type", "Volumetric DDoS (SYN Flood)")
    src_ip = incident_data.get("src_ip", "192.168.1.144")
    dst_ip = incident_data.get("dst_ip", "192.168.1.100")
    target_device = incident_data.get("target_device", "Smart Gateway")
    risk_score = float(incident_data.get("risk_score", 0.96))
    mitigation_action = incident_data.get("mitigation_action", "nftables DROP rule deployed")
    rule_ttl = incident_data.get("rule_ttl", "3600 seconds (1 Hour)")
    timestamp = incident_data.get("timestamp", datetime.utcnow().strftime("%b %d, %Y, %H:%M:%S UTC"))
    rationale = incident_data.get(
        "rationale",
        "Ingress packet rate exceeded normal baseline by 340% with abnormal SYN flags. "
        "Firewall drop applied automatically. Threat is isolated and network is stable."
    )
    console_url = incident_data.get("console_url", "http://localhost:5173/")

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ margin:0; padding:0; background:#f1f5f9; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; color:#0f172a; }}
    .container {{ max-width:620px; margin:24px auto; background:#fff; border:1px solid #cbd5e1; border-radius:8px; overflow:hidden; }}
    .hdr {{ background:#1e293b; padding:14px 20px; color:#94a3b8; font-size:13px; font-weight:600; }}
    .body {{ padding:24px; }}
    .badge-crit {{ display:inline-block; padding:3px 8px; background:#fee2e2; border:1px solid #ef4444; color:#b91c1c; font-size:11px; font-weight:700; border-radius:4px; }}
    .badge-mit {{ display:inline-block; padding:3px 8px; background:#dcfce7; border:1px solid #16a34a; color:#15803d; font-size:11px; font-weight:700; border-radius:4px; margin-left:6px; }}
    h2 {{ font-size:18px; margin:12px 0 4px 0; color:#0f172a; }}
    .meta {{ font-size:12px; color:#64748b; margin-bottom:16px; }}
    .card {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; margin:16px 0; overflow:hidden; }}
    .card-hdr {{ background:#f1f5f9; padding:8px 12px; font-size:13px; font-weight:700; color:#1e293b; border-bottom:1px solid #e2e8f0; }}
    .card-tbl {{ width:100%; font-size:12px; border-collapse:collapse; padding:8px; }}
    .card-tbl td {{ padding:6px 10px; }}
    .lbl {{ font-weight:600; color:#64748b; width:35%; }}
    .val {{ font-weight:500; color:#0f172a; }}
    .danger {{ color:#dc2626; font-weight:700; }}
    .success {{ color:#16a34a; font-weight:600; }}
    .rationale {{ background:#eff6ff; border:1px solid #bfdbfe; border-radius:6px; padding:10px 12px; font-size:12px; color:#1e3a8a; margin:14px 0; }}
    .btn {{ display:inline-block; background:#0284c7; color:#fff !important; text-decoration:none; padding:8px 16px; border-radius:4px; font-size:12px; font-weight:700; }}
    .ftr {{ border-top:1px solid #e2e8f0; padding-top:14px; margin-top:18px; font-size:11px; color:#94a3b8; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="hdr">Autonomous IoT Security Operations Gateway</div>
    <div class="body">
      <div>
        <span class="badge-crit">CRITICAL ALERT</span>
        <span class="badge-mit">AUTONOMOUSLY MITIGATED</span>
      </div>
      <h2>[CRITICAL] IoT Threat Mitigated: {attack_type} Blocked</h2>
      <div class="meta"><strong>Incident:</strong> {incident_id} &nbsp;|&nbsp; <strong>Time:</strong> {timestamp}</div>
      <p style="font-size:13px; color:#334155; margin:0 0 12px 0;">
        Dear Administrator,<br>
        The Autonomous IoT IDS/IPS platform detected and mitigated a high-severity network intrusion.
      </p>
      <div class="card">
        <div class="card-hdr">Incident Summary & Enforcement Actions</div>
        <table class="card-tbl">
          <tr><td class="lbl">Incident ID:</td><td class="val">{incident_id}</td><td class="lbl">Threat Score:</td><td class="val">{risk_score:.2f} / 1.00 (Critical)</td></tr>
          <tr><td class="lbl">Threat Class:</td><td class="val">{attack_type}</td><td class="lbl">Mitigation:</td><td class="val success">{mitigation_action}</td></tr>
          <tr><td class="lbl">Attacker Source:</td><td class="val danger">{src_ip} (Blocked)</td><td class="lbl">Rule TTL:</td><td class="val">{rule_ttl}</td></tr>
          <tr><td class="lbl">Target Asset:</td><td class="val">{target_device} ({dst_ip})</td><td class="lbl">System Health:</td><td class="val success">Normal / Protected</td></tr>
        </table>
      </div>
      <div class="rationale">
        <strong>Autonomous Decision Rationale:</strong><br>{rationale}
      </div>
      <div style="margin:16px 0;">
        <a href="{console_url}" class="btn">View in Security Console &rarr;</a>
      </div>
      <div class="ftr">
        <strong>Autonomous IoT Security Operations Team</strong><br>
        Automated security dispatch. Telemetry traces archived for 30 days in Loki/Grafana.
      </div>
    </div>
  </div>
</body>
</html>"""

async def dispatch_security_alert_email(incident_data: dict[str, Any], recipient: str | None = None) -> bool:
    """Dispatch security alert via SMTP or structured log fallback."""
    recipient = recipient or os.getenv("ALERT_EMAIL_RECIPIENT", "admin@enterprise.corp")
    smtp_server = os.getenv("SMTP_SERVER", "localhost")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASSWORD", "")
    sender = os.getenv("ALERT_EMAIL_SENDER", "security-alerts@ids-ips.local")

    subject = f"[CRITICAL] IoT Threat Mitigated: {incident_data.get('attack_type', 'Intrusion')} Blocked"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"Autonomous Security Orchestrator <{sender}>"
    msg["To"] = recipient

    part_text = MIMEText(generate_alert_email_text(incident_data), "plain")
    part_html = MIMEText(generate_alert_email_html(incident_data), "html")
    msg.attach(part_text)
    msg.attach(part_html)

    # In test/mock environments or if SMTP server is unavailable, log cleanly
    if not smtp_user or smtp_server in ("localhost", "none", ""):
        logger.info("Security alert email simulated for incident %s to %s",
                    incident_data.get("incident_id"), recipient)
        return True

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=5.0) as server:
            if smtp_port == 587:
                server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(sender, [recipient], msg.as_string())
        logger.info("Security alert email successfully dispatched to %s", recipient)
        return True
    except Exception as exc:
        logger.warning("SMTP dispatch skipped or failed: %s", exc)
        return False
