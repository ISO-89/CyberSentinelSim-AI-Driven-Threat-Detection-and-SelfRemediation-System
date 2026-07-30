import os
import datetime
from collections import Counter
from database.database import get_all_incidents, get_dashboard_stats
from config import (
    QUARANTINE_FILE,
    REPORTS_DIR,
    APP_NAME,
)

REPORT_TITLE       = f"{APP_NAME} — Incident Report"
REPORT_MAX_INCIDENTS = 1000


# READ INCIDENTS

def read_incidents():
    incidents = get_all_incidents(limit=REPORT_MAX_INCIDENTS)
    return incidents


def read_quarantine():
    if not os.path.exists(QUARANTINE_FILE):
        return []

    incidents = []

    with open(QUARANTINE_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for line in lines[-REPORT_MAX_INCIDENTS:]:
        line = line.strip()
        if not line:
            continue

        try:
            parts    = {}
            segments = line.split(" | ")
            parts["timestamp"] = segments[0].strip()

            for segment in segments[1:]:
                if ":" in segment:
                    key, value = segment.split(":", 1)
                    parts[key.strip()] = value.strip()

            incidents.append({
                "timestamp"  : parts.get("timestamp",  "Unknown"),
                "category"   : parts.get("CATEGORY",   "Unknown"),
                "severity"   : parts.get("SEVERITY",   "Unknown"),
                "ip"         : parts.get("IP",         "Unknown"),
                "confidence" : parts.get("CONFIDENCE", "Unknown"),
                "mitre"      : parts.get("MITRE",      "Unknown"),
                "action"     : parts.get("ACTION",     "Unknown"),
                "log"        : parts.get("LOG",        "Unknown"),
            })
        except Exception:
            continue

    return incidents


# GENERATE REPORT

def generate_report():
    incidents = read_incidents()
    stats     = get_dashboard_stats()
    now       = datetime.datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    filename  = f"incident_report_{now.strftime('%Y%m%d_%H%M%S')}.txt"
    filepath  = os.path.join(REPORTS_DIR, filename)

    total          = len(incidents)
    categories     = Counter(i["threat_category"] for i in incidents)
    severities     = Counter(i["severity"]         for i in incidents)
    ips            = Counter(i["source_ip"]        for i in incidents if i.get("source_ip"))
    statuses       = Counter(i["status"]           for i in incidents)
    mitre_tags     = Counter(
        f"{i['mitre_id']} · {i['mitre_name']}"
        for i in incidents if i.get("mitre_id")
    )

    confidences    = [i["confidence"] for i in incidents if i.get("confidence")]
    avg_confidence = round(sum(confidences) / len(confidences) * 100, 2) if confidences else 0
    max_confidence = round(max(confidences) * 100, 2)                     if confidences else 0
    min_confidence = round(min(confidences) * 100, 2)                     if confidences else 0

    os.makedirs(REPORTS_DIR, exist_ok=True)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"{'═'*70}\n")
        f.write(f"  {REPORT_TITLE}\n")
        f.write(f"  Generated : {timestamp}\n")
        f.write(f"{'═'*70}\n\n")

        f.write(f"  EXECUTIVE SUMMARY\n")
        f.write(f"  {'─'*66}\n")
        f.write(f"  Total Incidents       : {total}\n")
        f.write(f"  Threats Last 24h      : {stats.get('threats_last_24h', 0)}\n")
        f.write(f"  Threats Last Hour     : {stats.get('threats_last_hour', 0)}\n")
        f.write(f"  IPs Currently Blocked : {stats.get('blocked_count', 0)}\n")
        f.write(f"  Avg Confidence        : {avg_confidence}%\n")
        f.write(f"  Max Confidence        : {max_confidence}%\n")
        f.write(f"  Min Confidence        : {min_confidence}%\n\n")

        f.write(f"  THREAT CATEGORY BREAKDOWN\n")
        f.write(f"  {'─'*66}\n")
        for category, count in categories.most_common():
            pct = round(count / total * 100, 1) if total else 0
            f.write(f"  {category:<25} : {count:>5} incidents ({pct}%)\n")
        f.write("\n")

        f.write(f"  SEVERITY BREAKDOWN\n")
        f.write(f"  {'─'*66}\n")
        for severity, count in severities.most_common():
            pct = round(count / total * 100, 1) if total else 0
            f.write(f"  {severity:<25} : {count:>5} incidents ({pct}%)\n")
        f.write("\n")

        f.write(f"  INCIDENT STATUS BREAKDOWN\n")
        f.write(f"  {'─'*66}\n")
        for status, count in statuses.most_common():
            pct = round(count / total * 100, 1) if total else 0
            f.write(f"  {status:<25} : {count:>5} incidents ({pct}%)\n")
        f.write("\n")

        f.write(f"  TOP ATTACKER IPs\n")
        f.write(f"  {'─'*66}\n")
        for ip, count in ips.most_common(10):
            f.write(f"  {ip:<25} : {count:>5} incidents\n")
        f.write("\n")

        f.write(f"  MITRE ATT&CK TECHNIQUES OBSERVED\n")
        f.write(f"  {'─'*66}\n")
        for mitre, count in mitre_tags.most_common():
            f.write(f"  {mitre:<45} : {count:>5} times\n")
        f.write("\n")

        f.write(f"  FULL INCIDENT LOG\n")
        f.write(f"  {'─'*66}\n")
        for i, incident in enumerate(incidents, 1):
            f.write(f"\n  [{i}] {incident.get('timestamp', 'Unknown')}\n")
            f.write(f"      Category   : {incident.get('threat_category', 'Unknown')}\n")
            f.write(f"      Severity   : {incident.get('severity', 'Unknown')}\n")
            f.write(f"      IP         : {incident.get('source_ip', 'Unknown')}\n")
            f.write(f"      Country    : {incident.get('country', 'Unknown')}\n")
            f.write(f"      Confidence : {round(incident.get('confidence', 0) * 100, 2)}%\n")
            f.write(f"      MITRE      : {incident.get('mitre_id', 'N/A')} · {incident.get('mitre_name', 'N/A')}\n")
            f.write(f"      Status     : {incident.get('status', 'Unknown')}\n")
            f.write(f"      Log        : {incident.get('raw_log', 'Unknown')[:80]}\n")

        f.write(f"\n{'═'*70}\n")
        f.write(f"  End of Report — {APP_NAME}\n")
        f.write(f"{'═'*70}\n")

    return filepath





    
    