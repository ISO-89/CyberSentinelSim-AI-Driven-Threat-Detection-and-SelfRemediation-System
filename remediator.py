import re
import datetime
from config import (
    QUARANTINE_FILE,
    BRUTE_FORCE_THRESHOLD,
    PORT_SCAN_THRESHOLD,
    SEVERITY_WEIGHTS,
    REMEDIATION_ACTIONS,
)
from database.database import insert_incident, insert_blocked_ip
from services.audit_service import log_incident_created, log_ip_blocked

blocked_ips        = set()
flagged_ips        = set()
locked_accounts    = set()
threat_scores      = {}
brute_force_counts = {}
port_scan_counts   = {}
active_alerts      = []
quarantine_log     = []

THREAT_SCORE_THRESHOLD = 20


# HELPERS

def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def update_threat_score(ip, severity):
    if not ip or ip == "Unknown":
        return

    weight = SEVERITY_WEIGHTS.get(severity, 0)

    if ip not in threat_scores:
        threat_scores[ip] = 0

    threat_scores[ip] += weight

    if threat_scores[ip] >= THREAT_SCORE_THRESHOLD:
        blocked_ips.add(ip)


def log_to_quarantine(result, action):
    timestamp = get_timestamp()
    line      = (
        f"{timestamp} | "
        f"CATEGORY: {result['category']} | "
        f"SEVERITY: {result['severity']} | "
        f"IP: {result['ip_address']} | "
        f"CONFIDENCE: {round(result['confidence'] * 100, 2)}% | "
        f"MITRE: {result['mitre_id']} · {result['mitre_tactic']} | "
        f"ACTION: {action} | "
        f"LOG: {result['log_line'][:80]}"
    )

    with open(QUARANTINE_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

    quarantine_log.append({
        "timestamp"   : timestamp,
        "category"    : result["category"],
        "severity"    : result["severity"],
        "ip"          : result["ip_address"],
        "confidence"  : result["confidence"],
        "mitre_id"    : result["mitre_id"],
        "mitre_tactic": result["mitre_tactic"],
        "action"      : action,
        "log_line"    : result["log_line"],
    })


def write_to_database(result, action, status):
    remediation = REMEDIATION_ACTIONS.get(result["category"], {})

    incident_id = insert_incident({
        "timestamp"            : get_timestamp(),
        "raw_log"              : result["log_line"],
        "threat_category"      : result["category"],
        "severity"             : result["severity"],
        "confidence"           : result["confidence"],
        "source_ip"            : result["ip_address"],
        "country"              : result.get("country"),
        "city"                 : result.get("city"),
        "latitude"             : result.get("latitude"),
        "longitude"            : result.get("longitude"),
        "mitre_id"             : result["mitre_id"],
        "mitre_name"           : result["mitre_name"],
        "mitre_tactic"         : result["mitre_tactic"],
        "remediation_action"   : remediation.get("action"),
        "remediation_simulated": remediation.get("simulated"),
        "status"               : status,
    })

    log_incident_created(incident_id, result["category"], result["severity"])
    return incident_id


    # RESPONSE FUNCTIONS

def respond_brute_force(result):
    ip = result["ip_address"]

    if ip not in brute_force_counts:
        brute_force_counts[ip] = 0
    brute_force_counts[ip] += 1

    if brute_force_counts[ip] >= BRUTE_FORCE_THRESHOLD:
        blocked_ips.add(ip)
        status = "Mitigated"
        action = f"IP {ip} BLOCKED after {brute_force_counts[ip]} failed attempts (SIMULATED: iptables -A INPUT -s {ip} -j DROP)"
    else:
        status = "Open"
        action = f"IP {ip} WARNING — failed attempt {brute_force_counts[ip]}/{BRUTE_FORCE_THRESHOLD}"

    update_threat_score(ip, result["severity"])
    incident_id = write_to_database(result, action, status)
    log_to_quarantine(result, action)

    if status == "Mitigated" and ip:
        insert_blocked_ip(ip, f"Brute Force — {brute_force_counts[ip]} failed attempts", result["category"], incident_id)
        log_ip_blocked(incident_id, ip, result["category"])

    return action


def respond_sql_injection(result):
    ip = result["ip_address"]
    blocked_ips.add(ip)
    action      = f"CRITICAL ALERT — IP {ip} BLOCKED — SQL injection attempt logged (SIMULATED: iptables -A INPUT -s {ip} -j DROP)"
    incident_id = write_to_database(result, action, "Mitigated")
    log_to_quarantine(result, action)

    if ip:
        insert_blocked_ip(ip, "SQL Injection attack detected", result["category"], incident_id)
        log_ip_blocked(incident_id, ip, result["category"])

    update_threat_score(ip, result["severity"])
    return action


def respond_malware(result):
    ip = result["ip_address"]
    blocked_ips.add(ip)
    action      = f"MALWARE QUARANTINED — IP {ip} BLOCKED — file isolated (SIMULATED: iptables -A INPUT -s {ip} -j DROP)"
    incident_id = write_to_database(result, action, "Mitigated")
    log_to_quarantine(result, action)

    if ip:
        insert_blocked_ip(ip, "Malware upload detected", result["category"], incident_id)
        log_ip_blocked(incident_id, ip, result["category"])

    update_threat_score(ip, result["severity"])
    return action


def respond_port_scan(result):
    ip = result["ip_address"]

    if ip not in port_scan_counts:
        port_scan_counts[ip] = 0
    port_scan_counts[ip] += 1

    if port_scan_counts[ip] >= PORT_SCAN_THRESHOLD:
        flagged_ips.add(ip)
        status = "Investigating"
        action = f"IP {ip} FLAGGED after {port_scan_counts[ip]} ports probed (SIMULATED: alert --level=low --source={ip})"
    else:
        status = "Open"
        action = f"IP {ip} port probe {port_scan_counts[ip]}/{PORT_SCAN_THRESHOLD} — monitoring"

    update_threat_score(ip, result["severity"])
    write_to_database(result, action, status)
    log_to_quarantine(result, action)
    return action


def respond_privilege_escalation(result):
    ip         = result["ip_address"]
    user_match = re.search(r'(\w+)\s*:\s*UNAUTHORIZED', result["log_line"])
    user       = user_match.group(1) if user_match else "unknown_user"

    locked_accounts.add(user)
    blocked_ips.add(ip)
    action      = f"ACCOUNT {user} LOCKED — IP {ip} BLOCKED — escalation terminated (SIMULATED: usermod -L {user})"
    incident_id = write_to_database(result, action, "Mitigated")
    log_to_quarantine(result, action)

    if ip:
        insert_blocked_ip(ip, f"Privilege escalation by {user}", result["category"], incident_id)
        log_ip_blocked(incident_id, ip, result["category"])

    update_threat_score(ip, result["severity"])
    return action


def respond_unauthorized_access(result):
    ip = result["ip_address"]
    blocked_ips.add(ip)
    action = f"SESSION TERMINATED — IP {ip} BLOCKED — unauthorized access logged (SIMULATED: alert --level=critical --source={ip})"
    write_to_database(result, action, "Investigating")
    log_to_quarantine(result, action)
    update_threat_score(ip, result["severity"])
    return action


def respond_normal(result):
    return "No action required — activity is normal"


# REMEDIATE

def remediate(result):
    category = result["category"]
    ip       = result["ip_address"]

    if category == "Brute Force":
        action = respond_brute_force(result)
    elif category == "SQL Injection":
        action = respond_sql_injection(result)
    elif category == "Malware Upload":
        action = respond_malware(result)
    elif category == "Port Scan":
        action = respond_port_scan(result)
    elif category == "Privilege Escalation":
        action = respond_privilege_escalation(result)
    elif category == "Unauthorized Access":
        action = respond_unauthorized_access(result)
    else:
        action = respond_normal(result)

    if category != "Normal":
        active_alerts.append({
            "timestamp"   : get_timestamp(),
            "category"    : category,
            "severity"    : result["severity"],
            "ip"          : ip,
            "confidence"  : result["confidence"],
            "mitre_id"    : result["mitre_id"],
            "mitre_tactic": result["mitre_tactic"],
            "action"      : action,
            "threat_score": threat_scores.get(ip, 0),
        })

    return {
        "action"          : action,
        "blocked_ips"     : list(blocked_ips),
        "flagged_ips"     : list(flagged_ips),
        "locked_accounts" : list(locked_accounts),
        "threat_scores"   : threat_scores,
        "active_alerts"   : active_alerts,
    }




    