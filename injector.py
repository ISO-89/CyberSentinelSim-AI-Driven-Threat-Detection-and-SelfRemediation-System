import random
import datetime
import os
import json

from config import CONFIG_DIR, LOG_FILE


def _load_data():
    path = os.path.join(CONFIG_DIR, "injector", "injector_data.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


_data = _load_data()


def random_ip():
    prefix = random.choice(_data["ip_prefixes"])
    return f"{prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def write_log(line):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    return line


def inject_brute_force():
    ip = random_ip()
    cfg = _data["brute_force"]
    lines = []
    service = random.choice(cfg["services"])
    attempts = random.randint(*cfg["attempts_range"])

    for i in range(attempts):
        user = random.choice(cfg["users"])
        password = random.choice(cfg["passwords"])
        port = random.randint(1024, 65535)
        pid = random.randint(1000, 9999)
        line = (
            f"{timestamp()} WARN {service}[{pid}]: "
            f"Failed password for {user} from {ip} port {port} ssh2 "
            f"-- tried password: {password} "
            f"-- authentication failure count: {i + 1} "
            f"-- blocking threshold approaching"
        )
        lines.append(write_log(line))
    return lines


def inject_sql_injection():
    ip = random_ip()
    cfg = _data["sql_injection"]
    payload = random.choice(cfg["payloads"])
    endpoint = random.choice(cfg["endpoints"])
    method = random.choice(cfg["methods"])
    field = random.choice(cfg["fields"])
    server = random.choice(cfg["servers"])
    pid = random.randint(1000, 9999)

    line = (
        f"{timestamp()} ERROR {server}[{pid}]: "
        f"[client {ip}] ModSecurity: SQL Injection Attack Detected "
        f"via {method} {endpoint}?{field}={payload} HTTP/1.1 "
        f"-- rule id 942100 "
        f"-- severity: CRITICAL "
        f"-- request blocked, connection logged"
    )
    return [write_log(line)]


def inject_port_scan():
    ip = random_ip()
    cfg = _data["port_scan"]
    lines = []

    ports = list(set(cfg["well_known_ports"] + random.sample(range(1024, 9000), random.randint(5, 10))))
    random.shuffle(ports)
    ports = ports[:random.randint(*cfg["probe_range"])]

    scan_type = random.choice(cfg["scan_types"])
    protocol = random.choice(cfg["protocols"])

    for port in ports:
        pid = random.randint(1000, 9999)
        src_port = random.randint(1024, 65535)
        line = (
            f"{timestamp()} WARN kernel[{pid}]: "
            f"iptables DROPPED: SRC={ip} DST=192.168.1.1 "
            f"PROTO={protocol} SPT={src_port} DPT={port} "
            f"SCAN_TYPE={scan_type} "
            f"FLAGS=SYN ACK RST "
            f"TTL={random.randint(40, 128)} "
            f"-- possible {scan_type} port scan detected "
            f"-- packet dropped"
        )
        lines.append(write_log(line))
    return lines


def inject_malware_upload():
    ip = random_ip()
    cfg = _data["malware"]
    pid = random.randint(1000, 9999)

    line = (
        f"{timestamp()} CRITICAL {random.choice(cfg['scanners'])}[{pid}]: "
        f"ALERT: Malware detected in upload from {ip} -- "
        f"file: {random.choice(cfg['upload_paths'])}/{random.choice(cfg['filenames'])} "
        f"size: {random.randint(50, 9999)}KB "
        f"signature: {random.choice(cfg['malware_names'])} "
        f"hash: {hex(random.randint(100000000, 999999999))} "
        f"-- {random.choice(cfg['actions'])}"
    )
    return [write_log(line)]


def inject_privilege_escalation():
    ip = random_ip()
    cfg = _data["privilege_escalation"]
    pid = random.randint(1000, 9999)

    user = random.choice(cfg["users"])
    command = random.choice(cfg["commands"])
    method = random.choice(cfg["methods"])
    tty = random.choice(cfg["ttys"])

    line = (
        f"{timestamp()} CRITICAL sudo[{pid}]: "
        f"{user} : UNAUTHORIZED privilege escalation attempt from {ip} ; "
        f"TTY={tty} ; "
        f"PWD=/home/{user} ; "
        f"METHOD={method} ; "
        f"command: {command} "
        f"-- escalation blocked, "
        f"account flagged for review, "
        f"session terminated"
    )
    return [write_log(line)]


def inject_unauthorized_access():
    ip = random_ip()
    cfg = _data["unauthorized_access"]
    pid = random.randint(1000, 9999)

    line = (
        f"{timestamp()} ERROR {random.choice(cfg['servers'])}[{pid}]: "
        f"Unauthorized access attempt from {ip} "
        f"to restricted resource: {random.choice(cfg['endpoints'])} "
        f"method: {random.choice(cfg['methods'])} "
        f"user-agent: {random.choice(cfg['user_agents'])} "
        f"-- HTTP {random.choice(cfg['response_codes'])} returned, "
        f"{random.choice(cfg['actions'])}"
    )
    return [write_log(line)]


def inject_normal_login():
    ip = random_ip()
    cfg = _data["normal_events"]
    pid = random.randint(1000, 9999)

    line = (
        f"{timestamp()} INFO {random.choice(cfg['services'])}[{pid}]: "
        f"Accepted {random.choice(cfg['auth_methods'])} for {random.choice(cfg['users'])} from {ip} "
        f"port {random.randint(1024, 65535)} ssh2 "
        f"-- {random.choice(cfg['session_types'])} "
        f"-- session id: {hex(random.randint(100000, 999999))} "
        f"-- location: {random.choice(cfg['locations'])} "
        f"-- MFA verified"
    )
    return [write_log(line)]


def inject_normal_system_event():
    cfg = _data["normal_events"]
    tpl = random.choice(cfg["event_templates"])
    pid = random.randint(1000, 9999)
    line = tpl.format(
        pid=pid,
        timestamp=timestamp(),
        size=random.randint(100, 9999),
        duration=random.randint(1, 60),
        temp=random.randint(35, 55),
        fan_speed=random.randint(1000, 3000),
        files=random.randint(1, 10),
        freed=random.randint(100, 999),
        offset=round(random.uniform(0.001, 0.009), 3),
        stratum=random.randint(1, 4),
        bad_sectors=random.randint(1, 5),
        events=random.randint(1000, 9999),
        rules=random.randint(10, 50),
        ver=f"{random.randint(1,9)}.{random.randint(100,999)}.{random.randint(1000,9999)}",
        mem_used=random.randint(20, 60),
        mem_avail=random.randint(4, 16),
        swap=random.randint(0, 20),
        sessions=random.randint(1, 10),
        containers=random.randint(1, 20),
        days=random.randint(30, 365),
        speed=random.choice(["100Mbps", "1Gbps", "10Gbps"]),
    )
    full_line = f"{timestamp()} {line}"
    return [write_log(full_line)]