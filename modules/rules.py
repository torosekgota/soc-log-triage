"""
Five detection rules mapped to ISO 27001 A.8.16 (Monitoring Activities).
Each rule returns a list of alert dicts.
"""
from collections import defaultdict
from datetime import timedelta

def rule_brute_force_success(events, threshold=5, window_seconds=60):
    """Failed logins >threshold within window, followed by success from same IP."""
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    for ip, evs in by_ip.items():
        evs.sort(key=lambda x: x["timestamp"])
        for i, e in enumerate(evs):
            if e["action"] != "Accepted":
                continue
            window_start = e["timestamp"] - timedelta(seconds=window_seconds)
            recent_fails = [
                x for x in evs[:i]
                if x["action"] == "Failed" and x["timestamp"] >= window_start
            ]
            if len(recent_fails) >= threshold:
                alerts.append({
                    "rule": "BRUTE_FORCE_THEN_SUCCESS",
                    "severity": "CRITICAL",
                    "ip": ip,
                    "user": e["user"],
                    "timestamp": e["timestamp"].isoformat(),
                    "detail": f"{len(recent_fails)} failed logins in 60s before successful login for '{e['user']}'.",
                })
    return alerts

def rule_impossible_travel(events, window_minutes=5):
    """Same user, two different IPs, within N minutes."""
    alerts = []
    by_user = defaultdict(list)
    for e in events:
        if e["action"] == "Accepted":
            by_user[e["user"]].append(e)

    for user, evs in by_user.items():
        evs.sort(key=lambda x: x["timestamp"])
        for i in range(1, len(evs)):
            prev, curr = evs[i - 1], evs[i]
            delta = curr["timestamp"] - prev["timestamp"]
            if delta <= timedelta(minutes=window_minutes) and prev["ip"] != curr["ip"]:
                alerts.append({
                    "rule": "IMPOSSIBLE_TRAVEL",
                    "severity": "HIGH",
                    "ip": f"{prev['ip']} -> {curr['ip']}",
                    "user": user,
                    "timestamp": curr["timestamp"].isoformat(),
                    "detail": f"User '{user}' logged in from {prev['ip']} and {curr['ip']} within {int(delta.total_seconds() // 60)} min.",
                })
    return alerts

def rule_password_spray(events, distinct_users=5, window_seconds=120):
    """One fail per user across many users from single IP in short window."""
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        if e["action"] == "Failed":
            by_ip[e["ip"]].append(e)

    for ip, evs in by_ip.items():
        evs.sort(key=lambda x: x["timestamp"])
        for i in range(len(evs)):
            start = evs[i]["timestamp"]
            window_end = start + timedelta(seconds=window_seconds)
            users_in_window = {
                x["user"] for x in evs
                if start <= x["timestamp"] <= window_end
            }
            if len(users_in_window) >= distinct_users:
                alerts.append({
                    "rule": "PASSWORD_SPRAY",
                    "severity": "HIGH",
                    "ip": ip,
                    "user": f"{len(users_in_window)} distinct users",
                    "timestamp": start.isoformat(),
                    "detail": f"Failed login attempts against {len(users_in_window)} users from {ip} within {window_seconds}s.",
                })
                break  # one alert per IP is enough
    return alerts

def rule_privilege_escalation(events):
    """Placeholder: sudo/admin command after fresh session (needs sudo logs)."""
    return []

def rule_web_recon(events):
    """Placeholder: requires web server access logs (404/403 flood)."""
    return []

ALL_RULES = [
    rule_brute_force_success,
    rule_impossible_travel,
    rule_password_spray,
    rule_privilege_escalation,
    rule_web_recon,
]

def run_all_rules(events):
    all_alerts = []
    for rule in ALL_RULES:
        all_alerts.extend(rule(events))
    return all_alerts