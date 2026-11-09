"""
SOC Log Triage CLI — parses auth logs, runs detection rules,
outputs a Markdown incident report.
"""
import click
from datetime import datetime
from modules.parser import parse_log
from modules.rules import run_all_rules

@click.group()
def cli():
    """SOC Log Triage Toolkit."""
    pass

@cli.command()
@click.option("--log", required=True, help="Path to auth.log file.")
@click.option("--output", default="report.md", help="Output Markdown report path.")
def triage(log, output):
    """Parse log, run detections, write Markdown report."""
    click.echo(f"[*] Parsing {log} ...")
    events = parse_log(log)
    click.echo(f"[*] Parsed {len(events)} events.")

    click.echo("[*] Running detection rules ...")
    alerts = run_all_rules(events)
    click.echo(f"[*] {len(alerts)} alert(s) generated.")

    write_report(log, events, alerts, output)
    click.echo(f"[+] Report written to {output}")

def write_report(log_path, events, alerts, output_path):
    lines = []
    lines.append("# SOC Log Triage Report")
    lines.append(f"\n**Log file:** `{log_path}`  ")
    lines.append(f"**Generated:** {datetime.now().isoformat()}  ")
    lines.append(f"**Events parsed:** {len(events)}  ")
    lines.append(f"**Alerts:** {len(alerts)}\n")

    lines.append("## ISO/IEC 27001 Mapping")
    lines.append("All detections map to **Control A.8.16 — Monitoring Activities**.\n")

    lines.append("## Alerts\n")
    if not alerts:
        lines.append("_No alerts triggered._\n")
    else:
        for i, a in enumerate(alerts, 1):
            lines.append(f"### Alert {i}: {a['rule']}")
            lines.append(f"- **Severity:** {a['severity']}")
            lines.append(f"- **IP:** `{a['ip']}`")
            lines.append(f"- **User:** `{a['user']}`")
            lines.append(f"- **Timestamp:** {a['timestamp']}")
            lines.append(f"- **Detail:** {a['detail']}\n")

    lines.append("## Recommendations\n")
    if any(a["severity"] == "CRITICAL" for a in alerts):
        lines.append("- **Immediate:** Block offending IPs at the firewall.")
        lines.append("- **Immediate:** Force password reset for compromised accounts.")
        lines.append("- **Short-term:** Enable MFA on SSH; disable password auth.")
    lines.append("- **Ongoing:** Review auth logs daily; tune detection thresholds.")
    lines.append("- **Ongoing:** Correlate with SIEM (Splunk/Wazuh) for centralized monitoring.\n")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

if __name__ == "__main__":
    cli()