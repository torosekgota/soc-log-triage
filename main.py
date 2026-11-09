import click
from datetime import datetime
from modules.parser import parse_log
from modules.rules import run_all_rules
from modules.phish_checker import analyze_url # NEW IMPORT

@click.group()
def cli():
    """SOC Log Triage & Phishing Analyzer Toolkit."""
    pass

@cli.command()
@click.option("--log", required=True, help="Path to auth.log file.")
@click.option("--output", default="report.md", help="Output Markdown report path.")
def triage(log, output):
    """Parse log, run detections, write Markdown report."""
    # ... (leave your existing triage code exactly as it is) ...
    click.echo(f"[*] Parsing {log} ...")
    events = parse_log(log)
    click.echo(f"[*] Parsed {len(events)} events.")
    click.echo("[*] Running detection rules ...")
    alerts = run_all_rules(events)
    click.echo(f"[*] {len(alerts)} alert(s) generated.")
    write_report(log, events, alerts, output)
    click.echo(f"[+] Report written to {output}")

def write_report(log_path, events, alerts, output_path):
    # ... (leave your existing write_report code exactly as it is) ...
    # Just keep the function as it was in your previous code
    pass # Replace this pass with your actual code if you are copying this manually

# NEW COMMAND HERE
@cli.command()
@click.option("--url", required=True, help="Suspicious URL to analyze.")
def analyze_url_cmd(url):
    """Analyze a URL for phishing indicators."""
    click.echo(f"[*] Analyzing: {url}")
    result = analyze_url(url)
    
    click.echo(f"\n[!] Risk Score: {result['risk_score']}/100 ({result['severity']} severity)")
    
    if result['alerts']:
        click.echo("\n[!] Findings:")
        for alert in result['alerts']:
            click.echo(f"  - {alert}")
    else:
        click.echo("\n[+] No obvious phishing indicators found.")

if __name__ == "__main__":
    cli()