import click
from datetime import datetime
from modules.parser import parse_log
from modules.rules import run_all_rules
from modules.phish_checker import analyze_url 
from modules.fim import create_baseline, audit_directory

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
@cli.command()
@click.option("--dir", required=True, help="Directory to monitor.")
@click.option("--action", type=click.Choice(['baseline', 'audit']), required=True, help="Create baseline or run audit.")
def fim(dir, action):
    """File Integrity Monitor: detect unauthorized changes to files."""
    if action == 'baseline':
        click.echo(f"[*] Creating baseline for: {dir}")
        create_baseline(dir)
        click.echo("[+] Baseline created and saved to baseline.json")
    elif action == 'audit':
        click.echo(f"[*] Auditing directory: {dir}")
        results = audit_directory(dir)
        
        if "error" in results:
            click.echo(f"[!] {results['error']}")
            return
            
        click.echo("\n[+] Audit Complete:")
        click.echo(f"  - Modified files: {len(results['modified'])}")
        click.echo(f"  - Created files: {len(results['created'])}")
        click.echo(f"  - Deleted files: {len(results['deleted'])}\n")
        
        for file in results['modified']:
            click.echo(f"  [WARNING] Modified: {file}")
        for file in results['created']:
            click.echo(f"  [WARNING] Created: {file}")
        for file in results['deleted']:
            click.echo(f"  [WARNING] Deleted: {file}")
@cli.command()
@click.option("--log", default="samples/sample_auth.log", help="Log file to triage.")
@click.option("--dir", default="test_dir", help="Directory to audit.")
def run_all(log, dir):
    """Run Log Triage, URL Analysis, and FIM Audit in one go."""
    click.echo("=========================================")
    click.echo("      Starting SOC Toolkit Master Run    ")
    click.echo("=========================================\n")
    
    # 1. Triage
    click.echo("[*] Running Log Triage...")
    events = parse_log(log)
    alerts = run_all_rules(events)
    write_report(log, events, alerts, "report.md")
    click.echo(f"[+] Triage complete. {len(alerts)} alerts saved to report.md\n")
    
    # 2. FIM
    click.echo(f"[*] Running FIM Audit on {dir}...")
    results = audit_directory(dir)
    if "error" in results:
        click.echo(f"[!] FIM Error: {results['error']}\n")
    else:
        click.echo(f"[+] FIM complete. Modified files: {len(results['modified'])}\n")
        
    click.echo("[+] Master run finished. Review report.md for details.")
if __name__ == "__main__":
    cli()