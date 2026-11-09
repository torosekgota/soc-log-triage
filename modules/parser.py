"""
Parses Linux auth.log style lines into structured dictionaries.
"""
import re
from datetime import datetime

# Regex for SSH failed/accepted password lines
SSH_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"\S+\s+sshd\[\d+\]:\s"
    r"(?P<action>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def parse_log(filepath):
    events = []
    with open(filepath, "r") as f:
        for line in f:
            match = SSH_PATTERN.search(line)
            if match:
                # Parse timestamp with current year (auth.log omits year)
                ts_str = f"{datetime.now().year} {match.group('timestamp')}"
                try:
                    ts = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
                except ValueError:
                    continue
                events.append({
                    "timestamp": ts,
                    "action": match.group("action"),
                    "user": match.group("user"),
                    "ip": match.group("ip"),
                })
    return events