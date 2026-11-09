"""
Rule-based phishing URL analyzer.
Checks for raw IPs, URL shorteners, suspicious keywords, and typosquatting.
"""
import math
from collections import Counter
from urllib.parse import urlparse

# Common URL shorteners used in phishing
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}

# Brands frequently impersonated in phishing
TARGET_BRANDS = ["paypal", "microsoft", "apple", "netflix", "facebook", "absa", "fnb", "stanbic"]

def calculate_entropy(text):
    """Calculates Shannon entropy to detect randomly generated strings."""
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def analyze_url(url):
    alerts = []
    risk_score = 0
    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = parsed.netloc.lower()
    
    # 1. Check for IP address instead of domain name
    if domain.replace(".", "").isdigit():
        alerts.append("Host is a raw IP address, not a domain name.")
        risk_score += 40

    # 2. Check for URL shorteners
    if domain in SHORTENERS:
        alerts.append(f"Uses a known URL shortener ({domain}), hiding the true destination.")
        risk_score += 30

    # 3. Check for excessive subdomains (e.g., login.secure.update.paypal.com.evil.com)
    if domain.count(".") > 3:
        alerts.append("Excessive subdomains detected (common obfuscation tactic).")
        risk_score += 20

    # 4. Brand impersonation check (Simple string matching)
    for brand in TARGET_BRANDS:
        if brand in domain and not domain.endswith(f"{brand}.com"):
            alerts.append(f"Potential brand impersonation detected: mentions '{brand}' but isn't the official domain.")
            risk_score += 30

    # 5. Entropy check on the longest part of the domain
    longest_part = max(domain.split("."), key=len)
    if calculate_entropy(longest_part) > 4.0 and len(longest_part) > 8:
        alerts.append("High entropy in domain string (looks randomly generated).")
        risk_score += 20

    # 6. Check for suspicious characters
    if "@" in url:
        alerts.append("Contains '@' symbol, which can be used to mask the real destination.")
        risk_score += 20

    # Cap score at 100
    risk_score = min(risk_score, 100)
    
    return {
        "url": url,
        "risk_score": risk_score,
        "severity": "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 30 else "LOW",
        "alerts": alerts
    }