# SOC Log Triage Report

**Log file:** `samples/sample_auth.log`  
**Generated:** 2026-11-09T21:56:11.189045  
**Events parsed:** 20  
**Alerts:** 2

## ISO/IEC 27001 Mapping
All detections map to **Control A.8.16 — Monitoring Activities**.

## Alerts

### Alert 1: BRUTE_FORCE_THEN_SUCCESS
- **Severity:** CRITICAL
- **IP:** `192.168.1.50`
- **User:** `itadmin`
- **Timestamp:** 2026-01-10T08:01:45
- **Detail:** 6 failed logins in 60s before successful login for 'itadmin'.

### Alert 2: PASSWORD_SPRAY
- **Severity:** HIGH
- **IP:** `203.0.113.9`
- **User:** `11 distinct users`
- **Timestamp:** 2026-01-10T08:10:00
- **Detail:** Failed login attempts against 11 users from 203.0.113.9 within 120s.

## Recommendations

- **Immediate:** Block offending IPs at the firewall.
- **Immediate:** Force password reset for compromised accounts.
- **Short-term:** Enable MFA on SSH; disable password auth.
- **Ongoing:** Review auth logs daily; tune detection thresholds.
- **Ongoing:** Correlate with SIEM (Splunk/Wazuh) for centralized monitoring.
