"""
AI-Assisted Alert Triage
------------------------
Pulls recent alerts from the Wazuh Indexer, enriches any file hashes or IPs
found in them via VirusTotal and AbuseIPDB, then asks Google's Gemini
to draft a plain-English triage summary for each alert. 
NOTE: The AI only drafts a suggestion; the analyst makes the final call.

SETUP: fill in the CONFIG section below with your own credentials before running.
RUN:   python3 ai_triage.py
OUTPUT: a timestamped triage_results_*.csv file in the same folder.
"""

import requests
import json
import csv
import time
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===================== CONFIG - FILL THESE IN =====================
WAZUH_INDEXER_HOST = "PASTE_YOUR_WAZUH_INDEXER_IP_HERE"
WAZUH_INDEXER_PORT = 9200
WAZUH_INDEXER_USER = "PASTE_YOUR_INDEXER_USERNAME_HERE"
WAZUH_INDEXER_PASS = "PASTE_YOUR_INDEXER_PASSWORD_HERE"

VIRUSTOTAL_API_KEY = "PASTE_YOUR_VIRUSTOTAL_API_KEY_HERE"
ABUSEIPDB_API_KEY = "PASTE_YOUR_ABUSEIPDB_API_KEY_HERE"

GEMINI_API_KEY = "PASTE_YOUR_GEMINI_API_KEY_HERE"
GEMINI_MODEL = "gemini-flash-lite-latest"

NUMBER_OF_ALERTS_TO_PULL = 10
# =====================================================================


def get_recent_alerts(n=10):
    url = f"https://{WAZUH_INDEXER_HOST}:{WAZUH_INDEXER_PORT}/wazuh-alerts-*/_search"
    query = {
        "size": n,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"match_all": {}}
    }
    resp = requests.get(
        url,
        auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS),
        json=query,
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    hits = resp.json().get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]


def extract_indicators(alert):
    indicators = {"md5": None, "sha256": None, "ip": None}
    data = alert.get("data", {})

    win = data.get("win", {}).get("eventdata", {})
    if "hashes" in win:
        hashes = win["hashes"]
        if "MD5=" in hashes:
            indicators["md5"] = hashes.split("MD5=")[1].split(",")[0]
        if "SHA256=" in hashes:
            indicators["sha256"] = hashes.split("SHA256=")[1].split(",")[0]

    for ip_field in ["srcip", "src_ip"]:
        if ip_field in data:
            indicators["ip"] = data[ip_field]

    return indicators


def enrich_with_virustotal(file_hash):
    if not file_hash or VIRUSTOTAL_API_KEY.startswith("PASTE"):
        return "No hash available or VirusTotal key not configured."
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 404:
            return "Hash not found in VirusTotal (never seen before, or test/benign file)."
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return f"VirusTotal: {stats['malicious']} malicious / {stats['harmless']} harmless vendor detections."
    except requests.exceptions.RequestException as e:
        return f"VirusTotal lookup failed: {e}"


def enrich_with_abuseipdb(ip):
    if not ip or ABUSEIPDB_API_KEY.startswith("PASTE"):
        return "No IP available or AbuseIPDB key not configured."
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        resp.raise_for_status()
        d = resp.json()["data"]
        return f"AbuseIPDB: {d['abuseConfidenceScore']}% confidence of abuse, {d['totalReports']} reports."
    except requests.exceptions.RequestException as e:
        return f"AbuseIPDB lookup failed: {e}"


def build_prompt(alert, enrichment_notes):
    rule = alert.get("rule", {})
    return f"""You are assisting a junior SOC analyst with drafting (not finalizing) a triage note.

ALERT DETAILS:
- Rule description: {rule.get('description', 'N/A')}
- Rule level (severity): {rule.get('level', 'N/A')}
- Rule ID: {rule.get('id', 'N/A')}
- Agent: {alert.get('agent', {}).get('name', 'N/A')}
- Timestamp: {alert.get('timestamp', 'N/A')}
- Full raw event (for context): {json.dumps(alert.get('data', {}))[:800]}

ENRICHMENT DATA:
{enrichment_notes}

Please provide, in plain text with these exact three labeled sections:
1. SUMMARY: One paragraph, plain English, what likely happened.
2. SUGGESTED TRIAGE: One of [Benign test activity / Needs escalation / Likely false positive], with a one-sentence reason.
3. LIKELY MITRE TECHNIQUE: The most probable technique ID and name, or "Unclear" if not determinable.

Keep the whole response under 150 words. This is a DRAFT for a human analyst to review, not a final decision."""


def call_gemini(prompt, max_retries=4):
    if GEMINI_API_KEY.startswith("PASTE"):
        return "[Skipped - Gemini API key not configured]"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    headers = {
        "Content-Type": "application/json",
        "X-goog-api-key": GEMINI_API_KEY,
    }
    body = {
        "contents": [{"parts": [{"text": prompt}]}]
    }

    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=60)
            if resp.status_code == 503:
                last_error = "503 Service Unavailable (model overloaded)"
                wait = attempt * 5
                print(f"   -> Gemini overloaded (attempt {attempt}/{max_retries}), waiting {wait}s...")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            candidates = resp.json().get("candidates", [])
            if not candidates:
                return "[Gemini returned no candidates - check your prompt/quota]"
            parts = candidates[0].get("content", {}).get("parts", [])
            return "".join(p.get("text", "") for p in parts)
        except requests.exceptions.Timeout:
            last_error = "Request timed out"
            wait = attempt * 5
            print(f"   -> Gemini timed out (attempt {attempt}/{max_retries}), waiting {wait}s...")
            time.sleep(wait)
        except requests.exceptions.RequestException as e:
            return f"[Gemini API call failed: {e}]"

    return f"[Gemini API call failed after {max_retries} attempts - last error: {last_error}]"


def main():
    print(f"Pulling {NUMBER_OF_ALERTS_TO_PULL} recent alerts from Wazuh...")
    alerts = get_recent_alerts(NUMBER_OF_ALERTS_TO_PULL)
    print(f"Retrieved {len(alerts)} alerts.\n")

    results = []
    for i, alert in enumerate(alerts, start=1):
        rule_desc = alert.get("rule", {}).get("description", "Unknown")
        print(f"[{i}/{len(alerts)}] Processing: {rule_desc[:70]}")

        indicators = extract_indicators(alert)
        enrichment_notes = []
        if indicators["md5"]:
            enrichment_notes.append(enrich_with_virustotal(indicators["md5"]))
        if indicators["sha256"]:
            enrichment_notes.append(enrich_with_virustotal(indicators["sha256"]))
        if indicators["ip"]:
            enrichment_notes.append(enrich_with_abuseipdb(indicators["ip"]))
        enrichment_text = "\n".join(enrichment_notes) if enrichment_notes else "No hash or IP present in this alert to enrich."

        prompt = build_prompt(alert, enrichment_text)
        ai_draft = call_gemini(prompt)

        results.append({
            "timestamp": alert.get("timestamp", ""),
            "rule_description": rule_desc,
            "rule_level": alert.get("rule", {}).get("level", ""),
            "rule_id": alert.get("rule", {}).get("id", ""),
            "enrichment": enrichment_text,
            "ai_draft_triage": ai_draft,
            "your_final_verdict": "",
        })
        if ai_draft.startswith("[Gemini") or ai_draft.startswith("[Skipped"):
            print(f"   -> FAILED: {ai_draft}\n")
        else:
            print(f"   -> AI draft generated successfully.\n")
        time.sleep(3)

    out_file = f"triage_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"Done. Saved {len(results)} rows to {out_file}")
    print("Open the CSV and fill in 'your_final_verdict' for each row after reviewing the AI's draft.")


if __name__ == "__main__":
    main()
