import os
import sys
import requests
import json
from pathlib import Path # Import the pathlib library
import time

# --- Configuration ---
try:
    # __file__ is the path to the current script (.../app/scripts/check_abuseipdb.py)
    # .parent gives the directory (app/scripts/)
    # .parent.parent gives the project root (.../devops-soar/)
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    SECRETS_FILE = PROJECT_ROOT / 'secrets.yml'
    
    API_KEY = ''
    with open(SECRETS_FILE, 'r') as f:
        for line in f:
            if 'virustotal_key:' in line:
                API_KEY = line.split(':')[1].strip()
                break
except FileNotFoundError:
    print(json.dumps({"error": f"Secrets file not found at {SECRETS_FILE}"}))
    sys.exit(1)

if not API_KEY:
    print(json.dumps({"error": "VirusTotal API key not found or is empty in secrets.yml"}))
    sys.exit(1)

# Endpoint URL for VirusTotal IP reports
URL = 'https://www.virustotal.com/api/v3/ip_addresses/'

# --- Main Script Logic ---
def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No IP address provided."}))
        sys.exit(1)

    ip_address = sys.argv[1]

    headers = {
        'accept': 'application/json',
        'x-apikey': API_KEY
    }

    try:
        response = requests.get(f"{URL}{ip_address}", headers=headers)
        response.raise_for_status()
        
        decoded_response = response.json()
        
        # Extract the relevant attributes from the 'data' part of the response
        attributes = decoded_response.get('data', {}).get('attributes', {})
        
        # We only want a few key pieces of info from VirusTotal
        stats = attributes.get('last_analysis_stats', {})
        owner = attributes.get('as_owner', 'N/A')
        
        # The free API is rate-limited to 4 lookups per minute. This small sleep helps.
        time.sleep(1) 
        
        result = {
            "as_owner": owner,
            "harmless": stats.get('harmless', 0),
            "malicious": stats.get('malicious', 0),
            "suspicious": stats.get('suspicious', 0),
            "undetected": stats.get('undetected', 0)
        }
        
        print(json.dumps(result))

    except requests.exceptions.RequestException as e:
        print(json.dumps({"error": f"API request failed: {e}"}))
        sys.exit(1)
    except json.JSONDecodeError:
        print(json.dumps({"error": "Failed to decode JSON response from API."}))
        sys.exit(1)


if __name__ == "__main__":
    main()