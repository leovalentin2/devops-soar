import os
import sys
import requests
import json
from pathlib import Path # Import the pathlib library

# --- Configuration ---
try:
    # __file__ is the path to the current script (.../app/scripts/check_abuseipdb.py)
    # .parent gives the directory (app/scripts/)
    # .parent.parent gives the project root (.../devops-soar/)
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    SECRETS_FILE = PROJECT_ROOT / 'secrets.yml'
    
    API_KEY = ''
    with open(SECRETS_FILE, 'r') as f:
        # Simple parsing for "abuseipdb_key: API_KEY"
        for line in f:
            if 'abuseipdb_key:' in line:
                API_KEY = line.split(':')[1].strip()
                break
except FileNotFoundError:
    print(json.dumps({"error": f"Secrets file not found. Looked at: {SECRETS_FILE}"}))
    sys.exit(1)

if not API_KEY:
    print(json.dumps({"error": "AbuseIPDB API key not found or is empty in secrets.yml"}))
    sys.exit(1)

# Endpoint URL for the AbuseIPDB API
URL = 'https://api.abuseipdb.com/api/v2/check'

# --- Main Script Logic ---
def main():
    # Check if an IP address was provided as a command-line argument
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No IP address provided."}))
        sys.exit(1)

    ip_address = sys.argv[1]

    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }

    try:
        response = requests.get(url=URL, headers=headers, params=querystring)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        
        decoded_response = response.json()
        
        # We only care about the 'data' part of the response.
        # Let's print it as a JSON string so Ansible can easily parse it.
        print(json.dumps(decoded_response.get('data', {})))

    except requests.exceptions.RequestException as e:
        print(json.dumps({"error": f"API request failed: {e}"}))
        sys.exit(1)
    except json.JSONDecodeError:
        print(json.dumps({"error": "Failed to decode JSON response from API."}))
        sys.exit(1)


if __name__ == "__main__":
    main()