# Building a Mini-SOAR with Ansible, Docker, and Flask to triage suspicious IP addresses

- **Names and KTH ID:** Leo Hansson Åkerberg (leo3@kTH.se)
- **Deadline:** Task 3
- **Category:** Executable tutorial

---

Welcome to this hands-on tutorial where you will build a miniature, event-driven SOAR (Security Orchestration, Automation, and Response) pipeline. You'll learn how to automate security workflows by integrating common DevOps tools like Ansible, Docker, and Flask to triage and respond to threats in real time.

### Learning Outcomes
By completing this tutorial, you will:
- Understand the core principles of a SOAR workflow (Trigger, Enrich, Respond).
- Get a grasp of Ansible, orchestrating a security process that calls external scripts and APIs.
- Manage the state of a running Docker container with Ansible to enforce a security policy.
- Build a simple Flask API endpoint to act as a webhook, making your automation triggerable by other services.
- Gain practical experience in building a complete, automated DevSecOps toolchain.

### Why This Matters for DevSecOps
Traditional security models, where testing happens at the end of the development cycle, are too slow for modern CI/CD. DevSecOps is about integrating automated security practices directly into the development and operations pipeline. This project is a practical example of this philosophy. By automating security responses, we can:
- **Detect and Respond Faster:** Reduce the time from alert to action from hours to seconds.
- **Reduce Human Toil:** Free up security analysts from repetitive, manual tasks like IP lookups.
- **Enforce Consistent Security:** Ensure that every alert is handled using a predefined, version-controlled process (an Ansible playbook).
- **Enable "Security as Code":** Treat your security workflows as code, allowing for versioning, peer review, and continuous improvement.

### Tutorial Architecture
This tutorial implements a complete, event-driven SOAR workflow. The process is initiated by a simulated alert, which triggers a series of automated enrichment and response actions.

![SOAR Workflow](soar_workflow.png)

### Learning Environment
You will work in a pre-configured, browser-based environment on mybinder.org containing:
- **Ansible:** The orchestration engine for our workflow.
- **Docker:** The container platform used to run our web server (Nginx).
- **Flask (Python):** The web framework for our API trigger.
- **External APIs:** Free threat intelligence feeds from AbuseIPDB and VirusTotal.

### Tutorial Flow
**Phase 1: Setup (Automated)**
- The `start` script will automatically prepare the environment, start the Docker service, and launch the Nginx and Flask servers.

**Phase 2: Manual Trigger and Automated Response**
- You will act as the "tripwire" (for example, an IDS) by manually sending an alert to the Flask API.
- You will then observe the fully automated enrichment and response workflow execute.

### Expected Duration
- **Total Time:** 10-15 minutes
- **Environment Build Time:** 3-5 minutes (first launch on mybinder.org)
- **Interactive Tutorial:** 5-10 minutes

### Prerequisites
- Familiarity with the command-line interface.
- General knowledge of web applications and security concepts

---

### **Let's Begin: Executing the Tutorial**

**Step 1: Launch the Environment**

Click the "launch binder" badge below. This will take a few minutes as it builds the complete environment.

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/YOUR_GITHUB_USERNAME/YOUR_REPO_NAME/main) 

**Step 2: Add API Keys**

To satisfy the `no-account` requirement, this tutorial requires you to use your own free API keys.

1.  When the Binder environment loads, you will be in a terminal. A `secrets.yml` file already exists in the file browser on the left.
2.  Double-click the `secrets.yml` file to open it.
3.  Paste your API keys into the file, like so, then save it (`Ctrl+S` or `File > Save`):
    ```yaml
    abuseipdb_key: YOUR_ABUSEIPDB_KEY_HERE
    virustotal_key: YOUR_VIRUSTOTAL_KEY_HERE
    ```

**Step 3: Test the SOAR Workflow**

The `start` script has already launched all necessary services. You can now interact with the API from your terminal.

1.  **Triage a MALICIOUS IP:** Copy and paste the following command into your terminal to simulate an alert for a known bad IP.
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"ip": "185.191.171.12"}' [http://127.0.0.1:5000/triage](http://127.0.0.1:5000/triage)
    ```
    You will see a JSON response containing a detailed report indicating the IP is malicious.

2.  **Verify the Block:** The playbook should have blocked this IP. Check the blocklist's contents:
    ```bash
    cat nginx/blocklist.conf
    ```
    You should see the line `deny 185.191.171.12;`.

3.  **Triage a GOOD IP:** Now, let's try a known-good IP to see the conditional logic in action.
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"ip": "8.8.8.8"}' [http://127.0.0.1:5000/triage](http://127.0.0.1:5000/triage)
    ```
    You will get a report showing this IP is clean. The `nginx/blocklist.conf` file will now be empty, as the playbook clears it for each run and did not find a reason to block this IP.

### Easter Egg

There's no place like home. Try triaging the localhost IP address to see a special message.
```bash
curl -X POST -H "Content-Type: application/json" -d '{"ip": "127.0.0.1"}' [http://127.0.0.1:5000/triage](http://127.0.0.1:5000/triage)
