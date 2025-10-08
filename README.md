# Executable Tutorial: Building a Mini-SOAR with Ansible, Docker, and Flask

- **Names and KTH ID:** Leo Hansson Åkerberg (leo3@kth.se)
- **Deadline:** Task 3
- **Category:** Executable tutorial

---

## Motivation (Why it matters for DevOps?)

In a modern DevOps culture, the principle of automation extends beyond deployment pipelines into operational domains, including security. This is the core of **DevSecOps**. This tutorial is motivated by the need to automate repetitive, high-volume tasks faced by Security Operations Centers (SOCs) to enable faster response times and reduce analyst burnout. By building a miniature Security Orchestration, Automation, and Response (SOAR) tool, we demonstrate key DevOps principles:
* **Automation:** Automating the entire security triage workflow from alert to response.
* **Infrastructure as Code (IaC):** Using Ansible and Docker to define and manage our security response environment in code.
* **APIs and Integration:** Building a cohesive toolchain by integrating multiple services (Flask, external APIs, Docker) via APIs.

## Background

A Security Operations Center (SOC) is a centralized unit that deals with security issues. Analysts are often flooded with thousands of alerts per day, many of which are false positives. A common first step for an alert involving a suspicious IP address is "threat intelligence enrichment"—finding out what is known about that IP. A SOAR platform helps automate this kind of workflow. In this tutorial, we will build our own lightweight version using common DevOps tools.

## Intended Learning Outcomes (ILOs)

Upon completing this tutorial, you will be able to:
1.  Understand the basic principles of a SOAR workflow (Trigger, Enrich, Respond).
2.  Use Ansible to orchestrate a workflow that calls external scripts and APIs.
3.  Manage the state of a running Docker container using Ansible.
4.  Create a simple API endpoint with Flask to trigger an automation playbook.

## Architecture (Illustrated)

The tutorial implements the following automated workflow:

![SOAR Workflow](soar_workflow.png)

## How to Run This Tutorial (Executable & Pedagogical)

This tutorial is designed to be fully executable in your browser using mybinder.org.

**Step 1: Launch the Environment**

Click the "launch binder" badge below. This will take a few minutes as it builds the Docker environment defined by our configuration files.

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/YOUR_GITHUB_USERNAME/YOUR_REPO_NAME/main) 
**Important:** You must replace `YOUR_GITHUB_USERNAME` and `YOUR_REPO_NAME` in the badge link above with your actual GitHub details!

**Step 2: Add API Keys (Handling the `no-account` requirement)**

The `start` script will automatically prepare the environment. However, to interact with external APIs, you must provide your own keys.

1.  When the Binder environment loads, you will be in a terminal. A `secrets.yml` file already exists.
2.  Double-click the `secrets.yml` file in the file browser on the left.
3.  Paste your API keys into the file, like so:
    ```yaml
    abuseipdb_key: YOUR_ABUSEIPDB_KEY_HERE
    virustotal_key: YOUR_VIRUSTOTAL_KEY_HERE
    ```
4.  Save the file (`Ctrl+S`).

**Step 3: Test the SOAR Workflow**

The `start` script has already launched the Flask API server in the background. You can now interact with it from your terminal.

1.  **Triage a MALICIOUS IP:** Copy and paste the following command into your terminal and press Enter.

    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"ip": "185.191.171.12"}' [http://127.0.0.1:5000/triage](http://127.0.0.1:5000/triage)
    ```
    You will see a JSON response containing a detailed report indicating the IP is malicious.

2.  **Verify the Block:** The playbook should have blocked this IP. Check the contents of the blocklist:
    ```bash
    cat nginx/blocklist.conf
    ```
    You should see the line `deny 185.191.171.12;`.

3.  **Triage a GOOD IP:** Now, let's try a known-good IP.
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"ip": "8.8.8.8"}' [http://127.0.0.1:5000/triage](http://127.0.0.1:5000/triage)
    ```
    You will get a report showing this IP is clean. If you check `nginx/blocklist.conf` again, it will now be empty, as the playbook clears it for each run and did not find a reason to block this IP.

## Easter Egg

There's no place like home. Try triaging the localhost IP address to see a special message.
```bash
curl -X POST -H "Content-Type: application/json" -d '{"ip": "127.0.0.1"}' [http://127.0.0.1:5000/triage](http://127.0.0.1:5000/triage)
