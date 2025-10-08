# Building a Mini-SOAR with Ansible, Docker, and Flask to triage suspicious IP addresses

Welcome to this hands-on tutorial where you will build and interact with a miniature, event-driven SOAR (Security Orchestration, Automation, and Response) pipeline. You'll learn how to automate security workflows by integrating common DevOps tools like Ansible, Docker, and Flask to triage and respond to threats in real time.

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

---

### **Interactive Walkthrough**

#### **A Note on Secrets**
This project requires API keys to function. These keys are kept secret and are not committed to the repository. In order to obtain the API keys, you need to decrypt `secrets.yml.gpg` by using the corresponding private GPG key. For this interactive tutorial, you will be providing your own keys in Step 2.

#### **Step 1: Launch the Environment**
Click the "launch binder" badge below. This will take a few minutes as it builds the complete, pre-configured environment. The `start` script will automatically run, preparing all the necessary services in the background.

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/leovalentin2/devops-soar/main)

#### **Step 2: Take a Look Around**
When the environment loads, you will be in a ready-to-use terminal. Let's verify the tools we have at our disposal. Run the following commands:

    ```bash
        python3 --version
        docker --version
        ansible --version
    ```

You can see all our core technologies are installed. Our orchestrator is Ansible, a powerful tool for automation. But what is it actually doing? Let's look at how the code is written for the playbook.

    ```yaml
    - name: Threat Intelligence Gathering and Response Playbook
    hosts: localhost
    connection: local
    # ...
    tasks:
        - name: Ensure blocklist is clean before run
        ansible.builtin.copy:
            content: ""
            dest: ../nginx/blocklist.conf

        - name: Run AbuseIPDB enrichment script
        command: "python3 ../app/scripts/check_abuseipdb.py {{ ip_to_check }}"
        register: abuse_raw_result

        - name: Parse AbuseIPDB JSON output
        set_fact:
            abuse_result: "{{ abuse_raw_result.stdout | from_json }}"
        
        # ... (VirusTotal tasks are very similar) ...

        - name: Block malicious IP if abuse score is high
        ansible.builtin.lineinfile:
            path: ../nginx/blocklist.conf
            line: "deny {{ ip_to_check }};"
        when: abuse_result.abuseConfidenceScore | int > 90 # We can change this score depending on our risk tolerance
    ```

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

There's no place like home! Try triaging the localhost IP address to see a special message.
```bash
curl -X POST -H "Content-Type: application/json" -d '{"ip": "127.0.0.1"}' [http://127.0.0.1:5000/triage](http://127.0.0.1:5000/triage)
```
