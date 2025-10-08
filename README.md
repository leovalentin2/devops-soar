# Building a Mini-SOAR with Ansible, Docker, and Flask to triage suspicious IP addresses

Welcome to this hands-on tutorial where you will build and interact with an event-driven SOAR (Security Orchestration, Automation, and Response) pipeline. You will learn how to automate security workflows by integrating common DevOps tools like Ansible, Docker, and Flask to triage and respond to threats in real time.

### Intended Learning Outcomes
By completing this tutorial, you will:
- Understand the core principles of a SOAR workflow (Trigger, Enrich, Respond).
- Get a grasp of Ansible, orchestrating a security process that calls external scripts and APIs.
- Manage the state of a running Docker container with Ansible to enforce a security policy.
- Utilize a simple Flask API endpoint acting as a webhook, making your automation triggerable by other services.
- Gain practical experience in working with a complete, automated DevSecOps toolchain.

### Why This Matters for DevSecOps
Traditional security models, where testing happens at the end of the development cycle, are too slow for modern CI/CD. DevSecOps is about integrating automated security practices directly into the development and operations pipeline. This project is a practical example of this philosophy. By automating security responses, we can:
- **Detect and Respond Faster:** Reduce time to action after an alert has been triggered.
- **Reduce manual labor:** Free up security analysts from repetitive, manual tasks like IP lookups.
- **Enforce Consistent Security:** Ensure that every alert is handled using a standardized, predefined process (an Ansible playbook).
- **Enable "Security as Code":** Treat your security workflows as code. This allows versioning, peer review, and continuous improvement.

### Tutorial Architecture
In this tutorial you will work with a complete, event-driven SOAR. The process is initiated by a simulated alert, which triggers a series of automated enrichment and response actions outlined in the flowchart below.

![SOAR Workflow](soar_workflow.png)

### Understanding the Core Technologies

Before we begin with the tutorial, let us explore some key concepts.

#### **What is SOAR?**
SOAR stands for **Security Orchestration, Automation, and Response**. It is not a single tool, but more like a philosophy for connecting security tools to automate workflows.
* **Orchestration:** This stands for the "connecting" part of our workflow. In this tutorial, the Ansible playbook acts as the orchestrator, connecting a Flask API together with Python scripts, external APIs, and a Docker container into a single, effective process.
* **Automation:** Once the workflow is triggered, it runs from start to finish without human intervention. This is what allows for near-instantaneous response times.
* **Response:** This is the final action taken by the system. In our case, the response is to add a malicious IP to a blocklist and reload our web server, but in a real-world scenario, it could also be to quarantine a machine, disable a user account, or create a ticket in a helpdesk system.

#### **What is Ansible and why do we use it?**
Ansible is a DevOps tool that typically is used for configuration management and application deployment, but its design makes it a good choice for SOAR orchestration.
* **Human-Readable Playbooks:** Tasks that we want to automate with Ansible are defined in YAML files called "Playbooks." As you'll see in our code, they are structured like a simple list of tasks, making them easy to read and understand.
* **Powerful Modules:** An important part of Ansible is its large library of modules. It contains pre-built pieces of code that perform specific actions. We use the `command` module to run our scripts, the `template` module to generate reports, and the `docker_container` module to manage our Nginx server running in Docker.
* **State Management:** This is a key principle in DevOps and means you can run the playbook many times and the outcome will always be the same: one running container. It makes the automation safe, reliable, and predictable.

---

### **The Interactive Walkthrough**

#### **A Note on Secrets**
This project requires API keys to function. These keys should be kept secret and are not committed to the repository. For this reason, a `secrets.yml.gpg` is included, which can be decrypted by using the corresponding private GPG key. For this interactive tutorial, you will be pasting these API keys into a yml-file in Step 4.

#### **Step 1: Launch the Environment**
Click the "launch binder" badge below. This will take a few minutes to build the environment and will open in a new tab.

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/leovalentin2/devops-soar/main)

#### **Step 2: Open a Terminal**
When the environment loads, you will see the JupyterLab interface shown below. In the main "Launcher" tab, find the "Other" section and click the **Terminal** icon. This will open a new tab with a command-line interface. All subsequent `bash` commands will be run here.

![JupyterLab Launcher](launcher_image_placeholder.png) 

#### **Step 3: Start the Background Services**
This tutorial requires two services to be running in the background: the Docker engine and our Flask API server.

1.  **Start the Docker Service:** Copy and paste the following command into the terminal. This starts the Docker daemon in the background so Ansible can communicate with it.
    ```bash
    sudo dockerd > /dev/null 2>&1 &
    ```
2.  **Start the Flask API Server:** Now, start our Flask application, also in the background. This will listen for our `curl` commands.
    ```bash
    python3 app/app.py > flask.log 2>&1 &
    ```
    After running these two commands, please wait about **10 seconds** for the services to initialize properly before proceeding to the next step.

#### **Step 4: Create and Populate the Secrets File**
The services are running, but they need API keys to function. We will now create the `secrets.yml` file.

1.  In the file browser on the left-hand side of the JupyterLab interface, right-click on the empty space in the file list and select **New File**.
2.  An untitled file will be created. Rename it to exactly `secrets.yml` and press `Enter`.
3.  Double-click your new `secrets.yml` file. It will open in the editor pane.
4.  Paste the following content into the file, replacing the placeholders with your actual keys.
    ```yaml
    abuseipdb_key: YOUR_ABUSEIPDB_KEY_HERE
    virustotal_key: YOUR_VIRUSTOTAL_KEY_HERE
    ```
5.  Save the file by pressing `Ctrl+S` or selecting `File > Save` from the top menu.

#### **Step 5: Take a Look Around**
Since your environment is now fully set up and ready, let's verify the tools we have at our disposal. Run the following commands:

```bash
python3 --version
docker --version
ansible --version
```

You can see all our core technologies are installed. Our orchestrator is **Ansible**. But what is it actually doing? Let us dive a bit deeper into the playbook.

In the file browser on the left, open `ansible/playbook.yml` and carefully study its contents:

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
    
    # ... (VirusTotal tasks are similar) ...

    - name: Block malicious IP if abuse score is high
      ansible.builtin.lineinfile:
        path: ../nginx/blocklist.conf
        line: "deny {{ ip_to_check }};"
      when: abuse_result.abuseConfidenceScore | int > 90 # Value can be changed, depending on risk tolerance
```

In this file, Ansible defines a series of **tasks**. It runs our Python script using the `command` module, captures the script's output with `register`, and then uses `set_fact` to parse that output into a structured variable (`abuse_result`). The most critical piece is the `when:` clause, which makes our automation "intelligent" by only running the blocking task if the abuse score is greater than 90.

#### **Step 6: Triage a Malicious IP**
Now, let's trigger the workflow. We will act as an IDS and send an alert about a known malicious IP to our Flask API.

```bash
curl -X POST -H "Content-Type: application/json" -d '{"ip": "185.191.171.12"}' http://127.0.0.1:5000/triage
```

The terminal will return a JSON object containing the full threat intelligence report for this IP.

#### **Step 7: Verify the Block & Understand the Workflow**
So, what just happened? The playbook executed the "Response" part of our SOAR workflow. Let's verify it.

```bash
cat nginx/blocklist.conf
```

You will see the line `deny 185.191.171.12;`. The IP has been blocked.

**Under the hood - what happened with the request?**
1.  Your `curl` command sent the IP to the **Flask API**.
2.  The Flask app triggered the **Ansible Playbook**.
3.  The playbook queried **AbuseIPDB** and found an `abuseConfidenceScore` of 100.
4.  The `when: abuse_result.abuseConfidenceScore | int > 90` condition evaluated to **TRUE**.
5.  Ansible therefore executed the final tasks: it updated the `blocklist.conf` file and then ran `docker exec` to command the Nginx container to reload its configuration, making the block take effect instantly.

#### **Step 8: Triage a Good IP**
Now, let us see how our system handles a non-threatening IP. This will test the playbook's conditional logic.

```bash
curl -X POST -H "Content-Type: application/json" -d '{"ip": "8.8.8.8"}' http://127.0.0.1:5000/triage
```

You will receive a clean report. The `abuseConfidenceScore` will be 0. Since 0 is not greater than 90, the `when:` condition in the playbook will evaluate to **FALSE**. Therefore, the blocking tasks should be skipped.

#### **Step 9: Verify No Action Was Taken**
Let us check the blocklist again.

```bash
cat nginx/blocklist.conf
```

As predicted, the file is now empty. The playbook ran its initial "clean slate" task but correctly skipped the tasks to add the IP and reload Nginx. This proves our intelligent automation is working. Congratulations! You have now gained some practical experience related to SOAR workflows!

### **Easter Egg**
Home, sweet home. Try triaging the localhost IP address.

```bash
curl -X POST -H "Content-Type: application/json" -d '{"ip": "127.0.0.1"}' http://127.0.0.1:5000/triage
```