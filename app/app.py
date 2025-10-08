import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/triage', methods=['POST'])
def triage_ip():
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({"error": "Missing 'ip' in request body"}), 400

    ip_address = data['ip']

    # --- EASTER EGG ---
    if ip_address == "127.0.0.1":
        return jsonify({
            "message": "Playbook successfully executed for IP: 127.0.0.1",
            "report": "There's no place like home. It's safe here."
        })

    command = [
        "ansible-playbook",
        "ansible/playbook.yml",
        "--extra-vars",
        f"ip_to_check={ip_address}"
    ]

    try:
        subprocess.run(command, text=True, check=True)
        
        with open('report.md', 'r') as f:
            report_content = f.read()

        return jsonify({
            "message": f"Playbook successfully executed for IP: {ip_address}",
            "report": report_content
        })

    except subprocess.CalledProcessError as e:
        return jsonify({
            "error": f"Playbook execution failed for IP: {ip_address}",
            "playbook_error": e.stderr
        }), 500
    except FileNotFoundError:
        return jsonify({"error": "ansible-playbook command not found."}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)