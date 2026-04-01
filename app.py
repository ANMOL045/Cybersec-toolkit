from flask import Flask, render_template, request
import socket
import re
import math
import os

from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)


def scan_single_port(target_ip, port, timeout=0.3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((target_ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            return {"port": port, "service": service}
    finally:
        s.close()
    return None

# Home page
@app.route('/')
def home():
    return render_template('index.html')


# PORT SCANNER
@app.route('/port', methods=['GET', 'POST'])
def port():
    open_ports = []
    error = None
    target = ""
    start_port = 1
    end_port = 1024
    
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        try:
            start_port = int(request.form.get('start_port', 1) or 1)
            end_port = int(request.form.get('end_port', 1024) or 1024)

            if not target:
                error = "Please enter a valid host/IP."
            elif start_port < 1 or end_port > 65535 or start_port > end_port:
                error = "Invalid port range. Use 1-65535 and keep start <= end."
            else:
                target_ip = socket.gethostbyname(target)
                ports_to_scan = list(range(start_port, end_port + 1))
                with ThreadPoolExecutor(max_workers=200) as executor:
                    results = executor.map(lambda p: scan_single_port(target_ip, p), ports_to_scan)
                open_ports = [item for item in results if item is not None]
        except socket.gaierror:
            error = "Unable to resolve host. Please check the target and try again."
        except ValueError:
            error = "Port values must be numbers."
    
    return render_template(
        'port.html',
        ports=open_ports,
        error=error,
        target=target,
        start_port=start_port,
        end_port=end_port,
    )


# PASSWORD CHECKER
@app.route('/password', methods=['GET', 'POST'])
def password():
    result = None
    feedback = []
    strength = None
    entropy = 0
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        score = 0
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Use at least 8 characters.")
        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Add uppercase letters.")
        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Add lowercase letters.")
        if re.search(r"[0-9]", password):
            score += 1
        else:
            feedback.append("Add numbers.")
        if re.search(r"[!@#$%^&*]", password):
            score += 1
        else:
            feedback.append("Add special characters like !@#$%^&*.")

        charset_size = 0
        if re.search(r"[a-z]", password):
            charset_size += 26
        if re.search(r"[A-Z]", password):
            charset_size += 26
        if re.search(r"[0-9]", password):
            charset_size += 10
        if re.search(r"[^a-zA-Z0-9]", password):
            charset_size += 32

        if password and charset_size > 0:
            entropy = round(len(password) * math.log2(charset_size), 1)

        if score <= 2:
            strength = "Weak"
        elif score == 3 or score == 4:
            strength = "Moderate"
        else:
            strength = "Strong"
        
        result = score
    
    return render_template('password.html', result=result, feedback=feedback, strength=strength, entropy=entropy)


if __name__ == "__main__":
  port = int(os.environ.get("PORT", 8080))
app.run(host="0.0.0.0", port=port)

@app.route('/ip', methods=['GET', 'POST'])
def ip_lookup():
    data = None

    if request.method == 'POST':
        ip = request.form['ip']
        
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}")
            data = res.json()
        except:
            data = {"error": "Invalid request"}

    return render_template('ip.html', data=data)

