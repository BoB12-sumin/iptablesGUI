from flask import Flask, render_template, request
import re, subprocess
# import time
from flask import jsonify

app = Flask(__name__)

# blocked_ips = []

def get_blocked_ips():
    result = subprocess.run(["sudo", "iptables", "-nvL"], capture_output=True, text=True)
    output = result.stdout

    forward_chain = re.search(r'Chain FORWARD.*?Chain', output, re.DOTALL)
    if not forward_chain:
        return []

    forward_chain_output = forward_chain.group(0)

    ips = re.findall(r'DROP\s+all\s+--\s+\*\s+\*\s+(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)|ACCEPT\s+all\s+--\s+\*\s+\*\s+(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)', forward_chain_output)

    flat_ips = [ip for tuple in ips for ip in tuple if ip]

    return flat_ips

@app.route("/")
def home():
    blocked_ips = get_blocked_ips()
    return render_template("index.html", blocked_ips=blocked_ips)

@app.route("/monitor")
def monitor():
    return render_template("monitor.html")

@app.route("/policy")
def policy():
    return render_template("policy.html")

@app.route("/block_ip", methods=["POST"])
def block_ip():
    ip_to_block = request.get_json()['ip']
    # print("차단할 IP:", ip_to_block)
    # blocked_ips.append(ip_to_block)
    subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", ip_to_block, "-j", "DROP"])
    response = {'status': 'success', 'message': 'IP deleted'}
    return jsonify(response)


@app.route("/delete_ip/<int:index>", methods=["POST"])
def delete_ip(index):
    blocked_ips = get_blocked_ips()
    if index < len(blocked_ips):
        ip = blocked_ips.pop(index)
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
        response = {'status': 'success', 'message': 'IP deleted'}
    else:
        response = {'status': 'error', 'message': 'Invalid index'}

    return jsonify(response)


@app.route("/edit_ip/<int:old_index>", methods=["POST"])
def edit_ip(old_index):
    new_ip = request.get_json()['new_ip']
    old_ip = get_blocked_ips()[old_index]
    print(old_index)
    print(old_ip)
    print(new_ip)
    if old_ip in get_blocked_ips():
        blocked_ips = get_blocked_ips()
        blocked_ips[old_index] = new_ip
        subprocess.run(["sudo", "iptables", "-R", "FORWARD", str(old_index + 1), "-s", new_ip, "-j", "DROP"])
        response = {'status': 'success', 'message': 'IP edited'}
    else:
        response = {'status': 'error', 'message': 'IP not found'}

    return jsonify(response)





if __name__ == "__main__":
    app.run(debug=True, threaded=True)
