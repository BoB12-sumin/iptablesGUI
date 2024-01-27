from flask import Flask, render_template, request
import re, subprocess
# import time
from flask import jsonify
from api.ipfunc import get_blocked_ips, get_conntrack

app = Flask(__name__)

# blocked_ips = []

@app.route("/")
def home():
    blocked_ips = get_blocked_ips()
    return render_template("index.html", blocked_ips=blocked_ips)

@app.route("/monitor")
def monitor():
    result=get_conntrack()

    return render_template("monitor.html", logs=result)

@app.route("/policy")
def policy():
    return render_template("policy.html")

@app.route("/block_ip", methods=["POST"])
def block_ip():
    ip_to_block = request.get_json()['ip']
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
