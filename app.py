from flask import Flask, render_template, request
import re, subprocess
# import time
from flask import jsonify

app = Flask(__name__)

blocked_ips = []

@app.route("/")
def home():
    return render_template("index.html", blocked_ips=blocked_ips)

@app.route("/block_ip", methods=["POST"])
def block_ip():
    ip_to_block = request.get_json()['ip']
    print("차단할 IP:", ip_to_block)
    blocked_ips.append(ip_to_block)
    subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", ip_to_block, "-j", "DROP"])
    response = {'status': 'success', 'message': 'IP deleted'}
    return jsonify(response)

@app.route("/delete_ip/<ip>", methods=["POST"])
def delete_ip(ip):
    print("삭제할 IP:", ip)
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
        response = {'status': 'success', 'message': 'IP deleted'}
    else:
        print("리스트에 IP가 존재하지 않음:", ip)
        response = {'status': 'error', 'message': 'IP not found'}
    return jsonify(response)

@app.route("/edit_ip/<old_ip>", methods=["POST"])
def edit_ip(old_ip):
    new_ip = request.get_json()['new_ip']
    if old_ip in blocked_ips:
        blocked_ips[blocked_ips.index(old_ip)] = new_ip
        subprocess.run(["sudo", "iptables", "-R", "FORWARD", str(blocked_ips.index(new_ip) + 1), "-s", new_ip, "-j", "DROP"])
        response = {'status': 'success', 'message': 'IP edited'}
    else:
        response = {'status': 'error', 'message': 'IP not found'}

    return jsonify(response)




if __name__ == "__main__":
    app.run(debug=True)