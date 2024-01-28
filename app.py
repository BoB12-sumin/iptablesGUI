from flask import Flask, render_template, request
import re, subprocess
# import time
from flask import jsonify
from api.ipfunc import get_blocked_ips, get_conntrack, block_kernel_cmd, allow_kernel_cmd, view_kernel_cmd

app = Flask(__name__)

# blocked_ips = []

@app.route("/")
def home():
    blocked_ips = get_blocked_ips()
    return render_template("index.html", blocked_ips=blocked_ips)

conntrack_result = []

@app.route("/monitor", methods=["GET"])
def monitor():
    # GET 요청을 처리하는 기존 코드
    return render_template("monitor.html")

@app.route("/search_ip", methods=["POST"])
def search_ip():
    json_data = request.get_json()
    if json_data and 'ip' in json_data:
        ipoption = json_data['ip']
        conntrack_result = get_conntrack(option=ipoption)
        return jsonify(conntrack_result)
    else:
        return jsonify({"error": "Invalid request"}), 400

@app.route("/block_kernel", methods=["POST"])
def block_kernel():
    json_data = request.get_json()
    print(json_data)
    if json_data and 'cmd' in json_data:
        option = json_data['cmd']
        print("option: ", option)
        result = block_kernel_cmd(option=option)
        return jsonify(str(result))
    else:
        return jsonify({"error": "Invalid request"}), 400


@app.route("/allow_kernel", methods=["POST"])
def allow_kernel():
    json_data = request.get_json()
    if json_data and 'cmd' in json_data:
        option = json_data['cmd']
        result = allow_kernel_cmd(option=option)
        return jsonify(result)
    else:
        return jsonify({"error": "Invalid request"}), 400


@app.route("/log_kernel", methods=["GET"])
def log_kernel():
    result = view_kernel_cmd()
    return jsonify(result)


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
