from flask import Flask, render_template, request
import re, subprocess
# import time
# from flask import jsonify

app = Flask(__name__)

blocked_ips = []

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/block_ip", methods=["POST"])
def block_ip():
   ip_to_block = request.form.get("ip")
   print("차단할 IP:", ip_to_block)
   blocked_ips.append(ip_to_block)

   subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", ip_to_block, "-j", "DROP"])
   return render_template("index.html", blocked_ips=blocked_ips)

@app.route("/unblock_ip/<ip>", methods=["POST"])
def delete_ip(ip):
    print("삭제할 IP:", ip)
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
    else:
        print("리스트에 IP가 존재하지 않음:", ip)
    
    return render_template("index.html", blocked_ips=blocked_ips)




if __name__ == "__main__":
    app.run(debug=True)