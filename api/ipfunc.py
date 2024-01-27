from flask import Flask
import re, subprocess

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

import subprocess
import re

def get_conntrack(ip_address=None):
    cmd = ["sudo", "conntrack", "-L"]
    
    if ip_address:
        cmd.extend(["-s", ip_address])

    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout
    lines = output.split('\n')

    conntrack_info = []

    for line in lines:
        if "TIME_WAIT" in line:
            # 정규 표현식을 사용하여 필요한 정보 추출
            match = re.search(r'src=(\d+\.\d+\.\d+\.\d+) dst=(\d+\.\d+\.\d+\.\d+) sport=(\d+) dport=(\d+)', line)
            if match:
                src_ip = match.group(1)
                dst_ip = match.group(2)
                sport = match.group(3)
                dport = match.group(4)
                conntrack_info.append({"src_ip": src_ip, "dst_ip": dst_ip, "sport": sport, "dport": dport})

    return conntrack_info

# export FLASK_APP=ipfunc.py