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



def get_conntrack(option=None):
    cmd = ["sudo", "conntrack", "-L"]

    print(option)
    if option:
        ooptlist=option.split(" ")
        cmd.extend(ooptlist)
        print(cmd)

    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout
    lines = output.split('\n')

    print(result)

    conntrack_info = []

    for line in lines:
        if "TIME_WAIT" in line:
            match = re.search(r'src=(\d+\.\d+\.\d+\.\d+) dst=(\d+\.\d+\.\d+\.\d+) sport=(\d+) dport=(\d+)', line)
            if match:
                src_ip = match.group(1)
                dst_ip = match.group(2)
                sport = match.group(3)
                dport = match.group(4)
                conntrack_info.append({"src_ip": src_ip, "dst_ip": dst_ip, "sport": sport, "dport": dport})

    return conntrack_info


def block_kernel_cmd(option=None):
    optlist=option.split(" ")
    cmd1 = ["sudo", "iptables", "-A", "FORWARD"] + optlist + ["-j", "LOG", "--log-prefix", "MYDROP: ", "--log-level", "4"]
    print(cmd1)

    result1 = subprocess.run(cmd1)
    print("{} 성공 {}".format(cmd1, result1))

    cmd2 = ["sudo", "iptables", "-A", "FORWARD"] + optlist + ["-j", "DROP"]
    print(cmd2)

    result2 = subprocess.run(cmd2)
    print("{} 성공 {}".format(cmd2, result2))

    return result2


def allow_kernel_cmd(option=None):
    optlist=option.split(" ")
    cmd1 = ["sudo", "iptables", "-D", "FORWARD"] + optlist + ["-j", "LOG", "--log-prefix", "MYDROP: ", "--log-level", "4"]
    print(cmd1)

    result1 = subprocess.run(cmd1)
    print("{} 성공 {}".format(cmd1, result1))

    cmd2 = ["sudo", "iptables", "-D", "FORWARD"] + optlist + ["-j", "DROP"]
    print(cmd2)

    result2 = subprocess.run(cmd2)
    print("{} 성공 {}".format(cmd2, result2))

    return result2

def view_kernel_cmd():
    try:
        logs = subprocess.check_output("dmesg -T | grep MYDROP", shell=True).decode("utf-8")
        print(logs)
        return logs
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return ""



# export FLASK_APP=ipfunc.py