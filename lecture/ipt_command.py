import subprocess

def get_iptables_rules():
    command = ["sudo iptables -nvL"]
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    print("iptables rules: ")
    print(result.stdout)

def set_iptables_rules(prarms):
    command = ["sudo", "iptables", "-A", "FORWARD"] + prarms
    result = subprocess.run(command)
    print("성공했음: ", result) #여기서 GUI만 만들면 된다.


def read_iptables_logs():
    # command = ["dmesg -T | grep MYDROP"]
    # result = subprocess.run(command, shell=True)
    # print("성공했음: ", result)
    logs = subprocess.check_output(["dmesg"]).decode("utf-8")
    print(logs)


# command1 = "sudo iptables -nvL"
# command2 = "sudo iptables -A FORWARD -p tcp --dport 80 -j DROP"
# command3 = "sudo iptables -F FORWARD"
# command4 = "sudo iptables -D FORWARD -p tcp --dport 80 -j DROP"
# command5 = "sudo iptables -A FORWARD -p tcp --dport 80 -j LOG --log-prefix 'MYDROP: ' --log-level 4"

params1 = ["-p tcp --dport 80 -j LOG --log-prefix 'MYDROP: ' --log-level 4"]
params2= ["-p", "tcp", "--dport", "80", "-j", "DROP"] #걍 귀찮으면 문자열로 해도 됨


set_iptables_rules(params1)
set_iptables_rules(params2)
print("========================================================================")
get_iptables_rules()
print("========================================================================")
read_iptables_logs()
