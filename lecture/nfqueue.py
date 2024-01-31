from netfilterqueue import NetfilterQueue
from scapy.all import IP,TCP, Raw
#nfqueue 인스턴스 생성

nfqueue = NetfilterQueue()

target_url = "10.0.2.3"

def packet_handler(packet):
    print("packet processed ", packet)
    
    ip_packet = IP(packet.get_payload())
    print("src IP: ", ip_packet.src)
    print("dst IP: ", ip_packet.dst)
    #packet.drop

    tcp_header = ip_packet[TCP]
    print("src port: ", tcp_header.sport)
    print("dst port: ", tcp_header.dport)

    http_request = IP(dst=target_url)/ TCP(dport=80) / Raw(load="GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_url)) #오리지날 데이터 패킷 그대로, Raw 데이터 가져오는 것
    print("http 요청: ", http_request

    if ip_packet.haslayer(Raw):
        payload = ip_packet[Raw].load
        modified_payload = payload.replace(b"bob", b"BoB")
        ip_packet[Raw].load = modified_payload
        packet.set_payload(bytes(ip_packet))

    packet.accept()

#만든 큐를, 커널에 등록 요청 해야됨, 0번 큐, 큐 번호 의미 없음. 1번에서 8번까지
nfqueue.bind(0, packet_handler)

print("시작 중..")
nfqueue.run()

nfqueue.unbind()
