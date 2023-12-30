import pcap
sniffer = pcap.pcap(name='\\Device\\NPF_{A99EFA4B-B984-4E10-A34C-B15B161A1697}', promisc=True, timeout_ms=50)


import socket
import struct
import random

ICMP_CODE = socket.getprotobyname('icmp')

icmpclient="83.235.46.166"
me_in_local="192.168.88.15"
sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
#sock.setsockopt(socket.SOL_SOCKET, 25, b"eth0")
sock.bind(("127.0.0.1", 55555))
import socket
import struct

ICMP_CODE = 1



def checksum(source_string):
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1]*256+source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer



def create_packet(id,data):
    
    ICMP_ECHO_REQUEST=0 #Код типа ICMP - в нашем случае ECHO
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = data+b"\x00\x11\x22"*(len(data)%2)

    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, 1)
    return header + data



def send(dest_addr,pkt):
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    host = socket.gethostbyname(dest_addr)

    while pkt:
        sent = my_socket.sendto(pkt, (dest_addr, 1))
        pkt = pkt[sent:]

    return my_socket

def vpn2tun(sock):
	while 1:
		global id
		send(icmpclient,create_packet(id,sock.recv(9999)))

id=123
import threading
t=threading.Thread(target=vpn2tun,args=(sock,))
t.start()

for _,p in sniffer:
    #print(p)
    if p[23]==1 and socket.inet_ntoa(p[30:34])==me_in_local and p[34]==8:
        id=int.from_bytes(p[38:40],"little",signed=False)
        print(len(p[42:].removesuffix(b"\x00\x11\x22")))
        sock.sendto(p[42:].removesuffix(b"\x00\x11\x22"),("127.0.0.1", 27005))
