import pcap
sniffer = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)


import socket
import struct
import random
import time

ICMP_CODE = socket.getprotobyname('icmp')

icmpclient="36.190.160.236"
me_in_local="10.100.23.247"

sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
sock.bind(("", 55555))
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
    ICMP_ECHO_REQUEST=8 #Код типа ICMP - в нашем случае ECHO
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = data+b"\x00\x11\x22"*(len(data)%2)

    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, 1)
    return header + data

def send(dest_addr,data):
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    host = socket.gethostbyname(dest_addr)

    #packet_id = random.randint(0,65535)
    #packet = create_packet(packet_id,data)
    
    while data:
        sent = my_socket.sendto(data, (dest_addr, 1))
        data = data[sent:]

    return my_socket

global addr
addr=("127.0.0.1",123)
def vpn2tun(sock):
	global addr
	while 1:
		d,a=sock.recvfrom(9999)
		addr=a
		print(len(d),a)
		try:
			send(icmpclient,create_packet(123,d))
		except Exception as e: print(e)
		#time.sleep(0.1)

import threading
t=threading.Thread(target=vpn2tun,args=(sock,))
t.start()

for _,p in sniffer:
	if p[23]==1 and p[34]==0 and socket.inet_ntoa(p[30:34])==me_in_local:
		print(len(p[42:].removesuffix(b"\x00\x11\x22")))
		sock.sendto(p[42:].removesuffix(b"\x00\x11\x22"), addr)
