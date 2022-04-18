#!/usr/bin/env python3
import random
import socket
import sys
import pdb
from scapy.all import IntField, BitField, IP, TCP, Ether, get_if_hwaddr, get_if_list,Packet, srp1, bind_layers, srp1flood,sendp
import csv
import time
count = 0
class Klass(Packet):
    name = "Klass"
    fields_desc=[
        BitField("hash", 0, 32),
        BitField("result", 0, 8),
		BitField("X10", 0, 32),
        BitField("X11", 0, 32),
        BitField("X14", 0, 32),
        BitField("X17", 0, 32),
        BitField("X27", 0, 32),
        BitField("start", 0, 64),
        BitField("truth",0, 8)]

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234:
        pkt.show2()
        sys.stdout.flush()

def main():

    if len(sys.argv)<2:
        print('pass 2 arguments: <destination>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    

    bind_layers(TCP, Klass, dport=1234)

    print("sending on interface %s to %s" % (iface, str(addr)))

    p_pkt = lambda p: print(p)
    global count

    with open("testing-data.csv","r") as test:
        csv_reader = csv.reader(test)
        for row in csv_reader:
            pkt =  Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:00:00')
            pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / Klass(hash=0, X10=int(row[10]),X11=int(row[11]),X14=int(row[14]),X17=int(row[17]),X27=int(row[27]), start=time.time_ns(), truth=int(int(row[-1])/1000))
            sendp(pkt, iface=iface, verbose=False)
            count +=1
            if count == 12000:
                break

if __name__ == '__main__':
    main()
