#!/usr/bin/env python3
import random
import socket
import sys
import pdb
from scapy.all import IntField, BitField, IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp,Packet
import pandas as pd

class Klass(Packet):
    name = "Klass"
    fields_desc=[
        BitField("hash", 0, 32),
        BitField("result", 0, 1),
		BitField("X10", 0, 32),
        BitField("X12", 0, 32),
        BitField("X14", 0, 32),
        BitField("X17", 0, 32)]

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

def main():

    if len(sys.argv)<2:
        print('pass 2 arguments: <destination>')
        exit(1)
    df = pd.read_csv("testing-data.csv")
    inputdata = df.iloc[:,[10,12,14,17]]
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    

    print("sending on interface %s to %s" % (iface, str(addr)))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    for index,row in inputdata,iterrows():
        pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / Klass(hash=0, X10=row['V10'],X12=row['V12'],X14=row['V14'],X17=row['V17'])
        sendp(pkt, iface=iface, verbose=False)
#    pdb.set_trace()
        break
    print(pkt)
    pkt.show2()
	 
    


if __name__ == '__main__':
    main()
