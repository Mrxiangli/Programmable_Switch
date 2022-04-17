#!/usr/bin/env python3
import os
import sys
import time
import csv

count = 0

result_dict= []

from scapy.all import (
    Packet,
    IntField,
    BitField,
    IP,
    TCP,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff,
    bind_layers,
    sendp
)
from scapy.layers.inet import _IPOption_HDR

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

def expand(x):
    yield x

    # open the file in the write mode
    with open('path/to/csv_file', 'w') as f:
        # create the csv writer
        writer = csv.writer(f)

        # write a row to the csv file
        writer.writerow(row)

        while x.payload:
            x = x.payload
            yield x

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234 and Klass in pkt:
        pkt[Klass] = decision_tree(pkt[Klass])

        tmp = pkt[IP].dst
        pkt[IP].dst = pkt[IP].src
        pkt[IP].src = tmp
        sendp(pkt, verbose=False)

def decision_tree(pkt):
    x10 = pkt.X10
    x11 = pkt.X11
    x14 = pkt.X14
    x17 = pkt.X17
    x27 = pkt.X27
    if x17 <= -2789:
        if x10 <= -1378:
            if x14 <= -3441:
                result = 1
            else:
                result = 0
        else:
            if x11 <= 3325:
                result = 0
            else:
                result = 1
    else:
        if x14 <= -8225:
            if x27 <= -463:
                result = 0
            else:
                result = 1
        else:
            if x14 <= -4661:
                result = 0
            else:
                result = 0
    pkt.result = result            
    return pkt

def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    bind_layers(TCP, Klass, dport=1234)
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
