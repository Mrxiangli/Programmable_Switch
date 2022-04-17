#!/usr/bin/env python3
import os
import sys
import time
import csv

count = 0

result_dict= [dict()]*50961

from scapy.all import (
    Packet,
    IntField,
    BitField,
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
    global count
    global result_dic
    if TCP in pkt and pkt[TCP].dport == 1234:
        sys.stdout.flush()
        latency = round(time.time()*1000) - pkt.start
        result_dict[count]["time"] = latency
        result_dict[count]["truth"] = pkt.truth
        result_dict[count]["result"] = pkt.result
        count += 1
    if count == 10:
        print(result_dict)
        with open("result.csv","w") as result:
            writer = csv.writer(result)
            for i in range(count):
                writer.writerow(result_dict[i].values())
        print("finish writing")

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
