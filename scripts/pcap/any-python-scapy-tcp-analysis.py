#!/usr/bin/env python

from __future__ import print_function

from pwn import *
from scapy.all import *

FLAG_START = 'flag{'
INTERESTING_PACKET_INDEX = 2

# read in the pcap
packets = rdpcap('capture.pcap')

# try rotating the data around
packet_data = packets[INTERESTING_PACKET_INDEX][Raw].load
for i in range(255):
    ords = [(ord(x) + i) % 255 for x in packet_data]
    print(''.join([chr(x) for x in ords]))

# print the ords of the interesting packet data and the expected flag format
print(' '.join([str(ord(x)) for x in packet_data]))
print(' '.join([str(ord(x)) for x in FLAG_START]))

# try xor-ing the flag out of the data
print(xor(packet_data, FLAG_START))
