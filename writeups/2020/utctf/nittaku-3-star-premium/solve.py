#!/usr/bin/env python3

from scapy.all import *

TARGET = '3.88.183.122'
NULL_DATA = b'\x00'*48

data = b''
i = 1
while True:
    pkt = IP(
        dst=TARGET
    ) / ICMP(
        type='echo-request',
        id=0x1337,
        seq=i
    ) / NULL_DATA

    resp = sr1(pkt)
    resp_data = resp[Raw].load.rstrip(b'\n\x00')

    if not resp_data:
        break

    data += resp_data
    i += 1

with open('out.b64', 'w') as f:
    f.write(data.decode())
