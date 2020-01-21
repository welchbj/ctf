#!/usr/bin/env python

"""
Basic analysis using scapy's HTTP layer.

For HTTP request fields, see:
https://scapy.readthedocs.io/en/latest/api/scapy.layers.http.html#scapy.layers.http.HTTPRequest

For HTTP response fields, see:
https://scapy.readthedocs.io/en/latest/api/scapy.layers.http.html#scapy.layers.http.HTTPResponse
"""

from collections import Counter
from functools import partial

from scapy.all import *
load_layer('http')

ANOMALOUS_USER_AGENT_COUNT_THRESHOLD = 2
PCAP_FILE = 'the.pcap'

print_info = partial(print, '[*] ', sep='')

user_agents = []
unknown_header_counter = Counter()

for i, pkt in enumerate(PcapReader(PCAP_FILE)):
    is_http_request = pkt.haslayer('HTTPRequest')
    is_http_response = pkt.haslayer('HTTPResponse')

    # accumulate unique request user agents, looking for anomalies
    if is_http_request:
        user_agent = pkt[HTTPRequest].User_Agent
        if user_agent is not None:
            user_agents.append(user_agent.decode())

    # annotate file downloads
    if is_http_response:
        content_disposition = pkt[HTTPResponse].Content_Disposition
        if content_disposition is not None:
            print_info('Packet ', i, 'looks like a file download based on '
                       'Content-Disposition header of ',
                       content_disposition.decode())

    # collect unrecognized headers
    if is_http_request or is_http_response:
        layer = HTTPRequest if is_http_request else HTTPResponse

        unknown_headers = pkt[layer].Unknown_Headers
        if unknown_headers is not None:
            unknown_header_counter.update(
                h.decode() for h in unknown_headers.keys()
            )


# post-process gathered user agents
user_agent_counter = Counter(user_agents)
print_info('Found the following anomalous user agents that appeared at most ',
           ANOMALOUS_USER_AGENT_COUNT_THRESHOLD, ' times:')
for user_agent, count in user_agent_counter.items():
    if count > ANOMALOUS_USER_AGENT_COUNT_THRESHOLD:
        continue

    print('Occured', count, 'times:')
    print(user_agent, end='\n\n')

# post-process unrecognized headers
print_info('Observed the following scapy-unrecognized headers, sorted by '
           'descending frequency:')
for header, count in unknown_header_counter.most_common():
    print('Occured', count, 'times:')
    print(header, end='\n\n')
