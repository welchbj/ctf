# PCAP Analysis

## Practice resources

The Wireshark project has assembled a collection of packet captures (PCAPs) for practice and/or testing. I recommend trying out the below tips with some of these PCAPs, which can be found [here](https://wiki.wireshark.org/SampleCaptures). You can also find some additional SMB2 capture files [here](https://wiki.wireshark.org/SMB2#Example_capture_files).

## Tool-agnostic advice

### Approaching these problems

You can think of PCAP analysis challenges as finding a needle in a haystack. You should always be looking for anomalies and what doesn't belong. This could be one of many things:

* A file transfer
* A password passed in the clear (i.e., not encrypted)
* Traffic that doesn't fit in (such as a few IPv6 packets in a PCAP comprised mostly of IPv4)

Anything that looks out of the ordinary is probably worth exploring.

### Avoiding PCAP tools altogether

You don't always have to examine a capture file in detail during on of these challenges. Most problems won't be this easy, but sometimes you can find a flag (or related information) by running something like:

```sh
strings capture.pcap | grep -i flag
```

If you just want to try to extract any files within the PCAP, `binwalk` (installed by default on Kali) might prove fruitful:
```sh
binwalk -e capture.pcap
```

## Wireshark

Wireshark is a useful graphical tool for displaying traffic, captured either in real-time or from a PCAP file. It has a lot of great tools that can't be easily replicated in command-line applications, such as following streams of traffic.

### Installation

Wireshark should already be installed if you are using Kali Linux. If not, try the commands below:

```sh
# yum-based distributions:
sudo yum install -y wireshark wireshark-gnome

# apt-based distributions:
sudo apt-get install -y wireshark tshark
```

### Scoping out a PCAP

You first step should be to look at the protocol hierarchy analysis, which can be done by selecting `Statistics -> Protocol Hierarchy` from the toolbar menu. This will show you a distribution of the different protocols present within the PCAP.

Following our goal of finding the needle in the hay stack, this is a great way to identify some low-frequency protocols for examination. For example, if you have a PCAP full of HTTPS traffic, but see a few packets of FTP data, you should probably start by looking at the FTP data.

To start looking at a specific category of traffic identified in the protocol hierarchy, richt click the desired category and click `Apply as Filter -> Selected`. You can also exclude other traffic that isn't super interesting at first glance (like ARP) via the `Apply as Filter -> Not Selected` option.

### Quick wins

Sometimes you do not need to do much work to find a flag, and can take some shortcuts to save time.

Occasionally, a PCAP challenge is only meant to involve pulling out a transferred file (via a protocol like HTTP or SMB) from the PCAP and doing some further analysis on that file. Files transferred via HTTP can be extracted from a PCAP in Wireshark via the `File -> Export Objects -> HTTP` option. The same can be done for SMB-transferred files via the `File -> Export Objects -> SMB` option. Note that this technique is not a 100% surefire method of extracting every file, as some files may have been transferred in non-standard ways that Wireshark is not innately privy to.

We can also just try searching different raw traffic for flag-related text. For example, we can search for the string `flag` in all TCP traffic with the following filter:

```
frame contains flag
```

It's also probably worthwhile to search for the start of the known flag format in its ASCII- and base64-encoded forms, too.

Sometimes, there might be extra information stored via Wireshark's commenting feature. To filter on packets that have comments, use the filter:

```
pkt_comment
```

### Decrypting SSL/TLS traffic

If you are in possession of the private key of a server from which you are examining recorded traffic, you can decrypt SSL/TLS-encrypted traffic from within Wireshark. You can configure this key by filling in the appropriate information in the `Edit -> Preferences -> RSA Keys -> Add new keyfile...` dialog.

### Modifying displayed columns

Wireshark allows you to customize what columns are displayed for matching packets. These can be edited in the `Edit -> Preferences -> Columns`. It may be helpful to add the following columns to your output:

* Source port
* Destination port
* Hostname
* Hex representation of transferred data

### Useful filters

There is a lot of traffic that is considered "ordinary" (i.e., you would see a lot of it in a PCAP on your computer outside of a CTF, too). A good way to filter it out is with something like:

```
not arp and not http and not (udp.port == 53)
```

Alternatively, if you want to keep the http traffic around, you can try (note that this will also exclude DNS over TCP, which you probably want to look at):

```
!(apr or icmp or dns or stp)
```

However, don't discount these classes of traffic just because they align with typical computer usage. DNS, HTTP, and even ARP can easily be an integral part of a PCAP analysis challenge.

Another useful thing to look at when doing something like examining malware is identify failed DNS requests, which involve some kind of C2 domain. This can be done with:

```
dns.flags.rcode != 0
```

To limit the displayed traffic to just what is occurring between two specific hosts, you can use:

```
ip.addr == 1.1.1.1 && ip.addr == 2.2.2.2
```

Abnormal TCP parameters can also be something worth looking into. Some of the below might be a good starting point:

* TCP resets - `tcp.flags.reset == 1`
* TCP pushes - `tcp.flags.push == 1`
* TCP SYN/ACKs - `tcp.flags == 0x012`
* Retransmissions / duplicate ACKs / zero windows - `tcp.analysis.flags && !tcp.analysis.window_update`

## `tshark`

You can think of `tshark` as the command-line version of the Wireshark program. While you won't be getting a nice graphical output of your captured traffic with `tshark`, you will be able to get more creative with how your data is presented and then pass it off to other command-line programs.

### Installation

`tshark` should already be on your system if you already have Wireshark installed.

### Useful options to know

There are a few commonly-used options we will use in the below examples that you should be acquainted with. These are:

* `-r` - TODO
* `-q` - don't continuously display the count of packets, just show it at the very end
* `-R` - TODO
* `-z` - TODO
* `-i` - TODO
* `-f` - TODO

### Useful output formats

Just like in Wireshark, we can print a concise layout of the different protocols present in our capture file. Do so with:
```sh
TODO
```

### Following streams

TODO

### Decrypting SSL/TLS traffic

See: https://minnmyatsoe.com/2016/01/26/using-tshark-to-decrypt-ssl-tls-packets/

Similar to Wireshark, `tshark` supports decrypting SSL/TLS traffic as long as we have the private key used on the server-under-analysis. We can do this with:

```sh
tshark -r encrypted_capture.pcap -V -x \
    -o 'ssl.debug_file:ssldebug.log' \
    -o 'ssl.desegment_ssl_records: TRUE' \
    -o 'ssl.desegment_ssl_appliction_data: TRUE' \
    -o 'ssl.keys_list:127.0.0.1,443,http,/path/to/server.pem'
    # last option is in the format server,port,protocol,private_key_location
```

We can also use our knowledge of following streams in `tshark` to follow stream `1` and print its contents as ASCII:

```sh
tshark -r encrypted_capture.pcap -q \
    -o 'ssl_keys_list:127.0.0.1,443,http,/path/to/server.pem' \
    -z 'follow,ssl,ascii,1'
```

### IP filtering

TODO

### Extracting files from captures

Just like in Wireshark, we can extract files from PCAPs. This can be done for HTTP and SMB with:
```sh
tshark -nr capture.pcap --export-objects smb,./
```

### Examining HTTP traffic metadata

A first good step when examining HTTP data is to print out a tree of all of the HTTP traffic within the specified capture file. This can be done with:

```sh
tshark -r capture.pcap -q -z http,tree
```

We also probably want to output some of the specific fields. Be on the lookout for odd HTTP headers, as this is an exfiltration method you might see in CTFs sometimes. It might be worth piping the below command to `sort | uniq -c | sort -n` in order to spot any anomalies right away.

```sh
tshark -r capture.pcap -Y http.request -T fields -e http.host -e http.user_agent
```

Looking for specific types of HTTP requests can be done with:

```sh
TODO
```

Some additional HTTP fields that might be worth examining can be found in the following command:

```sh
TODO
```

### DNS analysis

TODO

### Database traffic analysis

TODO

## Scapy

[Scapy](https://scapy.readthedocs.io/en/latest/) is a project that lets you read and manipulate network packets in Python.

### Extracting Data from Packets

It offers more fine-grained control for data manipulation than Wireshark or `tshark`. Here is an example of dumping UDP data from a PCAP:

```python
#!/usr/bin/env python

from scapy.all import *

packets = rdpcap("the.pcap")

with open("out.raw", "wb") as f:
    for p in packets:
        if UDP in p:
            chunk = bytes(p[Raw])
            f.write(chunk)
```
