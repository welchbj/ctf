# Lion

This was an interesting challenge.

The flow of the challenge goes:

* Start out with a PCAP, which you can extract some RAR files from
* Use the RAR files to extract a BH PE file
* Observe that this PE tries to read from a local file `keylog.txt` and send data to harcoded IP/port `192.168.206.161:33333`
* Go back to the PCAP to find some encrypted data being sent to the hardcoded IP
* Use the `bh.exe` program as an oracle for determing the plaintext that produced the ciphertext seen in the PCAP

You can find the post-`bh.exe`-extraction steps to this challenge in the [`solve.py`](./solve.py) script. The [`bh.exe`](./bh.exe) PE file is also included in this repository.
