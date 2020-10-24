#!/bin/bash
docker run -u root -p 1234:1234 -p 4444:4444 -it sparc-2 /chall/run_socat.sh 1
