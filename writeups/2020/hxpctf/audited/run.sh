#!/usr/bin/env bash

echo 'hxp{FLAG}' > flag.txt
docker build -t audited .
docker run --cap-add=SYS_ADMIN --security-opt apparmor=unconfined -ti -p 8007:1024 audited
