#!/bin/bash

# 2021 Collegiate eCTF
# Launch a test echo deployment
# Ben Janis
#
# (c) 2021 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
# This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
# and may not meet MITRE standards for quality. Use this code at your own risk!

set -e
set -m

if [ ! -d ".git" ]; then
    echo "ERROR: This script must be run from the root of the repo!"
    exit 1
fi

export DEPLOYMENT=echo
export SOCK_ROOT=$PWD/socks
export SSS_SOCK=sss.sock
export FAA_SOCK=faa.sock
export MITM_SOCK=mitm.sock
export START_ID=10
export END_ID=14
export SC_PROBE_SOCK=sc_probe.sock
export SC_RECVR_SOCK=sc_recvr.sock

# create deployment
make create_deployment
make add_sed SED=echo_server SCEWL_ID=10 NAME=echo_server
make add_sed SED=client1 SCEWL_ID=11 NAME=client1 CUSTOM='TGT_ID=10'
make add_sed SED=client2 SCEWL_ID=12 NAME=client2 CUSTOM='TGT_ID=10'
make add_sed SED=broad_cast_SED1 SCEWL_ID=13 NAME=broad_cast_SED1
make add_sed SED=broad_cast_SED2 SCEWL_ID=14 NAME=broad_cast_SED2
make remove_sed SED=broad_cast_SED2 SCEWL_ID=14 NAME=broad_cast_SED2


# launch deployment
make deploy

# launch transceiver in background
python3 tools/faa.py $SOCK_ROOT/$FAA_SOCK &

# launch seds detatched
make launch_sed_d NAME=echo_server SCEWL_ID=10

sleep 1
make launch_sed_d NAME=client1 SCEWL_ID=11

sleep 1
make launch_sed_d NAME=client2 SCEWL_ID=12

sleep 1
make launch_sed_d NAME=broad_cast_SED1 SCEWL_ID=13

# sleep 1
# make launch_sed_d NAME=broad_cast_SED2 SCEWL_ID=14

# bring transceiver back into foreground
fg

echo "Killing docker containers..."
docker kill $(docker ps -q) 2>/dev/null
