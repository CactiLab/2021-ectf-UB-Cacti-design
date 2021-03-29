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
export START_ID=161
export END_ID=169
export SC_PROBE_SOCK=sc_probe.sock
export SC_RECVR_SOCK=sc_recvr.sock

# create deployment
make create_deployment
make add_sed SED=broad_cast161 SCEWL_ID=161 NAME=broad_cast161
make add_sed SED=broad_cast162 SCEWL_ID=162 NAME=broad_cast162
make add_sed SED=broad_cast163 SCEWL_ID=163 NAME=broad_cast163
make add_sed SED=broad_cast164 SCEWL_ID=164 NAME=broad_cast164
make add_sed SED=broad_cast165 SCEWL_ID=165 NAME=broad_cast165
make add_sed SED=broad_cast166 SCEWL_ID=166 NAME=broad_cast166
make add_sed SED=broad_cast167 SCEWL_ID=167 NAME=broad_cast167
make add_sed SED=broad_cast168 SCEWL_ID=168 NAME=broad_cast168


# launch deployment
make deploy

# launch transceiver in background
python3 tools/faa.py $SOCK_ROOT/$FAA_SOCK &

# launch seds detatched
make launch_sed_d NAME=broad_cast161 SCEWL_ID=161
sleep 2

make launch_sed_d NAME=broad_cast162 SCEWL_ID=162
sleep 2

make launch_sed_d NAME=broad_cast163 SCEWL_ID=163
sleep 2

make launch_sed_d NAME=broad_cast164 SCEWL_ID=164
sleep 1


make launch_sed_d NAME=broad_cast165 SCEWL_ID=165
sleep 1

make launch_sed_d NAME=broad_cast166 SCEWL_ID=166
sleep 1

make launch_sed_d NAME=broad_cast167 SCEWL_ID=167
sleep 1

make launch_sed_d NAME=broad_cast168 SCEWL_ID=168
sleep 1
# sleep 1
# make launch_sed_d NAME=echo_server15 SCEWL_ID=125

# sleep 1
# make launch_sed_d NAME=echo_server16 SCEWL_ID=126

# bring transceiver back into foreground
fg

echo "Killing docker containers..."
docker kill $(docker ps -q) 2>/dev/null
