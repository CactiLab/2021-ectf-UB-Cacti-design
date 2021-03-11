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
export START_ID=109
export END_ID=125
export SC_PROBE_SOCK=sc_probe.sock
export SC_RECVR_SOCK=sc_recvr.sock

# create deployment
make create_deployment
make add_sed SED=broad_cast_SED1 SCEWL_ID=109 NAME=broad_cast_SED1
make add_sed SED=echo_server1 SCEWL_ID=111 NAME=echo_server1
make add_sed SED=echo_server2 SCEWL_ID=112 NAME=echo_server2
make add_sed SED=echo_server3 SCEWL_ID=113 NAME=echo_server3
make add_sed SED=echo_server4 SCEWL_ID=114 NAME=echo_server4
make add_sed SED=echo_server5 SCEWL_ID=115 NAME=echo_server5
make add_sed SED=echo_server6 SCEWL_ID=116 NAME=echo_server6
make add_sed SED=echo_server7 SCEWL_ID=117 NAME=echo_server7
make add_sed SED=echo_server8 SCEWL_ID=118 NAME=echo_server8
make add_sed SED=echo_server9 SCEWL_ID=119 NAME=echo_server9
make add_sed SED=echo_server10 SCEWL_ID=120 NAME=echo_server10
make add_sed SED=echo_server11 SCEWL_ID=121 NAME=echo_server11
make add_sed SED=echo_server12 SCEWL_ID=122 NAME=echo_server12
make add_sed SED=echo_server13 SCEWL_ID=123 NAME=echo_server13
make add_sed SED=echo_server14 SCEWL_ID=124 NAME=echo_server14
# make add_sed SED=echo_server15 SCEWL_ID=125 NAME=echo_server15
# make add_sed SED=echo_server16 SCEWL_ID=126 NAME=echo_server16

# launch deployment
make deploy

# launch transceiver in background
python3 tools/faa.py $SOCK_ROOT/$FAA_SOCK &

# launch seds detatched
make launch_sed_d NAME=broad_cast_SED1 SCEWL_ID=109
sleep 1
make launch_sed_d NAME=echo_server1 SCEWL_ID=111

sleep 1
make launch_sed_d NAME=echo_server2 SCEWL_ID=112

sleep 1
make launch_sed_d NAME=echo_server3 SCEWL_ID=113

sleep 1
make launch_sed_d NAME=echo_server4 SCEWL_ID=114

sleep 1
make launch_sed_d NAME=echo_server5 SCEWL_ID=115

sleep 1
make launch_sed_d NAME=echo_server6 SCEWL_ID=116

sleep 1
make launch_sed_d NAME=echo_server7 SCEWL_ID=117

sleep 1
make launch_sed_d NAME=echo_server8 SCEWL_ID=118

sleep 1
make launch_sed_d NAME=echo_server9 SCEWL_ID=119

sleep 1
make launch_sed_d NAME=echo_server10 SCEWL_ID=120

sleep 1
make launch_sed_d NAME=echo_server11 SCEWL_ID=121

sleep 1
make launch_sed_d NAME=echo_server12 SCEWL_ID=122

sleep 1
make launch_sed_d NAME=echo_server13 SCEWL_ID=123

sleep 1
make launch_sed_d NAME=echo_server14 SCEWL_ID=124

# sleep 1
# make launch_sed_d NAME=echo_server15 SCEWL_ID=125

# sleep 1
# make launch_sed_d NAME=echo_server16 SCEWL_ID=126

# bring transceiver back into foreground
fg

echo "Killing docker containers..."
docker kill $(docker ps -q) 2>/dev/null
