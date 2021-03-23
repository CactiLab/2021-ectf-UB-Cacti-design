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
export END_ID=115
export SC_PROBE_SOCK=sc_probe.sock
export SC_RECVR_SOCK=sc_recvr.sock

# create deployment
make create_deployment
make add_sed SED=broad_cast_SED SCEWL_ID=109 NAME=broad_cast_SED
make add_sed SED=brdcst_rec1 SCEWL_ID=111 NAME=brdcst_rec1 CUSTOM='TGT_ID=109'
make add_sed SED=brdcst_rec2 SCEWL_ID=112 NAME=brdcst_rec2 CUSTOM='TGT_ID=109'
make add_sed SED=brdcst_rec3 SCEWL_ID=113 NAME=brdcst_rec3 CUSTOM='TGT_ID=109'
make add_sed SED=brdcst_rec4 SCEWL_ID=114 NAME=brdcst_rec4 CUSTOM='TGT_ID=109'

# launch deployment
make deploy

# launch transceiver in background
python3 tools/faa.py $SOCK_ROOT/$FAA_SOCK &

# launch seds detatched
sleep 1
make launch_sed_d NAME=brdcst_rec1 SCEWL_ID=111

sleep 1
make launch_sed_d NAME=brdcst_rec2 SCEWL_ID=112

sleep 1
make launch_sed_d NAME=brdcst_rec3 SCEWL_ID=113

sleep 1
make launch_sed_d NAME=brdcst_rec4 SCEWL_ID=114

sleep 1
make launch_sed_d NAME=broad_cast_SED SCEWL_ID=109


# bring transceiver back into foreground
fg

echo "Killing docker containers..."
docker kill $(docker ps -q) 2>/dev/null
