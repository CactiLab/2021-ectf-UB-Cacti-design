# 2021 MITRE eCTF Challenge - Team Cacti (University at Buffalo): Secure Common Embedded Wireless Link (SCEWL)
This repository contains team Cacti's (University at Buffalo) system for MITRE's 2021 Embedded 
System CTF (eCTF). 

## Getting Started
Please see the [Getting Started Guide](getting_started.md).

Also see the [MITRE kick-off meeting slides](mitredoc/2021.01.20-2021 eCTF Kickoff_PRS.pdf), [rules](mitredoc/2021.01.20-eCTF_Rules_v1.0.pdf), and [code walkthrough](mitredoc/2021.01.27-2021 eCTF Walkthrough.pdf).

## Project Structure
The example code is structured as follows

* `controller/` - Contains everything to build the SCEWL Bus Controller. See [Controller README](controller/README.md)
* `cpu/` - Contains everything to build the user code of the CPU. See [CPU README](cpu/README.md)
* `dockerfiles/` - Contains all Dockerfiles to build system
* `radio/` - Contains the Radio Waves Emulator
* `socks/` - Directory to hold sockets for the network backend
* `tools/` - Miscellaneous tools to run and interract with deployments
* `Makefile` - Root Makefile to build deployments

## Design Doc
The design doc is in `designdoc/`. 
