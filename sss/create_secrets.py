#!/usr/bin/python3

# 2021 Team Cacti, University at Buffalo
# SCEWL Security Server
#
# Description: This file generates the RSA keys for add_SED, and deletes keys for remove_SED command
# usage: 
#       create_secrets.py [SCEWL_ID] [opt]
# input: SCEWL_ID
# output:  RSA_key pair, AES_key
# opt: generate_key, remove_key

import 

import socket
import select
import struct
import argparse
import logging
import os
from typing import NamedTuple


SSS_IP = 'localhost'
SSS_ID = 1

# mirroring scewl enum at scewl.c:4
ALREADY, REG, DEREG = -1, 0, 1

logging.basicConfig(level=logging.INFO)

Device = NamedTuple('Device', [('id', int), ('status', int), ('csock', socket.socket)])


class SSS:
    def __init__(self, sockf):
        # Make sure the socket does not already exist
        try:
            os.unlink(sockf)
        except OSError:
            if os.path.exists(sockf):
                raise

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(sockf)
        self.sock.listen(10)
        self.devs = {}
    
    @staticmethod
    def sock_ready(sock, op='r'):
        rready, wready, _ = select.select([sock], [sock], [], 0)
        return rready if op == 'r' else wready

    def handle_transaction(self, csock: socket.SocketType):
        logging.debug('handling transaction')
        data = b''
        while len(data) < 12:
            recvd = csock.recv(12 - len(data))
            data += recvd

            # check for closed connection
            if not recvd:
                raise ConnectionResetError
        logging.debug(f'Received buffer: {repr(data)}')
        _, _, _, _, dev_id, op = struct.unpack('<HHHHHH', data)

        # requesting repeat transaction
        if dev_id in self.devs and self.devs[dev_id] == op:
            resp_op = ALREADY
            logging.info(f'{dev_id}:already {"Registered" if op == REG else "Deregistered"}')
        # record transaction
        else:
            self.devs[dev_id] = Device(dev_id, op, csock)
            resp_op = op
            logging.info(f'{dev_id}:{"Registered" if op == REG else "Deregistered"}')

        # send response
        resp = struct.pack('<2sHHHHh', b'SC', dev_id, SSS_ID, 4, dev_id, resp_op)
        logging.debug(f'Sending response {repr(data)}')
        csock.send(resp)

    def start(self):
        unattributed_socks = set()

        # serve forever
        while True:
            # check for new client
            if self.sock_ready(self.sock):
                csock, _ = self.sock.accept()
                logging.info(f':New connection')
                unattributed_socks.add(csock)
                continue

            # check pool of unattributed sockets first
            for csock in unattributed_socks:
                try:
                    if self.sock_ready(csock):
                        self.handle_transaction(csock)
                        unattributed_socks.remove(csock)
                        break
                except (ConnectionResetError, BrokenPipeError):
                    logging.info(':Connection closed')
                    unattributed_socks.remove(csock)
                    csock.close()
                    break
            
            # check pool of attributed sockets first
            old_ids = []
            for dev in self.devs.values():
                if dev.csock and self.sock_ready(dev.csock):
                    try:
                        self.handle_transaction(dev.csock)
                    except (ConnectionResetError, BrokenPipeError):
                        logging.info(f'{dev.id}:Connection closed')
                        dev.csock.close()
                        old_ids.append(dev.id)
            
            for dev_id in old_ids:
                del self.devs[dev_id]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('sockf', help='Path to socket to bind the SSS to')
    return parser.parse_args()


def main():
    args = parse_args()
    # map of SCEWL IDs to statuses
    sss = SSS(args.sockf)
    sss.start()


if __name__ == '__main__':
    main()
