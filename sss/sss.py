#!/usr/bin/python3

# 2021 Collegiate eCTF
# SCEWL Security Server
# Ben Janis
#
# (c) 2021 The Team Cacti, University at Buffalo
#

# registration should attest the SED's private key

import socket
import select
import struct
import argparse
import logging
import os
from typing import NamedTuple


SSS_IP = 'localhost'
SSS_ID = 1

### registration_tmp and deregistration_tmp test
import rsa
provisionedList = []
dedicatedList = []
### registration_tmp and deregistration_tmp test

# mirroring scewl enum at scewl.c:4
ALREADY, REG, DEREG = -1, 0, 1

logging.basicConfig(filename= 'sss.log', filemode='w', level=logging.INFO)

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
        logging.info('handling transaction')
        provisioned_flag = False
        legit_SED_flag = False
        data = b''
        already_registered_sed = 0
        # the registration message will be signed by scewl's key and the length would be 64 bytes + 8 bytes of the header (72 bytes)
        while len(data) < 72:
            recvd = csock.recv(72 - len(data))
            data += recvd
            logging.info(f'data len: {len(data)}')
            # check for closed connection
            if not recvd:
                raise ConnectionResetError

        logging.info(f'Received buffer: {repr(data)}')
        #logging.info(f'Lenght of data: {len(data)}')
        _, target_id, src_id, _ = struct.unpack('<HHHH', data[:8])
        logging.info(f'header target: {target_id} header src: {src_id}')
        
        data = data[8:]
        logging.info(f'Received buffer: {repr(data)}')
        #logging.info(f'Lenght of data: {len(data)}')
        #logging.info(f'Lenght of data: {type(data)}')
        
        # try:
            cipher_file = open("rsa/cipher", "wb")
        # except 
        #cipher_file = open("cipher", "wb")
        cipher_file.write(data)
        cipher_file.close()
        #logging.info(f'source: {src_id}')
        auth_app_command = "./rsa/auth " + str(src_id)

        #logging.info(f'Calling auth application')
        logging.info(f'auth command: {auth_app_command}')
        if not os.system(auth_app_command):
                logging.info(f'command successfully executed')

        #decipher_data = open("rsa/decipher", "rb").read()
        with open("rsa/decipher", mode='rb') as file:
            decipher_data = file.read()
        d_data = struct.unpack('<32H', decipher_data)

        logging.info(f'Received buffer length: {len(decipher_data)}')
        logging.info(f'Received buffer: {repr(decipher_data)}')

        os.remove("rsa/decipher")
        os.remove("rsa/cipher")

        d_dev_id = d_data[0]
        d_op = d_data[1]
        d_target_id = d_data[2]
        d_src_id = d_data[3]
        op = d_op

        if d_target_id == target_id and d_src_id == src_id:
            logging.info(f'LeGIT SED {d_dev_id}')
            legit_SED_flag = True
            dev_id = d_dev_id
        else:
            logging.info(f'In valid Reigstration for SED')
            dev_id = target_id
            #resp_op = ALREADY

        logging.info(f'dev ID:{d_dev_id} op: {d_op} target: {d_target_id} src: {d_src_id}')
        
        if dev_id in provisionedList:
            provisioned_flag = True
            logging.info(f'ID: {dev_id} beloings to provisioned list')
            #resp_op = ALREADY
        
        
        if (provisioned_flag and legit_SED_flag) :
            logging.info(f'self.dev IDs{type(self.devs)}')
            logging.info(f'self.dev IDs{type(self.devs)}')
            
            registered_sed_list = list(self.devs.keys())
            logging.info(f'List IDs{registered_sed_list}')
            logging.info(f' TYpe IDs{type(registered_sed_list)}')
            already_registered_sed = len(registered_sed_list)
            # requesting repeat transaction

            if dev_id in self.devs and self.devs[dev_id] == op:
                resp_op = ALREADY
                logging.info(f'{dev_id}:already {"Registered" if op == REG else "Deregistered"}')
            # record transaction
            else:
                self.devs[dev_id] = Device(dev_id, op, csock)
                resp_op = op
                logging.info(f'{dev_id}:{"Registered" if op == REG else "Deregistered"}')
            logging.info(f'-----------DONE for {dev_id}------')
            logging.info(f'changed Dev ID: {dev_id} response op{resp_op}')
            if (op == 0):
                other_sed_pub = prepare_response(registered_sed_list)
                logging.info(f'Public key : {other_sed_pub}')
                logging.info(f'Public key length : {len(other_sed_pub)}')
                message_length = len(other_sed_pub) + 5
                resp = struct.pack('<2sHHHHhB', b'SC', dev_id, SSS_ID, message_length, dev_id, resp_op, already_registered_sed)
                resp = resp + other_sed_pub
                logging.info(f'Response : {resp}')
            else:
                resp = struct.pack('<2sHHHHh', b'SC', dev_id, SSS_ID, 4, dev_id, resp_op)

            # send response
            logging.debug(f'Sending response {repr(data)}')
            csock.send(resp)

    def start(self):
        unattributed_socks = set()
        preapred_provisioned_list()
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



#########################################################################

# The docker files to build the SSS and controller will create a (provisoned_list) file in SSS reading this file we check wheather
#SED with registration request belongs to the provisioned list or not
def preapred_provisioned_list():
        provisionedFile = open("../provisoned_list", "r")
        provisionedSEDLines = provisionedFile.readlines()
        for line in provisionedSEDLines:
            line.replace("\n","")
            provisionedList.append(int(line))
        logging.info(f'Provisioned SEDS: {provisionedList}')
        provisionedFile.close()

#For each SED there will be public key file in SSS container with the name SED_ID_publickey in /rsa folder here we just read the file
#and return the values to the caller
def get_publicKey(registed_SED_id):
    public_key_file_path = "rsa/" + str(registed_SED_id) + "_publicKey"
    logging.info(f'public_key_file_path {public_key_file_path}')

    pub_key_file_data = open(public_key_file_path,"rb").read()
    logging.info(f'public key for {registed_SED_id} is {repr(pub_key_file_data)}')

    return pub_key_file_data

# From the registered list preare the response with SED ID(2 byte) + public key(162 byte) for each previously reistered SED
def prepare_response(registered_sed_list):
    resp = b''
    for registered_sed_id in registered_sed_list:
                resp = resp + struct.pack('<H', registered_sed_id)
                publicKey_data = get_publicKey(registered_sed_id)
                resp = resp + publicKey_data
                logging.info(f'len: {len(publicKey_data)}')
    return resp


def main():

    args = parse_args()
    # map of SCEWL IDs to statuses
    sss = SSS(args.sockf)
    sss.start()




if __name__ == '__main__':
    main()
