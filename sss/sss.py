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
import datetime

SSS_IP = 'localhost'
SSS_ID = 1

### registration_tmp and deregistration_tmp test
import rsa
provisionedList = []
current_registered_sed = []
### registration_tmp and deregistration_tmp test

# mirroring scewl enum at scewl.c:4
ALREADY, REG, DEREG = -1, 0, 1

logging.basicConfig(filename= '/socks/sss.log', filemode='w', level=logging.INFO)

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
        ct = datetime.datetime.now()
        print('\n\n' + str(ct) + 'In function handle_transaction()', flush = True)
        #logging.info(f'{ct}\n\nIn function handle_transaction()')
        provisioned_flag = False
        legit_SED_flag = False
        data = b''
        already_registered_sed = 0
        # the registration message will be signed by scewl's key and the length would be 64 bytes + 8 bytes of the header (72 bytes)
        while len(data) < 72:
            recvd = csock.recv(72 - len(data))
            data += recvd
            # check for closed connection
            if not recvd:
                print('Connection Reset Error', flush = True)
                #logging.info(f'Connection Reset Error')
                raise ConnectionResetError
        print(f'---Received msg: {repr(data)}', flush = True)
        #logging.info(f'---Received msg: {repr(data)}')
        ##logging.info(f'Lenght of data: {len(data)}')
        _, target_id, src_id, _ = struct.unpack('<HHHH', data[:8])
        print(f'==={src_id}=== Target: {target_id}', flush = True)
        
        data = data[8:]
        cipher_file_name = "rsa/" + str(src_id) + "_cipher"
        try:
            cipher_file = open(cipher_file_name, "wb")
        except:
            print(f'==={src_id}=== Could not open Cipher file: {cipher_file_name}', flush = True)
            #logging.info(f'==={src_id}=== Could not open Cipher file')
            return

        #cipher_file = open("cipher", "wb")
        cipher_file.write(data)
        cipher_file.close()
        ##logging.info(f'source: {src_id}')
        auth_app_command = "./rsa/auth " + str(src_id)

        if not os.system(auth_app_command):
            print(f'==={src_id}=== Msg Decryption succeeds', flush = True)
            #logging.info(f'==={src_id}=== Msg Decryption succeeds')
        else:
            print(f'==={src_id}=== Msg Decryption fails', flush = True)
            #logging.info(f'==={src_id}=== Msg Decryption fails')
            return

        #decipher_data = open("rsa/decipher", "rb").read()
        decipher_file_name = "rsa/" + str(src_id) + "_decipher"
        try:
            with open(decipher_file_name, mode='rb') as file:
                decipher_data = file.read()
        except:
            print(f'==={src_id}=== Failed to open decipher file to read: {decipher_file_name}', flush = True)
            #logging.info(f'==={src_id}=== Failed to open decipher file to read {decipher_file_name}')
            return
        
        d_data = struct.unpack('<32H', decipher_data)

        #print(f'Received buffer length: {len(decipher_data)}')
        os.remove(cipher_file_name)
        os.remove(decipher_file_name)

        d_dev_id = d_data[0]
        d_op = d_data[1]
        d_target_id = d_data[2]
        d_src_id = d_data[3]
        op = d_op

        if d_target_id == target_id and d_src_id == src_id:
            print(f'==={src_id}=== IDs match', flush = True)
            #logging.info(f'==={src_id}=== IDs match')
            legit_SED_flag = True
            dev_id = d_dev_id
        else:
            print(f'==={src_id}=== Invalid Registration for SED', flush = True)
            #logging.info(f'==={src_id}=== Invalid Registration for SED')
            dev_id = target_id
            return
            #resp_op = ALREADY
        
        if dev_id in provisionedList:
            provisioned_flag = True
            print(f'==={dev_id}=== Belongs to provisioned list', flush = True)
            #logging.info(f'==={dev_id}=== Belongs to provisioned list')
        else:
            print(f'==={dev_id}=== Does not belog to provisioned list', flush = True)
            #logging.info(f'==={dev_id}=== Does not belog to provisioned list')
            return
        
        
        if (provisioned_flag and legit_SED_flag) :

            # requesting repeat transaction

            if dev_id in self.devs and self.devs[dev_id] == op:
                resp_op = ALREADY
                print(f'==={src_id}=== already {"Registered" if op == REG else "Deregistered"}', flush = True)
                #logging.info(f'---==={src_id}=== already {"Registered" if op == REG else "Deregistered"}')
            # record transaction
            else:
                self.devs[dev_id] = Device(dev_id, op, csock)
                resp_op = op
                print(f'==={dev_id}==={"Registered" if op == REG else "Deregistered"}', flush = True)
                #logging.info(f'==={dev_id}==={"Registered" if op == REG else "Deregistered"}')

            if (op == 0):
                #registered_sed_list = list(self.devs.keys())
                #print(f'==={src_id}=== Registered List IDs{registered_sed_list}')
                already_registered_sed = len(current_registered_sed)
                print('===' + str(src_id) + '=== Registration Operation', flush = True)
                #logging.info(f'---=== {src_id}=== Registration Operation')
                print('===' + str(src_id) + '=== Total previously registered SED:' + str(already_registered_sed), flush = True)
                print(f'==={src_id}=== Previously registered IDs {current_registered_sed}', flush = True)
                #logging.info(f'==={str(src_id)}=== Total previously registered SED:{str(already_registered_sed)}')
                #logging.info(f'==={src_id}=== Previously registered IDs {current_registered_sed}')
                ##logging.info(f'==={src_id}=== Previously registered IDs {current_registered_sed}')
                
                print('===' + str(src_id) + '=== Responsing total registered SED PKs:' + str(already_registered_sed), flush = True)
                print(f'==={src_id}=== Sending back registered PK for IDs{current_registered_sed[:already_registered_sed]}', flush = True)
                #logging.info(f'==={str(src_id)}=== Responsing total registered SED PKs: {str(already_registered_sed)}')
                #logging.info(f'==={src_id}=== Sending back registered PK for IDs{current_registered_sed[:already_registered_sed]}')
                other_sed_pub = prepare_response(current_registered_sed, already_registered_sed)
                
                own_pk_signature_by_sss = get_own_public_key_signature_from_sss(src_id) #226 bytes of signed own pK
                if own_pk_signature_by_sss == b'':
                    print('===' + str(src_id) + '=== Get Own  Public key signature fails', flush = True)
                    #logging.info(f'=== {str(src_id)} === Get Own  Public key signature fails')
                    return
                ##logging.info(f'==={src_id}=== own public key signature:\n {repr(own_pk_signature_by_sss)}')
                #print(f'==={src_id}=== own public key signature:\n {repr(own_pk_signature_by_sss)}')
                #message_length = len(other_sed_pub) + 5
                message_length = len(other_sed_pub) + len(own_pk_signature_by_sss) + 5
                resp = struct.pack('<2sHHHHhB', b'SC', dev_id, SSS_ID, message_length, dev_id, resp_op, already_registered_sed)
                #resp = struct.pack('<2sHHHHhB', b'SC', dev_id, SSS_ID, 5, dev_id, resp_op, already_registered_sed)
                #resp = resp + other_sed_pub
                resp = resp + other_sed_pub + own_pk_signature_by_sss
                current_registered_sed.append(dev_id)
                ##logging.info(f'Response : {resp}')
            else:
                print('===' + str(src_id) + '=== De-registration Operation', flush = True)
                #logging.info(f'---==={src_id}=== De-registration Operation')
                resp = struct.pack('<2sHHHHh', b'SC', dev_id, SSS_ID, 4, dev_id, resp_op)
                current_registered_sed.remove(dev_id)
                #logging.info(f'==={src_id}=== Previously registered IDs {current_registered_sed}')
            # send response
            print(f'Sending response {repr(data)}', flush = True)
            #logging.info(f'Sending response {repr(data)}')
            print(f'-----------DONE for {dev_id}------', flush = True)
            #logging.info(f'--------------DONE for {dev_id}------')
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
                #logging.info(f'{self.devs}')


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('sockf', help='Path to socket to bind the SSS to')
    return parser.parse_args()



#########################################################################

# The docker files to build the SSS and controller will create a (provisoned_list) file in SSS reading this file we check wheather
#SED with registration request belongs to the provisioned list or not
def preapred_provisioned_list():
    try:
        provisionedFile = open("../provisoned_list", "r")
    except:
        print(f'Failed to Open Provisioned LIST file: ../provisoned_list', flush = True)
        #logging.info(f'Failed to Open Provisioned LIST file')
        return
    provisionedSEDLines = provisionedFile.readlines()
    for line in provisionedSEDLines:
        line.replace("\n","")
        provisionedList.append(int(line))
    print(f'Provisioned SEDS: {provisionedList}', flush = True)
    #logging.info(f'Provisioned SEDS: {provisionedList}')
    provisionedFile.close()

#For each SED there will be public key file in SSS container with the name SED_ID_publickey in /rsa folder here we just read the file
#and return the values to the caller
def get_publicKey(registed_SED_id):
    public_key_file_path = "rsa/" + str(registed_SED_id) + "_publicKey"
    try:
        pub_key_file_data = open(public_key_file_path,"rb").read()
    except:
        print ("Could not open the public key file for :" + str(registed_SED_id) + public_key_file_path, flush = True)
        #logging.info (f'Could not open the public key file for : {str(registed_SED_id)}')
        return
    return pub_key_file_data

# From the registered list preare the response with SED ID(2 byte) + public key(162 byte) for each previously reistered SED
def prepare_response(registered_sed_list, already_registered_sed):
    #logging.info(f'Registered SED list { registered_sed_list}')
    resp = b''
    i = 0
    for registered_sed_id in registered_sed_list:
        resp = resp + struct.pack('<H', registered_sed_id)
        publicKey_data = get_publicKey(registered_sed_id)
        resp = resp + publicKey_data
        i = i + 1
        if i >= already_registered_sed:
            break
        
    return resp

#sign SED's own public key with SSS private key, it will return 226 bytes
def get_own_public_key_signature_from_sss(src_id):
    sign_app_command = "./rsa/sign " + str(src_id)
    if not os.system(sign_app_command):
        print(f'==={src_id}=== signature own public key by SSS success', flush = True)
        #logging.info(f'==={src_id}=== signature own public key by SSS success')
    else:
        print(f'==={src_id}=== signature own public key by SSS fails', flush = True)
        #logging.info(f'==={src_id}=== signature own public key by SSS fails')
        return b''

    signed_pk_file_name = "rsa/" + str(src_id) + "_publicKey_signed"
    try:
        with open(signed_pk_file_name, mode = 'rb') as file:
            signed_pk_data = file.read()
    except:
        print(f'==={src_id}=== Failed to open signed PK file to read: {signed_pk_file_name}', flush = True)
        #logging.info(f'==={src_id}=== Failed to open signed PK file to read  {signed_pk_file_name}')
        return b''
    
    return signed_pk_data

def main():

    args = parse_args()
    # map of SCEWL IDs to statuses
    sss = SSS(args.sockf)
    sss.start()




if __name__ == '__main__':
    main()