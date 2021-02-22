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
provisionedList = [0,1,2]
dedicatedList = []
### registration_tmp and deregistration_tmp test

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

# input signed message

#########################################################################
### 2021/2/22 modified by Qiqing Huang
### task5 registration and deregistration 

#   header = It has 2 bytes of magic number, 2 bytes of destination SCEWL ID, 2 bytes of source SCEWL ID, 2 bytes of body length in bytes.

#   message  = header + signed(header + device id + op)
#   message = header + signed(header + device id+ op) + device id + operation 

def createTmpMsg(deviceID):
    
    privateKey = str(deviceID) + ".pri"
    magicNumber = 0
    OP = 1
    descID = 0
    sourceID = 1
    length = 12

    header = struct.pack('!HHHH', magicNumber, descID, sourceID, length) 

    # _, _, _, _, dev_id, op = struct.unpack('<HHHHHH', data)
    # print(header)

    header_l = struct.unpack('!Q', header)

    # print(header_l[0])

    signedBody = struct.pack('!QHH', header_l[0], deviceID, OP)

    # print(signedBody)

    # writeFile  = open("tmp", mode='wb+')
    # writeFile.write(signedBody)

    with open(privateKey, mode='rb') as privatefile:
        keydata = privatefile.read()
        privkey = rsa.PrivateKey.load_pkcs1(keydata)

    encSignedBody = rsa.sign(signedBody, privkey, 'MD5') 

    # writeFile.close()
    # os.remove()
    # print(header)
    # print(type(encSignedBody))

    # signedMsg = str(header) + str(encSignedBody) + str(12) + str(OP)

    signedMsg = b"".join([header, encSignedBody, (deviceID).to_bytes(4, 'big'), OP.to_bytes(4, 'big')])



    # signedMsg = struct.pack('<ss', header, encSignedBody)
    print("signedMsg" + str(signedMsg) + "\r\n")

    return signedMsg


def registration_tmp(signedMsg):   

    ### STEP1 read the SCEWL_ID of the signed message
    # OP = signedMsg[-1:]
    # deviceID = signedMsg[187:-1]
    OP = signedMsg[-4:]
    OP_i = 0
    OP_i = int.from_bytes(OP, byteorder='big', signed=False)

    deviceID_i = 0
    deviceID = signedMsg[-8:-4]
    # print(deviceID)
    deviceID_i=int.from_bytes(deviceID, byteorder='big', signed=False)

    ### STEP2 check whether the ID is a provisioned SED or no
    if(deviceID_i in provisionedList):    

        ### STEP3 verify the header
        header = signedMsg[:8]
        # print(header)
        # header = It has 2 bytes of magic number, 2 bytes of destination SCEWL ID, 2 bytes of source SCEWL ID, 2 bytes of body length in bytes.
        magicNumber, descID, sourceID, length = struct.unpack('!hhhh', header)

        encSignedBody = signedMsg[8:-8]

        header_l = struct.unpack('!Q', header)

        verifyBody = struct.pack('!QHH', header_l[0], deviceID_i, OP_i)


        publicKey = str(deviceID_i) + ".pub"
        with open(publicKey, mode='rb') as publicfile:
            keydata = publicfile.read()
            pubkey = rsa.PublicKey.load_pkcs1(keydata)


        try:
            result = rsa.verify(verifyBody, encSignedBody, pubkey)
            ### STEP4 store the id to the dedicated list
            if(result):
                dedicatedList.append(deviceID_i)

                print("provisionedList: ")
                print(provisionedList)
                print("dedicatedList: ")
                print(dedicatedList)

                print(str(deviceID_i) + " registration done!\r\n")
            ### NEED TO DO STEP5 read local public key files and send them to the SED

        except:
            return False
    
    return

def deregistration_tmp(signedMsg):
    ### STEP1 read the SCEWL_ID of the signed message

    OP = signedMsg[-4:]
    OP_i = 0
    OP_i = int.from_bytes(OP, byteorder='big', signed=False)

    deviceID_i = 0
    deviceID = signedMsg[-8:-4]
    deviceID_i=int.from_bytes(deviceID, byteorder='big', signed=False)
    ### STEP2 check whether the ID is a provisioned SED & in the dedicated list or not
    if(deviceID_i in provisionedList and deviceID_i in dedicatedList): 
        header = signedMsg[:8]
        magicNumber, descID, sourceID, length = struct.unpack('!hhhh', header)

        encSignedBody = signedMsg[8:-8]

        header_l = struct.unpack('!Q', header)

        verifyBody = struct.pack('!QHH', header_l[0], deviceID_i, OP_i)


        publicKey = str(deviceID_i) + ".pub"
        with open(publicKey, mode='rb') as publicfile:
            keydata = publicfile.read()
            pubkey = rsa.PublicKey.load_pkcs1(keydata)

        try:
            ### STEP3 verify the header
            result = rsa.verify(verifyBody, encSignedBody, pubkey)
            ### STEP4 remove the ID from the dedicated list
            if(result):
                dedicatedList.remove(deviceID_i)

                print("provisionedList: ")
                print(provisionedList)
                print("dedicatedList: ")
                print(dedicatedList)

                print(str(deviceID_i) + " deregistration done!\r\n")
        except:
            return False
    return 



def main():

    ### registration_tmp and deregistration_tmp test
    # signedMsg = createTmpMsg(0)
    # registration_tmp(signedMsg)
    # deregistration_tmp(signedMsg)
    ### registration_tmp and deregistration_tmp test

    
    args = parse_args()

    # map of SCEWL IDs to statuses
    sss = SSS(args.sockf)
    sss.start()




if __name__ == '__main__':
    main()
