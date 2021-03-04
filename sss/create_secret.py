## INPUT: SCEWL_ID -> OUTPUT: SCEWL_ID.pub, SCEWL_ID.pri

import rsa
import sys
import os

def read_input():
    #TODO read input from command line (SHOULD ONLY BE 1 INPUT)
    if (len(sys.argv) != 3): 
        print("failure: input should be two argument\nUsage: python create_secret.py [SCEWL_ID] [generate_key/delete_key]")
        print("did not generate/delete keys")
        return "bad"
    else:
        if sys.argv[2] == "generate_key":
            enc_input(sys.argv[1])
        elif sys.argv[2] == "delete_key":
            del_input(sys.argv[1])
        else:
            print("failure: second parameter not recognised\nUsage: python create_secret.py [SCEWL_ID] [generate_key/delete_key]")
            print("did not generate/delete keys")


def del_input(scewl_id):
    #TODO: delete pub and private key files for scewl id (print bad if doesn't exist)
    pub_path = "/" + str(scewl_id) + "/privateKey.txt"
    pri_path = "/" + str(scewl_id) + "/publicKey.txt"
    keyHeader_path = "/" + str(scewl_id) + "/key.h"
    
    if os.path.exists(pub_path) and os.path.exists(pri_path):
        os.remove(pub_path)
        os.remove(pri_path)
        os.remove(keyHeader_path)
        print("success: deleted public, private key  and key headerfor id: ", scewl_id)
    else:
        print("failure: public and/or private key and/or Key header file does not exist for ", scewl_id)

def write_into_header_file(struct_name, key_file_header, list_of_key_values, name, int_index):
    last_index = len(list_of_key_values) - 1

    key_file_header.write(f'''
{struct_name} {name} = {{
        ''')

    cnt = 0
    for line_list in list_of_key_values:
        if cnt < int_index:
            key_file_header.write(f'''
    {{{", ".join(['0x' + u for u in line_list])}}},
            ''')
        elif cnt == last_index:
            dValue = ''.join(line_list)
            key_file_header.write(f'''
    0x{dValue}
            ''')
        else:
            dValue = ''.join(line_list)
            key_file_header.write(f'''
    0x{dValue},
            ''')
        cnt = cnt + 1

    key_file_header.write(f'''
}};
  
    ''')

def enc_input(scewl_id):
    key_file_name = "/" + str(scewl_id) + "/key.h"
    
    private_key_file_path = "/" + str(scewl_id) + "/privateKey.txt"
    public_key_file_path = "/" + str(scewl_id) + "/publicKey.txt"

    key_file_header = open(key_file_name, "w")
    privateKey_file = open(private_key_file_path, 'r')
    publicKey_file = open(public_key_file_path, 'r')

    pirvateKey_Lines = privateKey_file.readlines()
    publicKey_Lines = publicKey_file.readlines()

    cnt = 0
    for line in pirvateKey_Lines:
        line = line.replace('\n', '')
        pirvateKey_Lines[cnt] = [(line[i:i+4]) for i in range(0, len(line), 4)]
        cnt = cnt + 1
    
    cnt = 0
    for line in publicKey_Lines:
        line = line.replace('\n', '')
        publicKey_Lines[cnt] = [(line[i:i+4]) for i in range(0, len(line), 4)]
        cnt = cnt + 1
    
    key_file_header.write(f'''
#ifndef KEY_H
#define KEY_H
#include "keys.h"

    ''')

    write_into_header_file("rsa_sk", key_file_header, pirvateKey_Lines, "private_key", 11)
    write_into_header_file("rsa_pk", key_file_header, publicKey_Lines, "public_key", 3)
    
    key_file_header.write(f'''
#endif    
    ''')
    key_file_header.close()
    privateKey_file.close()
    publicKey_file.close()

if __name__ == '__main__':
    #read input from command line
    read_input()
    #encrypt input -> return public & private keys
    # if scewl_id != "bad":
    #     enc_input(scewl_id)
    # else:
    #     print("did not generate keys")
