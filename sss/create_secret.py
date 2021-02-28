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
    pub_path = str(scewl_id) + ".pub"
    pri_path = str(scewl_id) + ".pri"
    if os.path.exists(pub_path) and os.path.exists(pri_path):
        os.remove(pub_path)
        os.remove(pri_path)
        print("success: deleted public and private key for id: ", scewl_id)
    else:
        print("failure: public and/or private key does not exist for ", scewl_id)


def enc_input(scewl_id):
    #TODO: encrypt input -> return public pri key
    #should write to specific files
    (scewl_pub, scewl_pri) = rsa.newkeys(512)
    
    #get filenames
    fn_pub = str(scewl_id) + ".pub"
    fn_pri = str(scewl_id) + ".pri"
    
    #write to pub file
    myfile_pub = open(fn_pub, 'w')
    print(type(scewl_pub))
    # myfile_pub.write(str(scewl_pub))
    myfile_pub.write(scewl_pub.save_pkcs1().decode())

    myfile_pub.close()


    ########################02/28 add public key transform
    #   Qiqing Huang note:
    #   add this part is because the public key format in controller is in the format of  modulus (N) plus publicExponent (E). But the rsa python api for loading the key needs the PEM DER ASN.1 PKCS#1 format. So there we do a transformation from PEM DER ASN.1 PKCS#1 to just modulus (N) plus publicExponent (E)
    #   the details of public key format can be found in https://stackoverflow.com/questions/18039401/how-can-i-transform-between-the-two-styles-of-public-key-format-one-begin-rsa
    with open(fn_pub, mode='rb') as publicfile:
        keydata = publicfile.read()
        # pubkey = rsa.PublicKey.load_pkcs1(keydata)
        test = rsa.PublicKey.load_pkcs1(keydata)
        # print(test)
        module_s = str(test).split("(")[1].split(",")[0].strip()
        publicExponent_s = str(test).split(")")[0].split(",")[1].strip()

        module = format(int(module_s), 'x')
        publicExponent = format(int(publicExponent_s), 'x').zfill(8)

        pubkeyForSend = open(fn_pub + "_send", "w")
        pubkeyForSend.write(module)
        pubkeyForSend.write("\r\n")
        pubkeyForSend.write(publicExponent)
        pubkeyForSend.close()

    ###############################02/28 add public key transform



    #write to pri file
    f_pri = open(fn_pri, 'w')
    # f_pri.write(str(scewl_pri))
    f_pri.write(scewl_pri.save_pkcs1().decode())
    f_pri.close()
    
    print("success: created private and public keys for ", str(scewl_id))

if __name__ == '__main__':
    #read input from command line
    read_input()
    #encrypt input -> return public & private keys
    # if scewl_id != "bad":
    #     enc_input(scewl_id)
    # else:
    #     print("did not generate keys")
