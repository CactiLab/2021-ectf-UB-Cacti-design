## INPUT: SCEWL_ID -> OUTPUT: SCEWL_ID.pub, SCEWL_ID.pri

import rsa
import sys

def read_input():
    #TODO read input from command line (SHOULD ONLY BE 1 INPUT)
    if (len(sys.argv) != 2): 
        print("failure: input should be one argument\nUsage: python create_secret.py [SCEWL_ID]")
        return "bad"
    else:
        return sys.argv[1]

def enc_input(scewl_id):
    #TODO: encrypt input -> return public pri key
    #should write to specific files
    (scewl_pub, scewl_pri) = rsa.newkeys(256)
    
    #get filenames
    fn_pub = str(scewl_id) + ".pub"
    fn_pri = str(scewl_id) + ".pri"
    
    #write to pub file
    myfile_pub = open(fn_pub, 'w')
    myfile_pub.write(str(scewl_pub))
    myfile_pub.close()

    #write to pri file
    f_pri = open(fn_pri, 'w')
    f_pri.write(str(scewl_pri))
    f_pri.close()

    return "success"

if __name__ == '__main__':
    #read input from command line
    scewl_id = read_input()
    #encrypt input -> return public & private keys
    if scewl_id != "bad":
        enc_input(scewl_id)
    else:
        print("did not generate keys")
