## 02/10/2021

- Key generation and storage
  
  1. At 2b dockerfile: run a docker container to generate the RSA key
     - modified: sss/create_secrets.py
  
  2. At 2c: copy the pub and pri to the provisioned seds

  3. At registration, update all other pub keys to SEDs.
      - modified: sss/sss.py to check the private key for each SED
      - structure to store all public keys in the memory then delete the file: 128bit  64k

  4. When deleting the SED, remove the public and private key in the sss/secrets file

- Sequence number
  - 2^32 -> 4 bytes to store a sequence number
  - each SED maintains the sequence number for each one
  - the communication between a and b
    - a retrieves the sequence number, encrypt it.
    - b receive the msg and check the sequence number
    - should consider an overflow

## 02/02/2021

Need to change `dockerfiles/2b_create_sed_secrets.Dockerfile` file to generate secrets for each new SED.
This docker file gets invoked when each SED is created using `add_sed` command.

1. When we ran `add_sed` generate symmetric key pair for each one.

Message authentication and encryption: hamc + AES

msg:
header + body
          ||
header + AES(body) + hmac(header + AES(body))

## 02/01/2021

controller.c/
send_msg(): header, body
read_msg():  

sss_register: check scew_id


secret.h:
hashed 
a structure or file to store provisioned SEDs,
16 at the same time, at least 256 to a deployment


makefile:
1. add_sed, the SCEWL_ID is the provisioned SEDs, 
2. deploy: launch the recorded SEDs

echo/sss:latest - Contiains the SSS, any deployment-wide secrets, and the SED-specific secrets for the echo server and clients

sss.py: define the provisions SEDs, only register the valid SEDs with its hashed id

sss.Dockerfile:
Has the secrets folder, we can add secret files here to store the hash or whatever of the provisioned SEDs

Man in the middle attack
third party, public key?
Authenticate the communication between sss and SEDs, the attackers should not be able to read the message in between.

what if the message lost.
a structure to store the message body that contains the sequence number

typedef struct scewl_body_t {
  uint8_t sequence_num;
  /* data follows */
} scewl_body_t;


## 01/22/2021

Went through the rule doc and some parts of the source code.
- We are supposed to modify the controller parts, and other parts? (I don't remember.)
- Quick notes:
  - 4.6 Message Format
    - If the head is fixed, message body should be protected.
  - Security Requirements (rule doc page 25):
    - Confidentiality
      - Transitions should be encrypted: RSA or AES (mode is important)
    - Integrity and authentication
      - hmac or ...
      - different keys for different SEDs, where to store the keys?
    - Replay protection
      - Sequence number for each pair of SEDs? 
    - SED User code is not secure, and CPU interface is not secure
  - 7.1.2 Reverse Engineering Challenge
    - ch-1 passwd: `firstoneseasy`

