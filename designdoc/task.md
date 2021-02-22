## Updates 02/22/2021
1. RSA crypto `c` code implementation [Gursimran Singh]
   - Standalone project without OpenSSL
   - No need to run the eCTF project, local implementation is ok
   - 256 bit, 521 bit??
   - APIs

2. Modify the controller.c for sequence number [Md Armanuzzaman]
   - **Independent** Modify controller.c file to keep track of the paired sequence number
   - The structure to keep track of the sequence number should be indexed by SED ID
   - Values should be updated after each successful transmission
   - Implement the logic according to the design doc to identify any replay attack

3. Modification of sss.py [Anjie Sun, Qiqing Huang]
   1. registration  
       - <del>input: signed message [done]
       - operation
         - <del>read the SCEWL_ID of the signed message [done]
         - <del>check whether the ID is a provisioned SED or not [done]
         - <del>verify the header [done]
         - <del>store the id to the dedicated list [done]
         - read local public key files and send them to the SED
   2. deregistration
       - <del>input: signed message [done]
       - operation
         - <del>read the SCEWL_ID of the signed message [done] 
         - <del>check whether the ID is a provisioned SED & in the dedicated list or not [done]
         - <del>verify the header [done]
         - <del>remove the ID from the dedicated list [done]

4. Other small tasks [Malav]
   - Modification of 2b_create_sed_secrets.Dockerfile
      - <del>copy create_secret.py to sss/folder, and run [done]
   - Modification of 2c_build_controller.Dockerfile
      - copy the SCEWL_ID.pri to /sed/sed.secret
   - Modification of 3_remove_sed.Dockerfile
      - <del>Delete (SCEWL_ID.pub, SCEWL_ID.pri) from SSS container (`/secrect`)(python3 create_secret.py delete_key)
   - Check whether those commands work or not.

5. Bussiness logic [Xi Tan]
   - Suppose we already have all the APIs we need
     - Receive messages
       - input: encrypted message
       - operations
         - read the header, check the type: broadcast or others
         - verify the signature
         - decrypt and authenticate the message body
     - Send out messages
       - operations
         - sign the header
         - encrypt and sign the message body

## Design tasks [done]

1. <del>AES-GCM crypto `c` code implementation [Xi Tan] [done]
   - Stand-alone project without OpenSSL, 256 bit
   - APIs: 
     - **aes_gcm_encrypt_tag**
       - input: plaintext, pt_len, key, key_len, iv, iv_len, tag, tag_len
       - output: ciphertext, tag
     - **aes_gcm_decrypt_auth**
       - input: ciphertext, ct_len, key, key_len, iv, iv_len, tag, tag_len
       - output: auth, plaintext

2. <del>RSA crypto `python` code implementation [Ariel] [done]
   - Can use python libs: `pip install rsa`
   - Python filename: create_secret.py
   - Input: SCEWL_ID
   - Ouput: RSA key pair files: (SCEWL_ID.pub, SCEWL_ID.pri)
   - 256 bit??
   - **Advanced task**:
     - key pair geneartion:
       - usage: python create_secret.py [SCEWL_ID] [op]
       - example: python create_secret.py 12 generate_key
       - output: RSA key pair files: SCEWL_ID.pub, SCEWL_ID.pri
     - key pair destroy:
       - usage: python create_secret.py [SCEWL_ID] [op]
       - example: python create_secret.py 12 delete_key
       - output: delete key pair files: SCEWL_ID.pub, SCEWL_ID.pri

