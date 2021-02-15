
## Design tasks

1. AES-GCM crypto `c` code implementation [Xi Tan]
   - **Independent** project without OpenSSL or other libraries
   - No need to run the eCTF project, local implementation is ok
   - 256 bit
   - Advanced task: change the logic of controller.c to insert message encryption and decryption (AES-GCM part)
2. RSA crypto `c` code implementation [Gursimran Singh]
   - **Independent** project without OpenSSL or other libraries
   - No need to run the eCTF project, local implementation is ok
   - 256 bit
   - Advanced task: change the logic of controller.c to insert AES key encryption and decryption (RSA part)
3. Modify the controller.c for sequence number [Md Armanuzzaman]
   - **Independent** Modify controller.c file to keep track of the paired sequence number
   - The structure to keep track of the sequence number should be indexed by SED ID
   - Values should be updated after each successful transmission
   - Implement the logic according to the design doc to identify any replay attack
4. RSA crypto `python` code implementation [Ariel]
   - Can use python libs: `pip install rsa`
   - No need to run the eCTF project, local implementation is ok
   - Python filename: create_secret.py
   - Input: SCEWL_ID
   - Ouput: RSA key pair files: SCEWL_ID.pub, SCEWL_ID.pri
   - 256 bit
5. Modification of sss.py [Anjie Sun]
   1. registration  
       - input: signed message
       - operation
         - read the SCEWL_ID of the signed message 
         - check whether the ID is a provisioned SED or not
         - verify the header
         - store the id to the dedicated list
         - read local public key files and send them to the SED
    2. deregistration
       - input: signed message
       - operation
         - read the SCEWL_ID of the signed message 
         - check whether the ID is a provisioned SED & in the dedicated list or not
         - verify the header
         - remove the ID from the dedicated list
6. Other small tasks [Malav]
   - Modification of 2b_create_sed_secrets.Dockerfile
      - copy create_secret.py to sss/folder
   - Modification of 2c_build_controller.Dockerfile
      - copy the SCEWL_ID.pri to /sed/sed.secret
   - Modification of 3_remove_sed.Dockerfile
      - Delete SCEWL_ID.pub and SCEWL_ID.pri from SSS container (`/secrect`)