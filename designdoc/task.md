
## Design tasks

1. AES-GCM crypto `c` code implementation 
   - **Independent** project without openssl or other libraries
   - No need to run the eCTF project, local implementation is ok
   - 256 bit
   - Advanced task: change the logic of controller.c to insert message encryption and decryption (AES-GCM part)
2. RSA crypto `c` code implementation
   - **Independent** project without openssl or other libraries
   - No need to run the eCTF project, local implementation is ok
   - 256 bit
   - Advanced task: change the logic of controller.c to insert AES key encryption and decryption (RSA part)
3. RSA crypto `python` code implementation
   - Can use python libs: `pip install rsa`
   - No need to run the eCTF project, local implementation is ok
   - Python filename: create_secret.py
   - Input: SCEWL_ID
   - Ouput: RSA key pair files: SCEWL_ID.pub, SCEWL_ID.pri
   - 256 bit
4. Modification of sss.py
   1. registration  
       - input: signed message
       - operation
         - read the SCEWL_ID of the signed message 
         - check whether the ID is a provisoned SED or not
         - verify the header
         - store the id to the deticated list
         - read local public key files and send them to the SED
    1. deregistration
       - input: signed message
       - operation
         - read the SCEWL_ID of the signed message 
         - check whether the ID is a provisoned SED & in the deticated list or not
         - verify the header
         - remove the ID from the deticated list
5. Other small tasks
   - Modification of 2b_create_sed_secrets.Dockerfile
      - copy create_secret.py to sss/folder
   - Modification of 2c_build_controller.Dockerfile
      - copy the SCEWL_ID.pri to /sed/sed.secret
   - Modification os 3_remove_sed.Dockerfile
      - Delete SCEWL_ID.pub and SCEWL_ID.pri