#ifdef _AUTH_

/***********************************************************************************
 * 
 * This file is used to verify the signed messages
 * Input: cipher (should be written by sss.py, raw data)
 * Output: decipher (decrypted messages, will be read by sss.py to verify the header)
 * Usage: ./auth ${SCEWL_ID}

***********************************************************************************/

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <memory.h>
#include <stdlib.h>
#include <stdint.h>
#include "rsa.h"

int main(int argc, char *argv[])
{
    rsa_pk pk;

    DTYPE msg[MAX_MODULUS_LENGTH] = {0};
    DTYPE cipher[MAX_MODULUS_LENGTH] = {0};
    DTYPE plaintext[MAX_MODULUS_LENGTH] = {0};

    char message[MAX_MODULUS_LENGTH * 2] = {0};
    char publickey[300] = {0};
    char plainmsg[MAX_MODULUS_LENGTH * 2 + 1];

    char *m = "message.txt";
    char *c = "rsa/cipher";
    char *p = "rsa/decipher";
    char pub_file[100] = {0};
    char pri_file[100] = {0};

    memset(&pk, 0, sizeof(rsa_pk));

    if (argc < 2)
    {
        printf("usage: ./auth ${SCEWL_ID}\n");
        return -1;
    }

    sprintf(pub_file, "rsa/%s_publicKey", argv[1]);
    sprintf(pri_file, "%s_privateKey", argv[1]);

    // sprintf(pub_file, "publicKey");
    // sprintf(pri_file, "privateKey");

    // printf("%s\n", pub_file);
    // printf("%s\n", pri_file);

    FILE *fp;

    //read public key from file
    fp = fopen(pub_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", pub_file);
        return -1;
    }

    fread(&pk, sizeof(rsa_pk), 1, fp);
    fclose(fp);

    // configure the e
    BN_init(pk.e, MAX_PRIME_LENGTH);
    //e=2^16+1
    pk.e[MAX_PRIME_LENGTH - 2] = 1;
    pk.e[MAX_PRIME_LENGTH - 1] = 1;

    //read ciphertext from file
    fp = fopen(c, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", c);
        return 0;
    }
    fread(cipher, sizeof(cipher), 1, fp);
    fclose(fp);

    printf("Verify starts...\n");
    rsa_encrypt(plaintext, MAX_MODULUS_LENGTH, cipher, MAX_MODULUS_LENGTH, &pk);
    printf("Verify done...\n\n");

    //write plaintext into file
    hex_to_string(plainmsg, plaintext);
    fp = fopen(p, "w");
    fwrite(plainmsg, 1, MAX_MODULUS_LENGTH * 2, fp);
    fclose(fp);

    return 0;
}

#endif