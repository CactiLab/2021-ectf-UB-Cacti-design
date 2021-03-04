#ifdef _AUTH_

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
    rsa_sk sk;

    DTYPE msg[MAX_MODULUS_LENGTH] = {0};
    DTYPE cipher[MAX_MODULUS_LENGTH] = {0};
    DTYPE plaintext[MAX_MODULUS_LENGTH] = {0};

    char message[MAX_MODULUS_LENGTH * 2] = {0};
    char publickey[300] = {0};
    char plainmsg[MAX_MODULUS_LENGTH * 2 + 1];

    char *m = "message.txt";
    char *c = "aes_key";
    char *p = "auth_aes_key";
    char pub_file[100] = {0};
    char pri_file[100] = {0};

    memset(&pk, 0, sizeof(rsa_pk));
    memset(&sk, 0, sizeof(rsa_sk));

    if (argc < 2)
    {
        return -1;
    }

    sprintf(pub_file, "%s_publicKey", argv[1]);
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

    if (fread(&pk, sizeof(rsa_pk), 1, fp) == NULL)
    {
        printf("Read file error! %s\n", pub_file);
        return -1;
    }
    fclose(fp);

    // configure the e
    BN_init(pk.e, MAX_PRIME_LENGTH);
    //e=2^16+1
    pk.e[MAX_PRIME_LENGTH - 2] = 1;
    pk.e[MAX_PRIME_LENGTH - 1] = 1;

    // read private key from file
    fp = fopen(pri_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", pri_file);
        return -1;
    }
    if (fread(&sk, sizeof(rsa_sk), 1, fp) == NULL)
    {
        printf("Read file error! %s\n", pri_file);
        return -1;
    }
    fclose(fp);

    //read ciphertext from file
    fp = fopen(c, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", c);
        return 0;
    }
    if (fread(cipher, sizeof(cipher), 1, fp) == NULL)
    {
        printf("Read file error! %s\n", c);
        return -1;
    }
    fclose(fp);
    // BN_print_hex(cipher, sizeof(cipher));
    // string_to_hex(msg, message);

    printf("Verify starts...\n");
    rsa_encrypt(plaintext, MAX_MODULUS_LENGTH, cipher, MAX_MODULUS_LENGTH, &pk);
    printf("Verify done...\n\n");

    //write plaintext into file
    hex_to_string(plainmsg, plaintext);
    fp = fopen(p, "w");
    fwrite(plainmsg, 1, MAX_MODULUS_LENGTH * 2, fp);
    // fputs(plainmsg, fp);
    fclose(fp);

    return 0;
}

#endif