#ifdef _SIGN_

/***********************************************************************************
 * 
 * This file is used to sign the target pk
 * Input: ${SCEWL_ID}_publicKey
 * Output: ${SCEWL_ID}_publicKey_signed (signed target pk, will be responsed to the registered SED)
 * Usage: ./sign ${SCEWL_ID}

***********************************************************************************/

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <memory.h>
#include <stdlib.h>
#include <stdint.h>
#include "rsa.h"
// #include "sha1.h"
#include "md5.h"
#include "rsa_pk_sign.h"

int sign_pk(char *tgt_pub_file, char *tgt_pub_signed_file)
{
    rsa_sk sss_sk;

    rsa_pk tgt_pk;

    // unsigned char tgt_pk[PK_SIGN_SZ] = {0};
    char *sss_pri_file = "rsa/sss_privateKey";
    unsigned char output[64] = {0};

    DTYPE msg[MAX_MODULUS_LENGTH * 2] = {0};
    DTYPE cipher[MAX_MODULUS_LENGTH] = {0};

    memset(&sss_sk, 0, sizeof(rsa_sk));

    FILE *fp;

    //read sss private key from file
    fp = fopen(sss_pri_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", sss_pri_file);
        return -1;
    }

    fread(&sss_sk, sizeof(rsa_sk), 1, fp);
    fclose(fp);

    //read target public key from file
    fp = fopen(tgt_pub_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", tgt_pub_file);
        return -1;
    }

    fread((char *)&tgt_pk, sizeof(rsa_pk), 1, fp);
    fclose(fp);

    // configure the e
    BN_init(tgt_pk.e, MAX_PRIME_LENGTH);
    //e=2^16+1
    tgt_pk.e[MAX_PRIME_LENGTH - 2] = 1;
    tgt_pk.e[MAX_PRIME_LENGTH - 1] = 1;

    // printf("SHA1 of the target pk starts...\n");
    // SHA_Simple((unsigned char *)&tgt_pk, sizeof(rsa_pk), output);
    MD5Calc((const unsigned char *)&tgt_pk, sizeof(rsa_pk), output);

    // printf("sign the target pk digest...\n");
    rsa_decrypt(cipher, MAX_MODULUS_LENGTH, (DTYPE *)&output, MAX_MODULUS_LENGTH, &sss_sk);

    fp = fopen(tgt_pub_signed_file, "wb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", tgt_pub_signed_file);
        return -1;
    }

    // write pk to the file
    // fwrite(&tgt_pk, 1, sizeof(rsa_pk), fp);
    //write signed digest into file
    fwrite(cipher, 1, MAX_MODULUS_LENGTH * 2, fp);
    fclose(fp);

    return 0;
}

int auth_pk(char *tgt_pub_file, char *tgt_pub_signed_file)
{

    rsa_pk sss_pk;

    rsa_pk tgt_pk;
    char *sss_pub_file = "rsa/sss_publicKey";
    // char *tmp = "rsa/tmp";
    char tmp[100] = {0};
    unsigned char output[64] = {0};

    DTYPE msg[MAX_MODULUS_LENGTH * 2] = {0};
    DTYPE cipher[MAX_MODULUS_LENGTH] = {0};
    DTYPE decipher[MAX_MODULUS_LENGTH] = {0};

    memset(&sss_pk, 0, sizeof(rsa_pk));

    sprintf(tmp, "%s_tmp", tgt_pub_signed_file);

    FILE *fp;

    //read sss public key from file
    fp = fopen(sss_pub_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", sss_pub_file);
        return -1;
    }

    fread(&sss_pk, sizeof(rsa_pk), 1, fp);
    fclose(fp);

    //read target public key from file
    fp = fopen(tgt_pub_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", tgt_pub_file);
        return -1;
    }

    fread((char *)&tgt_pk, sizeof(rsa_pk), 1, fp);
    fclose(fp);

    // configure the e
    BN_init(tgt_pk.e, MAX_PRIME_LENGTH);
    //e=2^16+1
    tgt_pk.e[MAX_PRIME_LENGTH - 2] = 1;
    tgt_pk.e[MAX_PRIME_LENGTH - 1] = 1;

    // configure the e
    BN_init(sss_pk.e, MAX_PRIME_LENGTH);
    //e=2^16+1
    sss_pk.e[MAX_PRIME_LENGTH - 2] = 1;
    sss_pk.e[MAX_PRIME_LENGTH - 1] = 1;

    //read target signed public key from file
    fp = fopen(tgt_pub_signed_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", tgt_pub_signed_file);
        return -1;
    }

    // fread(tgt_pk, sizeof(rsa_pk), 1, fp);
    fread(cipher, MAX_MODULUS_LENGTH * 2, 1, fp);
    fclose(fp);

    printf("SHA1 of the target pk starts...\n");
    // SHA_Simple((unsigned char *)&tgt_pk, sizeof(rsa_pk), output);
    MD5Calc((const unsigned char *)&tgt_pk, sizeof(rsa_pk), output);

    printf("auth the target pk digest...\n");
    rsa_encrypt(decipher, MAX_MODULUS_LENGTH, cipher, MAX_MODULUS_LENGTH, &sss_pk);

    fp = fopen(tmp, "wb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", tmp);
        return -1;
    }

    // write sha1 to the file
    fwrite(output, 1, 64, fp);
    //write signed digest into file
    fwrite(decipher, 1, MAX_MODULUS_LENGTH * 2, fp);
    fclose(fp);

    // if (BN_cmp(decipher, MAX_MODULUS_LENGTH, (DTYPE *)&output, MAX_MODULUS_LENGTH) == 0)
    // {
    //     printf("\nAfter decryption, plaintext equal to message.\n");
    // }
    // else
    // {
    //     printf("\nAfter decryption, wrong answer.\n");
    // }

    return 0;
}

int main(int argc, char *argv[])
{
    char tgt_pub_file[100] = {0};
    char tgt_pub_signed_file[100] = {0};

    if (argc < 2)
    {
        printf("usage: ./auth ${SCEWL_ID}\n");
        return -1;
    }

    sprintf(tgt_pub_file, "rsa/%s_publicKey", argv[1]);
    sprintf(tgt_pub_signed_file, "rsa/%s_publicKey_signed", argv[1]);

    sign_pk(tgt_pub_file, tgt_pub_signed_file);
    auth_pk(tgt_pub_file, tgt_pub_signed_file);

    return 0;
}

#endif