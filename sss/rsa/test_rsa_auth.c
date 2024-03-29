#ifdef _TEST_

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

    char pk_tmp[162] = {0};
    char sk_tmp[486] = {0};
    char message[MAX_MODULUS_LENGTH * 2] = {0};
    char publickey[300] = {0};
    // char ciphertext[MAX_MODULUS_LENGTH * 4 + 1];
    char plainmsg[MAX_MODULUS_LENGTH * 2 + 1];

    char *m = "message.txt";
    char *c = "aes_key";
    char *p = "auth_aes_key";
    char pub_file[100] = {0};
    char pri_file[100] = {0};
    // 10_publicKey.txt
    // uint16_t scewl_id = argv[1];

    memset(pk_tmp, 0, 162);
    memset(&pk, 0, sizeof(rsa_pk));
    memset(&sk, 0, sizeof(rsa_sk));

    if (argc < 2)
    {
        return -1;
    }

    // sprintf(pub_file, "%s_publicKey", argv[1]);
    // sprintf(pri_file, "%s_privateKey", argv[1]);

    sprintf(pub_file, "publicKey");
    sprintf(pri_file, "privateKey");

    printf("%s\n", pub_file);
    printf("%s\n", pri_file);

    // printf("sizeof(pk):%ld\n", sizeof(rsa_pk));  //162
    // printf("sizeof(sk):%ld\n", sizeof(rsa_sk));  //486

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

    printf("print publickey..\n");
    BN_print_hex(pk.n, MAX_MODULUS_LENGTH);
    BN_print_hex(pk.e, MAX_PRIME_LENGTH);
    BN_print_hex(pk.r_mod, MAX_MODULUS_LENGTH);
    printf("%x\n", pk.n_inv);

    fp = fopen(pri_file, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", pri_file);
        return -1;
    }
    fread(&sk, sizeof(rsa_sk), 1, fp);
    fclose(fp);

    printf("print privatekey..\n");
    BN_print_hex(sk.n, sizeof(sk.n));
    BN_print_hex(sk.p, sizeof(sk.p));
    BN_print_hex(sk.q, sizeof(sk.q));
    BN_print_hex(sk.phi_n, sizeof(sk.phi_n));
    BN_print_hex(sk.d, sizeof(sk.d));
    BN_print_hex(sk.d1, sizeof(sk.d1));
    BN_print_hex(sk.d2, sizeof(sk.d2));
    BN_print_hex(sk.p_inv, sizeof(sk.p_inv));
    BN_print_hex(sk.r_mod, sizeof(sk.r_mod));
    BN_print_hex(sk.p_mod, sizeof(sk.p_mod));
    BN_print_hex(sk.q_mod, sizeof(sk.q_mod));
    printf("%x\n", sk.n_inv);
    printf("%x\n", sk.p0_inv);
    printf("%x\n", sk.q0_inv);

    // read message from file
    fp = fopen(m, "r");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", m);
        return 0;
    }
    fgets(message, MAX_MODULUS_LENGTH * 2, fp);
    fclose(fp);
    string_to_hex(msg, message);

    printf("Sign starts...\n");
    rsa_decrypt(cipher, MAX_MODULUS_LENGTH, msg, MAX_MODULUS_LENGTH, &sk);
    printf("Sign done...\n\n");

    //write ciphertext into file
    fp = fopen(c, "wb");
    fwrite(cipher, 1, MAX_MODULUS_LENGTH * 2, fp);
    fclose(fp);

    printf("Verify starts...\n");
    rsa_encrypt(plaintext, MAX_MODULUS_LENGTH, cipher, MAX_MODULUS_LENGTH, &pk);
    printf("Verify done...\n\n");

    //write plaintext into file
    hex_to_string(plainmsg, plaintext);
    fp = fopen(p, "w");
    fwrite(plainmsg, 1, MAX_MODULUS_LENGTH * 2, fp);
    // fputs(plainmsg, fp);
    fclose(fp);

    if (BN_cmp(msg, MAX_MODULUS_LENGTH, plaintext, MAX_MODULUS_LENGTH) == 0)
    {
        printf("\nAfter decryption, plaintext equal to message.\n");
    }
    else
    {
        printf("\nAfter decryption, wrong answer.\n");
    }

    return 0;
}

#endif