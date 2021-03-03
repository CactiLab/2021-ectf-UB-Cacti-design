#ifdef _KEYGEN_
#include<stdio.h>
#include<time.h>
#include<string.h>
#include<memory.h>
#include<stdlib.h>
#include<stdint.h>
#include "rsa.h"

int main(void)
{
	rsa_pk pk;
	rsa_sk sk;

	char *pkey = "publicKey.txt";
	char *skey = "privateKey.txt";
    char *pkey_raw = "publicKey";
    char *skey_raw = "privateKey";

	FILE *fp;

	printf("Key generation starts...\n");
	rsa_key_generation(&pk, &sk);
	printf("Key generation done...\n\n");

    //write public keys into file
    printf("Write public key...\n");
    fp = fopen(pkey, "w");
    fclose(fp);
    fp = fopen(pkey, "a");
    BN_printToFile(pk.n, MAX_MODULUS_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(pk.e, MAX_PRIME_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(pk.r_mod, MAX_MODULUS_LENGTH, fp);
    fputc('\n', fp);
    fprintf(fp, STD_FORMAT_STR, pk.n_inv);
    fputc('\n', fp);
    fclose(fp);

    printf("Write public raw key...\n");
    fp = fopen(pkey_raw, "wb");
    fclose(fp);
    fp = fopen(pkey_raw, "a");
    fwrite((char *)&pk.n, 1, MAX_MODULUS_LENGTH*2, fp );
    fwrite((char *)&pk.e, 1, MAX_PRIME_LENGTH*2, fp );
    fwrite((char *)&pk.r_mod, 1, MAX_MODULUS_LENGTH*2, fp );
    fwrite((char *)&pk.n_inv, 1, 2, fp );
    fclose(fp);


    //write private keys into file
    printf("Write private key...\n");
    fp = fopen(skey, "w");
    fclose(fp);
    fp = fopen(skey, "a");
    BN_printToFile(sk.n, MAX_MODULUS_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(sk.p, MAX_PRIME_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(sk.q, MAX_PRIME_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(sk.phi_n, MAX_MODULUS_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(sk.d, MAX_MODULUS_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(sk.d1, MAX_PRIME_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(sk.d2, MAX_PRIME_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(sk.p_inv, MAX_PRIME_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(sk.r_mod, MAX_MODULUS_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(sk.p_mod, MAX_PRIME_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(sk.q_mod, MAX_PRIME_LENGTH, fp);
    fputc('\n', fp);
    fprintf(fp, STD_FORMAT_STR, sk.n_inv);
    fputc('\n', fp);
    fprintf(fp, STD_FORMAT_STR, sk.p0_inv);
    fputc('\n', fp);
    fprintf(fp, STD_FORMAT_STR, sk.q0_inv);
    fputc('\n', fp);
    fclose(fp);

    printf("Write private raw key...\n");
    fp = fopen(skey_raw, "wb");
    fclose(fp);
    fp = fopen(skey_raw, "a");
    fwrite((char *)&sk.n, 1, MAX_MODULUS_LENGTH*2, fp);
    fwrite((char *)&sk.p, 1, MAX_PRIME_LENGTH*2, fp);
    fwrite((char *)&sk.q, 1, MAX_PRIME_LENGTH*2, fp);
    fwrite((char *)&sk.phi_n, 1, MAX_MODULUS_LENGTH*2, fp);
    fwrite((char *)&sk.d, 1, MAX_MODULUS_LENGTH*2, fp);
    fwrite((char *)&sk.d1, 1, MAX_PRIME_LENGTH*2, fp);
    fwrite((char *)&sk.d2, 1, MAX_PRIME_LENGTH*2, fp);
    fwrite((char *)&sk.p_inv, 1, MAX_PRIME_LENGTH*2, fp);
    fwrite((char *)&sk.r_mod, 1, MAX_MODULUS_LENGTH*2, fp);
    fwrite((char *)&sk.p_mod, 1, MAX_PRIME_LENGTH*2, fp);
    fwrite((char *)&sk.q_mod, 1, MAX_PRIME_LENGTH*2, fp);
    fwrite((char *)&sk.n_inv, 1, 2, fp);
    fwrite((char *)&sk.p0_inv, 1, 2, fp);
    fwrite((char *)&sk.q0_inv, 1, 2, fp);
    fclose(fp);

	return 0;
}

#endif