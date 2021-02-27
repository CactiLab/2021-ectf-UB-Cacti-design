#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "./lib/gmp.h"


#define MIN_MODLEN	  	  512

#define MAX_MODLEN		16384


#define NULL_TERMINATED		0



int generatekeypair(const unsigned long int key_size, char **kn, char **ke, char **kd)
{
	if (key_size < MIN_MODLEN || key_size > MAX_MODLEN) {
		return -1;
	}

	mpz_t prand, qrand, p, q, p1, q1, phi, n, d, e, gcd;
	mpz_inits(prand, qrand, p, q, p1, q1, phi, n, d, e, gcd, NULL_TERMINATED);


	mpz_set_ui(e, 65537);

	gmp_randstate_t state;
	gmp_randinit_default(state);

	clock_t tm = time(NULL);
	gmp_randseed_ui(state, tm);

	mp_bitcnt_t lp = (key_size + 1) >> 1;
	mp_bitcnt_t lq = key_size - lp;


	mpz_rrandomb(prand, state, lp);
	while (1) {
		mpz_nextprime(p, prand);
		do {

			gmp_randseed_ui(state, ++tm);
			mpz_rrandomb(qrand, state, lq);
			mpz_nextprime(q, qrand);
			/*p > q*/
			if (mpz_cmp(p, q) < 0) {
				mpz_swap(p, q);
			}
			mpz_mul(n, p, q);

		} while (mpz_sizeinbase(n, 2) < key_size);

		/*phi = (p-1)*(q-1)*/
		mpz_sub_ui(p1, p, 1);
		mpz_sub_ui(q1, q, 1);
		mpz_mul(phi, p1, q1);


		mpz_gcd(gcd, phi, e);
		if (0 != mpz_cmp_ui(gcd, 1)) {
			continue;
		}


		mpz_invert(d, e, phi);


		*kn = mpz_get_str(NULL, 62, n);
		*ke = mpz_get_str(NULL, 62, e);
		*kd = mpz_get_str(NULL, 62, d);

		break;
	}


	mpz_clears(prand, p, q, p1, q1, phi, n, d, e, gcd, NULL_TERMINATED);

	return 0;
}



int cipher(const char *msg, const unsigned int msg_len, const char *kn, const char *ke, char **cryptogram)
{
	char *km = (char*)malloc(2 * msg_len + 1);
	if (NULL == km) {
		return -1;
	}

	char hex[] = "0123456789ABCDEF";
	unsigned int i, j;
	for (i = 0, j = 0; j < msg_len; i += 2, j++) {
		km[i] = hex[msg[j] / 16]; //高位
		km[i + 1] = hex[msg[j] % 16];
	}
	km[2 * msg_len] = '\0';

	mpz_t m, n, e, res;
	mpz_inits(m, n, e, res, NULL_TERMINATED);


	if (0 != mpz_set_str(n, kn, 62) || 0 != mpz_set_str(e, ke, 62) || 0 != mpz_set_str(m, km, 16)) {
		mpz_clears(m, n, e, res, NULL_TERMINATED);
		free(km);
		return -1;
	}


	mpz_powm(res, m, e, n);


	*cryptogram = mpz_get_str(NULL, 62, res);

	mpz_clears(m, n, e, res, NULL_TERMINATED);
	free(km);

	return 0;
}


#define CHAR_TO_INT(c)	(c >= 'a' ? c - 'a' + 10 : (c >= 'A' ? c - 'A' + 10 : c - '0'))


#define CHARS_TO_INT(h, l)	(CHAR_TO_INT(h)*16 + CHAR_TO_INT(l))


int decipher(const char *cryptogram, const char *kn, const char *kd, char **msg)
{
	mpz_t m, n, d, out;
	mpz_inits(m, n, d, out, NULL_TERMINATED);


	if (0 != mpz_set_str(n, kn, 62) || 0 != mpz_set_str(d, kd, 62) || 0 != mpz_set_str(m, cryptogram, 62)) {
		mpz_clears(m, n, d, out, NULL_TERMINATED);
		return -1;
	}


	mpz_powm_sec(out, m, d, n);

	char *message = mpz_get_str(NULL, 16, out);

	unsigned int msg_len = strlen(message);
	if (msg_len % 2 != 0) {
		mpz_clears(m, n, d, out, NULL_TERMINATED);
		return -1;
	}

	*msg = (char*)malloc(msg_len / 2 + 1);
	if (NULL == *msg) {
		mpz_clears(m, n, d, out, NULL_TERMINATED);
		return -1;
	}


	for (unsigned int i = 0, j = 0; i < msg_len; i += 2, j++) {
		(*msg)[j] = CHARS_TO_INT(message[i], message[i+1]);
	}
	(*msg)[msg_len / 2] = '\0';

	mpz_clears(m, n, d, out, NULL_TERMINATED);

	return 0;
}


typedef char*	PCHAR;

int main()
{
	PCHAR n, e, d;
	generatekeypair(512, &n, &e, &d);

	// Qiqing Huang note:
	// I forked this rsa c imolementation from https://github.com/prophetss/rsa

	// to compile:gcc -o test -g -Wall -Wextra rsa.c -lgmp
	// in the compile, if it prompts that ld lack of some package, just install it to fix the link problem
	// the key size can be modified in the generatekeypair()'s first parameter


	// test output
	// n: xR9fAlrdKvCIINsqEBfT6BU8DptiTC4VZNC34wn8BAYwQ5yMrAqPp01xSP4kjaP2RVMt0HjNrQ2VURgeJpJQXP
	// e: H33
	// d: 6YJmhpzMI6QdHS24YXtnlh5Qj3N8ppKRetMNiGz53otN8svNx7j6Cyy3q07YQWf87hWphrLgwTqhzofnmFhkET

	// note:
	// public key ＝(E, N)
	// private key = (D, N)


	// unit tests:

	printf("n: %s\ne: %s\nd: %s\n", n, e, d);

	char msg[] = "I am What I am";
	printf("\noriginal: %s\n", msg);

	PCHAR cryptogram;
	cipher(msg, strlen(msg), n, e, &cryptogram);
	printf("encode: %s\n", cryptogram);

	PCHAR message;
	decipher(cryptogram, n, d, &message);
	printf("decode: %s\n", message);
}