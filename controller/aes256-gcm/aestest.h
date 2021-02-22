#ifndef TEST_H
#define TEST_H

#include <inttypes.h>

#define keyLen 32
#define ivLen 12
#define aadLen 0
#define ptLen 16
#define ctLen 16
#define tagLen 16

typedef struct msg{
    uint16_t key_len;
    uint16_t iv_len;
    uint16_t aad_len;
    uint16_t pt_len;
    uint16_t ct_len;
    uint16_t tag_len;
    char *key;
    char *iv;
    char *aad;
    char *pt;
    char *ct;
    char *tag;
}msg_buff;

#endif