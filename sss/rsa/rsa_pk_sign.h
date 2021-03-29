#ifndef RSA_PK_SIGN_H
#define RSA_PK_SIGN_H


#include "keys.h"

typedef struct __attribute__((packed)){
    rsa_pk pk;
    uint8_t signature[64];
}rsa_pk_signed;

#define PK_SZ sizeof(rsa_pk)
#define PK_SIGN_SZ sizeof(rsa_pk_signed)

#endif