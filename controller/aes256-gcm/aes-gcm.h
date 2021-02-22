//
//  aes-gcm.h
//  MKo
//
//  Created by Markus Kosmal on 20/11/14.
//  Modified by Xi Tan on 22/02/21
//
//

#ifndef aes_gcm_h
#define aes_gcm_h

#include "gcm.h"  

int aes_gcm_encrypt_tag(uint8_t* output, const uint8_t* input, int input_length, const uint8_t* key, const size_t key_len, const uint8_t * iv, const size_t iv_len, uint8_t *tag, const size_t tag_len);

int aes_gcm_decrypt_auth(uint8_t* output, const uint8_t* input, int input_length, const uint8_t* key, const size_t key_len, const uint8_t * iv, const size_t iv_len, uint8_t *check_tag, const size_t tag_len);

#endif
