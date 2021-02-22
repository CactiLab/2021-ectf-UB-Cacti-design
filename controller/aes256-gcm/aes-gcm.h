//
//  aes-gcm.h
//  MKo
//
//  Created by Markus Kosmal on 20/11/14.
//  Modified by Xi Tan on 22/02/21
//

#ifndef aes_gcm_h
#define aes_gcm_h

#include "gcm.h"  

int aes_gcm_encrypt_tag(unsigned char* output, const unsigned char* input, int input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len, uchar *tag, const size_t tag_len);

int aes_gcm_decrypt_auth(unsigned char* output, const unsigned char* input, int input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len, uchar *check_tag, const size_t tag_len);

#endif
