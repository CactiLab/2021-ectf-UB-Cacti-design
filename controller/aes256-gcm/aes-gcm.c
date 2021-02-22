//
//  aes-gcm.h
//  MKo
//
//  Created by Markus Kosmal on 20/11/14.
//  Modified by Xi Tan on 22/02/21
//

#include "aes-gcm.h"

int aes_gcm_encrypt_tag(unsigned char* output, const unsigned char* input, int input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len, uchar *tag, const size_t tag_len){
    
    int ret = 0;                // our return value
    gcm_context ctx;            // includes the AES context structure
    
    // size_t tag_len = 0;
    // unsigned char * tag_buf = NULL;
    
    gcm_setkey( &ctx, key, (const uint)key_len );
    
    ret = gcm_crypt_and_tag( &ctx, ENCRYPT, iv, iv_len, NULL, 0,
                            input, output, input_length, tag, tag_len);
    
    gcm_zero_ctx( &ctx );
    
    return( ret );
}

int aes_gcm_decrypt_auth(unsigned char* output, const unsigned char* input, int input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len, uchar *check_tag, const size_t tag_len){
    
    int ret = 0;                // our return value
    int diff;                   // an ORed flag to detect authentication errors
    size_t i;                   // our local iterator
    gcm_context ctx;            // includes the AES context structure
    
    // size_t tag_len = 0;
    uchar tag_buf[16];
    memset(tag_buf, 0, 16);
    
    gcm_setkey( &ctx, key, (const uint)key_len );
    ret = gcm_crypt_and_tag( &ctx, DECRYPT, iv, iv_len, NULL, 0,
                            input, output, input_length, tag_buf, tag_len);

    gcm_zero_ctx( &ctx );

    // now we verify the authentication tag in 'constant time'
    for( diff = 0, i = 0; i < tag_len; i++ )
        diff |= tag_buf[i] ^ check_tag[i];

    if( diff != 0 ) {                   // see whether any bits differed?
        memset( output, 0, input_length );    // if so... wipe the output data
        return( GCM_AUTH_FAILURE );     // return GCM_AUTH_FAILURE
    }

    return( ret );

}