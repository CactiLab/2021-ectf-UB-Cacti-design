/*
 * 2021 Collegiate eCTF
 * SCEWL Bus Controller implementation
 * Ben Janis
 *
 * (c) 2021 Cacti Team
 *
 */

#include <stdlib.h>
#include <time.h>
#include "controller.h"
#include "sha256.h"

// this will run if EXAMPLE_AES is defined in the Makefile
#ifdef EXAMPLE_AES
#include "aes.h"
#elif AES_GCM
#include "aes-gcm.h"

char int2char(uint8_t i) {
  char *hex = "0123456789abcdef";
  return hex[i & 0xf];
}
#endif

// message buffer
char buf[SCEWL_MAX_DATA_SZ];

int key_cryption()
{

  return 0;
}

// int body_encrypt_tag(intf_t *intf, char *data, uint16_t len)
int body_encrypt_tag()
{
  uint8_t aes_key[keyLen];
  int seed = 0;
  
  memset(aes_key, 0, keyLen);

  srand((unsigned int)aes_key);
  seed = rand();

  SHA256_Simple((const void *)seed, 32, aes_key);
  send_str("AES key:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyLen, (char *)aes_key);
  #ifdef KEY_CRYPTO
  #endif
  return 0;
}

int read_msg(intf_t *intf, char *data, scewl_id_t *src_id, scewl_id_t *tgt_id,
             size_t n, int blocking) {
  scewl_hdr_t hdr;
  int read, max;

  do {
    // clear buffer and header
    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, n);

    // find header start
    do {
      hdr.magicC = 0;

      if (intf_read(intf, (char *)&hdr.magicS, 1, blocking) == INTF_NO_DATA) {
        return SCEWL_NO_MSG;
      }

      // check for SC
      if (hdr.magicS == 'S') {
        do {
          if (intf_read(intf, (char *)&hdr.magicC, 1, blocking) == INTF_NO_DATA) {
            return SCEWL_NO_MSG;
          }
        } while (hdr.magicC == 'S'); // in case of multiple 'S's in a row
      }
    } while (hdr.magicS != 'S' && hdr.magicC != 'C');

    // read rest of header
    read = intf_read(intf, (char *)&hdr + 2, sizeof(scewl_hdr_t) - 2, blocking);
    if(read == INTF_NO_DATA) {
      return SCEWL_NO_MSG;
    }

    // unpack header
    *src_id = hdr.src_id;
    *tgt_id = hdr.tgt_id;

    // read body
    max = hdr.len < n ? hdr.len : n;
    read = intf_read(intf, data, max, blocking);

    // throw away rest of message if too long
    for (int i = 0; hdr.len > max && i < hdr.len - max; i++) {
      intf_readb(intf, 0);
    }

    // report if not blocking and full message not received
    if(read == INTF_NO_DATA || read < max) {
      return SCEWL_NO_MSG;
    }

  } while (intf != CPU_INTF && intf != SSS_INTF &&                       // always valid if from CPU or SSS
           ((hdr.tgt_id == SCEWL_BRDCST_ID && hdr.src_id == SCEWL_ID) || // ignore own broadcast
            (hdr.tgt_id != SCEWL_BRDCST_ID && hdr.tgt_id != SCEWL_ID))); // ignore direct message to other device

  return max;
}


int send_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data) {
  scewl_hdr_t hdr;

  // pack header
  hdr.magicS  = 'S';
  hdr.magicC  = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len    = len;

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  #ifdef MSG_CRYPTO
    body_encrypt_tag(intf, data, len);
  #endif
  intf_write(intf, data, len);

  return SCEWL_OK;
}


int handle_scewl_recv(char* data, scewl_id_t src_id, uint16_t len) {
  return send_msg(CPU_INTF, src_id, SCEWL_ID, len, data);
}


int handle_scewl_send(char* data, scewl_id_t tgt_id, uint16_t len) {
  return send_msg(RAD_INTF, SCEWL_ID, tgt_id, len, data);
}


int handle_brdcst_recv(char* data, scewl_id_t src_id, uint16_t len) {
  return send_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data);
}


int handle_brdcst_send(char *data, uint16_t len) {
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_BRDCST_ID, len, data);
}   


int handle_faa_recv(char* data, uint16_t len) {
  return send_msg(CPU_INTF, SCEWL_FAA_ID, SCEWL_ID, len, data);
}


int handle_faa_send(char* data, uint16_t len) {
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, data);
}


int handle_registration(char* msg) {
  scewl_sss_msg_t *sss_msg = (scewl_sss_msg_t *)msg;
  if (sss_msg->op == SCEWL_SSS_REG) {
    return sss_register();
  }
  else if (sss_msg->op == SCEWL_SSS_DEREG) {
    return sss_deregister();
  }

  // bad op
  return 0;
}


int sss_register() {
  scewl_sss_msg_t msg;
  scewl_id_t src_id, tgt_id;
  int status, len;

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_REG;
  
  // send registration
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // receive response
  len = read_msg(SSS_INTF, (char *)&msg, &src_id, &tgt_id, sizeof(scewl_sss_msg_t), 1);

  // notify CPU of response
  status = send_msg(CPU_INTF, src_id, tgt_id, len, (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // op should be REG on success
  return msg.op == SCEWL_SSS_REG;
}


int sss_deregister() {
  scewl_sss_msg_t msg;
  scewl_id_t src_id, tgt_id;
  int status, len;

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_DEREG;
  
  // send registration
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // receive response
  len = read_msg(SSS_INTF, (char *)&msg, &src_id, &tgt_id, sizeof(scewl_sss_msg_t), 1);

  // notify CPU of response
  status = send_msg(CPU_INTF, src_id, tgt_id, len, (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // op should be DEREG on success
  return msg.op == SCEWL_SSS_DEREG;
}

void add_sequence_number () {
  
}

int main() {
  int registered = 0, len;
  scewl_hdr_t hdr;
  uint16_t src_id, tgt_id;
  sequence_num messeage_sq;
  // intialize the sequence numbers to zero
  memset(&messeage_sq.sq_send, 0, sizeof(messeage_sq.sq_send));
  memset(&messeage_sq.sq_receive, 0, sizeof(messeage_sq.sq_receive));
  // initialize interfaces
  intf_init(CPU_INTF);
  intf_init(SSS_INTF);
  intf_init(RAD_INTF);

#ifdef EXAMPLE_AES
  // example encryption using tiny-AES-c
  struct AES_ctx ctx;
  uint8_t key[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
  uint8_t plaintext[16] = "0123456789abcdef";

  // initialize context
  AES_init_ctx(&ctx, key);

  // encrypt buffer (encryption happens in place)
  AES_ECB_encrypt(&ctx, plaintext);
  send_str("Example encrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)plaintext);

  // decrypt buffer (decryption happens in place)
  AES_ECB_decrypt(&ctx, plaintext);
  send_str("Example decrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)plaintext);
  // end example
#endif

#ifdef AES_GCM_TEST
// example encryption using aes-gcm 
    const uint8_t key[32] = {   0x31, 0xbd, 0xad, 0xd9, 
                                0x66, 0x98, 0xc2, 0x04, 
                                0xaa, 0x9c, 0xe1, 0x44,
                                0x8e, 0xa9, 0x4a, 0xe1, 
                                0xfb, 0x4a, 0x9a, 0x0b, 
                                0x3c, 0x9d, 0x77, 0x3b, 
                                0x51, 0xbb, 0x18, 0x22, 
                                0x66, 0x6b, 0x8f, 0x22  };

    const uint8_t iv[12] = {    0x0d, 0x18, 0xe0, 0x6c, 
                                0x7c, 0x72, 0x5a, 0xc9, 
                                0xe3, 0x62, 0xe1, 0xce};

    const uint8_t pt[16] = {    0x2d, 0xb5, 0x16, 0x8e,
                                0x93, 0x25, 0x56, 0xf8,
                                0x08, 0x9a, 0x06, 0x22,
                                0x98, 0x1d, 0x01, 0x7d};

    const uint8_t ct[16] = {      0xfa, 0x43, 0x62, 0x18, 
                                  0x96, 0x61, 0xd1, 0x63, 
                                  0xfc, 0xd6, 0xa5, 0x6d, 
                                  0x8b, 0xf0, 0x40, 0x5a};

    uint8_t tag[16];
    uint8_t output[ctLen];

    memset(tag, 0, 16);
    memset(output, 0, 16);
    
    // initialize context
    gcm_initialize();

    // encrypt buffer (encryption happens in place)
    ret = aes_gcm_encrypt_tag(output, pt, ptLen, key, keyLen, iv, ivLen, tag, tagLen);
    send_str("ciphertext:\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)output);
    send_str("tag:\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)tag);

    memset(output, 0, 16);

    // decrypt buffer (decryption happens in place)
    ret = aes_gcm_decrypt_auth(output, ct, ctLen, key, keyLen, iv, ivLen, tag, tagLen);
    if (ret != 0)
    {
        send_str("Authentication Failure!");
        return (-1);
    }
    
    send_str("Authentication Success!\n");
    send_str("plaintext:\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)output);
  // end example
#endif
#ifdef CRYPTO_TEST
  body_encrypt_tag();
#endif

  // serve forever
  while (1) {
    // register with SSS
    read_msg(CPU_INTF, buf, &hdr.src_id, &hdr.tgt_id, sizeof(buf), 1);

    if (hdr.tgt_id == SCEWL_SSS_ID) {
      registered = handle_registration(buf);
    }

    // server while registered
    while (registered) {
      memset(&hdr, 0, sizeof(hdr));

      // handle outgoing message from CPU
      if (intf_avail(CPU_INTF)) {
        // Read message from CPU
        len = read_msg(CPU_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);

        /*
        If the outgoing message is for broadcast or targeted transmission, the CIA properties should be maintained.
        No need to protect messages to SSS or FAA.
        */

        if (tgt_id == SCEWL_BRDCST_ID) {
          handle_brdcst_send(buf, len);
        } else if (tgt_id == SCEWL_SSS_ID) {
          registered = handle_registration(buf);
        } else if (tgt_id == SCEWL_FAA_ID) {
          add_sequence_number();
          handle_faa_send(buf, len);
        } else {
          handle_scewl_send(buf, tgt_id, len);
        }

        continue;
      }

      // handle incoming radio message
      if (intf_avail(RAD_INTF)) {
        // Read message from antenna
        len = read_msg(RAD_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);

        /*
        If the incoming message is broadcast or targeted transmission, the CIA properties should be verified.
        No need to check messages from FAA.
        */        

        if (tgt_id == SCEWL_BRDCST_ID) {
          handle_brdcst_recv(buf, src_id, len);
        } else if (src_id == SCEWL_FAA_ID) {
          handle_faa_recv(buf, len);
        } else {
          handle_scewl_recv(buf, src_id, len);
        }
      }
    }
  }
}
