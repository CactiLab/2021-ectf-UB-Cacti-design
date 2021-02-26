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

char int2char(uint8_t i)
{
  char *hex = "0123456789abcdef";
  return hex[i & 0xf];
}
#endif

// message buffer
char buf[SCEWL_MAX_DATA_SZ];
//sequence number structure
sequence_num messeage_sq;
int key_cryption()
{

  return 0;
}
//need to update header length before sending the header ex: len = len + sizeof(uint32_t)
void add_sequence_number(scewl_hdr_t *hdr,intf_t *intf)
{
  uint32_t updated_sq_num = ++messeage_sq.sq_send[hdr->tgt_id];
  intf_write(intf,(char *)&updated_sq_num,sizeof(uint32_t));
}

int send_enc_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data)
{
  scewl_hdr_t hdr;

  // pack header
  hdr.magicS = 'S';
  hdr.magicC = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len = len + sizeof(scewl_msg_hdr_t);

  scewl_msg_hdr_t crypto_msg_hdr;
  scewl_msg_t crypto_msg;
  // int ret = 0;
  uint8_t key[32] = {0x31, 0xbd, 0xad, 0xd9,
                     0x66, 0x98, 0xc2, 0x04,
                     0xaa, 0x9c, 0xe1, 0x44,
                     0x8e, 0xa9, 0x4a, 0xe1,
                     0xfb, 0x4a, 0x9a, 0x0b,
                     0x3c, 0x9d, 0x77, 0x3b,
                     0x51, 0xbb, 0x18, 0x22,
                     0x66, 0x6b, 0x8f, 0x22};

  uint8_t iv[12] = {0x0d, 0x18, 0xe0, 0x6c,
                    0x7c, 0x72, 0x5a, 0xc9,
                    0xe3, 0x62, 0xe1, 0xce};

  // uint8_t pt[16] = {0x2d, 0xb5, 0x16, 0x8e,
  //                         0x93, 0x25, 0x56, 0xf8,
  //                         0x08, 0x9a, 0x06, 0x22,
  //                         0x98, 0x1d, 0x01, 0x7d};

  // uint8_t ct[16] = {0xfa, 0x43, 0x62, 0x18,
  //                         0x96, 0x61, 0xd1, 0x63,
  //                         0xfc, 0xd6, 0xa5, 0x6d,
  //                         0x8b, 0xf0, 0x40, 0x5a};

  // uint8_t tag[16];
  uint8_t plaintext[len];
  uint8_t ciphertext[len];

  // memset(tag, 0, 16);
  memset(ciphertext, 0, len);
  memset(plaintext, 0, len);
  memset(&crypto_msg_hdr, 0, sizeof(crypto_msg_hdr));
  memset(&crypto_msg, 0, sizeof(crypto_msg));

  memcpy(crypto_msg.aes_key, key, keyLen);
  memcpy(crypto_msg.iv, iv, ivLen);

  // initialize context
  gcm_initialize();

  // encrypt buffer (encryption happens in place)
  aes_gcm_encrypt_tag(ciphertext, (const uint8_t *)data, len, crypto_msg.aes_key, keyLen, crypto_msg.iv, ivLen, crypto_msg.tag, tagLen);
  // memcpy(data, ciphertext, len);
  memcpy(crypto_msg.body, ciphertext, len);

#ifdef KEY_CRYPTO
#endif
#ifdef DEBUG
  send_str("------------------------------------------------------------------:\n");
  send_str("test enc message:\n");
  send_str("plaintext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)data);
  send_str("key:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyLen, (char *)crypto_msg.aes_key);
  send_str("iv:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, ivLen, (char *)crypto_msg.iv);
  send_str("tag:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, tagLen, (char *)crypto_msg.tag);
  send_str("ciphertext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)crypto_msg.body);
  send_str("------------------------------------------------------------------:\n");
  // memset(ciphertext, 0, 16);
#endif
  // int ret = 0;
  // ret = aes_gcm_decrypt_auth(plaintext, crypto_msg.body, len, crypto_msg.aes_key, keyLen, crypto_msg.iv, ivLen, crypto_msg.tag, tagLen);
  // if (ret != 0)
  // {
  //   send_str("Authentication Failure!");
  //   return (-1);
  // }

  // send_str("Authentication Success!\n");
  // send_str("plaintext:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)plaintext);

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  // intf_write(intf, data, len);
  intf_write(intf, (char *)&crypto_msg, hdr.len);

  return SCEWL_OK;
}

int send_auth_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data)
{
  scewl_hdr_t hdr;

  // pack header
  hdr.magicS = 'S';
  hdr.magicC = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len = len - sizeof(scewl_msg_hdr_t);

  // scewl_msg_hdr_t crypto_msg_hdr;
  scewl_msg_t *crypto_msg = NULL;
  // int ret = 0;
  // uint8_t key[32] = {0x31, 0xbd, 0xad, 0xd9,
  //                    0x66, 0x98, 0xc2, 0x04,
  //                    0xaa, 0x9c, 0xe1, 0x44,
  //                    0x8e, 0xa9, 0x4a, 0xe1,
  //                    0xfb, 0x4a, 0x9a, 0x0b,
  //                    0x3c, 0x9d, 0x77, 0x3b,
  //                    0x51, 0xbb, 0x18, 0x22,
  //                    0x66, 0x6b, 0x8f, 0x22};

  // uint8_t iv[12] = {0x0d, 0x18, 0xe0, 0x6c,
  //                   0x7c, 0x72, 0x5a, 0xc9,
  //                   0xe3, 0x62, 0xe1, 0xce};

  // uint8_t tag[tagLen] = {0xd6, 0x36, 0xac, 0x1b, 0xbe, 0xdd, 0x5c, 0xc3, 0xee, 0x72, 0x7d, 0xc2, 0xab, 0x4a, 0x94, 0x89};

  // uint8_t pt[16] = {0x2d, 0xb5, 0x16, 0x8e,
  //                         0x93, 0x25, 0x56, 0xf8,
  //                         0x08, 0x9a, 0x06, 0x22,
  //                         0x98, 0x1d, 0x01, 0x7d};

  // uint8_t ct[16] = {0xfa, 0x43, 0x62, 0x18,
  //                         0x96, 0x61, 0xd1, 0x63,
  //                         0xfc, 0xd6, 0xa5, 0x6d,
  //                         0x8b, 0xf0, 0x40, 0x5a};

  // uint8_t tag[16];
  uint8_t plaintext[len];
  uint8_t ciphertext[len];

  // memset(tag, 0, 16);
  memset(ciphertext, 0, len);
  memset(plaintext, 0, len);
  // memset(&crypto_msg_hdr, 0, sizeof(crypto_msg_hdr));
  // memset(&crypto_msg, 0, sizeof(crypto_msg));

  // memcpy(crypto_msg.aes_key, key, keyLen);
  // memcpy(crypto_msg.iv, iv, ivLen);

  crypto_msg = (scewl_msg_t *)data;

#ifdef KEY_CRYPTO
#endif

  // initialize context
  gcm_initialize();

  // encrypt buffer (encryption happens in place)
  // aes_gcm_encrypt_tag(ciphertext, (const uint8_t *)data, ptLen, crypto_msg.aes_key, keyLen, crypto_msg.iv, ivLen, crypto_msg.tag, tagLen);
  // memcpy(data, ciphertext, len);
  // memcpy(crypto_msg.body, ciphertext, len);

  // send_str("msg:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)&crypto_msg);

#ifdef DEBUF
  send_str("------------------------------------------------------------------:\n");
  send_str("test auth message:\n");
  send_str("key:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyLen, (char *)crypto_msg->aes_key);
  send_str("iv:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, ivLen, (char *)crypto_msg->iv);
  send_str("tag:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, tagLen, (char *)crypto_msg->tag);
  send_str("ciphertext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, hdr.len, (char *)crypto_msg->body);
  send_str("------------------------------------------------------------------:\n");
  // memset(ciphertext, 0, 16);
#endif
  int ret = 0;
  ret = aes_gcm_decrypt_auth(plaintext, crypto_msg->body, hdr.len, crypto_msg->aes_key, keyLen, crypto_msg->iv, ivLen, crypto_msg->tag, tagLen);

  if (ret != 0)
  {
    send_str("Authentication Failure!");
    return (-1);
  }

  send_str("Authentication Success!\n");
#ifdef DEBUG
  send_str("plaintext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, hdr.len, (char *)plaintext);
#endif

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  // intf_write(intf, data, len);
  intf_write(intf, plaintext, hdr.len);

  return SCEWL_OK;
}

int read_msg(intf_t *intf, char *data, scewl_id_t *src_id, scewl_id_t *tgt_id,
             size_t n, int blocking)
{
  scewl_hdr_t hdr;
  int read, max;

  // clear buffer and header
  memset(&hdr, 0, sizeof(hdr));
  memset(data, 0, n);

  // find header start
  do
  {
    hdr.magicC = 0;

    if (intf_read(intf, (char *)&hdr.magicS, 1, blocking) == INTF_NO_DATA)
    {
      return SCEWL_NO_MSG;
    }

    // check for SC
    if (hdr.magicS == 'S')
    {
      do
      {
        if (intf_read(intf, (char *)&hdr.magicC, 1, blocking) == INTF_NO_DATA)
        {
          return SCEWL_NO_MSG;
        }
      } while (hdr.magicC == 'S'); // in case of multiple 'S's in a row
    }
  } while (hdr.magicS != 'S' && hdr.magicC != 'C');

  // read rest of header
  read = intf_read(intf, (char *)&hdr + 2, sizeof(scewl_hdr_t) - 2, blocking);
  if (read == INTF_NO_DATA)
  {
    return SCEWL_NO_MSG;
  }

  // unpack header
  *src_id = hdr.src_id;
  *tgt_id = hdr.tgt_id;

  // read body
  max = hdr.len < n ? hdr.len : n;
  read = intf_read(intf, data, max, blocking);

#ifdef MSG_CRYPTO
#endif

  // throw away rest of message if too long
  for (int i = 0; hdr.len > max && i < hdr.len - max; i++)
  {
    intf_readb(intf, 0);
  }

  // report if not blocking and full message not received
  if (read == INTF_NO_DATA || read < max)
  {
    return SCEWL_NO_MSG;
  }

  return max;
}

int send_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data)
{
  scewl_hdr_t hdr;

  // pack header
  hdr.magicS = 'S';
  hdr.magicC = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len = len;

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  intf_write(intf, data, len);

  return SCEWL_OK;
}

int handle_scewl_recv(char *data, scewl_id_t src_id, uint16_t len)
{
#ifdef MSG_CRYPTO
  return send_auth_msg(CPU_INTF, src_id, SCEWL_ID, len, data);
#endif
  return send_msg(CPU_INTF, src_id, SCEWL_ID, len, data);
}

int handle_scewl_send(char *data, scewl_id_t tgt_id, uint16_t len)
{
#ifdef MSG_CRYPTO
  return send_enc_msg(RAD_INTF, SCEWL_ID, tgt_id, len, data);
#endif
  return send_msg(RAD_INTF, SCEWL_ID, tgt_id, len, data);
}

int handle_brdcst_recv(char *data, scewl_id_t src_id, uint16_t len)
{
  return send_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data);
}

int handle_brdcst_send(char *data, uint16_t len)
{
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_BRDCST_ID, len, data);
}

int handle_faa_recv(char *data, uint16_t len)
{
  return send_msg(CPU_INTF, SCEWL_FAA_ID, SCEWL_ID, len, data);
}

int handle_faa_send(char *data, uint16_t len)
{
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, data);
}

int handle_registration(char *msg)
{
  scewl_sss_msg_t *sss_msg = (scewl_sss_msg_t *)msg;
  if (sss_msg->op == SCEWL_SSS_REG)
  {
    return sss_register();
  }
  else if (sss_msg->op == SCEWL_SSS_DEREG)
  {
    return sss_deregister();
  }

  // bad op
  return 0;
}

int sss_register()
{
  scewl_sss_msg_t msg;
  scewl_id_t src_id, tgt_id;
  int status, len;

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_REG;

  // send registration
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
  if (status == SCEWL_ERR)
  {
    return 0;
  }

  // receive response
  len = read_msg(SSS_INTF, (char *)&msg, &src_id, &tgt_id, sizeof(scewl_sss_msg_t), 1);

  // notify CPU of response
  status = send_msg(CPU_INTF, src_id, tgt_id, len, (char *)&msg);
  if (status == SCEWL_ERR)
  {
    return 0;
  }

  // op should be REG on success
  return msg.op == SCEWL_SSS_REG;
}

int sss_deregister()
{
  scewl_sss_msg_t msg;
  scewl_id_t src_id, tgt_id;
  int status, len;

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_DEREG;

  // send registration
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
  if (status == SCEWL_ERR)
  {
    return 0;
  }

  // receive response
  len = read_msg(SSS_INTF, (char *)&msg, &src_id, &tgt_id, sizeof(scewl_sss_msg_t), 1);

  // notify CPU of response
  status = send_msg(CPU_INTF, src_id, tgt_id, len, (char *)&msg);
  if (status == SCEWL_ERR)
  {
    return 0;
  }

  // op should be DEREG on success
  return msg.op == SCEWL_SSS_DEREG;
}

bool strip_and_check_sequence_number(scewl_id_t source_SED)
{
  char received_suqence[10];
  int received_sq_number;

  memcpy(received_suqence, buf, 10);
  received_sq_number = atoi(received_suqence);

  if (messeage_sq.sq_receive[source_SED] < received_sq_number)
  {
    messeage_sq.sq_receive[source_SED] = received_sq_number;
    memcpy(buf, buf + 10, sizeof(buf) - 10);
    return true;
  }

  return false;
}

int main()
{
  int registered = 0, len;
  scewl_hdr_t hdr;
  uint16_t src_id, tgt_id;

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
  uint8_t key[16] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
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

#ifdef EXAMPLE_AES_GCM
  // example encryption using aes-gcm
  scewl_msg_hdr_t crypto_msg_hdr;
  int ret = 0;
  uint8_t key[32] = {0x31, 0xbd, 0xad, 0xd9,
                     0x66, 0x98, 0xc2, 0x04,
                     0xaa, 0x9c, 0xe1, 0x44,
                     0x8e, 0xa9, 0x4a, 0xe1,
                     0xfb, 0x4a, 0x9a, 0x0b,
                     0x3c, 0x9d, 0x77, 0x3b,
                     0x51, 0xbb, 0x18, 0x22,
                     0x66, 0x6b, 0x8f, 0x22};

  uint8_t iv[12] = {0x0d, 0x18, 0xe0, 0x6c,
                    0x7c, 0x72, 0x5a, 0xc9,
                    0xe3, 0x62, 0xe1, 0xce};

  uint8_t pt[16] = {0x2d, 0xb5, 0x16, 0x8e,
                    0x93, 0x25, 0x56, 0xf8,
                    0x08, 0x9a, 0x06, 0x22,
                    0x98, 0x1d, 0x01, 0x7d};

  uint8_t ct[16] = {0xfa, 0x43, 0x62, 0x18,
                    0x96, 0x61, 0xd1, 0x63,
                    0xfc, 0xd6, 0xa5, 0x6d,
                    0x8b, 0xf0, 0x40, 0x5a};

  // uint8_t tag[16];
  uint8_t plaintext[ctLen];
  uint8_t ciphertext[ctLen];

  // memset(tag, 0, 16);
  memset(ciphertext, 0, 16);
  memset(plaintext, 0, 16);
  memset(crypto_msg_hdr.aes_key, 0, keyLen);
  memset(crypto_msg_hdr.iv, 0, ivLen);
  memset(crypto_msg_hdr.tag, 0, tagLen);

  memcpy(crypto_msg_hdr.aes_key, key, keyLen);
  memcpy(crypto_msg_hdr.iv, iv, ivLen);

  // initialize context
  gcm_initialize();

  // encrypt buffer (encryption happens in place)
  ret = aes_gcm_encrypt_tag(ciphertext, pt, ptLen, crypto_msg_hdr.aes_key, keyLen, crypto_msg_hdr.iv, ivLen, crypto_msg_hdr.tag, tagLen);
  send_str("key:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)crypto_msg_hdr.aes_key);
  send_str("ciphertext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)ciphertext);
  send_str("tag:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)crypto_msg_hdr.tag);

  // memset(ciphertext, 0, 16);

  // decrypt buffer (decryption happens in place)
  ret = aes_gcm_decrypt_auth(plaintext, ciphertext, ctLen, crypto_msg_hdr.aes_key, keyLen, crypto_msg_hdr.iv, ivLen, crypto_msg_hdr.tag, tagLen);
  if (ret != 0)
  {
    send_str("Authentication Failure!");
    return (-1);
  }

  send_str("Authentication Success!\n");
  send_str("plaintext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)plaintext);
  // end example
#endif
#ifdef CRYPTO_TEST
  uint8_t pt[16] = {0x2d, 0xb5, 0x16, 0x8e,
                    0x93, 0x25, 0x56, 0xf8,
                    0x08, 0x9a, 0x06, 0x22,
                    0x98, 0x1d, 0x01, 0x7d};
  send_enc_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)pt);

  // read_auth_msg(RAD_INTF, buf, &hdr.src_id, &hdr.tgt_id, sizeof(buf), 1);
#endif

  // serve forever
  while (1)
  {
    // register with SSS
    read_msg(CPU_INTF, buf, &hdr.src_id, &hdr.tgt_id, sizeof(buf), 1);

    if (hdr.tgt_id == SCEWL_SSS_ID)
    {
      registered = handle_registration(buf);
    }

    // server while registered
    while (registered)
    {
      memset(&hdr, 0, sizeof(hdr));

      // handle outgoing message from CPU
      if (intf_avail(CPU_INTF))
      {
        // Read message from CPU
        len = read_msg(CPU_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);

        /*
        If the outgoing message is for broadcast or targeted transmission, the CIA properties should be maintained.
        No need to protect messages to SSS or FAA.
        */

        if (tgt_id == SCEWL_BRDCST_ID)
        {
          handle_brdcst_send(buf, len);
        }
        else if (tgt_id == SCEWL_SSS_ID)
        {
          registered = handle_registration(buf);
        }
        else if (tgt_id == SCEWL_FAA_ID)
        {
          //len =  add_sequence_number(tgt_id, len);
          handle_faa_send(buf, len);
        }
        else
        {
          //add_sequence_number(tgt_id, len);
          handle_scewl_send(buf, tgt_id, len);
        }

        continue;
      }

      // handle incoming radio message
      if (intf_avail(RAD_INTF))
      {
        // Read message from antenna
        len = read_msg(RAD_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);

        if (src_id != SCEWL_ID)
        { // ignore our own outgoing messages
          if (tgt_id == SCEWL_BRDCST_ID)
          {
            // receive broadcast message
            handle_brdcst_recv(buf, src_id, len);
          }
          else if (tgt_id == SCEWL_ID)
          {
            // receive unicast message
            if (src_id == SCEWL_FAA_ID)
            {
              /*if (strip_and_check_sequence_number(src_id)) {
			            //memcpy(buf, "VAlid", 5);
			            len = len - 10;
	            } else {
			            memcpy(buf, "Invalid sequence", sizeof("Invalid sequence"));
	            }*/
              handle_faa_recv(buf, len);
            }
            else
            {
              handle_scewl_recv(buf, src_id, len);
            }
          }
        }
      }
    }
  }
}
