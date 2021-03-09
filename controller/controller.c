/*
 * 2021 Collegiate eCTF
 * SCEWL Bus Controller implementation
 * Ben Janis
 *
 * (c) 2021 Cacti Team
 *
 */

#include <stdlib.h>
// #include <time.h>
#include "controller.h"
#include "rsa.h"
#include "key.h"

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
sequence_num_t messeage_sq;

volatile rsa_pk *own_pk = &public_key;
volatile rsa_sk *own_sk = &private_key;
volatile rsa_pk *tgt_pk = &public_key;
volatile rsa_sk *tgt_sk = &private_key;

volatile uint32_t sysTimer = 0;
volatile set_pk_flag = 0;

// an array to store all provisoned sed's public key
volatile scewl_pub_t scewl_pk[SCEWL_PK_NUM];
volatile scewl_id_t pre_scewl_id = 0;

void SysTick_Handler(void)
{
  sysTimer++;
}

int check_scewl_pk(scewl_id_t tgt_id)
{
  for (int i = 0; i < 16; i++)
  {
    if ((memcmp(&scewl_pk[i].scewl_id, &tgt_id, sizeof(scewl_id_t)) == 0))
    {
      if (scewl_pk[i].flag == 1)
      {
#ifdef DEBUG_PK_TEST
        send_str("tgt public key\n");
        send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 1, (char *)i);
        send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 1, (char *)&scewl_pk[i].flag);
        send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&scewl_pk[i].scewl_id);
        send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(rsa_pk), (char *)&scewl_pk[i].pk);
#endif
        // memcpy(&pk, &scewl_pk[i].pk, sizeof(rsa_pk));
        return i;
      }
      else
        return 0x55;
    }
  }
  return -1;
}

int print_scewl_pk()
{
  for (int i = 0; i < 16; i++)
  {
    if (scewl_pk[i].flag == 1)
    {
      send_str("tgt public key\n");
      send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 1, (char *)i);
      send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&scewl_pk[i].scewl_id);
      send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(rsa_pk), (char *)&scewl_pk[i].pk);
      return i;
    }
  }
  return -1;
}

int send_get_scewl_pk_msg(scewl_id_t tgt_id)
{
  int len = 0, enc_len = 0, send_len = 0;
  int idx = 0;
  char msg[200] = {0};
  char output[200] = {0};
  scewl_id_t tmp_tgt, tmp_src;
  char *get_pk = "NO";

  unsigned int start, end, delay;
  start = sysTimer;

  // send_str("send_get_scewl_pk_msg: ask for target pk...\n");
  // send_enc_msg(RAD_INTF, SCEWL_ID, tgt_id, 7, "get pk", RSA_REQ_PK);
  // ++messeage_sq.sq_send[tgt_id];
  send_msg(RAD_INTF, SCEWL_ID, tgt_id, 3, get_pk);

  // server while registered
  while (set_pk_flag == 0)
  {
    // handle outgoing message from CPU
    if (intf_avail(CPU_INTF))
    {
      // Read message from CPU
      len = read_msg(CPU_INTF, msg, &tmp_src, &tmp_tgt, sizeof(msg), 1);

      /*
        If the outgoing message is for broadcast or targeted transmission, the CIA properties should be maintained.
        No need to protect messages to SSS or FAA.
        */

      if (tmp_tgt == SCEWL_BRDCST_ID)
      {
        handle_brdcst_send(msg, len);
      }
      else if (tmp_tgt == SCEWL_FAA_ID)
      {
        handle_faa_send(msg, len);
      }
      else
      {
        handle_scewl_send(msg, tmp_tgt, len);
      }

      continue;
    }

    // handle incoming radio message
    if (intf_avail(RAD_INTF))
    {
      // Read message from antenna
      len = read_msg(RAD_INTF, msg, &tmp_src, &tmp_tgt, sizeof(msg), 1);

      if (tmp_src != SCEWL_ID)
      { // ignore our own outgoing messages
        if (tmp_tgt == SCEWL_BRDCST_ID)
        {
          // receive broadcast message
          // send_str("send_get_scewl_pk_msg: received the brdcst...\n");
          handle_brdcst_recv(msg, tmp_src, len);
        }
        else if (tmp_tgt == SCEWL_ID)
        {
          // receive unicast message
          if (tmp_src == SCEWL_FAA_ID)
          {
            // send_str("send_get_scewl_pk_msg: received the faa...\n");
            handle_faa_recv(msg, len);
          }
          else
          {
            handle_scewl_recv(msg, tmp_src, len);
            idx = check_scewl_pk(tgt_id);
            if ((idx >= 0) && (idx != 0x55))
            {
              send_str("send_get_scewl_pk_msg: set tgt pk!");
              send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&tgt_id);
              // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(rsa_pk), (char *)&scewl_pk[idx].pk);
              // set_pk_flag = 1;
              set_pk_flag = 0;
              return SCEWL_OK;
            }
          }
        }
      }
    }

    end = sysTimer;
    delay = end - start;
    if (delay > 600000)
    {
      send_str("send_get_scewl_pk_msg: get tgt pk timeout!");
      send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&tgt_id);
      set_pk_flag = 0;
      return SCEWL_ERR;
    }
  }
}

int key_enc(scewl_id_t src_id, scewl_id_t tgt_id, scewl_msg_t *scewl_msg, uint8_t rsa_mode)
{
  int idx = 0;
  uint8_t message[MAX_MODULUS_LENGTH * 2] = {0};
  // uint8_t tmp[32] = {0};
  DTYPE msg[MAX_MODULUS_LENGTH] = {0};
  DTYPE cipher[MAX_MODULUS_LENGTH] = {0};
  DTYPE decipher[MAX_MODULUS_LENGTH] = {0};
  DTYPE plaintext[MAX_MODULUS_LENGTH] = {0};

  memcpy(message, scewl_msg->aes_key, keyCryptoLen);

  int i;
  int j = MAX_MODULUS_LENGTH - 1;
  for (i = 63 - 1; i >= 1; i -= 2)
  {
    msg[j--] = (message[i - 1] << 8) | message[i];
  }
  if (i == 0)
  {
    msg[j--] = message[i];
  }
  while (j >= 0)
  {
    msg[j--] = 0;
  }

#ifdef DEBUG_KEY_CRYPTO
  send_str("crypto->aes_key before Encryption...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyCryptoLen, (char *)message);
  send_str("aes_key before Encryption...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)msg);
#endif

  switch (rsa_mode)
  {
    // handler broadcast aes_key crypto, private key to sign, public key to auth
  case RSA_SIGN:
  case RSA_REQ_PK:
    /* sign */
    rsa_decrypt(cipher, MAX_MODULUS_LENGTH, msg, MAX_MODULUS_LENGTH, own_sk);
    break;
  case RSA_ENC:
  case RSA_SEND_PK:
    // default means scewl messages, public key to encrypt, private key to decrypt
  default:
    // check target public key first
    idx = check_scewl_pk(tgt_id);
    if (idx < 0)
    {
      send_str("Key_enc: please get the target public key first!");
    }
    else
    {
      rsa_encrypt(cipher, MAX_MODULUS_LENGTH, msg, MAX_MODULUS_LENGTH, &scewl_pk[idx].pk);
    }

#ifdef DEBUG_KEY_CRYPTO
    send_str("aes_key Encryption done...\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)cipher);
#endif

    memcpy(scewl_msg->aes_key, (uint8_t *)&cipher, keyCryptoLen);
    break;
  }
  // memset(enc_aes_key, 0, keyLen);

  return 0;
}

int key_dec(scewl_id_t src_id, scewl_id_t tgt_id, scewl_msg_t *scewl_msg, uint8_t rsa_mode)
{
  DTYPE ciphertext[MAX_MODULUS_LENGTH] = {0};
  DTYPE plaintext[MAX_MODULUS_LENGTH] = {0};
  DTYPE decipher[MAX_MODULUS_LENGTH] = {0};
  int idx = 0;

  switch (rsa_mode)
  {
    // handler broadcast aes_key crypto, private key to sign, public key to auth
  case RSA_AUTH:
    // send_str("Key_dec: handler pk authentication");
    /* verify */
    // send_str("Key_dec: handler pk requirements");
    idx = check_scewl_pk(src_id);

    if (idx == 0x55)
    {
      send_str("Key_dec: source scewl already deregistered!");
      send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
      return SCEWL_OK;
    }
    else if (idx < 0)
    {
      send_str("Key_dec: does not have its public key!");
      send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
      return SCEWL_ERR;
    }
    else
    {
      // send_str("Authenticate the message!");
      // rsa_encrypt(cipher, MAX_MODULUS_LENGTH, msg, MAX_MODULUS_LENGTH, &scewl_pk[idx].pk);
      rsa_encrypt(decipher, MAX_MODULUS_LENGTH, (DTYPE *)scewl_msg->aes_key, MAX_MODULUS_LENGTH, &scewl_pk[idx].pk);
    }
    break;
  case RSA_DEC:
  default:

#ifdef DEBUG_KEY_CRYPTO
    send_str("aes_key Decryption starts...\n");
    send_str("aes_key before decryption...\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)scewl_msg->aes_key);
    send_str("sk->d1...\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 32, (char *)own_sk->d1);
#endif
    rsa_decrypt(decipher, MAX_MODULUS_LENGTH, (DTYPE *)scewl_msg->aes_key, MAX_MODULUS_LENGTH, own_sk);
#ifdef DEBUG_KEY_CRYPTO
    send_str("aes_key after decryption...\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)decipher);
#endif

    hex_to_string(plaintext, decipher);

#ifdef DEBUG_KEY_CRYPTO
    send_str("aes_key Decryption done...\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)plaintext);
#endif
    memcpy(scewl_msg->aes_key, (uint8_t *)&plaintext, keyCryptoLen);
    break;
  }
  // memset(dec_aes_key, 0, keyLen);
  return 0;
}

bool check_sequence_number(scewl_id_t source_SED, uint32_t received_sq_number, scewl_id_t target_SED)
{
  if (target_SED == 0)
  {
    source_SED = 0;
  }
  if (messeage_sq.sq_receive[source_SED] < received_sq_number)
  {
    messeage_sq.sq_receive[source_SED] = received_sq_number;
    return true;
  }
  return false;
}

int enc_msg(scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data, scewl_msg_t *send_scewl_msg, uint8_t rsa_mode)
{
  int tmp = (len + MSG_HDR + CRYPTO_HDR) % 4;
  int enc_len = len + tmp + CRYPTO_HDR; // plaintext data len + 10 bytes crypto_hdr

  int scewl_msg_body_len = MSG_HDR + enc_len; // crypto message: msg header + 4 bytes sequence number + body (data)

  uint8_t key[keyCryptoLen] = {0};
  uint8_t iv[ivLen] = {0};
  uint8_t tag[tagLen] = {0};
  int i = 0;

  scewl_msg_t scewl_msg;
  uint8_t ciphertext[SCEWL_MAX_CRYPTO_DATA_SZ];

  // initialize the structures
  memset(key, 0, keyCryptoLen);
  memset(iv, 0, ivLen);
  memset(ciphertext, 0, SCEWL_MAX_CRYPTO_DATA_SZ);
  memset(&scewl_msg, 0, sizeof(scewl_msg_t));

  // setup random aes_key and iv
  srand(sysTimer);
  for (i = 0; i < keyCryptoLen - 1; i++)
  {
    key[i] = rand() % 256;
  }

  for (i = 0; i < ivLen; i++)
  {
    iv[i] = rand() % 256;
  }

  // setup the crypto message structure
  scewl_msg.crypto_msg.tgt_id = tgt_id;
  scewl_msg.crypto_msg.src_id = src_id;
  scewl_msg.crypto_msg.len = scewl_msg_body_len;
  scewl_msg.crypto_msg.padding = tmp;
  scewl_msg.padding = tmp;
  if (tgt_id == 0)
  {
    messeage_sq.sq_send[tgt_id] = max(messeage_sq.sq_receive[tgt_id], messeage_sq.sq_send[tgt_id]);
    messeage_sq.sq_receive[tgt_id] = messeage_sq.sq_send[tgt_id];
  }
  scewl_msg.crypto_msg.sq = ++messeage_sq.sq_send[tgt_id]; // setup the sequence number
  memcpy(scewl_msg.crypto_msg.body, data, len);            // setup the plaintext

  // setup the scewl message
  if (rsa_mode == RSA_SEND_PK)
  {
    scewl_msg.magicP = 'P';
    scewl_msg.magicK = 'K';
  }
  else if (rsa_mode == RSA_REQ_PK)
  {
    scewl_msg.magicP = 'N';
    scewl_msg.magicK = 'O';
    send_str("sending rsa_re_pk...");
  }
  else
  {
    scewl_msg.magicP = 'X';
    scewl_msg.magicK = 'X';
  }
  memcpy(scewl_msg.aes_key, key, keyCryptoLen);
  memcpy(scewl_msg.iv, iv, ivLen);

#ifdef SQ_DEBUG
  send_str("Sending sq:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&scewl_msg.crypto_msg.sq);
#endif

#ifdef DEBUG_MSG_CRYPTO
  // send_str("------------------------------------------------------------------:\n");
  // send_str("test enc message:\n");
  // send_str("src_id:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&scewl_msg.crypto_msg.src_id);
  // send_str("tgt_id:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&scewl_msg.crypto_msg.tgt_id);
  // send_str("crypto len:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&scewl_msg.crypto_msg.len);
  send_str("plaintext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)&scewl_msg.crypto_msg.body);
  // send_str("crypto_msg body:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, enc_len, (char *)&scewl_msg.crypto_msg);
  // send_str("crypto len:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 8, (char *)&scewl_msg.crypto_msg.len);
  // send_str("sq:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&scewl_msg.crypto_msg.sq);
  send_str("key:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyCryptoLen, (char *)scewl_msg.aes_key);
  send_str("iv:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, ivLen, (char *)scewl_msg.iv);
#endif

  // initialize context
  gcm_initialize();

  // encrypt buffer (encryption happens in place)
  aes_gcm_encrypt_tag(ciphertext, (const uint8_t *)&scewl_msg.crypto_msg, enc_len, scewl_msg.aes_key, keyLen, scewl_msg.iv, ivLen, scewl_msg.tag, tagLen);
  memcpy(&scewl_msg.crypto_msg, ciphertext, enc_len);
  // memcpy(&scewl_msg->tag, tag, tagLen);
  // memcpy(&scewl_msg->crypto_msg, ciphertext, enc_len);

#ifdef KEY_CRYPTO
  key_enc(src_id, tgt_id, &scewl_msg, rsa_mode);
#endif

#ifdef KEY_CRYPTO
#endif
#ifdef DEBUG_MSG_CRYPTO
  // send_str("tag:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, tagLen, (char *)scewl_msg.tag);
  // send_str("enc_len:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&enc_len);
  send_str("send_scewl_msg:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, enc_len, (char *)&scewl_msg.crypto_msg);
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, enc_len + sizeof(scewl_msg_hdr_t), (char *)&scewl_msg);
#endif
  memcpy(send_scewl_msg, &scewl_msg, scewl_msg_body_len);

  return 0;
}

int send_enc_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data, uint8_t rsa_mode)
{
  scewl_hdr_t hdr;
  int tmp = 0;
  // char tmp_buf[SCEWL_MAX_DATA_SZ + 8] = {0};

  tmp = (len + MSG_HDR + CRYPTO_HDR) % 4;

  // pack header
  hdr.magicS = 'S';
  hdr.magicC = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len = len + MSG_HDR + CRYPTO_HDR + tmp; // crypto message: msg header + 4 bytes sequence number + body (data)

  scewl_msg_t send_scewl_msg;
  memset(&send_scewl_msg, 0, sizeof(scewl_msg_t));

  enc_msg(src_id, tgt_id, len, data, &send_scewl_msg, rsa_mode);

  // memcpy(tmp_buf, (char *)&hdr, sizeof(scewl_hdr_t));
  // memcpy(tmp_buf + sizeof(scewl_hdr_t), (char *)&send_scewl_msg, hdr.len);
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(scewl_hdr_t) + hdr.len, tmp_buf);
  // intf_write(intf, (char *)&tmp_buf, sizeof(scewl_hdr_t) + hdr.len);

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  // intf_write(intf, data, len);
  intf_write(intf, (char *)&send_scewl_msg, hdr.len);

  return SCEWL_OK;
}

int auth_msg(scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data, uint8_t *output, uint8_t rsa_mode)
{
  scewl_hdr_t hdr;
  int dec_len = len - MSG_HDR;
  int padding = 0;

  int crypto_msg_len = dec_len - CRYPTO_HDR;

  scewl_crypto_msg_t crypto_msg;
  scewl_msg_t *scewl_msg = NULL;

  memset(&crypto_msg, 0, sizeof(scewl_crypto_msg_t));

  // uint8_t plaintext[SCEWL_MAX_CRYPTO_DATA_SZ];
  // memset(plaintext, 0, SCEWL_MAX_CRYPTO_DATA_SZ);

  scewl_msg = (scewl_msg_t *)data;

#ifdef DEBUG_MSG_CRYPTO
  send_str("------------------------------------------------------------------:\n");
  send_str("test auth message:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)data);
  send_str("key:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyCryptoLen, (char *)scewl_msg->aes_key);
  send_str("iv:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, ivLen, (char *)scewl_msg->iv);
  send_str("tag:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, tagLen, (char *)scewl_msg->tag);
  send_str("ciphertext:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, dec_len, (char *)&scewl_msg->crypto_msg);
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)data);
#endif

// decrypt the aes_key
#ifdef KEY_CRYPTO
  key_dec(src_id, tgt_id, scewl_msg, rsa_mode);
#endif

  // initialize context
  gcm_initialize();

#ifdef DEBUG_MSG_CRYPTO
  send_str("decrypted key:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyCryptoLen, (char *)scewl_msg->aes_key);
  // send_str("tag:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, tagLen, (char *)scewl_msg->tag);
#endif
  int ret = 0;
  ret = aes_gcm_decrypt_auth((uint8_t *)&crypto_msg, (const uint8_t *)&scewl_msg->crypto_msg, dec_len, (const uint8_t *)&scewl_msg->aes_key, keyLen, (const uint8_t *)&scewl_msg->iv, ivLen, (uint8_t *)&scewl_msg->tag, tagLen);

#ifdef DEBUG_MSG_CRYPTO
  send_str("auth_msg: ret:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(int), (char *)&ret);
  send_str("auth_msg: plaintext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, crypto_msg_len, (char *)&crypto_msg.body);
#endif

  if (ret == 0)
  {
    // send_str("Checkging the header...\n");
#ifdef DEBUG_MSG_CRYPTO
    // send_str("src_id:\n");
    // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&crypto_msg.src_id);
    // send_str("tgt_id:\n");
    // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&crypto_msg.tgt_id);
    // send_str("crypto len:\n");
    // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&crypto_msg.len);
    // send_str("sq:\n");
    // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&crypto_msg.sq);
#endif
    if ((crypto_msg.src_id == src_id) && (crypto_msg.tgt_id == tgt_id) && (crypto_msg.len == len) && (crypto_msg.padding == scewl_msg->padding))
    {
      // send_str("Authentication Success!\n");
    }
    else
    {
      send_str("Integrity Authentication Failure!");
      return (-1);
    }
  }
  else
  {
    send_str("src_id:\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&crypto_msg.src_id);
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&crypto_msg.src_id);
    send_str("AES Authentication Failure!");
    return (-1);
  }

  if (check_sequence_number(src_id, crypto_msg.sq, tgt_id))
  {
    // send_str("Sequence numebr validation success");
  }
  else
  {
    send_str("Replay attack detected");
    return (-1);
  }

#ifdef DEBUG_MSG_CRYPTO
  send_str("Receiver Sequence number");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&crypto_msg.sq);
  send_str("crypto_msg.body:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, crypto_msg_len, (char *)&crypto_msg.body);
#endif

  padding = crypto_msg.padding;
  memcpy(output, crypto_msg.body, crypto_msg_len - padding);

  return SCEWL_OK;
}

int send_auth_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data, uint8_t rsa_mode)
{
  scewl_hdr_t hdr;
  uint8_t output[SCEWL_MAX_DATA_SZ]; //hdr.len
  scewl_msg_t *scewl_msg = (scewl_msg_t *)data;
  scewl_update_pk_t scewl_update_pk;
  char tmp_buf[SCEWL_MAX_CRYPTO_DATA_SZ] = {0};

  int ret = 0;

  // pack header
  hdr.magicS = 'S';
  hdr.magicC = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len = len - MSG_HDR - CRYPTO_HDR - scewl_msg->padding; // msg - crypto_hdr - scewl_hdr

  memset(output, 0, SCEWL_MAX_DATA_SZ);
  memset(&scewl_update_pk, 0, sizeof(scewl_update_pk_t));

  // send_str("received message, checking if it is for PK");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, data);

  if (memcmp(data, "NO", 2) == 0)
  {
    // send_str("send_auth_msg: required public key");
    // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
    scewl_update_pk.magicP = 'P';
    scewl_update_pk.magicK = 'U';
    scewl_update_pk.magicK = 'K';
    memcpy(&scewl_update_pk.pk, own_pk, sizeof(rsa_pk));
    send_msg(RAD_INTF, SCEWL_ID, src_id, sizeof(scewl_update_pk_t), (char *)&scewl_update_pk);
    // send_str("send_auth_msg: send out public key");
    return SCEWL_OK;
  }
  else if (memcmp(data, "PK", 2) == 0)
  {
    // send_str("send_auth_msg: update pk");

    if (check_scewl_pk(src_id) < 0)
    {
      for (size_t i = 0; i < 16; i++)
      {
        if (scewl_pk[i].flag == 0)
        {
          memcpy(&scewl_update_pk, data, sizeof(scewl_update_pk_t));
          memcpy(&scewl_pk[i].pk, &scewl_update_pk.pk, sizeof(rsa_pk));
          scewl_pk[i].scewl_id = src_id;
          scewl_pk[i].flag = 1;

          // configure the e
          BN_init(scewl_pk[i].pk.e, MAX_PRIME_LENGTH);
          //e=2^16+1
          scewl_pk[i].pk.e[MAX_PRIME_LENGTH - 2] = 1;
          scewl_pk[i].pk.e[MAX_PRIME_LENGTH - 1] = 1;
          scewl_pk[i].flag = 1;
#ifdef PK_TEST
          send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&scewl_pk[i].scewl_id);
          send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(rsa_pk), (char *)&scewl_pk[i].pk);
#endif
          if (pre_scewl_id != 0)
          {
#ifdef DEBUG_PK_TEST
            send_str("sending the public key...\n");
            send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(scewl_update_pk_t), (char *)&scewl_update_pk);
#endif
            send_msg(RAD_INTF, SCEWL_ID, pre_scewl_id, sizeof(scewl_update_pk_t), data);
          }

          i = 16;
        }
      }
    }

    return SCEWL_OK;
  }
  else
  {
    // send_str("send_auth_msg: normal message");
  }

  ret = auth_msg(src_id, tgt_id, len, data, output, rsa_mode);

  memcpy(tmp_buf, (char *)&hdr, sizeof(scewl_hdr_t));
  memcpy(tmp_buf + sizeof(scewl_hdr_t), (char *)&output, hdr.len);
  intf_write(intf, (char *)&tmp_buf, sizeof(scewl_hdr_t) + hdr.len);

  // send header
  // intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  // send_str("send_auth_msg: receive normal messages.");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, hdr.len, (char *)&output);
  // intf_write(intf, (char *)&output, hdr.len);

  return SCEWL_OK;
}

int send_sign_SSS_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data, uint16_t op)
{
  scewl_hdr_t hdr;
  scewl_sss_crypto_msg_t sss_crypto_msg;

  char message[MAX_MODULUS_LENGTH * 2] = {0};
  DTYPE cipher[MAX_MODULUS_LENGTH] = {0};
  DTYPE decipher[MAX_MODULUS_LENGTH] = {0};
  DTYPE msg[MAX_MODULUS_LENGTH] = {0};
  char plainmsg[MAX_MODULUS_LENGTH * 2 + 1] = {0};

  // pack header
  hdr.magicS = 'S';
  hdr.magicC = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len = RSA_BLOCK;

  // pack the sss_crypto_msg
  memset(&sss_crypto_msg, 0, RSA_BLOCK);
  sss_crypto_msg.dev_id = SCEWL_ID;
  sss_crypto_msg.op = op;
  sss_crypto_msg.src_id = src_id;
  sss_crypto_msg.tgt_id = tgt_id;

  memcpy(message, (char *)&sss_crypto_msg, RSA_BLOCK);

  // configure the e
  BN_init(own_pk->e, MAX_PRIME_LENGTH);
  //e=2^16+1
  own_pk->e[MAX_PRIME_LENGTH - 2] = 1;
  own_pk->e[MAX_PRIME_LENGTH - 1] = 1;

#ifdef DEBUG_REG_CRYPTO
  // send_str("sss_crypto_msg...\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)&sss_crypto_msg);
  // send_str("sss data...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)data);
  send_str("message...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)message);
#endif

  // send_str("sign sss_msg...\n");
  rsa_decrypt(cipher, MAX_MODULUS_LENGTH, message, MAX_MODULUS_LENGTH, own_sk);

#ifdef DEBUG_REG_CRYPTO
  send_str("after signing...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)cipher);
  send_str("verif sss_msg...\n");
  rsa_encrypt(decipher, MAX_MODULUS_LENGTH, cipher, MAX_MODULUS_LENGTH, own_pk);
  send_str("after verification...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)decipher);
#endif

#ifdef SEND_SIGN_REG
  memcpy((char *)&sss_crypto_msg, cipher, RSA_BLOCK);
#endif

#ifdef DEBUG_REG_CRYPTO
  send_str("sending sss_crypto_msg...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)&sss_crypto_msg);
#endif
  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

// send body
#ifdef REG_CRYPTO
  intf_write(intf, (char *)&sss_crypto_msg, RSA_BLOCK);
#else
  intf_write(intf, data, len);
#endif

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
  return send_auth_msg(CPU_INTF, src_id, SCEWL_ID, len, data, RSA_DEC);
#else
  return send_msg(CPU_INTF, src_id, SCEWL_ID, len, data);
#endif
}

int handle_scewl_send(char *data, scewl_id_t tgt_id, uint16_t len)
{
#ifdef MSG_CRYPTO
  // print_scewl_pk();
  int ret = check_scewl_pk(tgt_id);
  if (ret == 0x55)
  {
    send_str("handle_scewl_send: target scewl already deregistered!");
    return SCEWL_OK;
  }
  else if (ret < 0)
  {
    send_str("handle_scewl_send: does not have target public key");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&tgt_id);
    if (send_get_scewl_pk_msg(tgt_id) == SCEWL_ERR)
    {
      // send_str("handle_scewl_send: get tgt pk timeout!");
      return SCEWL_ERR;
    }
    // return SCEWL_OK;
  }

  return send_enc_msg(RAD_INTF, SCEWL_ID, tgt_id, len, data, RSA_ENC);
#else
  return send_msg(RAD_INTF, SCEWL_ID, tgt_id, len, data);
#endif
}

int handle_brdcst_recv(char *data, scewl_id_t src_id, uint16_t len)
{
#ifdef MSG_CRYPTO

  if (src_id == SCEWL_FAA_ID)
  {
    send_str("handle_brdcst_recv: receive faa brdcst!");
    return send_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data);
    // return send_auth_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data, RSA_AUTH);
  }
  else
  {
    int ret = check_scewl_pk(src_id);
    if (ret == 0x55)
    {
      send_str("handle_brdcst_recv: source scewl already deregistered!");
      send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
      return SCEWL_OK;
    }
    else if (ret < 0)
    {
      send_str("handle_brdcst_recv: does not have source public key");
      send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
      // send_get_scewl_pk_msg(src_id);
      if (send_get_scewl_pk_msg(src_id) == SCEWL_ERR)
      {
        // send_str("handle_scewl_send: get tgt pk timeout!");
        return SCEWL_ERR;
      }
      // return SCEWL_OK;
      else
      {
        return send_auth_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data, RSA_AUTH);
      }
    }
    else
    {
      return send_auth_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data, RSA_AUTH);
    }
  }
#else
  return send_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data);
#endif
}

int handle_brdcst_send(char *data, uint16_t len)
{
#ifdef MSG_CRYPTO
  return send_enc_msg(RAD_INTF, SCEWL_ID, SCEWL_BRDCST_ID, len, data, RSA_SIGN);
#else
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_BRDCST_ID, len, data);
#endif
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
}

int sss_register()
{
  scewl_sss_msg_t msg;
  scewl_id_t src_id = 0, tgt_id = 0;
  int status = 0, len = 0;
  int pos = 0, i = 0;
  uint8_t totalSEDs = 0;
  scewl_update_pk_t scewl_update_pk;

  memset(&scewl_update_pk, 0, sizeof(scewl_update_pk_t));

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_REG;

// send registration
#ifdef REG_CRYPTO
  status = send_sign_SSS_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg, msg.op);
#else
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
#endif
  if (status == SCEWL_ERR)
  {
    return 0;
  }

  // split the received response
  // 1. receive the whole messages
  len = read_msg(SSS_INTF, (char *)&buf, &src_id, &tgt_id, sizeof(buf), 1);
#ifdef DEBUG_REG_CRYPTO
  send_str("receive sss msg...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)&buf);
#endif

  // 2. split the response
  // current (4 bytes)
  memcpy(&msg, (char *)&buf, sizeof(scewl_sss_msg_t));
#ifdef DEBUG_REG_CRYPTO
  send_str("sss response current\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(scewl_sss_msg_t), (char *)&msg);
#endif

  // totalSED 1 byte
  memcpy(&totalSEDs, (char *)&buf + sizeof(scewl_sss_msg_t), 1);
#ifdef DEBUG_REG_CRYPTO
  send_str("totalSEDs\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 1, (char *)&totalSEDs);
#endif
  // loop to set scewl public key
  if (totalSEDs == 0)
  {
    // this sed is the first regitered one
    pre_scewl_id = 0;
  }
  else
  {
    for (i = 0; i < totalSEDs; i++)
    {
      // set_scewl_pk(tgt_id, (rsa_pk *)&buf + sizeof(scewl_sss_msg_t) + i * sizeof(scewl_pub_t));
      // current header(4) + totalSEDs(1) + (dev_id(2) + rsa_pk(162)) * totalSEDs
      memcpy(&scewl_pk[i].scewl_id, (char *)&buf + 5 + (sizeof(rsa_pk) + 2) * i, sizeof(scewl_pub_t));
      // configure the e
      BN_init(scewl_pk[i].pk.e, MAX_PRIME_LENGTH);
      //e=2^16+1
      scewl_pk[i].pk.e[MAX_PRIME_LENGTH - 2] = 1;
      scewl_pk[i].pk.e[MAX_PRIME_LENGTH - 1] = 1;
      scewl_pk[i].flag = 1;
      pos = i;
#ifdef DEBUG_REG_CRYPTO
      send_str("idx\n");
      send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(uint8_t), (char *)&i);
      send_str("SED_id\n");
      send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(scewl_id_t), (char *)&scewl_pk[i].scewl_id);
      send_str("SED_id publick key\n");
      send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(rsa_pk), (char *)&scewl_pk[i].pk);
#endif
    }
    pre_scewl_id = scewl_pk[pos].scewl_id;
#ifdef DEBUG_PK_TEST
    send_str("previous sed...\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&scewl_pk[pos].scewl_id);
#endif
    // pack broadcast header to notify the scewl that want the publik key
    scewl_update_pk.magicP = 'P';
    scewl_update_pk.magicK = 'K';
    memcpy(&scewl_update_pk.pk, own_pk, sizeof(rsa_pk));
#ifdef DEBUG_PK_TEST
    send_str("sending the public key...\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(scewl_update_pk_t), (char *)&scewl_update_pk);
#endif
    send_msg(RAD_INTF, SCEWL_ID, pre_scewl_id, sizeof(scewl_update_pk_t), (char *)&scewl_update_pk);
  }

  // notify CPU of response
  // send_str("notify the cpu...\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(scewl_sss_msg_t), (char *)&msg);

  status = send_msg(CPU_INTF, src_id, tgt_id, sizeof(scewl_sss_msg_t), (char *)&msg);
  // #endif
  if (status == SCEWL_ERR)
  {
    return 0;
  }

  // op should be REG on success
  return msg.op == SCEWL_SSS_REG;
}

// purpose is to let every one know about the de-registration
/*
void notify_deregistration()
{
  send_str("sending de-register message to every one");
  char de_register_message[10] = {'D', 'E', 'R', 'E', 'G', 'I', 'S', 'T', 'E', 'R'};

  handle_brdcst_send(de_register_message, 10);
}*/

int sss_deregister()
{
  scewl_sss_msg_t msg;
  scewl_id_t src_id, tgt_id;
  int status, len;

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_DEREG;

// send registration
#ifdef REG_CRYPTO
  status = send_sign_SSS_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg, msg.op);
#else
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
#endif
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

  //broad cast deregistration message to every other SED currectly deployed
  // notify_deregistration();

  // op should be DEREG on success
  return msg.op == SCEWL_SSS_DEREG;
}

int main()
{
  int registered = 0, len;
  scewl_hdr_t hdr;
  uint16_t src_id, tgt_id;

  // Initial systick
  if (SysTick_Config(SystemFrequency / 1000) != 0)
  { /* Check return code for errors */
    return -1;
  }
  // intialize the sequence numbers to zero
  memset(&messeage_sq, 0, sizeof(sequence_num_t));

  memset(&scewl_pk, 0, sizeof(scewl_pub_t) * SCEWL_PK_NUM);

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
  send_enc_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)pt, RSA_ENC);
#endif

#ifdef RSA_TEST
  // uint8_t tmp[16] = {0x2d, 0xb5, 0x16, 0x8e,
  //                    0x93, 0x25, 0x56, 0xf8,
  //                    0x08, 0x9a, 0x06, 0x22,
  //                    0x98, 0x1d, 0x01, 0x7d};

  uint8_t message[64] = {0xbd, 0xbd, 0x2d, 0x7d, 0x92, 0x89, 0x01, 0x7d,
                         0x85, 0x01, 0x7d, 0x7d, 0x7d, 0x9c, 0xbb, 0x08,
                         0x03, 0x08, 0x08, 0xcf, 0xf3, 0x08, 0x08, 0x94,
                         0xe9, 0x08, 0xca, 0x94, 0x08, 0xfb, 0x08, 0xaf,
                         0xbd, 0xbd, 0x2d, 0x7d, 0x92, 0x89, 0x01, 0x7d,
                         0x85, 0x01, 0x7d, 0x7d, 0x7d, 0x9c, 0xbb, 0x08,
                         0x03, 0x08, 0x08, 0xcf, 0xf3, 0x08, 0x08, 0x94,
                         0xe9, 0x08, 0xca, 0x94, 0x08, 0xfb, 0x08};

  rsa_pk *pk = &public_key;
  rsa_sk *sk = &private_key;

  // configure the e
  BN_init(pk->e, MAX_PRIME_LENGTH);
  //e=2^16+1
  pk->e[MAX_PRIME_LENGTH - 2] = 1;
  pk->e[MAX_PRIME_LENGTH - 1] = 1;

  DTYPE msg[MAX_MODULUS_LENGTH] = {0};
  DTYPE cipher[MAX_MODULUS_LENGTH] = {0};
  DTYPE plaintext[MAX_MODULUS_LENGTH] = {0};
  DTYPE decipher[MAX_MODULUS_LENGTH] = {0};

  int i;
  int j = MAX_MODULUS_LENGTH - 1;
  for (i = 63 - 1; i >= 1; i -= 2)
  {
    msg[j--] = (message[i - 1] << 8) | message[i];
  }
  if (i == 0)
  {
    msg[j--] = message[i];
  }
  while (j >= 0)
  {
    msg[j--] = 0;
  }

  send_str("message...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)message);
  send_str("msg...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)&msg);

  send_str("Encryption starts...\n");
  rsa_encrypt(cipher, MAX_MODULUS_LENGTH, msg, MAX_MODULUS_LENGTH, pk);
  send_str("Encryption done...\n\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)cipher);

  send_str("Decryption starts...\n");
  rsa_decrypt(decipher, MAX_MODULUS_LENGTH, cipher, MAX_MODULUS_LENGTH, sk);
  send_str("Decryption done...\n\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)decipher);
  hex_to_string(plaintext, decipher);
  send_str("Plaintext...\n\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)plaintext);

  if (BN_cmp(message, MAX_MODULUS_LENGTH, plaintext, MAX_MODULUS_LENGTH) == 0)
  {
    send_str("\nAfter decryption, plaintext equal to message.\n");
  }
  else
  {
    send_str("\nAfter decryption, wrong answer.\n");
  }
#endif

#ifdef RSA_SIG_TEST
  // uint8_t tmp[16] = {0x2d, 0xb5, 0x16, 0x8e,
  //                    0x93, 0x25, 0x56, 0xf8,
  //                    0x08, 0x9a, 0x06, 0x22,
  //                    0x98, 0x1d, 0x01, 0x7d};

  uint8_t message[64] = {0xbd, 0xbd, 0x2d, 0x7d, 0x92, 0x89, 0x01, 0x7d,
                         0x85, 0x01, 0x7d, 0x7d, 0x7d, 0x9c, 0xbb, 0x08,
                         0x03, 0x08, 0x08, 0xcf, 0xf3, 0x08, 0x08, 0x94,
                         0xe9, 0x08, 0xca, 0x94, 0x08, 0xfb, 0x08, 0xaf,
                         0xbd, 0xbd, 0x2d, 0x7d, 0x92, 0x89, 0x01, 0x7d,
                         0x85, 0x01, 0x7d, 0x7d, 0x7d, 0x9c, 0xbb, 0x08,
                         0x03, 0x08, 0x08, 0xcf, 0xf3, 0x08, 0x08, 0x94,
                         0xe9, 0x08, 0xca, 0x94, 0x08, 0xfb, 0x08};

  rsa_pk *pk = &public_key;
  rsa_sk *sk = &private_key;

  // configure the e
  BN_init(pk->e, MAX_PRIME_LENGTH);
  //e=2^16+1
  pk->e[MAX_PRIME_LENGTH - 2] = 1;
  pk->e[MAX_PRIME_LENGTH - 1] = 1;

  DTYPE msg[MAX_MODULUS_LENGTH] = {0};
  DTYPE cipher[MAX_MODULUS_LENGTH] = {0};
  DTYPE plaintext[MAX_MODULUS_LENGTH] = {0};
  DTYPE decipher[MAX_MODULUS_LENGTH] = {0};

  int i;
  int j = MAX_MODULUS_LENGTH - 1;
  for (i = 63 - 1; i >= 1; i -= 2)
  {
    msg[j--] = (message[i - 1] << 8) | message[i];
  }
  if (i == 0)
  {
    msg[j--] = message[i];
  }
  while (j >= 0)
  {
    msg[j--] = 0;
  }

  send_str("message...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)message);
  send_str("msg...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)&msg);

  send_str("Sign starts...\n");
  // rsa_encrypt(cipher, MAX_MODULUS_LENGTH, msg, MAX_MODULUS_LENGTH, pk);
  rsa_decrypt(cipher, MAX_MODULUS_LENGTH, msg, MAX_MODULUS_LENGTH, sk);
  send_str("Sign done...\n\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)cipher);

  send_str("Decryption starts...\n");
  rsa_encrypt(decipher, MAX_MODULUS_LENGTH, cipher, MAX_MODULUS_LENGTH, pk);
  // rsa_decrypt(decipher, MAX_MODULUS_LENGTH, cipher, MAX_MODULUS_LENGTH, sk);
  send_str("Decryption done...\n\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)decipher);
  hex_to_string(plaintext, decipher);
  send_str("Plaintext...\n\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)plaintext);

  if (BN_cmp(message, MAX_MODULUS_LENGTH, plaintext, MAX_MODULUS_LENGTH) == 0)
  {
    send_str("\nAfter decryption, plaintext equal to message.\n");
  }
  else
  {
    send_str("\nAfter decryption, wrong answer.\n");
  }
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
          handle_faa_send(buf, len);
        }
        else
        {
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
