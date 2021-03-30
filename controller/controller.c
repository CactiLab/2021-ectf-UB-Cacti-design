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
// #include "sha1.h"
#include "md5.h"

// this will run if EXAMPLE_AES is defined in the Makefile
#include "aes-gcm.h"

// message buffer
char buf[SCEWL_MAX_CRYPTO_DATA_SZ];

//sequence number structure
sequence_num_t g_messeage_sq[max_sequenced_SEDS];

broadcast_sequence_num_t g_broadcast_rcv[max_sequenced_SEDS];

uint32_t g_broadcast_send_sequence = 0;

rsa_sk *own_sk = &private_key;

uint32_t sysTimer = 0;

// an array to store all provisoned sed's public key
scewl_pub_t g_scewl_pk[SCEWL_PK_NUM];
DTYPE g_own_pk_sig[RSA_BLOCK / 2];

void SysTick_Handler(void)
{
  sysTimer++;
}

uint8_t get_broadcast_sequence_numebr_index(scewl_id_t source_SED)
{
  for (int i = 0; i < max_sequenced_SEDS; i++)
  {
    if (g_broadcast_rcv[i].sed_id == 0 || g_broadcast_rcv[i].sed_id == source_SED)
    {
      g_broadcast_rcv[i].sed_id = source_SED;
      return i;
    }
  }
  return -1;
}

uint8_t get_targeted_sequence_numebr_index(scewl_id_t source_SED)
{
  for (int i = 0; i < max_sequenced_SEDS; i++)
  {
    if (g_messeage_sq[i].sed_id == 0 || g_messeage_sq[i].sed_id == source_SED)
    {
      g_messeage_sq[i].sed_id = source_SED;
      return i;
    }
  }
  return -1;
}

bool check_sequence_number(scewl_id_t source_SED, uint32_t received_sq_number, scewl_id_t target_SED)
{
  uint8_t index;
  if (target_SED == 0)
  {
    index = get_broadcast_sequence_numebr_index(source_SED);
    if (g_broadcast_rcv[index].rcv_sq < received_sq_number)
    {
      g_broadcast_rcv[index].rcv_sq = received_sq_number;
      return true;
    }
  }
  else
  {
    index = get_targeted_sequence_numebr_index(source_SED);
    if (g_messeage_sq[index].sq_receive < received_sq_number)
    {
      g_messeage_sq[index].sq_receive = received_sq_number;
      return true;
    }
  }
  return false;
}

void init_pk_e(rsa_pk *pk)
{
  // configure the e
  BN_init(pk->e, MAX_PRIME_LENGTH);
  //e=2^16+1
  pk->e[MAX_PRIME_LENGTH - 2] = 1;
  pk->e[MAX_PRIME_LENGTH - 1] = 1;
}

int check_scewl_pk(scewl_id_t tgt_id)
{
  for (int i = 0; i < SCEWL_PK_NUM; i++)
  {
    if (g_scewl_pk[i].scewl_id == tgt_id)
    {
      if (g_scewl_pk[i].flag == 1)
      {
        // configure the e
        BN_init(g_scewl_pk[i].pk.e, MAX_PRIME_LENGTH);
        //e=2^16+1
        g_scewl_pk[i].pk.e[MAX_PRIME_LENGTH - 2] = 1;
        g_scewl_pk[i].pk.e[MAX_PRIME_LENGTH - 1] = 1;

        // #ifdef DEBUG_PK_TEST
        //         send_str("find tgt public key\n");
        //         send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 1, (char *)&i);
        //         send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&g_scewl_pk[i].scewl_id);
        //         send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(rsa_pk), (char *)&g_scewl_pk[i].pk);
        // #endif
        return i;
      }
    }
  }
  return -1;
}

int check_signed_pk(scewl_update_pk_t *scew_update_pk)
{
  // unsigned char output[RSA_BLOCK] = {0};
  DTYPE decipher[MAX_MODULUS_LENGTH] = {0};
  init_pk_e(&sss_public_key);

  // #ifdef DEBUG_PK_TEST
  //   send_str("check_signed_pk: signature :\n");
  //   send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, RSA_BLOCK, (char *)(scew_update_pk->sig));
  //   send_str("check_signed_pk: sss_pk :\n");
  //   send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(rsa_pk), (char *)&sss_public_key);
  // #endif

  rsa_encrypt(decipher, MAX_MODULUS_LENGTH, scew_update_pk->sig, MAX_MODULUS_LENGTH, &sss_public_key);

#ifdef DEBUG_PK_TEST
  send_str("check_signed_pk: authentication result :\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, RSA_BLOCK, (char *)&decipher);
#endif

  memset(&(scew_update_pk->sig), 0, RSA_BLOCK);

  // SHA_Simple((unsigned char *)&(scew_update_pk->pk), sizeof(rsa_pk), (unsigned char *)&(scew_update_pk->sig));
  MD5Calc((const unsigned char *)&(scew_update_pk->pk), sizeof(rsa_pk), (unsigned char *)&(scew_update_pk->sig));

  // #ifdef DEBUG_PK_TEST
  //   send_str("check_signed_pk: SHA1 :\n");
  //   send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, RSA_BLOCK, (char *)(scew_update_pk->sig));
  // #endif

//   if (BN_cmp(decipher, MAX_MODULUS_LENGTH, (DTYPE *)&(scew_update_pk->sig), MAX_MODULUS_LENGTH) == 0)
//   {
// #ifdef DEBUG_PK_TEST
//     send_str("check_signed_pk: authentication success\n");
// #endif
//     return SCEWL_OK;
//   }
//   else
//   {
// #ifdef DEBUG_PK_TEST
//     send_str("check_signed_pk: authentication failure\n");
// #endif
//     return SCEWL_ERR;
//   }
  return SCEWL_OK;
}

void send_own_pk(scewl_id_t tgt_id)
{
  scewl_update_pk_t scewl_update_pk;
  memset(&scewl_update_pk, 0, sizeof(scewl_update_pk_t));

  scewl_update_pk.magicP = 'P';
  scewl_update_pk.magicK = 'K';
  memcpy(&scewl_update_pk.pk, &public_key, sizeof(rsa_pk));
  memcpy(&scewl_update_pk.sig, g_own_pk_sig, RSA_BLOCK);

  // #ifdef DEBUG_PK_TEST
  //   send_str("send_own_pk:\n");
  //   send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(scewl_update_pk_t), (char *)&scewl_update_pk);
  // #endif

  send_msg(RAD_INTF, SCEWL_ID, tgt_id, sizeof(scewl_update_pk_t), (char *)&scewl_update_pk);
}

int set_tgt_pk(scewl_id_t src_id, scewl_update_pk_t *scewl_update_pk)
{
  if (check_scewl_pk(src_id) < 0)
  {
    for (size_t i = 0; i < SCEWL_PK_NUM; i++)
    {
      if (g_scewl_pk[i].flag == 0)
      {
        if (check_signed_pk(scewl_update_pk) < 0)
        {
#ifdef DEBUG_PK_TEST
          send_str("set_tgt_pk: wrong pk!\n");
          send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
#endif
          return SCEWL_ERR;
        }
        memcpy(&g_scewl_pk[i].pk, &scewl_update_pk->pk, sizeof(rsa_pk));
        g_scewl_pk[i].scewl_id = src_id;
        g_scewl_pk[i].flag = 1;

        init_pk_e(&g_scewl_pk[i].pk);

#ifdef DEBUG_PK_TEST
        send_str("set_tgt_pk: set pk!");
        send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
        // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(rsa_pk), (char *)&g_scewl_pk[i].pk);
#endif
        return i;
        // i = SCEWL_PK_NUM;
      }
    }
  }
}

int send_get_scewl_pk_msg(scewl_id_t tgt_id)
{
  char *get_pk = "NO";

  send_msg(RAD_INTF, SCEWL_ID, tgt_id, strlen(get_pk), get_pk);

  // #ifdef DEBUG_PK_TEST
  //   send_str("send_get_scewl_pk_msg: send out pk request");
  //   send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&tgt_id);
  // #endif

  scewl_id_t tmp_src, tmp_tgt;
  scewl_update_pk_t scewl_update_pk;

  int len = 0, count = 0;

  char tmp_buf[SCEWL_MAX_CRYPTO_DATA_SZ] = {0};
  memset(&scewl_update_pk, 0, sizeof(scewl_update_pk_t));

  while (count < 3)
  {
    if (intf_avail(RAD_INTF))
    {
      // Read message from antenna
      len = read_msg(RAD_INTF, tmp_buf, &tmp_src, &tmp_tgt, sizeof(tmp_buf), 1);

      if (tmp_src != SCEWL_ID)
      { // ignore our own outgoing messages

        if (tmp_tgt == SCEWL_ID)
        {
          // receive unicast message
          if (tmp_src == tgt_id)
          {
            count++;
            if ((tmp_buf[0] == 'P') && (tmp_buf[1] == 'K'))
            {
              if (set_tgt_pk(tgt_id, tmp_buf) >= 0)
              {
                count = 10;
                return SCEWL_NO_MSG;
              }
            }
          }
          else if ((tmp_buf[0] == 'N') && (tmp_buf[1] == 'O'))
          {
            send_own_pk(tmp_src);
          }
        }
      }
    }
  }
  return SCEWL_ERR;
}

int key_enc(scewl_id_t src_id, scewl_id_t tgt_id, scewl_msg_t *scewl_msg, uint8_t rsa_mode)
{
  int idx = 0;
  uint8_t message[MAX_MODULUS_LENGTH * 2] = {0};
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
      // send_str("Key_enc: please get the target public key first!");
      return SCEWL_ERR;
    }
    else
    {
      rsa_encrypt(cipher, MAX_MODULUS_LENGTH, msg, MAX_MODULUS_LENGTH, &g_scewl_pk[idx].pk);
    }

#ifdef DEBUG_KEY_CRYPTO
    send_str("aes_key Encryption done...\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)cipher);
#endif

    memcpy(scewl_msg->aes_key, (uint8_t *)&cipher, keyCryptoLen);
    break;
  }

  return SCEWL_OK;
}

int key_dec(scewl_id_t src_id, scewl_id_t tgt_id, scewl_msg_t *scewl_msg, uint8_t rsa_mode)
{
  DTYPE plaintext[MAX_MODULUS_LENGTH] = {0};
  DTYPE decipher[MAX_MODULUS_LENGTH] = {0};
  int idx = 0;

  switch (rsa_mode)
  {
    // handler broadcast aes_key crypto, private key to sign, public key to auth
  case RSA_AUTH:
    /* verify */
    idx = check_scewl_pk(src_id);

    if (idx < 0)
    {
      // send_str("Key_dec: does not have its public key!");
      // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
      return SCEWL_ERR;
    }
    else
    {
      rsa_encrypt(decipher, MAX_MODULUS_LENGTH, (DTYPE *)scewl_msg->aes_key, MAX_MODULUS_LENGTH, &g_scewl_pk[idx].pk);
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
  return 0;
}

int enc_msg(scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data, scewl_msg_t *scewl_msg, uint8_t rsa_mode)
{
  int i = 0, ret = 0, enc_len = 0;
  uint16_t padding_size = 0;
  int scewl_msg_body_len = MSG_HDR_SZ + enc_len; // crypto message: msg header + body (data)

  padding_size = (len + MSG_HDR_SZ + CRYPTO_HDR_SZ) % 4 ? 4 - (len + MSG_HDR_SZ + CRYPTO_HDR_SZ) % 4 : 0;
  enc_len = len + padding_size + CRYPTO_HDR_SZ;

  uint8_t key[keyCryptoLen] = {0};
  uint8_t iv[ivLen] = {0};
  uint8_t tag[tagLen] = {0};
  uint8_t index = 0;
  // scewl_msg_t scewl_msg;
  uint8_t ciphertext[SCEWL_MAX_CRYPTO_DATA_SZ] = {0};

  // initialize the structures
  // memset(&scewl_msg, 0, sizeof(scewl_msg_t));

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
  scewl_msg->crypto_msg.tgt_id = tgt_id;
  scewl_msg->crypto_msg.src_id = src_id;
  scewl_msg->crypto_msg.len = scewl_msg_body_len;
  scewl_msg->crypto_msg.padding_size = padding_size;
  scewl_msg->padding_size = padding_size;
  if (tgt_id == 0)
  {
    scewl_msg->crypto_msg.sq = ++g_broadcast_send_sequence;
  }
  else
  {
    index = get_targeted_sequence_numebr_index(tgt_id);
    if (index < 0)
    {
      return SCEWL_ERR;
    }
    scewl_msg->crypto_msg.sq = ++g_messeage_sq[index].sq_send; // setup the sequence number
  }
  memcpy(scewl_msg->crypto_msg.body, data, len); // setup the plaintext

  // setup the scewl message
  if (rsa_mode == RSA_SEND_PK)
  {
    scewl_msg->magicP = 'P';
    scewl_msg->magicK = 'K';
  }
  else if (rsa_mode == RSA_REQ_PK)
  {
    scewl_msg->magicP = 'N';
    scewl_msg->magicK = 'O';
  }
  else
  {
    scewl_msg->magicP = 'X';
    scewl_msg->magicK = 'X';
  }
  memcpy(scewl_msg->aes_key, key, keyCryptoLen);
  memcpy(scewl_msg->iv, iv, ivLen);

#ifdef SQ_DEBUG
  send_str("Sending sq:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&scewl_msg->crypto_msg.sq);
#endif

#ifdef DEBUG_MSG_CRYPTO
  send_str("data:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)data);
  send_str("plaintext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)&scewl_msg->crypto_msg.body);
  send_str("key:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyCryptoLen, (char *)key);
  send_str("iv:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, ivLen, (char *)iv);
#endif

  // initialize context
  gcm_initialize();

#ifdef DEBUG_MSG_CRYPTO
  // send_str("send_scewl_msg (plaintext):\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, enc_len, (char *)&ciphertext);
  char scewl_msg_hdr_size[10] = {0};
  itoa(sizeof(scewl_msg_t), scewl_msg_hdr_size, 10);
  send_str("send_scewl_msg header:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 10, (char *)scewl_msg_hdr_size);

  memset(scewl_msg_hdr_size, 0, 10);
  itoa(sizeof(scewl_crypto_msg_t), scewl_msg_hdr_size, 10);
  send_str("send_crypto_scewl_msg header:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 10, (char *)scewl_msg_hdr_size);

  send_str("plaintext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)&scewl_msg->crypto_msg.body);
  send_str("send_scewl_msg:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, enc_len + sizeof(scewl_msg_t) - sizeof(scewl_crypto_msg_t), (char *)scewl_msg);
#endif

  // encrypt buffer (encryption happens in place)
  aes_gcm_encrypt_tag(ciphertext, (const uint8_t *)(&(scewl_msg->crypto_msg)), enc_len, key, keyLen, iv, ivLen, scewl_msg->tag, tagLen);
  memcpy(&scewl_msg->crypto_msg, ciphertext, enc_len);

#ifdef KEY_CRYPTO
  ret = key_enc(src_id, tgt_id, scewl_msg, rsa_mode);

#ifdef DEBUG_MSG_CRYPTO
  send_str("encrypted key:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyCryptoLen, (char *)scewl_msg->aes_key);
#endif

  if (ret == SCEWL_ERR)
  {
    return SCEWL_ERR;
  }

#endif

#ifdef DEBUG_MSG_CRYPTO
  send_str("send_scewl_msg (ciphertext):\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, enc_len, (char *)&ciphertext);
  send_str("send_scewl_msg:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, enc_len + sizeof(scewl_msg_t) - sizeof(scewl_crypto_msg_t), (char *)scewl_msg);
#endif
  // memcpy(send_scewl_msg, &scewl_msg, scewl_msg_body_len);

  return SCEWL_OK;
}

int send_enc_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data, uint8_t rsa_mode)
{
  send_scewl_msg_t send_scewl_msg;
  // scewl_hdr_t hdr;
  uint16_t padding_size = 0, ret = 0;
  // char tmp_buf[SCEWL_MAX_DATA_SZ + 8] = {0};

  padding_size = (len + MSG_HDR_SZ + CRYPTO_HDR_SZ) % 4 ? 4 - (len + MSG_HDR_SZ + CRYPTO_HDR_SZ) % 4 : 0;

  // scewl_msg_t send_scewl_msg;
  memset(&send_scewl_msg, 0, sizeof(send_scewl_msg_t));

  // pack header
  send_scewl_msg.hdr.magicS = 'S';
  send_scewl_msg.hdr.magicC = 'C';
  send_scewl_msg.hdr.src_id = src_id;
  send_scewl_msg.hdr.tgt_id = tgt_id;
  send_scewl_msg.hdr.len = len + MSG_HDR_SZ + CRYPTO_HDR_SZ + padding_size; // crypto message: msg header + body (data)

  ret = enc_msg(src_id, tgt_id, len, data, &send_scewl_msg.scewl_msg, rsa_mode);
#ifdef DEBUG_MSG_CRYPTO
  send_str("send_enc_msg:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, send_scewl_msg.hdr.len + sizeof(scewl_hdr_t));
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, send_scewl_msg.hdr.len + sizeof(scewl_hdr_t), (char *)&send_scewl_msg);
#endif
  if (ret == SCEWL_ERR)
  {
    return SCEWL_ERR;
  }

  // memcpy(tmp_buf, (char *)&hdr, sizeof(scewl_hdr_t));
  // memcpy(tmp_buf + sizeof(scewl_hdr_t), (char *)&send_scewl_msg, hdr.len);
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(scewl_hdr_t) + hdr.len, tmp_buf);
  // intf_write(intf, (char *)&tmp_buf, sizeof(scewl_hdr_t) + hdr.len);

  // send the full scewl_msg

  // pack header again
  send_scewl_msg.hdr.magicS = 'S';
  send_scewl_msg.hdr.magicC = 'C';
  send_scewl_msg.hdr.src_id = src_id;
  send_scewl_msg.hdr.tgt_id = tgt_id;
  send_scewl_msg.hdr.len = len + MSG_HDR_SZ + CRYPTO_HDR_SZ + padding_size; // crypto message: msg header + body (data)

  intf_write(intf, (char *)&send_scewl_msg, sizeof(scewl_hdr_t) + send_scewl_msg.hdr.len);

  return SCEWL_OK;
}

int auth_msg(scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, scewl_msg_t *recv_data, scewl_msg_t *output, uint8_t rsa_mode)
{
  // scewl_crypto_msg_t *crypto_msg;
  // scewl_msg_t *scewl_msg = NULL;
  int dec_len = len - MSG_HDR_SZ;
  int ret = 0;
  int padding_size = 0;
  int crypto_msg_len = dec_len - CRYPTO_HDR_SZ;

  // memset(&crypto_msg, 0, sizeof(scewl_crypto_msg_t));
  // scewl_msg = (scewl_msg_t *)data;

#ifdef DEBUG_MSG_CRYPTO
  send_str("------------------------------------------------------------------:\n");
  send_str("test auth message:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)recv_data);
  send_str("key:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyCryptoLen, (char *)recv_data->aes_key);
  send_str("iv:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, ivLen, (char *)recv_data->iv);
  send_str("tag:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, tagLen, (char *)recv_data->tag);
#endif

// decrypt the aes_key
#ifdef KEY_CRYPTO
  ret = key_dec(src_id, tgt_id, recv_data, rsa_mode);

#ifdef DEBUG_MSG_CRYPTO
  send_str("decrypted key:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyCryptoLen, (char *)recv_data->aes_key);
#endif

  if (ret == SCEWL_ERR)
  {
    return SCEWL_ERR;
  }
#endif

  // initialize context
  gcm_initialize();

  ret = aes_gcm_decrypt_auth((uint8_t *)&output->crypto_msg, (const uint8_t *)&recv_data->crypto_msg, dec_len, (const uint8_t *)&recv_data->aes_key, keyLen, (const uint8_t *)&recv_data->iv, ivLen, (uint8_t *)&recv_data->tag, tagLen);

#ifdef DEBUG_MSG_CRYPTO
  send_str("auth_msg: ret:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(int), (char *)&ret);
  send_str("auth_msg: plaintext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, crypto_msg_len, (char *)&output->crypto_msg.body);
#endif

  if (ret == 0)
  {
#ifdef DEBUG_MSG_CRYPTO
    send_str("Authentication Success!\n");

    send_str("src_id:\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&output->crypto_msg.src_id);
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
    send_str("tgt_id:\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&output->crypto_msg.tgt_id);
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&tgt_id);
    send_str("msg_len:\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&output->crypto_msg.len);
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&len);
#endif

    if ((output->crypto_msg.src_id == src_id) && (output->crypto_msg.tgt_id == tgt_id) && (output->crypto_msg.len == len))
    {
#ifdef DEBUG_MSG_CRYPTO
      send_str("Right message!");
#endif
    }
    else
    {
#ifdef DEBUG_MSG_CRYPTO
      send_str("Wrong message!");
#endif
      return SCEWL_ERR;
    }
  }
  else
  {
#ifdef DEBUG_MSG_CRYPTO
    send_str("Integrity Authentication Failure!");
#endif
    return SCEWL_ERR;
  }

  if (check_sequence_number(src_id, output->crypto_msg.sq, tgt_id))
  {
#ifdef DEBUG_MSG_CRYPTO
    send_str("Sequence numebr validation success");
#endif
  }
  else
  {
#ifdef DEBUG_MSG_CRYPTO
    send_str("Replay attack detected");
#endif
    return SCEWL_ERR;
  }

#ifdef DEBUG_MSG_CRYPTO
  send_str("Receiver Sequence number");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&output->crypto_msg.sq);
  send_str("crypto_msg.body:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, crypto_msg_len, (char *)&output->crypto_msg.body);
#endif

  // padding = crypto_msg.padding_size;
  // memcpy(output, crypto_msg.body, crypto_msg_len - padding_size);

  return SCEWL_OK;
}

int send_auth_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data, uint8_t rsa_mode)
{
  scewl_hdr_t hdr;
  scewl_msg_t output;
  // uint8_t output[SCEWL_MAX_DATA_SZ]; //hdr.len
  scewl_msg_t *scewl_msg = (scewl_msg_t *)data;
  scewl_update_pk_t scewl_update_pk;
  // char tmp_buf[SCEWL_MAX_CRYPTO_DATA_SZ] = {0};

  int ret = 0;

  // pack header
  hdr.magicS = 'S';
  hdr.magicC = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len = len - MSG_HDR_SZ - CRYPTO_HDR_SZ - scewl_msg->padding_size; // msg - CRYPTO_HDR_SZ - scewl_hdr

  memset(&output, 0, sizeof(scewl_msg_t));
  memset(&scewl_update_pk, 0, sizeof(scewl_update_pk_t));

  if ((data[0] == 'N') && (data[1] == 'O'))
  {
#ifdef DEBUG_PK_TEST
    send_str("send_auth_msg: receive pk requests");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
#endif

    send_own_pk(src_id);

    return SCEWL_NO_MSG;
  }
  else if ((data[0] == 'P') && (data[1] == 'K'))
  {
#ifdef DEBUG_PK_TEST
    send_str("send_auth_msg: receive pk");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
#endif

    set_tgt_pk(src_id, data);
    return SCEWL_NO_MSG;
  }

#ifdef DEBUG_PK_TEST
  send_str("send_auth_msg: targeted message");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
#endif

  if (check_scewl_pk(src_id) < 0)
  {

#ifdef DEBUG_PK_TEST
    send_str("send_auth_msg: ask for pk");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
#endif
    if (send_get_scewl_pk_msg(src_id) < 0)
    {
#ifdef DEBUG_PK_TEST
      send_str("handle_brdcst_recv: request tgt pk failure!");
#endif
      return SCEWL_NO_MSG;
    }
  }

  ret = auth_msg(src_id, tgt_id, len, data, &output, rsa_mode);

  // write header
  // pack header again
  hdr.magicS = 'S';
  hdr.magicC = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len = len - MSG_HDR_SZ - CRYPTO_HDR_SZ - scewl_msg->padding_size; // msg - CRYPTO_HDR_SZ - scewl_hdr
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // write body
  intf_write(intf, (char *)&output.crypto_msg.body, hdr.len);
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

  // send_str("sign sss_msg...\n");
  rsa_decrypt(cipher, MAX_MODULUS_LENGTH, message, MAX_MODULUS_LENGTH, own_sk);

  memcpy((char *)&sss_crypto_msg, cipher, RSA_BLOCK);

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  intf_write(intf, (char *)&sss_crypto_msg, RSA_BLOCK);

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

  if (check_scewl_pk(tgt_id) < 0)
  {
#ifdef DEBUG_PK_TEST
    send_str("handle_scewl_send: pk requests");
#endif
    if (send_get_scewl_pk_msg(tgt_id) < 0)
    {
#ifdef DEBUG_PK_TEST
      send_str("handle_scewl_send: Request tgt pk failure!");
#endif
      return SCEWL_ERR;
    }
  }
  return send_enc_msg(RAD_INTF, SCEWL_ID, tgt_id, len, data, RSA_ENC);
#else
  return send_msg(RAD_INTF, SCEWL_ID, tgt_id, len, data);
#endif
}

int handle_brdcst_recv(char *data, scewl_id_t src_id, uint16_t len)
{
#ifdef MSG_CRYPTO

  if (src_id != SCEWL_FAA_ID)
  {
    if ((data[0] == 'P') && (data[1] == 'K'))
    {
#ifdef DEBUG_PK_TEST
      send_str("send_auth_msg: receive pk");
      send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&src_id);
#endif

      set_tgt_pk(src_id, data);
      return SCEWL_NO_MSG;
    }
    else
    {
      if (check_scewl_pk(src_id) < 0)
      {
#ifdef DEBUG_PK_TEST
        send_str("handle_brdcst_recv: pk requests");
#endif
        if (send_get_scewl_pk_msg(src_id) < 0)
        {
#ifdef DEBUG_PK_TEST
          send_str("handle_brdcst_recv: Request tgt pk failure!");
#endif
          return SCEWL_NO_MSG;
        }
      }
    }

    return send_auth_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data, RSA_AUTH);
  }

  // if it is a faa brdcst
  return send_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data);
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

  // bad op
  return 0;
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

  // 2. split the response
  // current (4 bytes)
  memcpy(&msg, (char *)&buf, sizeof(scewl_sss_msg_t));
  // totalSED 1 byte
  memcpy(&totalSEDs, (char *)&buf + sizeof(scewl_sss_msg_t), 1);

  // loop to set scewl public key

  for (i = 0; i < totalSEDs; i++)
  {
    // current header(4) + totalSEDs(1) + (dev_id(2) + rsa_pk(162)) * totalSEDs
    memcpy(&g_scewl_pk[i].scewl_id, (char *)&buf + 5 + (sizeof(rsa_pk) + 2) * i, sizeof(scewl_pub_t));

    g_scewl_pk[i].flag = 1;
    pos = i;
  }

  // read the signature of its own pk
  memcpy(g_own_pk_sig, (char *)&buf + 5 + (sizeof(rsa_pk) + 2) * totalSEDs, RSA_BLOCK);

  // #ifdef DEBUG_PK_TEST
  //   send_str("own pk signature\n");
  //   send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, RSA_BLOCK, (char *)&g_own_pk_sig);
  // #endif

  // check_signed_pk(g_own_pk_sig);

  send_own_pk(SCEWL_BRDCST_ID);

  // notify CPU of response
  status = send_msg(CPU_INTF, src_id, tgt_id, sizeof(scewl_sss_msg_t), (char *)&msg);

  if (status == SCEWL_ERR)
  {
    return SCEWL_ERR;
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
  status = send_msg(CPU_INTF, src_id, tgt_id, sizeof(scewl_sss_msg_t), (char *)&msg);

#ifdef DEBUG_REG
  send_str("deregister response:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, sizeof(scewl_sss_msg_t), (char *)&msg);
  send_str("deregister response:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 2, (char *)&status);
#endif

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
  memset(&g_messeage_sq, 0, 16 * sizeof(sequence_num_t));
  memset(&g_broadcast_rcv, 0, 16 * sizeof(broadcast_sequence_num_t));
  memset(&g_scewl_pk, 0, sizeof(scewl_pub_t) * SCEWL_PK_NUM);

  // initialize e of the pk
  init_pk_e(&public_key);
  init_pk_e(&sss_public_key);

  // initialize interfaces
  intf_init(CPU_INTF);
  intf_init(SSS_INTF);
  intf_init(RAD_INTF);

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
