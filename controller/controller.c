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

volatile rsa_pk *pk = &public_key;
volatile rsa_sk *sk = &private_key;
volatile uint32_t sysTimer = 0;

void SysTick_Handler(void)
{
  sysTimer++;
}

int key_enc(scewl_id_t src_id, scewl_id_t tgt_id, scewl_msg_t *scewl_msg)
{
  uint8_t message[MAX_MODULUS_LENGTH * 2] = {0};
  // uint8_t tmp[32] = {0};
  DTYPE msg[MAX_MODULUS_LENGTH] = {0};
  DTYPE cipher[MAX_MODULUS_LENGTH] = {0};
  DTYPE decipher[MAX_MODULUS_LENGTH] = {0};
  DTYPE plaintext[MAX_MODULUS_LENGTH] = {0};

  // configure the e
  BN_init(pk->e, MAX_PRIME_LENGTH);
  //e=2^16+1
  pk->e[MAX_PRIME_LENGTH - 2] = 1;
  pk->e[MAX_PRIME_LENGTH - 1] = 1;

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

  switch (tgt_id)
  {
    // handler broadcast aes_key crypto, private key to sign, public key to auth
  case SCEWL_BRDCST_ID:
    /* sign */
    rsa_decrypt(cipher, MAX_MODULUS_LENGTH, msg, MAX_MODULUS_LENGTH, sk);
    break;
  case SCEWL_SSS_ID:
    /* sign */
    // rsa_decrypt(cipher, MAX_MODULUS_LENGTH, msg, MAX_MODULUS_LENGTH, sk);
    break;
  case SCEWL_FAA_ID:
    break;

    // default means scewl messages, public key to encrypt, private key to decrypt
  default:
    // send_str("aes_key Encryption starts...\n");
    rsa_encrypt(cipher, MAX_MODULUS_LENGTH, msg, MAX_MODULUS_LENGTH, pk);

#ifdef DEBUG_KEY_CRYPTO
    send_str("aes_key Encryption done...\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)cipher);
#endif

    memcpy(scewl_msg->aes_key, (uint8_t *)&cipher, keyCryptoLen);
    break;
  }
  // memset(enc_aes_key, 0, keyLen);

#ifdef DEBUG_KEY_CRYPTO
  send_str("Decryption starts...\n");
  send_str("sk->d1...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 32, (char *)sk->d1);
  rsa_decrypt(decipher, MAX_MODULUS_LENGTH, scewl_msg->aes_key, MAX_MODULUS_LENGTH, sk);
  hex_to_string(plaintext, decipher);
  send_str("Decryption done...\n\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)decipher);

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

  return 0;
}

int key_dec(scewl_id_t src_id, scewl_id_t tgt_id, scewl_msg_t *scewl_msg)
{
  DTYPE ciphertext[MAX_MODULUS_LENGTH] = {0};
  DTYPE plaintext[MAX_MODULUS_LENGTH] = {0};
  DTYPE decipher[MAX_MODULUS_LENGTH] = {0};

  switch (tgt_id)
  {
    // handler broadcast aes_key crypto, private key to sign, public key to auth
  case SCEWL_BRDCST_ID:
    /* verify */
    rsa_encrypt(decipher, MAX_MODULUS_LENGTH, (DTYPE *)scewl_msg->aes_key, MAX_MODULUS_LENGTH, pk);
    break;
  case SCEWL_SSS_ID:
    // rsa_encrypt(decipher, MAX_MODULUS_LENGTH, (DTYPE *)scewl_msg->aes_key, MAX_MODULUS_LENGTH, pk);
    break;
  case SCEWL_FAA_ID:
    break;

    // default means scewl messages, public key to encrypt, private key to decrypt
  default:

#ifdef DEBUG_KEY_CRYPTO
    send_str("aes_key Decryption starts...\n");
    send_str("aes_key before decryption...\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, MAX_MODULUS_LENGTH * 2, (char *)scewl_msg->aes_key);
    send_str("sk->d1...\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 32, (char *)sk->d1);
#endif
    rsa_decrypt(decipher, MAX_MODULUS_LENGTH, (DTYPE *)scewl_msg->aes_key, MAX_MODULUS_LENGTH, sk);
#ifdef DEBUG_KEY_CRYPTO
    send_str("decipher...\n");
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

bool check_sequence_number(scewl_id_t source_SED, uint32_t received_sq_number)
{
  if (messeage_sq.sq_receive[source_SED] < received_sq_number)
  {
    messeage_sq.sq_receive[source_SED] = received_sq_number;
    return true;
  }

  return false;
}

/*
  Check message type:
    CPU_INTF UART0
    SSS_INTF UART1
    RAD_INTF UART2
*/

int send_enc_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data)
{
  scewl_hdr_t hdr;
  int enc_len = len + sizeof(scewl_crypto_msg_hdr_t); // plaintext data len + 4 bytes sequence number

  // pack header
  hdr.magicS = 'S';
  hdr.magicC = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len = sizeof(scewl_msg_hdr_t) + enc_len; // crypto message: msg header + 4 bytes sequence number + body (data)

  scewl_msg_t msg;
  scewl_crypto_msg_t crypto_msg;

  uint8_t key[keyCryptoLen] = {0};
  uint8_t iv[ivLen] = {0};
  int i = 0;

  uint8_t plaintext[enc_len];
  uint8_t ciphertext[enc_len];

  // initialize the structures
  memset(key, 0, keyCryptoLen);
  memset(iv, 0, ivLen);
  memset(ciphertext, 0, enc_len);
  memset(plaintext, 0, enc_len);
  memset(&msg, 0, sizeof(scewl_msg_t));
  memset(&crypto_msg, 0, sizeof(scewl_crypto_msg_t));

  // setup random aes_key and iv
  // srand((unsigned int)(&msg + SCEWL_ID));

  srand(sysTimer);
#ifdef DEBUG_TIMER
  send_str("timer:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&sysTimer);
#endif
  for (i = 0; i < keyCryptoLen - 1; i++)
  {
    key[i] = rand() % 256;
  }

  for (i = 0; i < ivLen; i++)
  {
    iv[i] = rand() % 256;
  }

  // setup the crypto message structure
  crypto_msg.tgt_id = tgt_id;
  crypto_msg.src_id = src_id;
  crypto_msg.len = hdr.len;
  crypto_msg.sq = ++messeage_sq.sq_send[hdr.tgt_id]; // setup the sequence number
  memcpy(crypto_msg.body, data, len);                // setup the plaintext

  // setup the scewl message
  memcpy(msg.aes_key, key, keyCryptoLen);
  memcpy(msg.iv, iv, ivLen);

#ifdef SQ_DEBUG
  send_str("Sending sq:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&crypto_msg.sq);
#endif

#ifdef DEBUG_MSG_CRYPTO
  send_str("------------------------------------------------------------------:\n");
  send_str("test enc message:\n");
  // send_str("src_id:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)crypto_msg.src_id);
  // send_str("tgt_id:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)crypto_msg.tgt_id);
  // send_str("crypto len:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)crypto_msg.len);
  send_str("plaintext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, (char *)crypto_msg.body);
  // send_str("crypto len:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 8, (char *)crypto_msg.len);
  // send_str("sq:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)crypto_msg.sq);
  send_str("key:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyCryptoLen, (char *)msg.aes_key);
  // send_str("iv:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, ivLen, (char *)msg.iv);
#endif

  // initialize context
  gcm_initialize();

  // encrypt buffer (encryption happens in place)
  aes_gcm_encrypt_tag(ciphertext, (const uint8_t *)&crypto_msg, enc_len, msg.aes_key, keyLen, msg.iv, ivLen, msg.tag, tagLen);
  memcpy(msg.body, ciphertext, enc_len);

#ifdef KEY_CRYPTO
  key_enc(src_id, tgt_id, &msg);
#ifdef DEBUG_KEY_CRYPTO
  send_str("encrypted key...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyCryptoLen, (char *)msg.aes_key);
#endif
#endif

#ifdef KEY_CRYPTO
#endif
#ifdef DEBUG_MSG_CRYPTO
  send_str("tag:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, tagLen, (char *)msg.tag);
  send_str("ciphertext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, enc_len, (char *)ciphertext);
  send_str("ciphertext in msg body:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, enc_len, (char *)msg.body);
  send_str("------------------------------------------------------------------:\n");
  memset(ciphertext, 0, 16);
#endif

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  // intf_write(intf, data, len);
  intf_write(intf, (char *)&msg, hdr.len);

  return SCEWL_OK;
}

int send_auth_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data)
{
  scewl_hdr_t hdr;
  int dec_len = len - sizeof(scewl_msg_hdr_t);

  // pack header
  hdr.magicS = 'S';
  hdr.magicC = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len = dec_len - sizeof(scewl_crypto_msg_hdr_t);

  scewl_crypto_msg_t *crypto_msg = NULL;
  scewl_msg_t *msg = NULL;

  uint8_t plaintext[dec_len];
  uint8_t ciphertext[dec_len];

  memset(ciphertext, 0, dec_len);
  memset(plaintext, 0, dec_len);

  msg = (scewl_msg_t *)data;

#ifdef DEBUG_MSG_CRYPTO
  send_str("------------------------------------------------------------------:\n");
  send_str("test auth message:\n");
  send_str("key:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyCryptoLen, (char *)msg->aes_key);
  send_str("iv:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, ivLen, (char *)msg->iv);
  send_str("tag:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, tagLen, (char *)msg->tag);
  send_str("ciphertext:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, dec_len, (char *)msg->body);
  // send_str("------------------------------------------------------------------:\n");
#endif

// decrypt the aes_key
#ifdef KEY_CRYPTO
  key_dec(src_id, tgt_id, msg);
#ifdef DEBUG_KEY_CRYPTO
  send_str("decrypted key...\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyCryptoLen, (char *)msg->aes_key);
#endif
#endif

  // initialize context
  gcm_initialize();

#ifdef DEBUG_MSG_CRYPTO
  // send_str("------------------------------------------------------------------:\n");
  // send_str("test auth message:\n");
  send_str("key:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, keyCryptoLen, (char *)msg->aes_key);
  // send_str("iv:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, ivLen, (char *)msg->iv);
  // send_str("tag:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, tagLen, (char *)msg->tag);
  // send_str("ciphertext:\n");
  // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, dec_len, (char *)msg->body);
  // send_str("------------------------------------------------------------------:\n");
#endif
  int ret = 0;
  ret = aes_gcm_decrypt_auth(plaintext, (const uint8_t *)msg->body, dec_len, msg->aes_key, keyLen, msg->iv, ivLen, msg->tag, tagLen);

#ifdef DEBUG_MSG_CRYPTO
  send_str("plaintext before checking header:\n");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, dec_len, (char *)plaintext);
#endif

  if (ret == 0)
  {

#ifdef DEBUG_MSG_CRYPTO
    // send_str("plaintext:\n");
    // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, dec_len, (char *)plaintext);
#endif

    send_str("Checkging the header...\n");
    crypto_msg = (scewl_crypto_msg_t *)plaintext;
#ifdef DEBUG_MSG_CRYPTO
    // send_str("src_id:\n");
    // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)crypto_msg->src_id);
    // send_str("tgt_id:\n");
    // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)crypto_msg->tgt_id);
    // send_str("crypto len:\n");
    // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)crypto_msg->len);
    // send_str("sq:\n");
    // send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)crypto_msg->sq);
    send_str("plaintext:\n");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, hdr.len, (char *)crypto_msg->body);
#endif
    if ((crypto_msg->src_id == src_id) && (crypto_msg->tgt_id == tgt_id) && (crypto_msg->len == len))
    {
      send_str("Authentication Success!\n");
    }
    else
    {
      send_str("Authentication Failure!");
      return (-1);
    }
  }
  else
  {
    send_str("Authentication Failure!");
    return (-1);
  }

  if (check_sequence_number(hdr.src_id, crypto_msg->sq))
  {

#ifdef DEBUG_MSG_CRYPTO
    send_str("Receiver Sequence number");
    send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 4, (char *)&crypto_msg->sq);
#endif
    send_str("Sequence numebr validation success");
  }
  else
  {
    send_str("Replay attack detected");
    return (-1);
  }

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  intf_write(intf, crypto_msg->body, hdr.len);

  return SCEWL_OK;
}

int send_reg_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data)
{
  scewl_hdr_t hdr;
  int dec_len = len - sizeof(scewl_msg_hdr_t);

  // pack header
  hdr.magicS = 'S';
  hdr.magicC = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len = dec_len - sizeof(scewl_crypto_msg_hdr_t);

  scewl_crypto_msg_t *crypto_msg = NULL;
  scewl_msg_t *msg = NULL;

  uint8_t plaintext[dec_len];
  uint8_t ciphertext[dec_len];

  memset(ciphertext, 0, dec_len);
  memset(plaintext, 0, dec_len);

  msg = (scewl_msg_t *)data;


// decrypt the aes_key
#ifdef KEY_CRYPTO
  key_dec(src_id, tgt_id, msg);
#endif

  // initialize context
  gcm_initialize();

  int ret = 0;
  ret = aes_gcm_decrypt_auth(plaintext, (const uint8_t *)msg->body, dec_len, msg->aes_key, keyLen, msg->iv, ivLen, msg->tag, tagLen);

  if (ret == 0)
  {
    send_str("Checkging the header...\n");
    crypto_msg = (scewl_crypto_msg_t *)plaintext;

    if ((crypto_msg->src_id == src_id) && (crypto_msg->tgt_id == tgt_id) && (crypto_msg->len == len))
    {
      send_str("Authentication Success!\n");
    }
    else
    {
      send_str("Authentication Failure!");
      return (-1);
    }
  }
  else
  {
    send_str("Authentication Failure!");
    return (-1);
  }

  if (check_sequence_number(hdr.src_id, crypto_msg->sq))
  {
    send_str("Sequence numebr validation success");
  }
  else
  {
    send_str("Replay attack detected");
    return (-1);
  }

  // fill the structure

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  intf_write(intf, crypto_msg->body, hdr.len);

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

// int send_reg_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data)
// {
//   scewl_hdr_t hdr;

//   // pack header
//   hdr.magicS = 'S';
//   hdr.magicC = 'C';
//   hdr.src_id = src_id;
//   hdr.tgt_id = tgt_id;
//   hdr.len = len;

//   // send header
//   intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

//   // send body
//   intf_write(intf, data, len);

//   return SCEWL_OK;
// }

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
#else
  return send_msg(CPU_INTF, src_id, SCEWL_ID, len, data);
#endif
}

int handle_scewl_send(char *data, scewl_id_t tgt_id, uint16_t len)
{
#ifdef MSG_CRYPTO
  return send_enc_msg(RAD_INTF, SCEWL_ID, tgt_id, len, data);
#else
  return send_msg(RAD_INTF, SCEWL_ID, tgt_id, len, data);
#endif
}

int handle_brdcst_recv(char *data, scewl_id_t src_id, uint16_t len)
{
#ifdef MSG_CRYPTO
  return send_auth_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data);
#else
  return send_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data);
#endif
}

int handle_brdcst_send(char *data, uint16_t len)
{
#ifdef MSG_CRYPTO
  return send_enc_msg(RAD_INTF, SCEWL_ID, SCEWL_BRDCST_ID, len, data);
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
  scewl_id_t src_id, tgt_id;
  int status, len;

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_REG;

// send registration
#ifdef REG_CRYPTO
  status = send_enc_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
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
#ifdef REG_CRYPTO
  status = send_reg_msg(CPU_INTF, src_id, tgt_id, len, (char *)&msg);
#else
  status = send_msg(CPU_INTF, src_id, tgt_id, len, (char *)&msg);
#endif
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
#ifdef REG_CRYPTO
  status = send_enc_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
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
