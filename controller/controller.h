/*
 * 2021 Collegiate eCTF
 * SCEWL Bus Controller header
 * Ted Clifford
 *
 * (c) 2021 Cacti Team
 *
 */

#ifndef CONTROLLER_H
#define CONTROLLER_H

#include "interface.h"
#include "lm3s/lm3s_cmsis.h"

#include <stdint.h>
#include <string.h>
//#include <stdio.h>
#include <math.h>
#include <stdbool.h>
#define SCEWL_MAX_DATA_SZ 0x4000
// change this value when want change max SEDs
#define max_sequenced_SEDS 256
// type of a SCEWL ID
typedef uint16_t scewl_id_t;

// SCEWL_ID defined at compile
#ifndef SCEWL_ID
#warning SCEWL_ID not defined, using bad default of 0
#define SCEWL_ID 0
#endif

#define send_str(M) send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, strlen(M), M)
#define BLOCK_SIZE 16
#define CRYPTO_SIZE 16

#define keyLen 32
#define ivLen 12
#define aadLen 0
#define ptLen 16
#define ctLen 16
#define tagLen 16
#define msgHeader 60

/******************************** start example ********************************/
// #define EXAMPLE_AES_GCM 1
// #define CRYPTO_TEST 1
/******************************** end example ********************************/


/******************************** start crypto ********************************/
#define MSG_CRYPTO 1
#define DEBUG_MSG_CRYPTO 1
// #define SQ_DEBUG 1
// #define KEY_CRYPTO 1
// #define RSA_CRYPTO 1
/******************************** end crypto ********************************/

// SCEWL bus channel header
// NOTE: This is the required format to comply with Section 4.6 of the rules
typedef struct scewl_hdr_t
{
  uint8_t magicS; // all messages must start with the magic code "SC"
  uint8_t magicC;
  scewl_id_t tgt_id;
  scewl_id_t src_id;
  uint16_t len;
  /* data follows */
} scewl_hdr_t;

// message format: | scewl_header | AENCpk(ka) | IV | tag | ENC(ka, iva)(header + message) |
// size: keyLen + ivLen + tagLen + crypto_bodyLen = 32 + 12 + 16 + bodyLen = 60 + bodyLen
typedef struct scewl_msg_hdr_t
{
  uint8_t aes_key[keyLen]; // asymmetric encrypted aes key
  uint8_t iv[ivLen];       //
  uint8_t tag[tagLen];
} scewl_msg_hdr_t;

typedef struct scewl_msg_t
{
  uint8_t aes_key[keyLen]; // asymmetric encrypted aes key
  uint8_t iv[ivLen];       //
  uint8_t tag[tagLen];
  uint8_t body[SCEWL_MAX_DATA_SZ];
} scewl_msg_t;

typedef struct scewl_crypto_msg_hdr_t
{
  scewl_id_t tgt_id;
  scewl_id_t src_id;
  uint16_t len;
  uint32_t sq;
} scewl_crypto_msg_hdr_t;

typedef struct scewl_crypto_msg_t
{
  scewl_id_t tgt_id;
  scewl_id_t src_id;
  uint16_t len;
  uint32_t sq;
  uint8_t body[SCEWL_MAX_DATA_SZ];
} scewl_crypto_msg_t;

// sequence number for each SED
typedef struct sequence_num_t
{
  uint32_t sq_send[max_sequenced_SEDS];
  uint32_t sq_receive[max_sequenced_SEDS];
} sequence_num_t;

// registration message
typedef struct scewl_sss_msg_t
{
  scewl_id_t dev_id;
  uint16_t op;
} scewl_sss_msg_t;

typedef struct scewl_sss_crypto_msg_t
{
  uint8_t sig[64]; // signature, same size with the RSA private key. 512 bit
  scewl_id_t dev_id;
  uint16_t op;
} scewl_sss_crypto_msg_t;

// SCEWL status codes
enum scewl_status
{
  SCEWL_ERR = -1,
  SCEWL_OK,
  SCEWL_ALREADY,
  SCEWL_NO_MSG
};

// registration/deregistration options
enum scewl_sss_op_t
{
  SCEWL_SSS_ALREADY = -1,
  SCEWL_SSS_REG,
  SCEWL_SSS_DEREG
};

// reserved SCEWL IDs
enum scewl_ids
{
  SCEWL_BRDCST_ID,
  SCEWL_SSS_ID,
  SCEWL_FAA_ID
};

/*
 * send_enc_msg
 * 
 * Sends a message in the SCEWL pkt format to an interface
 * 
 * Args:
 *   intf - pointer to the physical interface device
 *   src_id - the id of the sending device
 *   tgt_id - the id of the receiving device
 *   len - the length of message
 *   data - pointer to the message
 */
int send_enc_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data);

/*
 * send_auth_msg
 * 
 * Sends a message in the SCEWL pkt format to an interface
 * 
 * Args:
 *   intf - pointer to the physical interface device
 *   src_id - the id of the sending device
 *   tgt_id - the id of the receiving device
 *   len - the length of message
 *   data - pointer to the message
 */
int send_auth_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data);

/*
 * read_msg
 *
 * Gets a message in the SCEWL pkt format from an interface
 *
 * Args:
 *   intf - pointer to the physical interface device
 *   buf - pointer to the message buffer
 *   src_id - pointer to a src_id
 *   tgt_id - pointer to a tgt_id
 *   n - maximum characters to be read into buf
 *   blocking - whether to wait for a message or not
 */
int read_msg(intf_t *intf, char *buf, scewl_id_t *src_id, scewl_id_t *tgt_id,
             size_t n, int blocking);

/*
 * send_msg
 * 
 * Sends a message in the SCEWL pkt format to an interface
 * 
 * Args:
 *   intf - pointer to the physical interface device
 *   src_id - the id of the sending device
 *   tgt_id - the id of the receiving device
 *   len - the length of message
 *   data - pointer to the message
 */
int send_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data);

/*
 * handle_scewl_recv
 * 
 * Interprets a SCEWL tranmission from another SED and sends the message to the CPU
 */
int handle_scewl_recv(char *data, scewl_id_t src_id, uint16_t len);

/*
 * handle_scewl_send
 * 
 * Sends a message to another SED from the CPU
 */
int handle_scewl_send(char *buf, scewl_id_t tgt_id, uint16_t len);

/*
 * handle_brdcst_recv
 * 
 * Interprets a broadcast message from another SED and passes it to the CPU
 */
int handle_brdcst_recv(char *data, scewl_id_t src_id, uint16_t len);

/*
 * handle_brdcst_send
 * 
 * Broadcasts a message from the CPU to SEDS over the antenna
 */
int handle_brdcst_send(char *data, uint16_t len);

/*
 * handle_faa_recv
 * 
 * Receives an FAA message from the antenna and passes it to the CPU
 */
int handle_faa_recv(char *data, uint16_t len);

/*
 * handle_faa_send
 * 
 * Sends an FAA message from the CPU to the antenna
 */
int handle_faa_send(char *data, uint16_t len);

/*
 * handle_registration
 * 
 * Interprets a CPU registration message
 * 
 * args:
 *   op - pointer to the operation message received by the CPU
 */
int handle_registration(char *op);

/*
 * sss_register
 * 
 * Performs a registration with the SSS
 */
int sss_register();

/*
 * sss_deregister
 * 
 * Performs a deregistration with the SSS
 */
int sss_deregister();

/* Handle sequence number checking from*/
bool check_sequence_number(scewl_id_t source_SED, uint32_t received_sq_number);
#endif
