/*
 * 2021 Collegiate eCTF
 * Example echo client
 * Ben Janis
 *
 * (c) 2021 The MITRE Corporation
 *
 * This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 */

#include "scewl_bus_driver/scewl_bus.h"

#include <stdio.h>
#include <string.h>

#define BUF_SZ 0x2000

// SCEWL_ID and TGT_ID need to be defined at compile
#ifndef TGT_ID
#warning TGT_ID not defined, using bad default of 0xffff
#define TGT_ID ((scewl_id_t)0xffff)
#endif

int main(void) {
  scewl_id_t src_id, tgt_id;
  uint16_t len;
  int i = 0;
  char *msg = "hello world1!";
  char data[BUF_SZ];

  // open log file
  FILE *log = stderr;
  // NOTE: you can write to a file inside the Docker container instead:
  // FILE *log = fopen("cpu.log", "a");

  // initialize SCEWL
  scewl_init();

  // register
  if (scewl_register() != SCEWL_OK) {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK) {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK) {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }

  fprintf(log, "Sending hello...\n");
  scewl_send(TGT_ID, 14, msg);

  // receive response (block until response received)
  fprintf(log, "Waiting for response...\n");
  scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

  while (i< 10) { 
    
    scewl_send(TGT_ID, 13, msg);

    // receive response (block until response received)
    fprintf(log, "Waiting for response...\n");
    scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

    fprintf(log, "receive response...\n");

    i ++;
  }
  i = 0;

  // deregister
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");

  // register2
  if (scewl_register() != SCEWL_OK) {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK) {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK) {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }

  fprintf(log, "Sending hello...\n");
  scewl_send(TGT_ID, 14, msg);

  // receive response (block until response received)
  fprintf(log, "Waiting for response...\n");
  scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

  while (i< 10) { 
    
    scewl_send(TGT_ID, 13, msg);

    // receive response (block until response received)
    fprintf(log, "Waiting for response...\n");
    scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

    fprintf(log, "receive response...\n");

    i ++;
  }
  i = 0;

  // deregister2
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");

  // register3
  if (scewl_register() != SCEWL_OK) {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK) {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK) {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }

  fprintf(log, "Sending hello...\n");
  scewl_send(TGT_ID, 14, msg);

  // receive response (block until response received)
  fprintf(log, "Waiting for response...\n");
  scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

  while (i< 10) { 
    
    scewl_send(TGT_ID, 13, msg);

    // receive response (block until response received)
    fprintf(log, "Waiting for response...\n");
    scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

    fprintf(log, "receive response...\n");

    i ++;
  }
  i = 0;

  // deregister3
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");

  // deregister4
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");

    // deregister5
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");

}
