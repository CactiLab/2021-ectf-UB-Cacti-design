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

#define debug_message 1

/*void parse_input(char *input, char **cmd, char **arg1, char **arg2) {
    *cmd = strtok(input, " \r\n");
    *arg1 = strtok(NULL, " \r\n");
    *arg2 = strtok(NULL, " \r\n");
}*/

int main(void)
{
  scewl_id_t src_id, tgt_id;
  uint16_t len;
  scewl_id_t fw_SED;
  char data[BUF_SZ];
  char *command = NULL, *cmd = NULL, *arg1 = NULL, *arg2 = NULL;
  // open log file
  FILE *log = stderr;
  // NOTE: you can write to a file inside the Docker container instead:
  // FILE *log = fopen("cpu.log", "a");
  char *msg = "test sending1";
  int i;

  // initialize SCEWL
  scewl_init();

  // register1
  if (scewl_register() != SCEWL_OK)
  {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK)
    {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK)
    {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }
  i = 0;
  fw_SED = 0;
  while (i < 10)
  {
#ifdef debug_message
#endif
    scewl_send(fw_SED, 14, msg);

    // receive response (block until response received)
    fprintf(log, "Waiting for response...\n");
    scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

    // check if response matches
    if (!strcmp(msg, data))
    {
      // decode and print flag
      fprintf(log, "Received correct response!!!\n");
    }
    else
    {
      fprintf(log, "Bad response!\n");
    }
    i++;
  }
  // deregister1
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK)
  {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");

  // register2
  if (scewl_register() != SCEWL_OK)
  {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK)
    {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK)
    {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }
  i = 0;
  fw_SED = 0;
  while (i < 10)
  {
#ifdef debug_message
#endif
    scewl_send(fw_SED, 14, msg);

    // receive response (block until response received)
    fprintf(log, "Waiting for response...\n");
    scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

    // check if response matches
    if (!strcmp(msg, data))
    {
      // decode and print flag
      fprintf(log, "Received correct response!!!\n");
    }
    else
    {
      fprintf(log, "Bad response!\n");
    }
    i++;
  }
  // deregister2
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK)
  {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");

  // register3
  if (scewl_register() != SCEWL_OK)
  {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK)
    {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK)
    {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }
  i = 0;
  fw_SED = 0;
  while (i < 10)
  {
#ifdef debug_message
#endif
    scewl_send(fw_SED, 14, msg);

    // receive response (block until response received)
    fprintf(log, "Waiting for response...\n");
    scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

    // check if response matches
    if (!strcmp(msg, data))
    {
      // decode and print flag
      fprintf(log, "Received correct response!!!\n");
    }
    else
    {
      fprintf(log, "Bad response!\n");
    }
    i++;
  }
  // deregister3
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK)
  {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");

  // register
  if (scewl_register() != SCEWL_OK)
  {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK)
    {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK)
    {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }
  i = 0;
  fw_SED = 0;
  while (i < 10)
  {
#ifdef debug_message
#endif
    scewl_send(fw_SED, 14, msg);

    // receive response (block until response received)
    fprintf(log, "Waiting for response...\n");
    scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

    // check if response matches
    if (!strcmp(msg, data))
    {
      // decode and print flag
      fprintf(log, "Received correct response!!!\n");
    }
    else
    {
      fprintf(log, "Bad response!\n");
    }
    i++;
  }
  // deregister4
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK)
  {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");

  // register
  if (scewl_register() != SCEWL_OK)
  {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK)
    {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK)
    {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }
  i = 0;
  fw_SED = 0;
  while (i < 10)
  {
#ifdef debug_message
#endif
    scewl_send(fw_SED, 14, msg);

    // receive response (block until response received)
    fprintf(log, "Waiting for response...\n");
    scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

    // check if response matches
    if (!strcmp(msg, data))
    {
      // decode and print flag
      fprintf(log, "Received correct response!!!\n");
    }
    else
    {
      fprintf(log, "Bad response!\n");
    }
    i++;
  }
  // deregister4
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK)
  {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");

  // deregister5
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK)
  {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");

  // deregister6
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK)
  {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");

  // deregister7
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK)
  {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");
}
