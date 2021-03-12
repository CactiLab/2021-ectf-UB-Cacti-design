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

int main(void) {
  scewl_id_t src_id, tgt_id;
  uint16_t len;
  scewl_id_t fw_SED;
  char data[BUF_SZ];
  char *command = NULL, *cmd = NULL, *arg1 = NULL, *arg2 = NULL;
  // open log file
  FILE *log = stderr;
  // NOTE: you can write to a file inside the Docker container instead:
  // FILE *log = fopen("cpu.log", "a");

  // initialize SCEWL
  scewl_init();

  // register
  if (scewl_register() != SCEWL_OK) {
    fprintf(log, "brdcst_SED: BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK) {
      fprintf(log, "brdcst_SED: BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK) {
      fprintf(log, "brdcst_SED: BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }
  sleep(2);
  int i = 0;
  fw_SED = 0;
  while (i< 10) { 
    
    arg2 = "test sending";
    #ifdef debug_message
    //fprintf(log, "Debug info.\n");
    //scewl_send(SCEWL_FAA_ID, sizeof("debug info"), "debug info");
    //fprintf(log, "No issue in scwel command\n");
    //scewl_send(SCEWL_FAA_ID,sizeof(cmd),cmd);
    //scewl_send(SCEWL_FAA_ID,sizeof(arg1),arg1);
    //scewl_send(SCEWL_FAA_ID,13,arg2);
    #endif
    scewl_send(fw_SED, 13, arg2);

    // receive response (block until response received)
    fprintf(log, "brdcst_SED: Waiting for response...\n");
    scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

    // check if response matches
    if (!strcmp(arg2, data)) {
      // decode and print flag
      fprintf(log, "brdcst_SED: Received the ecoho messeage correctly!!!\n");
    } else {
      fprintf(log, "brdcst_SED: Bad response!\n");
    }
    i ++;
  }
  // deregister
  fprintf(log, "brdcst_SED: Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "brdcst_SED: BAD DEREGISTRATION!\n");
  }
  fprintf(log, "brdcst_SED: Exiting...\n");
}
