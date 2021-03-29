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
#include <stdlib.h>
#include <unistd.h>
#define BUF_SZ 0x4000

#define debug_message 1

/*void parse_input(char *input, char **cmd, char **arg1, char **arg2) {
    *cmd = strtok(input, " \r\n");
    *arg1 = strtok(NULL, " \r\n");
    *arg2 = strtok(NULL, " \r\n");
}*/
 
char data[BUF_SZ];
char *g_msg_tobe_send = ": test sending boradcast test sending boradcast test sending boradcast test sending boradcast test sending boradcast test sending boradcast test sending boradcast";
char g_send_buffer[200] = {0};
char g_msg_tobe_recv[200] = {0};

int main(void)
{
  scewl_id_t src_id, tgt_id;
  uint16_t len;
  scewl_id_t fw_SED;

  char *command = NULL, *cmd = NULL, *arg1 = NULL, *arg2 = NULL;
 
  // open log file
  FILE *log = stderr;
  // NOTE: you can write to a file inside the Docker container instead:
  // FILE *log = fopen("cpu.log", "a");

  // initialize SCEWL
  scewl_init();

  // register
  if (scewl_register() != SCEWL_OK)
  {
    fprintf(log, "brdcst_SED %d: BAD REGISTRATION! Reregistering...\n", SCEWL_ID);

    if (scewl_deregister() != SCEWL_OK)
    {
      fprintf(log, "brdcst_SED %d: BAD DEREGISTRATION!\n", SCEWL_ID);
      return 1;
    }

    if (scewl_register() != SCEWL_OK)
    {
      fprintf(log, "brdcst_SED161: BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }

  //sleep(2);
  int i = 0;
  fw_SED = 0;
  int limit = 8;

  int ret = scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

  if (ret == -1) {
    fprintf(log, "%d Received a wrong length from %d\n", SCEWL_ID, src_id);
    return 1;
  }
  	

  if (src_id == SCEWL_FAA_ID && !strcmp("start", data))
  {
    fprintf(log, "SED %d start broadcasting and receiving\n\n", SCEWL_ID);

    sprintf(g_send_buffer, "%d", SCEWL_ID);
    strcat(g_send_buffer, g_msg_tobe_send);    

    while (i < limit)
    {
      //sleep(1);
      scewl_send(fw_SED, strlen(g_send_buffer), g_send_buffer);
      i++;
    }

    i = 0; 

    while (i < limit)
    {
      // receive response (block until response received)
      //fprintf(log, "%d: Waiting for response...\n", SCEWL_ID);
      ret = scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);
      
      if (ret == -1) {
        fprintf(log, "%d Received a wrong length from %d \n", SCEWL_ID, src_id);
        return 1;
      }
  		  
  	  //else
    	//fprintf(log, "%d received %d bytes from %d\n\n", SCEWL_ID, ret, src_id); 

      //fprintf(log, "brdcst_SED161: Received response for source: %d \n", src_id);
      //fprintf(log, "%s", data);
      //fprintf(log, "\n\n");

      sprintf(g_msg_tobe_recv, "%d", src_id);
      strcat(g_msg_tobe_recv, g_msg_tobe_send);
 
      if (!strncmp(g_msg_tobe_recv, data, strlen(data)))
      {
        fprintf(log, "%d received #%d message from %d OK!\n\n", SCEWL_ID, i, src_id);
      }
      else
      {
        fprintf(log, "%d received #%d message from %d BAD!\n", SCEWL_ID, i, src_id);
        fprintf(log, "Received data: \n%s\n\n", data);
      }
      i++;
    }
  }
  // deregister
  fprintf(log, "%d: Deregistering...\n", SCEWL_ID);
  if (scewl_deregister() != SCEWL_OK)
  {
    fprintf(log, "%d: BAD DEREGISTRATION!\n", SCEWL_ID);
  }

  fprintf(log, "%d: Exiting...\n", SCEWL_ID);
}
