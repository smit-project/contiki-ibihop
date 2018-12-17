/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */
/*

This is the implementation file for the client/tag side of IBIHOP protocol.
It can intercat with a server and return the resutlt of IBIHOP authentication.
*/

#include "contiki.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ip/uip-udp-packet.h"
#include "sys/ctimer.h"
#include "ibihop.h"
#include "nano-ecc.h"
//#include "ecdh.h"
//#include "ecdsa.h"

#ifdef WITH_COMPOWER
#include "powertrace.h"
#endif
#include <stdio.h>
#include <string.h>
#include "dev/watchdog.h"

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#define UDP_EXAMPLE_ID  190

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#ifndef PERIOD
#define PERIOD 500
#endif

#define START_INTERVAL		(15 * CLOCK_SECOND)
#define SEND_INTERVAL		(PERIOD * CLOCK_SECOND)
#define SEND_TIME		(random_rand() % (SEND_INTERVAL))
#define MAX_PAYLOAD_LEN		30

#define PKS { \
    {0x58, 0x5B, 0x01, 0xC2, 0x6B, 0xEA, 0xF3, 0xD1, 0x81, 0x09, 0xA9, 0x47, 0x54, 0xEC, 0x0B, 0x44, 0x18, 0x9C, 0xE2, 0xE1, 0xF4, 0x76, 0x2E, 0x90}, \
    {0x0F, 0x34, 0x16, 0xE8, 0xB9, 0xC0, 0xE1, 0x9F, 0x11, 0x41, 0x97, 0x84, 0xAD, 0xFC, 0xE1, 0xB6, 0x42, 0x03, 0x62, 0x79, 0x37, 0x86, 0x22, 0x15}}

#define SKC {0x3F, 0xFC, 0xED, 0xF0, 0xFC, 0x76, 0x8E, 0x06, 0x93, 0x15, 0x0B, 0x10, 0xF5, 0x8E, 0xFA, 0xCD, 0xF8, 0x62, 0xB8, 0x37, 0xDF, 0x77, 0x1D, 0x73}



static EccPoint E;
static EccPoint R;
static EccPoint pk_s = PKS;	//Server's public keys.

static uint8_t r[NUM_ECC_DIGITS];
static uint8_t f[NUM_ECC_DIGITS];
static uint8_t s[NUM_ECC_DIGITS];
static uint8_t sk_c[NUM_ECC_DIGITS] = SKC; //Client's private keys

static struct uip_udp_conn *client_conn;
static uip_ipaddr_t server_ipaddr;
static clock_time_t start_time;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
    char *str = NULL;
    char buf[50];
    unsigned i;
    buf[0] = 0;
    if(uip_newdata()) {
	str = (char*)uip_appdata;
	/*Recived reader's challenge and send nonce R to reader*/
     	if (strncmp(uip_appdata,"1",1) == 0)	
    	{
    	    for(i = 0; i < NUM_ECC_DIGITS; ++i)
    	    {
                E.x[i] = (uint8_t)str[i+1];
	        E.y[i] = (uint8_t)str[i+NUM_ECC_DIGITS+1];
    	    }
	    start_time = clock_time();

	    /*pass 2: tag responds reader's challenge*/
            IBIHOP_Pass2(&R, r);	
	    printf("P2: Completion time %lu / %lu\n", (unsigned long)clock_time() - start_time, CLOCK_SECOND);	/* Print the time consumption (number of ticks) of IBIHOP_Pass2(). 1 clock second = 128 ticks */
            buf[0] = '2';

    	    for(i = 0; i < NUM_ECC_DIGITS; ++i)
    	    {
	        buf[i+1] = R.x[i];
	   	buf[i+NUM_ECC_DIGITS+1] = R.y[i];
    	    }
            buf[2*NUM_ECC_DIGITS+1] = 0;

	    uip_udp_packet_sendto(client_conn, buf, sizeof(buf), &server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));
        }
    else if(strncmp(uip_appdata,"3",1) == 0)
    {
	for(i = 0; i < NUM_ECC_DIGITS; ++i)
	{
	    f[i] = (uint8_t)str[i+1];
	}
	start_time = clock_time();

	/* Run pass4 and check the validity of reader.*/
	if (IBIHOP_Pass4(s, &pk_s, &E, f, r, sk_c) != 0)	
	{   /* Reader authentication failed. */
	    buf[0] = '8';
	    buf[1] = 0;
	    PRINTF("Reader is invalid!\n");
	}
	else{/*Reader/server authentication succeed and send tag's response.*/
	   printf("P4: Completion time %lu / %lu\n", (unsigned long)clock_time() - start_time, CLOCK_SECOND);
	   buf[0] = '4';
           for(i = 0; i < NUM_ECC_DIGITS; ++i)
    	   {
               buf[i+1] = s[i];
    	   }
               buf[NUM_ECC_DIGITS+1] = 0;
	}

	PRINTF("Reader is authenticated!\n");
	uip_udp_packet_sendto(client_conn, buf, sizeof(buf), &server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));
    }
    else if(strncmp(uip_appdata,"5",1) == 0)	/*Reader confirmed tag is valid*/
    {
	PRINTF("OK! Mutual authentication succeed!\n");	
    }
    else
    {
	PRINTF("Authentication failed.\n");
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
send_packet(void *ptr)
{
    char buf[] = "hello";

    uip_udp_packet_sendto(client_conn, buf, strlen(buf),
                        &server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Client IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
      /* hack to make address "final" */
      if (state == ADDR_TENTATIVE) {
	uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
set_global_address(void)
{
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

// uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0x0, 0x0, 0x0, 0x1);

/* The choice of server address determines its 6LoPAN header compression.
 * (Our address will be compressed Mode 3 since it is derived from our link-local address)
 * Obviously the choice made here must also be selected in udp-server.c.
 *
 * For correct Wireshark decoding using a sniffer, add the /64 prefix to the 6LowPAN protocol preferences,
 * e.g. set Context 0 to aaaa::.  At present Wireshark copies Context/128 and then overwrites it.
 * (Setting Context 0 to aaaa::1111:2222:3333:4444 will report a 16 bit compressed address of aaaa::1111:22ff:fe33:xxxx)
 *
 * Note the IPCMV6 checksum verification depends on the correct uncompressed addresses.
 */
 
#if 0
/* Mode 1 - 64 bits inline */
//   uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
#elif 1
/* Mode 2 - 16 bits inline */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#else
/* Mode 3 - derived from server link-local (MAC) address */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0x0250, 0xc2ff, 0xfea8, 0xcd1a); //redbee-econotag
#endif
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic;
  static struct ctimer backoff_timer;
#if WITH_COMPOWER
  static int print = 0;
#endif
char buf[] = "hello";
  PROCESS_BEGIN();

  PROCESS_PAUSE();

  set_global_address();
  
  PRINTF("UDP client process started\n");

  print_local_addresses();
  watchdog_stop();	/*avoid dead lock*/
  /* new connection with remote host */
  client_conn = udp_new(NULL, UIP_HTONS(UDP_SERVER_PORT), NULL); 
  if(client_conn == NULL) {
    PRINTF("No UDP connection available, exiting the process!\n");
    PROCESS_EXIT();
  }
  udp_bind(client_conn, UIP_HTONS(UDP_CLIENT_PORT)); 

  PRINTF("Created a connection with the server ");
  PRINT6ADDR(&client_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
	UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

#if WITH_COMPOWER
  powertrace_sniff(POWERTRACE_ON);
#endif
	
  etimer_set(&periodic, SEND_INTERVAL);

  PROCESS_YIELD();
      
  uip_udp_packet_sendto(client_conn, buf, strlen(buf), &server_ipaddr, UIP_HTONS(UDP_SERVER_PORT)); /*Send hello to reader*/

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }


    if(etimer_expired(&periodic)) {
      etimer_reset(&periodic);
      ctimer_set(&backoff_timer, SEND_TIME, send_packet, NULL);

#if WITH_COMPOWER
      if (print == 0) {
	powertrace_print("#P");
      }
      if (++print == 3) {
	print = 0;
      }
#endif
    
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
