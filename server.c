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

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/uip.h"
#include "net/rpl/rpl.h"

#include "net/netstack.h"
#include "dev/button-sensor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "dev/watchdog.h"
#include "ibihop.h"
#include "nano-ecc.h"

#define DEBUG DEBUG_NONE
#include "net/ip/uip-debug.h"

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

#define UDP_EXAMPLE_ID  190

#define PKC { \
    {0xEE, 0xB9, 0x10, 0x51, 0x7B, 0xBD, 0xF3, 0x7A, 0x68, 0x48, 0x50, 0xF7, 0xD5, 0xAF, 0xD5, 0x4E, 0x6F, 0x9D, 0xA6, 0xFE, 0x83, 0x50, 0x6C, 0x73}, \
    {0x4A, 0x91, 0xDD, 0x1F, 0x30, 0x05, 0x1D, 0x88, 0xB7, 0x76, 0x3D, 0xE1, 0x9F, 0x4E, 0x8A, 0x5F, 0xA9, 0xE4, 0x80, 0x12, 0xD5, 0x4D, 0x8B, 0xDD}}

#define SKS {0x61, 0xAC, 0x91, 0xAE, 0xBC, 0xF3, 0x33, 0x86, 0x2C, 0xEF, 0xBB, 0x11, 0x01, 0x23, 0xD7, 0x1B, 0xB9, 0x4A, 0xBE, 0xAC, 0x9B, 0xF5, 0xBE, 0x46}

static struct uip_udp_conn *server_conn;


static EccPoint E;
static EccPoint R;
static EccPoint pk_c = PKC;	//Client's public key
static uint8_t sk_s[NUM_ECC_DIGITS] = SKS;	//Server's private key
static uint8_t e[NUM_ECC_DIGITS],e_inv[NUM_ECC_DIGITS]; 
static uint8_t f[NUM_ECC_DIGITS];
static uint8_t s[NUM_ECC_DIGITS];
static clock_time_t start_time;

PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
    char *appdata;
    char buf[50];
    unsigned i;
    buf[0] = 0;

    if(uip_newdata()) {
    	appdata = (char *)uip_appdata;
    	appdata[uip_datalen()] = 0;
    	PRINTF("SERVER: DATA recv '%s' from ", appdata);
    	PRINTF("%d",
        UIP_IP_BUF->srcipaddr.u8[sizeof(UIP_IP_BUF->srcipaddr.u8) - 1]);
    	PRINTF("\n");

    if ( strncmp(appdata, "hello", 5) == 0 )	/*Recieved tag's request and send a challenge to tag.*/
    {
//
	start_time = clock_time();
    	IBIHOP_Pass1(&E, e, e_inv);	/*pass 1: reader sends challenge to tag*/
	printf("P1: Completion time %lu / %lu\n", (unsigned long)clock_time() - start_time, CLOCK_SECOND); /* Print the time consumption (number of ticks) of IBIHOP_Pass1(). 1 clock second = 128 ticks */
    	PRINTF("SERVER: DATA sending reply\n");
    
    	buf[0] = '1';				/*Reader's challenge message*/
    	for(i = 0; i < NUM_ECC_DIGITS; ++i)
    	{
        	buf[i+1] = E.x[i];
		buf[i+NUM_ECC_DIGITS+1] = E.y[i];
    	}
    	buf[2*NUM_ECC_DIGITS+1] = 0;
    }
    else if ( strncmp(appdata, "2", 1) == 0 )	/*Recived tag's challenge and response an authentication message.*/
    {
       for(i = 0; i < NUM_ECC_DIGITS; ++i)
    	{
            R.x[i] = (uint8_t)appdata[i+1];
	    R.y[i] = (uint8_t)appdata[i+NUM_ECC_DIGITS+1];
    	}

//
	start_time = clock_time();
    	IBIHOP_Pass3(f, &R, e, sk_s);	/*pass 3: reader replies tag by f.*/
	printf("P3: Completion time %lu / %lu\n", (unsigned long)clock_time() - start_time, CLOCK_SECOND);
    	PRINTF("SERVER: Reply f to tag.\n");
    
    
    	buf[0] = '3';				/*Authentication message flag.*/
    	for(i = 0; i < NUM_ECC_DIGITS; ++i)
    	{
            buf[i+1] = f[i];
    	}
	buf[NUM_ECC_DIGITS+1] = 0;
    }
    else if( strncmp(appdata, "4", 1) == 0 )	/*Tag confirmed reader is valid.*/
    {
    	printf("Reader authentication done!\n");

    	for (i = 0; i < NUM_ECC_DIGITS; ++i){
	    s[i] = (uint8_t)appdata[i+1];
    	}

	start_time = clock_time();
	if (IBIHOP_TagVerf(R, e_inv, s, pk_c) != 0)		/*Tag is authenticated.*/
	{
	    printf("Tag is invalid!\n");
    	}
    	else
    	{
	    printf("TagVerf: Completion time %lu / %lu\n", (unsigned long)clock_time() - start_time, CLOCK_SECOND);
	    buf[0] = '5';				
	    buf[1] = 0;
    	}
    }
    else if(strncmp(appdata, "8", 1) == 0)
    {
	PRINTF("Reader authentication failed!!\n");
    }
    else
    {
	PRINTF("Authentication failed!\n");
    }

    if(strlen(buf) > 0)	/*Send message to tag.*/
    {
	uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
	uip_udp_packet_send(server_conn, buf, sizeof(buf));
	uip_create_unspecified(&server_conn->ripaddr);
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Server IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(state == ADDR_TENTATIVE || state == ADDR_PREFERRED) {
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
PROCESS_THREAD(udp_server_process, ev, data)
{
  uip_ipaddr_t ipaddr;
  struct uip_ds6_addr *root_if;

  PROCESS_BEGIN();

  PROCESS_PAUSE();

  SENSORS_ACTIVATE(button_sensor);

  PRINTF("UDP server started\n");
watchdog_stop();
#if UIP_CONF_ROUTER
/* The choice of server address determines its 6LoPAN header compression.
 * Obviously the choice made here must also be selected in udp-client.c.
 *
 * For correct Wireshark decoding using a sniffer, add the /64 prefix to the 6LowPAN protocol preferences,
 * e.g. set Context 0 to aaaa::.  At present Wireshark copies Context/128 and then overwrites it.
 * (Setting Context 0 to aaaa::1111:2222:3333:4444 will report a 16 bit compressed address of aaaa::1111:22ff:fe33:xxxx)
 * Note Wireshark's IPCMV6 checksum verification depends on the correct uncompressed addresses.
 */
 
#if 0
/* Mode 1 - 64 bits inline */
   uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
#elif 1
/* Mode 2 - 16 bits inline */
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#else
/* Mode 3 - derived from link local (MAC) address */
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
#endif

  uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);
  root_if = uip_ds6_addr_lookup(&ipaddr);
  if(root_if != NULL) {
    rpl_dag_t *dag;
    dag = rpl_set_root(RPL_DEFAULT_INSTANCE,(uip_ip6addr_t *)&ipaddr);
    uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
    rpl_set_prefix(dag, &ipaddr, 64);
    PRINTF("created a new RPL dag\n");
  } else {
    PRINTF("failed to create a new RPL DAG\n");
  }
#endif /* UIP_CONF_ROUTER */
  
  print_local_addresses();

  /* The data sink runs with a 100% duty cycle in order to ensure high 
     packet reception rates. */
  NETSTACK_MAC.off(1);

  server_conn = udp_new(NULL, UIP_HTONS(UDP_CLIENT_PORT), NULL);
  if(server_conn == NULL) {
    PRINTF("No UDP connection available, exiting the process!\n");
    PROCESS_EXIT();
  }
  udp_bind(server_conn, UIP_HTONS(UDP_SERVER_PORT));

  PRINTF("Created a server connection with remote address ");
  PRINT6ADDR(&server_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n", UIP_HTONS(server_conn->lport),
         UIP_HTONS(server_conn->rport));

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    } else if (ev == sensors_event && data == &button_sensor) {
      PRINTF("Initiaing global repair\n");
      rpl_repair_root(RPL_DEFAULT_INSTANCE);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
