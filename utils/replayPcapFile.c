/*
 *  Copyright (C) 2009 Luca Deri <deri@ntop.org>
 *
 *  			http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>

#ifndef DLT_ANY
#define DLT_ANY 113
#endif

pcap_t *in_pcap_file;
int verbose = 0;
uint packet_id = 0, count = (uint)-1;
struct sockaddr_in client_addr;
int sock, datalink;

/* ************************************* */

static void help() {
  printf("replayPcapFile [-v] [-c <count>] -o <host>:<port> -i <file>.pcap [-f <filter>]\n");
  printf("   -c <count>       | Send up to <count> packets\n");
  printf("   -o <host>:<port> | Collector host where flows will be sent\n");
  printf("   -i <pcap>        | File to be sent\n");
  printf("   -f <BPF filter>  | BPF filter to be applied to the pcap file\n");
  printf("   -v               | Verbose\n");
  printf("\n");
  printf("Send the flows from the specified pcap file to the remote \n");
  printf("netflow collector. This is a debug tool!\n");

  exit(0);
}

/* ************************************* */

void processPacket(u_char *_deviceId,
		   const struct pcap_pkthdr *h,
		   const u_char *p) {
  ssize_t rc;
  int shift = datalink == DLT_ANY ? 44 : 42;
  int len = h->caplen-shift;

  packet_id++;

  if(packet_id > count) exit(0);
  if(len <= 0)          return;
  
  rc = sendto(sock, &p[shift], len, 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
  if(verbose) printf("Sending packet %d [len=%d]: %s\n", packet_id, len, (rc == len) ? "OK" : "Error");
}

/* ************************************* */

int main(int argc, char* argv[]) {
  char *in_file = NULL, errbuf[256], c;
  char *host, *port, *netFilter = NULL /* "udp and port 2055" */;
  struct hostent *h;
  struct bpf_program fcode;
  struct in_addr netmask;

  memset(&client_addr, 0, sizeof(client_addr));

  while((c = getopt(argc, argv, "c:f:i:o:v")) != -1) {
    switch(c) {
    case 'c':
      count = atoi(optarg);
      break;
    case 'f':
      netFilter = strdup(optarg);
      break;
    case 'i':
      in_file = strdup(optarg);
      break;
    case 'o':
      host = optarg;
      port = strchr(host, ':');
      if(port) {
	port[0] = '\0';
	port++;
      } else {
	help();
	return(-1);
      }

      if(!(h = gethostbyname(host))) {
	printf("[ERROR] Unknown host '%s'\n", host);
	return(-1);
      } else {
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = (*(struct in_addr *)h->h_addr_list[0]).s_addr;
	client_addr.sin_port = htons(atoi(port));
	printf("Sending flows towards %s:%d\n", host, atoi(port));
      }
      break;
    case 'v':
      verbose = 1;
      break;
    }
  }

  if((in_file == NULL) || (client_addr.sin_family == 0)) {
    help();
    return(-1);
  }

  in_pcap_file = pcap_open_offline(in_file, errbuf);

  if(in_pcap_file == NULL) {
    printf("[ERROR] pcap_dump_open[%s]: %s", in_file, errbuf);
    return(-1);
  }

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if(sock < 0) {
    printf("[ERROR] Unable to create UDP socket");
    return(-1);
  }

  if(netFilter != NULL) {
    if((pcap_compile(in_pcap_file, &fcode, netFilter, 1, netmask.s_addr) < 0)
       || (pcap_setfilter(in_pcap_file, &fcode) < 0)) {
      printf("[ERROR] Unable to set filter %s. Filter ignored.\n",
	     netFilter);
      return(-1);
    } else
      printf("Set input pcap filter '%s'\n", netFilter);
  }

  datalink = pcap_datalink(in_pcap_file);

  pcap_loop(in_pcap_file, -1, processPacket, NULL);
  pcap_close(in_pcap_file);

  return(0);
}
