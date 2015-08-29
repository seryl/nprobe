#include <pcap.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


pcap_t *in_pcap;
int sockfd, num_pkts, datalink, pkts_sent = 0;
struct sockaddr_in sockIn;

/* ************************************* */

void help(void) {
  printf("sendPcap <file>.pcap <port> [<num pkts>]\n");
  _exit(0);
}

/* ************************************* */

void processPacket(u_char *_deviceId,
		   const struct pcap_pkthdr *h,
		   const u_char *p) {
  u_int len = sizeof(sockIn);
  int offset;
  u_int toSend;
  int rc;

  if(datalink == DLT_EN10MB) {
    if((p[12] == 0x08) && (p[13] == 0x00))
      offset = 42;
    else
      offset = 62;
  } else
    offset = 44;

  toSend = h->len - offset;

  if(toSend < 40) return;

  // sleep(1);

  rc = sendto(sockfd, &p[offset], toSend, 0, 
	      (struct sockaddr *)&sockIn, len);

  pkts_sent++;
  printf("Sent %d/%d [offset=%d]\n",
	 rc, toSend, offset);

  if(num_pkts > 0) {
    if(num_pkts == 1)
      exit(0);
    else
      num_pkts--;
  }
}

/* ************************************* */

int main(int argc, char* argv[]) {
  char *in_file = NULL, errbuf[256];
  int port;

  if(argc < 3)
    help();  

  in_file = argv[1];
  port = atoi(argv[2]);

  if(argc == 4)
    num_pkts = atoi(argv[3]);
  else
    num_pkts = 0;

  if((in_file == NULL) || (port == 0))
    help();

  in_pcap = pcap_open_offline(in_file, errbuf);

  if(in_pcap == NULL) {
    printf("pcap_open: %s\n", errbuf);
    return(-1);
  }

  datalink = pcap_datalink(in_pcap);  

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if(sockfd < 0) {
    printf("socket() error %d\n", errno);
    return(-1);
  }

  sockIn.sin_family      = AF_INET;
  sockIn.sin_port        = (int)htons(port);
  sockIn.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
  //sockIn.sin_addr.s_addr = inet_addr("195.113.231.131");
  //sockIn.sin_addr.s_addr = inet_addr("192.168.1.80");

  pcap_loop(in_pcap, -1, processPacket, NULL);
  pcap_close(in_pcap);
  socket(AF_INET, SOCK_DGRAM, 0);

  printf("Sent %u packets\n", pkts_sent);
  return(0);
}
