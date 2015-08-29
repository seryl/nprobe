#include <pcap.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


pcap_t *in_pcap;
pcap_dumper_t *out_pcap;

/* ************************************* */

void help(void) {
  printf("shiftPcap <in file>.pcap <out file>.pcap\n");
  _exit(0);
}

/* ************************************* */

void processPacket(u_char *_deviceId,
		   const struct pcap_pkthdr *_h,
		   const u_char *p) {
  struct pcap_pkthdr *h = (struct pcap_pkthdr*)_h;
  int shift = 106;

  if(h->caplen < shift) return;

  h->caplen -= shift, h->len -= shift, p = &p[shift];
  pcap_dump((u_char*)out_pcap, h, p);
}

/* ************************************* */

int main(int argc, char* argv[]) {
  char *in_file = NULL, *out_file = NULL, errbuf[256];

  if(argc < 3)
    help();  

  in_file  = argv[1];
  out_file = argv[2];

  if((in_file == NULL) || (out_file == NULL))
    help();

  in_pcap = pcap_open_offline(in_file, errbuf);
  
  if(in_pcap == NULL) {
    printf("pcap_open: %s\n", errbuf);
    return(-1);
  }

  out_pcap = pcap_dump_open(pcap_open_dead(1 /* linktype */, 1500 /* snaplen */), out_file);
  
  if(out_pcap == NULL) {
    printf("pcap_dump_open(%s): %s\n", out_file, errbuf);
    return(-1);
  }


  pcap_loop(in_pcap, -1, processPacket, NULL);
  pcap_close(in_pcap);
  pcap_dump_close(out_pcap);

  return(0);
}
