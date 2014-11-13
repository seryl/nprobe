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
u_int low_id, high_id, pkt_id = 0;

/* ************************************* */

void help(void) {
  printf("extractPcap <in file>.pcap <out file>.pcap <low packet id> <high packet id>\n");
  _exit(0);
}

/* ************************************* */

void processPacket(u_char *_deviceId,
		   const struct pcap_pkthdr *h,
		   const u_char *p) {
  pkt_id++;

  if(low_id <= pkt_id)
    pcap_dump((u_char*)out_pcap, h, p);

  if(pkt_id > high_id) {
    pcap_close(in_pcap);
    pcap_dump_close(out_pcap);

    exit(0);
  }
}

/* ************************************* */

int main(int argc, char* argv[]) {
  char *in_file = NULL, *out_file = NULL, errbuf[256];

  if(argc < 5)
    help();  

  in_file  = argv[1];
  out_file = argv[2];
  low_id   = atoi(argv[3]);
  high_id  = atoi(argv[4]);

  if((in_file == NULL) || (out_file == NULL) || (high_id < low_id))
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
