/*
 *  Copyright (C) 2007-10 Luca Deri <deri@ntop.org>
 *
 *  		       http://www.ntop.org/
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

#ifdef HAVE_PF_RING

/* ****************************************************** */

static void processPfringPktHdr(struct pfring_pkthdr *hdr, char *packet) {
  IpAddress src, dst;
  struct in_addr addr;
  int payload_offset = hdr->extended_hdr.parsed_pkt.pkt_detail.offset.eth_offset
    +hdr->extended_hdr.parsed_pkt.pkt_detail.offset.payload_offset;
  int payload_len = (payload_offset > hdr->len) ? 0 : hdr->len - payload_offset;
  struct eth_header ehdr;
  struct pcap_pkthdr h;

  if(readOnlyGlobals.numProcessThreads > 1) pthread_rwlock_wrlock(&readWriteGlobals->statsRwLock);
  readWriteGlobals->accumulateStats.pkts++, readWriteGlobals->accumulateStats.bytes += hdr->len;
  readWriteGlobals->currentPkts++, readWriteGlobals->currentBytes += hdr->len;
  if(readOnlyGlobals.numProcessThreads > 1) pthread_rwlock_unlock(&readWriteGlobals->statsRwLock);

  memcpy(&ehdr.ether_dhost, hdr->extended_hdr.parsed_pkt.dmac, 6);
  memcpy(&ehdr.ether_shost, hdr->extended_hdr.parsed_pkt.smac, 6);
  ehdr.ether_type = hdr->extended_hdr.parsed_pkt.eth_type;

  if(hdr->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4 */) {
    h.len = hdr->len, h.caplen = hdr->caplen;
    h.ts.tv_sec = hdr->ts.tv_sec, h.ts.tv_usec = hdr->ts.tv_usec;

    src.ipVersion = 4, dst.ipVersion = 4;

    addr.s_addr = hdr->extended_hdr.parsed_pkt.ipv4_src;
    if(readOnlyGlobals.ignoreIP || (!isLocalAddress(&addr)))
      src.ipType.ipv4 = 0; /* 0.0.0.0 */
    else
      src.ipType.ipv4 = addr.s_addr;

    addr.s_addr = hdr->extended_hdr.parsed_pkt.ipv4_dst;
    if(readOnlyGlobals.ignoreIP || (!isLocalAddress(&addr)))
      dst.ipType.ipv4 = 0; /* 0.0.0.0 */
    else
      dst.ipType.ipv4 = addr.s_addr;

    queueParsedPkt(hdr->extended_hdr.parsed_pkt.l3_proto, 
		   0 /* numFragments */, 
		   0 /* sampledPacket */, 
		   1 /* numPkts */,
		   hdr->extended_hdr.parsed_pkt.ipv4_tos,
		   (hdr->extended_hdr.parsed_pkt.vlan_id != (u_int16_t)-1) ? hdr->extended_hdr.parsed_pkt.vlan_id : 0, 0,
		   &ehdr,
		   &src, hdr->extended_hdr.parsed_pkt.l4_src_port,
		   &dst, hdr->extended_hdr.parsed_pkt.l4_dst_port,
		   0, NULL, 0, NULL, 0, /* Untunneled info */
		   hdr->len, hdr->extended_hdr.parsed_pkt.tcp.flags, 
		   hdr->extended_hdr.parsed_pkt.tcp.seq_num,
		   0, 0,
		   0, NULL,
		   NO_INTERFACE_INDEX, NO_INTERFACE_INDEX, /* Will be computed later on */
		   &h, (u_char*)packet,
		   payload_offset, payload_len, payload_len, 0,
		   0, 0, 0, 0, 0 /* flow_sender_ip */);
  }
}

/* ****************************************************** */

struct n2disk_metadata_header {
  u_int16_t version;
  u_int16_t metadata_len;
};

struct n2disk_metadata {
  u_int32_t pkt_offset;
  struct pfring_pkthdr metadata;
};

static void* readMetadataPkts(void) {
  struct n2disk_metadata_header metadata_hdr;
  struct n2disk_metadata entry;
  int n;

  n = fread((void*)&metadata_hdr, 1, sizeof(metadata_hdr), readOnlyGlobals.metadata_fd);
  if(n != sizeof(metadata_hdr)) {
    traceEvent(TRACE_WARNING, "Metadatda file is too short");
    return(NULL);
  }

  while(fread((void*)&entry, 1, sizeof(entry), readOnlyGlobals.metadata_fd) == sizeof(entry)) {
    processPfringPktHdr(&entry.metadata, NULL);    
  }

  return(NULL);
}

/* ****************************************************** */

void* fetchPfRingPackets(void* notUsed) {
  struct pfring_pkthdr hdr;
  char *packet;
  int rc, use_full_packet = 0;  
  struct pcap_pkthdr h;

  if(readOnlyGlobals.metadata_fd) return(readMetadataPkts());

  traceEvent(TRACE_NORMAL, "Using PF_RING in-kernel accelerated packet parsing");

  packet = (char*)malloc(readOnlyGlobals.snaplen+1);

  if(packet == NULL) {
    traceEvent(TRACE_WARNING, "Not enough memory!");
    return(NULL);
  }

  if(readOnlyGlobals.pktSampleRate > 1)
    rc = pfring_set_sampling_rate(readWriteGlobals->ring, readOnlyGlobals.pktSampleRate);

  if(readOnlyGlobals.snaplen > PCAP_DEFAULT_SNAPLEN) {
    use_full_packet = 1;
    traceEvent(TRACE_NORMAL, "Using PF_RING application packet parsing");
  }

  while(!readWriteGlobals->shutdownInProgress) {
    rc = pfring_recv(readWriteGlobals->ring, packet, readOnlyGlobals.snaplen, &hdr, 1 /* wait_for_incoming_packet */);

    if(rc > 0) {
      if(!use_full_packet) {
	processPfringPktHdr(&hdr, packet);
      } else {

	h.len = hdr.len, h.caplen = hdr.caplen;
	h.ts.tv_sec = hdr.ts.tv_sec, h.ts.tv_usec = hdr.ts.tv_usec;
	 
	if(0) {
	  int j =0;

	  for(j=0; j<32; j++) {
	    printf("%d=%02X\n", j, packet[j] & 0xFF);
	  }
	    
	  printf("\n");
	}

	decodePacket(&h, (u_char*)packet, 
		     (readOnlyGlobals.pktSampleRate > 1) ? 1 : 0 /* sampledPacket */, 
		     readOnlyGlobals.pktSampleRate /* numPkts */,
		     hdr.extended_hdr.if_index, 
		     hdr.extended_hdr.if_index,
		     0 /* flow_sender_ip */);
      }      
    }
  }

  return(NULL);
}

/* ********************************************* */

pfring* open_ring(char *dev, u_char *open_device) {
  pfring* the_ring = NULL;

  if((the_ring = pfring_open(dev,
			     readOnlyGlobals.promisc_mode /* promiscuous */,
			     readOnlyGlobals.snaplen,
			     1 /* reentrant */)) != NULL) {
    u_int32_t version;
    int rc;

    rc = pfring_version(the_ring, &version);

    if((rc == -1) || (version < 0x030502)) {
      traceEvent(TRACE_WARNING,
		 "nProbe requires PF_RING v.3.9.3 or above (you have v.%d.%d.%d)",
		 (version & 0xFFFF0000) >> 16,
		 (version & 0x0000FF00) >> 8,
		 version & 0x000000FF);
      pfring_close(the_ring);
      the_ring = NULL;
    } else {
      traceEvent(TRACE_INFO, "Successfully open PF_RING v.%d.%d.%d on device %s\n",
		 (version & 0xFFFF0000) >> 16,
		 (version & 0x0000FF00) >> 8,
		 (version & 0x000000FF),
		 readOnlyGlobals.tmpDev);
      *open_device = 0;
      readOnlyGlobals.datalink = DLT_EN10MB;
      pfring_set_application_name(the_ring, "nProbe");
    }
  }
  
  return(the_ring);
}

#endif /* HAVE_PF_RING */
