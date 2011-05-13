/*
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6
 *
 *       Copyright (C) 2002-11 Luca Deri <deri@ntop.org>
 *
 *                     http://www.ntop.org/
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* ************************************************************************

History:

1.0    [06/02]        Initial release
1.3    [07/02]        First public release

************************************************************************ */

#include "nprobe.h"

#define BLANK_SPACES               "                     "

/* #define NETFLOW_DEBUG  */

/* #define HASH_DEBUG */

/* #define TIME_PROTECTION  */

#define MAX_SAMPLE_RATE    ((u_short)-1)

/* *************************************** */

/*
  #define OPTION_TEMPLATE "%SYSTEM_ID %SAMPLING_INTERVAL %SAMPLING_ALGORITHM %TOTAL_BYTES_EXP %TOTAL_PKTS_EXP %TOTAL_FLOWS_EXP %FLOW_ACTIVE_TIMEOUT %FLOW_INACTIVE_TIMEOUT"
*/

#define V9_OPTION_TEMPLATE "%TOTAL_FLOWS_EXP %TOTAL_PKTS_EXP"

/* IMPORTANT: when you modify it please also change exportBucketToNetflowV5 */
#define DEFAULT_V9_IPV4_TEMPLATE "%IPV4_SRC_ADDR %IPV4_DST_ADDR %IPV4_NEXT_HOP %INPUT_SNMP %OUTPUT_SNMP %IN_PKTS %IN_BYTES %FIRST_SWITCHED " \
"%LAST_SWITCHED %L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS %PROTOCOL %SRC_TOS %SRC_AS %DST_AS %IPV4_SRC_MASK %IPV4_DST_MASK"

#define DEFAULT_V9_OPTION_TEMPLATE_ID (DEFAULT_TEMPLATE_ID+1)
#define TEMPLATE_PACKETS_DELTA        10

/* *********** Globals ******************* */

#ifdef HAVE_PF_RING
#include "pro/pf_ring.c"
#endif

/* ****************************************************** */

/* Forward */
static void checkExportQueuedFlows(int forceExport);
static void printStats(int force);
static void shutdown_nprobe(void);
static pthread_t *packetProcessThread;
static int parseOptions(int argc, char* argv[], u_int8_t reparse_options);
static void compileTemplates(u_int8_t reloadTemplate);

static int argc_;
static char **argv_;

#ifdef HAVE_OPTRESET
extern int optreset; /* defined by BSD, but not others */
#endif

static const struct option long_options[] = {
  { "all-collectors",                   required_argument,       NULL, 'a' },
  { "as-list",                          required_argument,       NULL, 'A' },
  { "verbose",                          required_argument,       NULL, 'b' },
  { "count-delay",                      required_argument,       NULL, 'B' },
  { "local-hosts-only",                 no_argument,             NULL, 'c' },
  { "flow-lock",                        required_argument,       NULL, 'C' },
  { "idle-timeout",                     required_argument,       NULL, 'd' },
  { "dump-format",                      required_argument,       NULL, 'D' },
  { "flow-delay",                       required_argument,       NULL, 'e' },
  { "netflow-engine",                   required_argument,       NULL, 'E' },
  { "bpf-filter",                       required_argument,       NULL, 'f' },
  { "dump-frequency",                   required_argument,       NULL, 'F' },
  { "pid-file",                         required_argument,       NULL, 'g' },
#ifndef WIN32
  { "daemon-mode",                      no_argument,             NULL, 'G' },
#endif
  { "help",                             no_argument,             NULL, 'h' },
  { "interface",                        required_argument,       NULL, 'i' },
  { "syslog",                           required_argument,       NULL, 'I' },
  { "queue-timeout",                    required_argument,       NULL, 'l' },
  { "local-networks",                   required_argument,       NULL, 'L' },
  { "min-num-flows",                    required_argument,       NULL, 'm' },
  { "max-num-flows",                    required_argument,       NULL, 'M' },
  { "collector",                        required_argument,       NULL, 'n' },
  { "rebuild-hash",                     no_argument,             NULL, 'N' },
  { "flows-intra-templ",                required_argument,       NULL, 'o' },
  { "num-threads",                      required_argument,       NULL, 'O' },
  { "aggregation",                      required_argument,       NULL, 'p' },
  { "dump-path",                        required_argument,       NULL, 'P' },
#ifdef IP_HDRINCL
  { "sender-address",                   required_argument,       NULL, 'q' },
#endif
  { "out-iface-idx",                    required_argument,       NULL, 'Q' },
  { "local-traffic-direction",          no_argument,             NULL, 'r' },
  { "payload-length",                   required_argument,       NULL, 'R' },
  { "scan-cycle",                       required_argument,       NULL, 's' },
  { "sample-rate",                      required_argument,       NULL, 'S' },
  { "lifetime-timeout",                 required_argument,       NULL, 't' },
  { "flow-templ",                       required_argument,       NULL, 'T' },
  { "in-iface-idx",                     required_argument,       NULL, 'u' },
  { "flow-templ-id",                    required_argument,       NULL, 'U' },
  { "hash-size",                        required_argument,       NULL, 'w' },
  { "no-ipv6",                          no_argument,             NULL, 'W' },
  { "payload-policy",                   required_argument,       NULL, 'x' },
  { "version",                          no_argument,             NULL, 'v' },
  { "flow-version",                     required_argument,       NULL, 'V' },
  { "min-flow-size",                    required_argument,       NULL, 'z' },

#ifdef HAVE_MYSQL
  { "mysql",                            required_argument,       NULL, '0' /* ignored */},
  { "mysql-skip-db-creation",           no_argument,             NULL, '0' /* ignored */},
#endif
  { "if-networks",                      required_argument,       NULL, '1' },
  { "count",                            required_argument,       NULL, '2' },
  { "collector-port",                   required_argument,       NULL, '3' },
#ifdef linux
  { "cpu-affinity",                     required_argument,       NULL, '4' },
#endif
  { "tunnel",                           no_argument,             NULL, '5' },
  /* Handled by the plugin */
  { "no-promisc",                       no_argument,             NULL, '6' },
  { "smart-udp-frags",                  no_argument,             NULL, '7' },
  { "ipsec-auth-data-len",              required_argument,       NULL, '8' },
  { "dump-stats",                       required_argument,       NULL, '9' },
  { "black-list",                       required_argument,       NULL, '!' },
  { "vlanid-as-iface-idx",              no_argument,             NULL, '@' },
  { "pcap-file-list",                   required_argument,       NULL, '$' },
  { "csv-separator",                    required_argument,       NULL, '^' },
  { "city-list",                        required_argument,       NULL, ',' },
#ifdef HAVE_FASTBIT
  { "fastbit",                          required_argument,       NULL, '[' },
  { "fastbit-rotation",                 required_argument,       NULL, ']' },
  { "fastbit-template",                 required_argument,       NULL, '(' },
#ifndef WIN32
  { "fastbit-index",                    required_argument,       NULL, ')' },
#endif
  { "fastbit-exec",                     required_argument,       NULL, '#' },
#endif

  { "dont-drop-privileges",             no_argument,             NULL, '\\' },
  { "bi-directional",                   no_argument,             NULL, '{' },
  { "account-l2",                       no_argument,             NULL, '}' },
  { "dump-metadata",                    required_argument,       NULL, '=' },
  { "event-log",                        required_argument,       NULL, '+' },

  /*
     Options for plugins. These options are not handled by the main
     program but it's important to have them defined here otherwise we
     get a warning from the probe
  */
  { "dont-hash-cookies",                no_argument,       NULL, 251 /* dummy */ },
  { "dont-nest-dump-dirs",              no_argument,       NULL, 251 /* dummy */ },
  { "max-http-log-lines",               required_argument, NULL, 252 /* dummy */ },
  { "http-dump-dir",                    required_argument, NULL, 252 /* dummy */ },
  { "http-exec-cmd",                    required_argument, NULL, 252 /* dummy */ },

  { "max-mysql-log-lines",              required_argument, NULL, 252 /* dummy */ },
  { "mysql-dump-dir",                   required_argument, NULL, 252 /* dummy */ },
  { "http-exec-cmd",                    required_argument, NULL, 252 /* dummy */ },

  { "dns-dump-dir",                     required_argument, NULL, 253 /* dummy */ },
  { "ntop-ng",                          required_argument, NULL, 254 /* dummy */ },
  { "bgp-port",                         required_argument, NULL, 255 /* dummy */ },


  /* End of probe options */
  { NULL,                               no_argument,       NULL,  0 }
};

/* ****************************************************** */

void printPcapStats(pcap_t *pcapPtr) {
  struct pcap_stat pcapStat;

  if(pcap_stats(pcapPtr, &pcapStat) >= 0) {
    u_long rcvd_diff, drop_diff;
    char msg[256];

    /* Some pcap implementations resetthe stats at each call */
    if(pcapStat.ps_recv >= readWriteGlobals->last_ps_recv) {
      rcvd_diff = pcapStat.ps_recv-readWriteGlobals->last_ps_recv;
      drop_diff = pcapStat.ps_drop-readWriteGlobals->last_ps_drop;
    } else {
      rcvd_diff = pcapStat.ps_recv, drop_diff = pcapStat.ps_drop;
    }

    snprintf(msg, sizeof(msg), "Packet stats: "
	     "%u/%u pkts rcvd/dropped [%.1f%%] [Last %lu/%lu pkts rcvd/dropped]",
	     pcapStat.ps_recv, pcapStat.ps_drop,
	     pcapStat.ps_recv > 0 ?
	     (float)(pcapStat.ps_drop*100)/(float)pcapStat.ps_recv : 0,
	     rcvd_diff, drop_diff);

    traceEvent(TRACE_INFO, "%s", msg);
    if(drop_diff > 0) dumpLogEvent(packet_drop, severity_warning, msg);

    readWriteGlobals->last_ps_recv = pcapStat.ps_recv, readWriteGlobals->last_ps_drop = pcapStat.ps_drop;
  } else {
#ifdef DEBUG
    traceEvent(TRACE_WARNING, "Unable to read pcap statistics: %s",
	       pcap_geterr(pcapPtr));
#endif
  }
}

/* ****************************************************** */

#ifndef WIN32

void reloadCLI(int signo) {
  traceEvent(TRACE_NORMAL, "Received signal %d: reloading CLI options", signo);

  parseOptions(argc_, argv_, 1);
}

/* ****************************************************** */

void cleanup(int signo) {
  static u_char statsPrinted = 0;

  if(!nprobe_up) exit(0);

  if(!statsPrinted) {
    statsPrinted = 1;
    if(readOnlyGlobals.pcapPtr != NULL) {
      printPcapStats(readOnlyGlobals.pcapPtr);
    }
  }

  shutdown_nprobe();
  /* exit(0); */
}
#endif

/* ****************************************************** */

#ifndef WIN32
void brokenPipe(int signo) {
#ifdef DEBUG
  traceEvent(TRACE_WARNING, "Broken pipe (socket %d closed) ?\n", currSock);
#endif
  signal(SIGPIPE, brokenPipe);
}
#endif

/* ****************************************************** */

void decodePacket(struct pcap_pkthdr *h, const u_char *p,
		  u_int8_t sampledPacket,
		  u_short numPkts, int input_index, int output_index,
		  u_int32_t flow_sender_ip) {
  struct eth_header ehdr;
  u_int caplen = h->caplen, length = h->len, offset = 0;
  u_short eth_type, off=0;
  u_int8_t tcpFlags = 0, proto = 0;
  u_int32_t tunnel_id = 0, tcpSeqNum = 0;
  struct ip ip = { 0 };
#ifndef IPV4_ONLY
  struct ip6_hdr ipv6;
  struct ip6_ext ipv6ext;
#endif
  struct tcphdr tp = { 0 };
  struct udphdr up = { 0 };
  struct icmp_hdr icmpPkt = { 0 };
  u_int16_t payload_shift = 0;
  int originalPayloadLen = 0, payloadLen = 0; /* Do not set it to unsigned */
  IpAddress src = { 0 }, dst = { 0 };
  IpAddress untunneled_src = { 0 }, untunneled_dst = { 0 };
  u_int16_t untunneled_sport = 0, untunneled_dport = 0;
  u_int8_t untunneled_proto = 0;
  u_short numFragments = 0;
  u_int ehshift = 0;
#ifdef DEBUG
  traceEvent(TRACE_INFO, ".");
#endif

  if(readWriteGlobals->stopPacketCapture) return;

  if(readOnlyGlobals.initialSniffTime.tv_sec == 0) {
    /* Set it with the first incoming packet */
    memcpy(&readOnlyGlobals.initialSniffTime, &h->ts, sizeof(struct timeval));
  }

  readWriteGlobals->now = h->ts.tv_sec;

  if(caplen >= sizeof(struct eth_header)) {
    u_int plen, hlen = 0, ip_len = 0;
    u_short sport, dport, numMplsLabels = 0, tcp_len;
    u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN];
    u_int32_t null_type;
    struct ppp_header ppphdr;

    if(readOnlyGlobals.numProcessThreads > 1) pthread_rwlock_wrlock(&readWriteGlobals->statsRwLock);
    readWriteGlobals->accumulateStats.pkts++, readWriteGlobals->accumulateStats.bytes += length;
    readWriteGlobals->currentPkts++, readWriteGlobals->currentBytes += length;
    if(readOnlyGlobals.numProcessThreads > 1) pthread_rwlock_unlock(&readWriteGlobals->statsRwLock);

    // traceEvent(TRACE_INFO, "Datalink: %d", datalink);

    switch(readOnlyGlobals.datalink) {
    case DLT_ANY: /* Linux 'any' device */
      eth_type = DLT_ANY;
      memset(&ehdr, 0, sizeof(struct eth_header));
      break;
    case DLT_RAW: /* Raw packet data */
      if(((p[0] & 0xF0) >> 4) == 4)
	eth_type = ETHERTYPE_IP;
      else
	eth_type = ETHERTYPE_IPV6;
      ehshift = 0;
      break;
    case DLT_NULL: /* loopaback interface */
      ehshift = 4;
      memcpy(&null_type, p, sizeof(u_int32_t));
      //null_type = ntohl(null_type);
      /* All this crap is due to the old little/big endian story... */
      /* FIX !!!! */
      switch(null_type) {
      case BSD_AF_INET:
	eth_type = ETHERTYPE_IP;
	break;
      case BSD_AF_INET6_BSD:
      case BSD_AF_INET6_FREEBSD:
      case BSD_AF_INET6_DARWIN:
	eth_type = ETHERTYPE_IPV6;
	break;
      default:
	return; /* Any other non IP protocol */
      }
      memset(&ehdr, 0, sizeof(struct eth_header));
      break;
    case DLT_PPP:
      memcpy(&ppphdr, p, sizeof(struct ppp_header));
      if(ntohs(ppphdr.proto) == 0x0021 /* IP */)
	eth_type = ETHERTYPE_IP, ehshift = sizeof(struct ppp_header);
      else
	return;
      break;
    default:
      ehshift = sizeof(struct eth_header);
      memcpy(&ehdr, p, ehshift);
      eth_type = ntohs(ehdr.ether_type);
      break;
    }

    if((eth_type == ETHERTYPE_IP)
       || (eth_type == ETHERTYPE_IPV6)
       || (eth_type == ETHERTYPE_VLAN) /* Courtesy of Mikael Cam <mca@mgn.net> - 2002/08/28 */
       || (eth_type == ETHERTYPE_MPLS)
       || (eth_type == ETHERTYPE_PPPoE)
       || (eth_type == DLT_NULL)
       || (eth_type == DLT_ANY)
       || (eth_type == 16385 /* MacOSX loopback */)
       || (eth_type == 16390 /* MacOSX loopback */)
       ) {
      u_short vlanId = 0;
      u_int estimatedLen = 0;

      if(eth_type == ETHERTYPE_MPLS) {
	char bos; /* bottom_of_stack */

	memset(mplsLabels, 0, sizeof(mplsLabels));
	bos = 0;
	while(bos == 0) {
	  memcpy(&mplsLabels[numMplsLabels], p+ehshift, MPLS_LABEL_LEN);

	  bos = (mplsLabels[numMplsLabels][2] & 0x1), ehshift += 4, numMplsLabels++;
	  if((ehshift > caplen) || (numMplsLabels >= MAX_NUM_MPLS_LABELS))
	    return; /* bad packet */
	}
	eth_type = ETHERTYPE_IP;
      } else if((eth_type == ETHERTYPE_IP) || (eth_type == ETHERTYPE_IPV6)) {
	if((ehshift == 0) && (readOnlyGlobals.datalink != DLT_RAW)) /* still not set (used to handle the DLT_NULL case) */
	  ehshift = sizeof(struct eth_header);
      } else if(eth_type == ETHERTYPE_PPPoE) {
	eth_type = ETHERTYPE_IP, ehshift += 8;
      } else if(eth_type == ETHERTYPE_VLAN) {
	Ether80211q qType;

	while(eth_type == ETHERTYPE_VLAN) {
	  memcpy(&qType, p+ehshift, sizeof(Ether80211q));
	  vlanId = ntohs(qType.vlanId) & 0xFFF;
	  eth_type = ntohs(qType.protoType);
	  ehshift += sizeof(qType);
	  /* printf("VlanId: %d\n", vlanId); <<<== NOT USED YET */
	}

	if(eth_type == 0x0800) {
	  /* Sanity check */

	  if(p[ehshift] == 0x60)
	    eth_type = ETHERTYPE_IPV6;
	}
      } else if(eth_type == DLT_ANY) {
	ehshift += sizeof(AnyHeader);
	eth_type = ntohs(((AnyHeader*)p)->protoType);
      } else
	ehshift += NULL_HDRLEN;

    parse_ip:
      if(eth_type == ETHERTYPE_IP) {
	u_short ip_ip_len;

	memcpy(&ip, p+ehshift, sizeof(struct ip));
	if(ip.ip_v != 4) return; /* IP v4 only */

	/* blacklist check */
	if(isBlacklistedAddress(&ip.ip_src) || isBlacklistedAddress(&ip.ip_dst)) return;

	ip_ip_len = htons(ip.ip_len);

	ip_len = ((u_short)ip.ip_hl * 4);
	estimatedLen = ehshift + ip_ip_len;
	hlen = ip_len;
	payloadLen = htons(ip.ip_len)-ip_len;

	if(readOnlyGlobals.roundPacketLenWithIPHeaderLen)
	  length = estimatedLen;

	src.ipVersion = 4, dst.ipVersion = 4;
	if(readOnlyGlobals.ignoreIP || (readOnlyGlobals.setAllNonLocalHostsToZero && (!isLocalAddress(&ip.ip_src))))
	  src.ipType.ipv4 = 0; /* 0.0.0.0 */
	else
	  src.ipType.ipv4 = ntohl(ip.ip_src.s_addr);

	if(readOnlyGlobals.ignoreIP || (readOnlyGlobals.setAllNonLocalHostsToZero && (!isLocalAddress(&ip.ip_dst))))
	  dst.ipType.ipv4 = 0; /* 0.0.0.0 */
	else
	  dst.ipType.ipv4 = ntohl(ip.ip_dst.s_addr);

	proto = ip.ip_p;
	off = ntohs(ip.ip_off) & 0x3fff;
	numFragments = off ? 1 : 0;
#ifndef IPV4_ONLY
      } else if(eth_type == ETHERTYPE_IPV6) {
	u_short ipv6_ip_len;

	if(readOnlyGlobals.disableIPv6) return;

	memcpy(&ipv6, p+ehshift, sizeof(struct ip6_hdr));
	if(((ipv6.ip6_vfc >> 4) & 0x0f) != 6) return; /* IP v6 only */

	ipv6_ip_len = htons(ipv6.ip6_plen);
	estimatedLen = sizeof(struct ip6_hdr)+ehshift+ipv6_ip_len;

	if(readOnlyGlobals.roundPacketLenWithIPHeaderLen)
	  length = estimatedLen;

	hlen = sizeof(struct ip6_hdr);
	src.ipVersion = 6, dst.ipVersion = 6;
	payloadLen = ipv6_ip_len - hlen;

	/* FIX: blacklist check for IPv6 */

	/* FIX: isLocalAddress doesn't work with IPv6 */
	if(readOnlyGlobals.ignoreIP)
	  memset(&src.ipType.ipv6, 0, sizeof(struct in6_addr));
	else
	  memcpy(&src.ipType.ipv6, &ipv6.ip6_src, sizeof(struct in6_addr));

	if(readOnlyGlobals.ignoreIP)
	  memset(&dst.ipType.ipv6, 0, sizeof(struct in6_addr));
	else
	  memcpy(&dst.ipType.ipv6, &ipv6.ip6_dst, sizeof(struct in6_addr));

	proto = ipv6.ip6_nxt; /* next header (protocol) */

	if(proto == 0) {
	  /* IPv6 hop-by-hop option */

	  memcpy(&ipv6ext, p+ehshift+sizeof(struct ip6_hdr), sizeof(struct ip6_ext));
	  hlen += (ipv6ext.ip6e_len+1)*8;
	  proto = ipv6ext.ip6e_nxt;
	}
#endif
      } else
	return; /* Anything else that's not IPv4/v6 */

      originalPayloadLen = payloadLen;
      plen = length-ehshift;
      if(caplen > estimatedLen) caplen = estimatedLen;
      payloadLen -= (estimatedLen-caplen);

      sport = dport = 0; /* default */
      offset = ehshift+hlen;

      if(readOnlyGlobals.tunnel_mode) {
	switch(proto) {
	case IPPROTO_ESP:
	  /* http://www.unixwiz.net/techtips/iguide-ipsec.html */
	  if(payloadLen > readOnlyGlobals.ipsec_auth_data_len) {
	    proto = p[offset+payloadLen-readOnlyGlobals.ipsec_auth_data_len-1];
	    offset += 8;
	  }
	  break;

	case IPPROTO_GRE:
	  {
	    struct gre_header gre;

	    memcpy(&gre, &p[offset], sizeof(gre));
	    gre.flags_and_version = ntohs(gre.flags_and_version);
	    gre.proto = ntohs(gre.proto);

	    offset += sizeof(struct gre_header);
	    if(gre.flags_and_version & GRE_HEADER_CHECKSUM) offset += 4;
	    if(gre.flags_and_version & GRE_HEADER_ROUTING)  offset += 4;
	    if(gre.flags_and_version & GRE_HEADER_KEY)      offset += 4;
	    if(gre.flags_and_version & GRE_HEADER_SEQ_NUM)  offset += 4;

	    eth_type = gre.proto;

	    if(eth_type == 0x8881 /* CDMA2000 */) {
	      offset++; /* PPP in HDLC-Like Framing */
	      memcpy(&ppphdr, &p[offset], sizeof(struct ppp_header));
	      if(ntohs(ppphdr.proto) == 0x0021 /* IP */)
		eth_type = ETHERTYPE_IP;

	      ehshift = sizeof(struct ppp_header)+offset;
	    } else
	      ehshift = offset;

	    memcpy(&untunneled_src, &src, sizeof(IpAddress)), memcpy(&untunneled_dst, &dst, sizeof(IpAddress));
	    untunneled_proto = proto, untunneled_sport = sport, untunneled_dport = dport;
	    goto parse_ip;
	    break;
	  }
	}
      }

      switch(proto) {
      case IPPROTO_TCP:
	if(plen < (hlen+sizeof(struct tcphdr))) return; /* packet too short */
	memcpy(&tp, p+offset, sizeof(struct tcphdr));
	if(!readOnlyGlobals.ignorePorts) sport = ntohs(tp.th_sport);
	if(!readOnlyGlobals.ignorePorts) dport = ntohs(tp.th_dport);
	tcpFlags = tp.th_flags, tcpSeqNum = ntohl(tp.th_seq);
	tcp_len = (tp.th_off * 4);
	payloadLen -= tcp_len, originalPayloadLen -= tcp_len;
	if(payloadLen > 0)
	  payload_shift = offset+tcp_len;
	else {
	  payloadLen    = 0;
	  payload_shift = 0;
	}
	break;

      case IPPROTO_UDP:
	if(plen < (hlen+sizeof(struct udphdr))) return; /* packet too short */
	memcpy(&up, p+offset, sizeof(struct udphdr));
	if(!readOnlyGlobals.ignorePorts) sport = ntohs(up.uh_sport);
	if(!readOnlyGlobals.ignorePorts) dport = ntohs(up.uh_dport);
	originalPayloadLen = payloadLen = ntohs(up.uh_ulen)-sizeof(struct udphdr);
	if(payloadLen > 0)
	  payload_shift = offset+sizeof(struct udphdr);
	else {
	  payloadLen    = 0;
	  payload_shift = 0;
	}

	if((readOnlyGlobals.tunnel_mode) && (payloadLen > sizeof(struct gtp_header))) {
	  if(dport == GTP_DATA_PORT) {
	    struct gtp_header *gtp = (struct gtp_header*)&p[payload_shift];
	    u_int gtp_header_len = 8 /* min size of struct gtp_header */;

	    if(((gtp->flags & 0x30) == 0x30) /* GTPv1 */
	       && (ntohs(gtp->total_length) >= (payloadLen-gtp_header_len))) {
	      tunnel_id = ntohl(gtp->tunnel_id);

	      /* Now compute gtp_header_len precisely */
	      if(gtp->flags & 0x04) gtp_header_len += 1; /* next_ext_header is present */
	      if(gtp->flags & 0x02) gtp_header_len += 2; /* sequence_number is present */
	      if(gtp->flags & 0x01) gtp_header_len += 1; /* pdu_number is present */

	      payload_shift += gtp_header_len;
	      ehshift = payload_shift;

	      if(p[payload_shift] == 0x60)
		eth_type = ETHERTYPE_IPV6;
	      else
		eth_type = ETHERTYPE_IP;

	      memcpy(&untunneled_src, &src, sizeof(IpAddress)), memcpy(&untunneled_dst, &dst, sizeof(IpAddress));
	      untunneled_proto = proto, untunneled_sport = sport, untunneled_dport = dport;
	      goto parse_ip;
	    }
	  }
	}

#ifdef NETFLOW_DEBUG
	if((payloadLen > 0)
	   && (numFragments == 0) && (off == 0) /* Do not process fragmented packets */
	   && ((dport == 2055)
	       || (dport == 2057)
	       || (dport == 9999)
	       || (dport == 3000)
	       || (dport == 6000)
	       )) {
	  /* traceEvent(TRACE_NORMAL, "Dissecting flow packets (%d bytes)", payloadLen); */
	  dissectNetFlow(0, (char*)&p[payload_shift], payloadLen);
	  return;
	}
#endif
	break;
      case IPPROTO_ICMP:
      case IPPROTO_ICMPV6:
	if(plen < (hlen+sizeof(struct icmp_hdr))) return; /* packet too short */
	memcpy(&icmpPkt, p+offset, sizeof(struct icmp_hdr));
	payloadLen = caplen - offset- sizeof(struct icmp_hdr);
	//traceEvent(TRACE_ERROR, "[icmp_type=%d][icmp_code=%d]", icmpPkt.icmp_type, icmpPkt.icmp_code);
	if(!(readOnlyGlobals.ignorePorts || readOnlyGlobals.ignorePorts)) {
	  if(readOnlyGlobals.usePortsForICMP)
	    sport = 0, dport = (icmpPkt.icmp_type * 256) + icmpPkt.icmp_code;
	}

	if(payloadLen > 0) {
	  payload_shift = offset;

	  if(proto == IPPROTO_ICMP)
	    payload_shift += sizeof(struct icmp_hdr);
	  else
	    payload_shift += 64; /* ICMPv6 */
	} else {
	  payloadLen    = 0;
	  payload_shift = 0;
	}
	break;

      default:
	payloadLen = 0;
      }

      /* ************************************************ */

      /* Is this is a fragment ?
	 NOTE: IPv6 doesn't have the concept of fragments
      */
      if(readOnlyGlobals.handleFragments && (numFragments > 0)) {
	u_short fragmentOffset = (off & 0x1FFF)*8, fragmentId = ntohs(ip.ip_id);
	u_short fragment_list_idx = (src.ipType.ipv4 + dst.ipType.ipv4) % NUM_FRAGMENT_LISTS;
	IpV4Fragment *list, *prev = NULL;

	if((readOnlyGlobals.smart_udp_frags_mode == 0) || (proto != IPPROTO_UDP)) {
	  pthread_mutex_lock(&readWriteGlobals->fragmentMutex[fragment_list_idx]);
	  list = readWriteGlobals->fragmentsList[fragment_list_idx];

	  while(list != NULL) {
	    if((list->src == src.ipType.ipv4)
	       && (list->dst == dst.ipType.ipv4)
	       && (list->fragmentId == fragmentId))
	      break;
	    else {
	      if((h->ts.tv_sec-list->firstSeen) > 30 /* sec */) {
		/* Purge expired fragment */
		IpV4Fragment *next = list->next;

		if(prev == NULL)
		  readWriteGlobals->fragmentsList[fragment_list_idx] = next;
		else
		  prev->next = next;

		free(list);
		readWriteGlobals->fragmentListLen[fragment_list_idx]--;
		list = next;
	      } else {
		prev = list;
		list = list->next;
	      }
	    }
	  }

	  if(list == NULL) {
	    /* Fragment not found */
	    IpV4Fragment *frag = (IpV4Fragment*)malloc(sizeof(IpV4Fragment));

	    /* We have enough memory */
	    if(frag != NULL) {
	      memset(frag, 0, sizeof(IpV4Fragment));
	      frag->next = readWriteGlobals->fragmentsList[fragment_list_idx];
	      readWriteGlobals->fragmentsList[fragment_list_idx] = frag;
	      frag->src = src.ipType.ipv4, frag->dst = dst.ipType.ipv4;
	      frag->fragmentId = fragmentId;
	      frag->firstSeen = h->ts.tv_sec;
	      list = frag, prev = NULL;;
	      readWriteGlobals->fragmentListLen[fragment_list_idx]++;
	    } else
	      traceEvent(TRACE_ERROR, "Not enough memory?");
	  }

	  if(list != NULL) {
	    if(fragmentOffset == 0)
	      list->sport = sport, list->dport = dport;

	    list->len += plen, list->numPkts++;

	    if(!(off & IP_MF)) {
	      /* last fragment->we know the total data size */
	      IpV4Fragment *next = list->next;
	      sport = list->sport, dport = list->dport;
	      plen = list->len, numPkts = list->numPkts;

	      /* We can now free the fragment */
	      if(prev == NULL)
		readWriteGlobals->fragmentsList[fragment_list_idx] = next;
	      else
		prev->next = next;

	      readWriteGlobals->fragmentListLen[fragment_list_idx]--;
	      free(list);
	      pthread_mutex_unlock(&readWriteGlobals->fragmentMutex[fragment_list_idx]);
	      numFragments = numPkts;
	    } else {
	      pthread_mutex_unlock(&readWriteGlobals->fragmentMutex[fragment_list_idx]);
	      /* More fragments: we'll handle the packet later */
	      return;
	    }
	  }
	} else {
	  if(fragmentOffset > 0) {
	    /*
	      Ignore fragments that do not have the initial
	      fragmented packet info
	    */
	    return;
	  } else {
	    /*
	      We use 2* because we want to be as precise as possible given
	      that we have at least two fragments, we account twice the
	      IP packt header
	    */
	    plen = ntohs(up.uh_ulen)+2*ip_len, numPkts = 2;
	  }
	}
      }

      /* ************************************************ */

#ifdef DEBUG
      {
	char buf[256], buf1[256];

	printf("%2d) %s:%d -> %s:%d [len=%d][payloadLen=%d]\n",
	       ip.ip_p, _intoaV4(ip.ip_src.s_addr, buf, sizeof(buf)), sport,
	       _intoaV4(ip.ip_dst.s_addr, buf1, sizeof(buf1)), dport,
	       plen, payloadLen);
      }
#endif

      if((src.ipVersion == 4) && (src.ipType.ipv4 == 0)
	 && (dst.ipType.ipv4 == 0) && (!(readOnlyGlobals.ignoreIP)))
	return; /* Flow to skip */

      queueParsedPkt(proto, numFragments, sampledPacket,
		     numPkts, ip.ip_tos,
		     vlanId, tunnel_id, &ehdr, &src, sport, &dst, dport,
		     untunneled_proto, &untunneled_src, untunneled_sport, &untunneled_dst, untunneled_dport,
		     readOnlyGlobals.accountL2Traffic ? h->len : plen,
		     tcpFlags, tcpSeqNum,
		     ((proto == IPPROTO_ICMP) || (proto == IPPROTO_ICMPV6)) ?  icmpPkt.icmp_type : 0,
		     ((proto == IPPROTO_ICMP) || (proto == IPPROTO_ICMPV6)) ? icmpPkt.icmp_code : 0,
		     numMplsLabels, mplsLabels,
		     input_index, output_index,
		     (struct pcap_pkthdr*)h, (u_char*)p,
		     payload_shift, payloadLen,
		     originalPayloadLen, 0,
		     0, 0, 0, 0, 0 /* flow_sender_ip */);
    }
#ifdef DEBUG
    else {
      if(traceMode)
	traceEvent(TRACE_WARNING, "Unknown ethernet type: 0x%X (%d)",
		   eth_type, eth_type);
    }
#endif
  }
}

/* ****************************************************** */

void dummyProcessPacket(u_char *_deviceId,
			 const struct pcap_pkthdr *h,
			 const u_char *p) {
  // traceEvent(TRACE_NORMAL, "Got %d bytes packet", h->len);
  decodePacket((struct pcap_pkthdr*)h, p,
	       0 /* sampledPacket */, 1 /* numPkts */,
	       NO_INTERFACE_INDEX, NO_INTERFACE_INDEX,
	       0 /* flow_sender_ip */);
}

/* ****************************************************** */

void allocateHostHash(void) {
  if(readOnlyGlobals.enableHostStats) {
    readWriteGlobals->theHostHash =
      (HostHashBucket**)calloc(readOnlyGlobals.hostHashSize, sizeof(HostHashBucket*));

    if(readWriteGlobals->theHostHash == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory");
      exit(-1);
    }
  }
}

/* ****************************************************** */

void freeHostHash(void) {
  if(readOnlyGlobals.enableHostStats) {
    traceEvent(TRACE_INFO, "MISSING implement freeHostHash()");
  }
}

/* ****************************************************** */

/* There's 1 dequeue thread per queue */
void* dequeuePackets(void* notused) {
  u_long num, queue_id = (long)notused;  /* Range 0..readOnlyGlobals.numProcessThreads */
  PacketQueue *queue = &readWriteGlobals->packetQueue[queue_id];

  traceEvent(TRACE_INFO, "Started dequeue packets thread id %d...\n", queue_id);

  while(!readWriteGlobals->shutdownInProgress) {
    QueuedPacket *slot = &queue->queue[queue->remove_idx];

    /* Wait for packets */
    while((num = queuedPkts(queue)) == 0) {
      if(readWriteGlobals->shutdownInProgress) break;

      if(0)
	traceEvent(TRACE_ERROR, "No queued packets [num=%d][queue_id=%d][queued=%u/dequeued=%u]",
		   num, queue_id, queue->num_queued_pkts, queue->num_dequeued_pkts);

      waitCondvar(&queue->dequeue_condvar);
    }

    if(readWriteGlobals->shutdownInProgress) break;

    if(0) traceEvent(TRACE_ERROR, "packet dequeued[queue_id=%d][num_queued=%d]", queue_id, queuedPkts(queue));

    processFlowPacket(slot->idx, queue_id,
		      slot->proto, slot->numFragments,
		      slot->sampledPacket,
		      slot->numPkts, slot->tos,
		      slot->vlanId, slot->tunnel_id,
		      &slot->ehdr,
		      &slot->src, slot->sport,
		      &slot->dst, slot->dport,
		      slot->untunneled_proto,
		      &slot->untunneled_src, slot->untunneled_sport,
                      &slot->untunneled_dst, slot->untunneled_dport,
		      slot->len, slot->tcpFlags,
		      slot->tcpSeqNum,
		      slot->icmpType, slot->icmpCode,
		      slot->numMplsLabels,
		      slot->mplsLabels,
		      slot->if_input, slot->if_output,
		      &slot->h, slot->p,
		      slot->payload_shift, slot->payloadLen,
		      slot->originalPayloadLen, slot->_firstSeen,
		      slot->src_as, slot->dst_as,
		      slot->src_mask, slot->dst_mask,
		      slot->flow_sender_ip);

    queue->num_dequeued_pkts++,
      queue->remove_idx = (queue->remove_idx + 1) % queue->queue_capacity;

    signalCondvar(&queue->queue_condvar, 0);
  }

  traceEvent(TRACE_INFO, "Dequeue packets thread id %d is over...\n", queue_id);

  return(NULL);
}

/* ****************************************************** */

void allocateFlowHash(int idx) {
  u_int mallocSize = sizeof(FlowHashBucket*)*readOnlyGlobals.flowHashSize;

  readWriteGlobals->theFlowHash[idx] = (FlowHashBucket**)calloc(1, mallocSize);
  if(readWriteGlobals->theFlowHash[idx] == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory");
    exit(-1);
  }
}

/* ****************************************************** */

static void msecSleep(u_int msSleep) {
#ifndef WIN32
  struct timespec timeout;
  
  timeout.tv_sec = 0, timeout.tv_nsec = 1000000*msSleep;
  
  while((nanosleep(&timeout, &timeout) == -1) && (errno == EINTR))
    ; /* Do nothing */  
#else
  waitForNextEvent(msSleep);
#endif
}

/* ****************************************************** */

/*
  From the tests carried on, the very best approach
  is to have a periodic thread that scans for expired
  flows.
*/
void* hashWalker(void* notused) {
  u_short sleep_time, msSleep = 100;
  long idx;

  /* Wait until all the data structures have been allocated */
  while(readWriteGlobals->theFlowHash[readOnlyGlobals.numProcessThreads-1] == NULL) ntop_sleep(1);

  /* Align to the scan cycle */
  sleep_time = readOnlyGlobals.scanCycle - (time(NULL) % readOnlyGlobals.scanCycle);

  if(readOnlyGlobals.traceMode == 2)
    traceEvent(TRACE_INFO, "Sleeping %d sec before walking hash for the first time", sleep_time);
  ntop_sleep(sleep_time);

  while((readWriteGlobals->shutdownInProgress == 0)
	&& (readWriteGlobals->stopPacketCapture == 0)) {
    struct timeval begin, end;
    u_int msDiff;

    gettimeofday(&begin, NULL);

    for(idx=0; idx<readOnlyGlobals.numProcessThreads; idx++) {
      if(readOnlyGlobals.rebuild_hash) {
	int i;

	traceEvent(TRACE_INFO, "[%d] Rebuilding hash...", idx);

	/* stop all activities and create a new hash */
	for(i=0; i<MAX_HASH_MUTEXES; i++) pthread_rwlock_wrlock(&readWriteGlobals->flowHashRwLock[idx][i]);

	readWriteGlobals->thePrevFlowHash[idx] = readWriteGlobals->theFlowHash[idx];

	allocateFlowHash(idx);
	allocateHostHash();

	for(i=0; i<MAX_HASH_MUTEXES; i++) pthread_rwlock_unlock(&readWriteGlobals->flowHashRwLock[idx][i]);

	traceEvent(TRACE_INFO, "The hash has been rebuilt.");
      }

      walkHash(idx, readOnlyGlobals.rebuild_hash);

      if(readWriteGlobals->thePrevFlowHash[idx] != NULL) {
	free(readWriteGlobals->thePrevFlowHash[idx]);
	readWriteGlobals->thePrevFlowHash[idx] = NULL;
      }

#ifndef WIN32
      sched_yield();
#endif

      /* Relax a bit */
      gettimeofday(&end, NULL);
      msDiff = msTimeDiff(&end, &begin);

      if(msSleep > msDiff) {
	u_int diff = msSleep-msDiff;

	/* traceEvent(TRACE_NORMAL, "Sleeping %u msec", diff); */
	msecSleep(diff);
      }
    } /* for */

    /* End of scan */
    printStats(0);

    checkNetFlowExport(0);

    if(readOnlyGlobals.traceMode == 2)
      traceEvent(TRACE_INFO, "Sleeping %d sec before walking hash...", readOnlyGlobals.scanCycle);

    ntop_sleep(readOnlyGlobals.scanCycle);
  } /* while */

  traceEvent(TRACE_INFO, "Hash walker thread terminated");
  return(NULL);
}

/* ****************************************************** */

void probeVersion(void) {
  printf("\nWelcome to nprobe v.%s (%s) for %s\n"
	 "%s\n"
	 "Built on %s\n"
	 "Copyright 2002-11 by Luca Deri <deri@ntop.org>\n",
	 version, nprobe_revision, osName,
#ifdef HAVE_PF_RING
	 "with native PF_RING acceleration.\n",
#else
	 "",
#endif
	 buildDate
	 );
}

/* ******************************************************** */

void usage(void) {
  char buf[16];

  probeVersion();
  printf("\nUsage:\n");

  printf("nprobe -n <host:port|none> [-i <interface|dump file>] [-t <lifetime timeout>]\n"
	 "              [-d <idle timeout>] [-l <queue timeout>] [-s <scan cycle>] [-N]\n"
	 "              [-p <aggregation>] [-f <filter>] [-a] [-b <level>]"
#ifndef WIN32
	 " [-G]"
	 " [-O <# threads>]"
#if defined(linux) || defined(__linux__)
	 " [-X]"
#endif
#endif
	 "\n              "
	 "[-P <path>] [-F <dump timeout>] [-D <format>] "
	 "\n              "
	 "[-u <in dev idx>] [-Q <out dev idx>]"
	 "\n              "
#ifndef WIN32
	 "[-I <probe name>] "
#endif
	 "[-v] [-w <hash size>] [-e <flow delay>] [-B <packet count>]\n"
	 "              [-z <min flow size>] [-M <max num flows>]"
	 "[-R <payload Len>]"
	 "\n              [-x <payload policy>] [-E <engine>] [-C <flow lock file>]"
	 "\n              [-m <min # flows>]"
#ifdef IP_HDRINCL
	 "[-q <host:port>]"
#endif
	 "\n              [-S <sample rate>] [-A <AS list>] [-g <PID file>]"
	 "\n              [-T <flow template>] [-U <flow template id>]"
	 "\n              [-o <v9 templ. export policy>] [-L <local nets>] [-c] [-r]"
	 "\n              [-1 <interface nets>] [-2 <number>] [-3 <port>] [-4] [-5 <port>] [-6]"
	 "\n              [-9 <path>] [--black-list <networks>] [--pcap-file-list <filename>]"
#ifdef HAVE_FASTBIT
	 "\n              [--fastbit <dir>] [--fastbit-rotation <mins>]"
	 "\n              [--fastbit-template <flow template>]"
#ifndef WIN32
	 " [--fastbit-index <flow template>]"
#endif
	 "\n              [--fastbit-exec <cmd>]"
#endif
#ifndef WIN32
	 " [--dont-drop-privileges]\n"
#endif
	 "\n\n"
	 );

  printf("[--collector|-n] <host:port|none>   | Address of the NetFlow collector(s).\n"
	 "                                    | Multiple collectors can be defined using\n"
         "                                    | multiple -n flags. In this case flows\n"
         "                                    | will be sent in round robin mode to\n"
         "                                    | all defined collectors if the -a flag\n"
	 "                                    | is used. Note that you can specify\n"
	 "                                    | both IPv4 and IPv6 addresses.\n"
         "                                    | If you specify none as value,\n"
         "                                    | no flow will be export; in this case\n"
	 "                                    | the -P parameter is mandatory.\n");
#ifndef WIN32
  printf("[--interface|-i] <iface|pcap>       | Interface name from which packets are\n");
  printf("                                    | captured, or .pcap file (debug only)\n");
#else
  printf("[--interface|-i] <iface>            | Index or name of the interface from which\n");
  printf("                                    | packets are captured. Type -h to print\n");
  printf("                                    | all the know interfaces.\n");
#endif
  printf("[--lifetime-timeout|-t] <timeout>   | It specifies the maximum (seconds) flow\n"
	 "                                    | lifetime [default=%d]\n", readOnlyGlobals.lifetimeTimeout);
  printf("[--idle-timeout|-d] <timeout>       | It specifies the maximum (seconds) flow\n"
         "                                    | idle lifetime [default=%d]\n", readOnlyGlobals.idleTimeout);
  printf("[--queue-timeout|-l] <timeout>      | It specifies how long expired flows\n"
     	 "                                    | (queued before delivery) are emitted\n"
	 "                                    | [default=%d]\n", readOnlyGlobals.sendTimeout);
  printf("[--scan-cycle|-s <scan cycle>]      | It specifies how often (seconds) expired\n"
	 "                                    | flows are emitted [default=%d].\n"
	 "                                    | If -P is used, the scan cycle will be\n"
	 "                                    | set to the value of the -F parameter\n",
	 readOnlyGlobals.scanCycle);
  printf("[--rebuild-hash|N]                  | Rebuild the hash at each scan. Useful for\n"
	 "                                    | producing flows that last as the scan\n"
	 "                                    | cycle as netflow collectors do. This\n"
	 "                                    | option is ignored when -P is not used.\n");
  printf("[--aggregation|-p] <aggregation>    | It specifies the flow aggiregation level:\n"
	 "                                    | <VLAN Id>/<proto>/<IP>/<port>/<TOS>/<AS>\n"
	 "                                    | where each element can be set to 0=ignore\n"
	 "                                    | or 1=take care. Example \'-p 1/0/1/1/1/1\'\n"
	 "                                    | ignores the protocol, whereas\n"
	 "                                    | \'-p 0/0/1/0/0/0\' ignores everything\n"
	 "                                    | but the IP\n");
  printf("[--bpf-filter|-f] <BPF filter>      | BPF filter for captured packets\n"
	 "                                    | [default=no filter]\n");
  printf("[--all-collectors|-a]               | If several collectors are defined, this\n"
         "                                    | option gives the ability to send all\n"
         "                                    | collectors all the flows. If the flag is\n"
	 "                                    | omitted collectors are selected in\n"
	 "                                    | round robin.\n");
  printf("[--verbose|-b] <level>              | Verbose output:\n"
         "                                    | 0 - No verbose logging\n"
	 "                                    | 1 - Limited logging (traffic statistics)\n"
         "                                    | 2 - Full verbose logging\n");

#ifndef WIN32
  printf("[--daemon-mode|-G]                  | Start as daemon.\n");
#endif
  printf("[--num-threads|-O] <# threads>      | Number of packet fetcher threads\n"
	 "                                    | [default=%u]. Use 1 unless you know\n"
	 "                                    | what you're doing.\n",
	 readOnlyGlobals.numProcessThreads);
  printf("[--dump-path|-P] <path>             | Directory where dump files will\n"
	 "                                    | be stored.\n");
  printf("[--dump-frequency|-F] <dump timeout>| Dump files dump frequencey (sec).\n"
         "                                    | Default: %d\n", readOnlyGlobals.file_dump_timeout);
  printf("[--dump-format|-D] <format>         | <format>: flows are saved as:\n"
	 "                                    | b       : raw/uncompressed flows\n"
	 "                                    | t       : text flows\n"
#ifdef HAVE_SQLITE
	 "                                    | d       : SQLite\n"
#endif
	 "                                    | Example: -D b. Note: this flag has no\n"
	 "                                    | effect without -P.\n");
  printf("[--in-iface-idx|-u] <in dev idx>    | Index of the input device used in the\n");
  printf("                                    | emitted flows (incoming traffic). The default\n"
	 "                                    | value is %d. Use -1 as value to dynamically\n"
	 "                                    | set to the last two bytes of\n"
	 "                                    | the MAC address of the flow sender.\n",
	 readOnlyGlobals.inputInterfaceIndex);
  printf("[--out-iface-idx|-Q] <out dev idx>  | Index of the output device used in the\n");
  printf("                                    | emitted flows (outgoing traffic). The default\n"
	 "                                    | value is %d. Use -1 as value to dynamically\n"
	 "                                    | set to the last two bytes of\n"
	 "                                    | the MAC address of the flow receiver.\n",
	 readOnlyGlobals.outputInterfaceIndex);
  printf("[--vlanid-as-iface-idx]             | Use vlanId (or 0 if the traffic isn't tagged)\n"
	 "                                    | as interface index. Note that this option\n"
	 "                                    | superseedes the --in/out-iface-idx options\n");
  printf("[--nprobe-version|-v]               | Prints the program version.\n");
  printf("[--flow-lock|-C] <flow lock>        | If the flow lock file is present no flows\n"
	 "                                    | are emitted. This facility is useful to\n"
	 "                                    | implement high availability by means of\n"
	 "                                    | a daemon that can create a lock file\n"
	 "                                    | when this instance is in standby.\n");
  printf("[--help|-h]                         | Prints this help.\n");
#ifndef WIN32
  printf("[--syslog|-I] <probe name>          | Log to syslog as <probe name>\n"
	 "                                    | [default=stdout]\n");
#endif
  printf("[--hash-size|-w] <hash size>        | Flows hash size [default=%d]\n",
	 readOnlyGlobals.flowHashSize);
  printf("[--no-ipv6|-W]                      | IPv6 packets/traffic will not be accounted\n");
  printf("[--flow-delay|-e] <flow delay>      | Delay (in ms) between two flow\n"
	 "                                    | exports [default=%d]\n",
	 readOnlyGlobals.flowExportDelay);
  printf("[--count-delay|-B] <packet count>   | Send this many packets before\n"
	 "                                    | the -e delay [default=%d]\n",
	 readOnlyGlobals.packetFlowGroup);

  if(readOnlyGlobals.minFlowSize == 0)
    strcpy(buf, "unlimited");
  else
    sprintf(buf, "%u", readOnlyGlobals.minFlowSize);
  printf("[--min-flow-size|-z] <min flow size>| Minimum TCP flow size (in bytes).\n"
	 "                                    | If a TCP flow is shorter than the\n"
	 "                                    | specified size the flow is not\n"
	 "                                    | emitted [default=%s]\n", buf);


  printf("[--max-num-flows|-M] <max num flows>| Limit the number of active flows. This is\n"
         "                                    | useful if you want to limit the memory\n"
	 "                                    | or CPU allocated to nProbe in case of non\n"
	 "                                    | well-behaved applications such as\n"
	 "                                    | worms or DoS. [default=%u]\n",
	 readOnlyGlobals.maxNumActiveFlows);
  printf("[--payload-length|-R] <payload Len> | Specify the max payload length\n"
	 "                                    | [default: %d bytes]\n", readOnlyGlobals.maxPayloadLen);
  printf("[--payload-policy|-x] <policy>      | Specify the max payload export policy.\n"
	 "                                    | Format: TCP:UDP:ICMP:OTHER where all\n"
	 "                                    | parameters can se set to:\n"
	 "                                    | 0: no payload for the selected protocol\n"
	 "                                    | 1: payload for the selected protocol\n"
	 "                                    | 2: payload for TCP sessions with SYN flag\n"
	 "                                    | Example -x 2:0:0:0 [default=%d:%d:%d:%d]\n",
	 readOnlyGlobals.tcpPayloadExport, readOnlyGlobals.udpPayloadExport,
	 readOnlyGlobals.icmpPayloadExport, readOnlyGlobals.otherPayloadExport);

  printf("[--netflow-engine|-E] <engine>      | Specify the engine type and id.\n"
	 "                                    | The format is engineType:engineId.\n"
	 "                                    | [default=%d:%d] where engineId is a\n"
	 "                                    | random number.\n",
	 readOnlyGlobals.engineType, readOnlyGlobals.engineId);
  printf("[--min-num-flows|-m] <min # flows>  | Minimum number of flows per packet\n"
	 "                                    | unless an expired flow is queued\n"
	 "                                    | for too long (see -l) [default=%d\n"
	 "                                    | for v5, dynamic for v9]\n",
	 V5FLOWS_PER_PAK);
  printf("[--sender-address|-q] <host:port>   | Specifies the address:port of the flow\n"
	 "                                    | sender. This optionis useful for hosts\n"
	 "                                    | with multiple interfaces or if flows\n"
	 "                                    | must be emitted from a static port\n");
  printf("[--sample-rate|-S] <pkt rate>:<flow rate>\n"
	 "                                    | Packet capture sampling rate and flow\n"
	 "                                    | sampling rate. If <pkt rate> starts with '@'\n"
	 "                                    | it means that nprobe will report the specified\n"
	 "                                    | sampling rate but will not sample itself\n"
	 "                                    | as incoming packets are already sampled\n"
	 "                                    | on the specified capture device at the\n"
	 "                                    | specified rate. Default: 1:1 [no sampling]\n");
  printf("[--as-list|-A] <AS list>            | GeoIP file containing the list of known ASs.\n"
	 "                                    | Example: GeoIPASNum.dat\n");
  printf("[--city-list] <City list>           | GeoIP file containing the city/IP mapping.\n"
	 "                                    | Example: GeoLiteCity.dat\n");
  printf("[--pid-file|-g] <PID file>          | Put the PID in the specified file\n");
  printf("[--flow-templ|-T] <flow template>   | Specify the NFv9 template (see below).\n");
  printf("[--flow-templ-id|-U] <templ. id>    | Specify the NFv9 template identifier\n"
	 "                                    | [default: %d]\n", readOnlyGlobals.idTemplate);
  printf("[--flow-version|-V] <version>       | NetFlow Version: 5=v5, 9=v9, 10=IPFIX\n");
  printf("[--flows-intra-templ|-o] <num>      | Specify how many flow pkts are exported\n"
	 "                                    | between template exports [default: %d]\n",
	 readOnlyGlobals.templatePacketsDelta);
  printf("[--local-networks|-L] <nets>        | Specify the list of local networks whose\n"
	 "                                    | format is <net>/<mask> (if multiple use comma).\n");
  printf("[--local-hosts-only|-c]             | All the IPv4 hosts outside the local\n"
	 "                                    | network lists will be set to 0.0.0.0\n"
	 "                                    | (-L must be specified before -c).\n"
	 "                                    | This reduces the load on the probe\n"
	 "                                    | instead of discarding flows on the\n"
	 "                                    | collector side.\n");
  printf("[--local-traffic-direction|-r]      | All the traffic going towards\n"
	 "                                    | the local networks (-L must also be\n"
	 "                                    | specified before -r) is assumed incoming\n"
	 "                                    | traffic all the rest is assumed outgoing\n"
	 "                                    | (see also -u and -Q).\n");
  printf("[--if-networks|-1] <nets>           | Specify the binding between interfaceId\n"
	 "                                    | and a network (see below).\n");
  printf("[--count|-2] <number>               | Capture a specified number of packets\n"
	 "                                    | and quit (debug only)\n");
  printf("[--collector-port|-3] <port>        | NetFlow/sFlow collector port for incoming flows\n");
#ifdef linux
  printf("[--cpu-affinity|-4] <CPU/Core Id>   | Binds this process to the specified CPU/Core\n"
	 "                                    | Note: the first available CPU corresponds to 0.\n");
#endif
  printf("[--tunnel|-5]                       | Compute flows on tunneled traffic rather than\n"
	 "                                    | on the external envelope\n");
  printf("[--no-promisc|-6]                   | Capture packets in non-promiscuous mode\n");
  printf("[--smart-udp-frags|-7]              | Ignore UDP fragmented packets with fragment offset\n"
	 "                                    | greater than zero, and compute the fragmented\n"
	 "                                    | packet length on the initial fragment header.\n");
  printf("[--ipsec-auth-data-len|-8] <len>    | Length of the authentication data of IPSec\n"
	 "                                    | in tunnel mode. If not set, IPSec will not be decoded\n");
  printf("[--dump-stats|-9] <path>            | Periodically dump traffic stats into the\n"
	 "                                    | specified file\n");
  printf("--black-list <networks>             | All the IPv4 hosts inside the networks\n"
         "                                    | black-list will be discarded.\n"
         "                                    | This reduces the load on the probe\n"
         "                                    | instead of discarding flows on the\n"
         "                                    | collector side.\n");
  printf("--pcap-file-list <filename>         | Specify a filename containing a list\n"
	 "                                    | of pcap files.\n"
	 "                                    | If you use this flag the -i option will be\n"
	 "                                    | ignored.\n");
  printf("--csv-separator <separator>         | Specify the separator for text files (see -P)\n"
	 "                                    | Default is '|' (pipe)\n");
#ifdef HAVE_FASTBIT
  printf("--fastbit <dir>                     | Base directory where FastBit files will be created.\n");
  printf("--fastbit-rotation <mins>           | Every <mins> minutes a new FastBit sub-directory is created\n"
	 "                                    | so that each directory contains at most <mins> minutes.\n"
	 "                                    | Default %d min(s).\n",
	 readOnlyGlobals.fastbit_mins_rotation);
  printf("--fastbit-template <flow template>  | Fields that will be dumped on FastBit partition. Its syntax\n"
	 "                                    | is the same as the -T flag. If this flag is not specified,\n"
	 "                                    | all the specified flow elements (-T) will be dumped.\n");
  printf("--fastbit-index <flow template>     | Index each directory containing FastBit files as soon as\n"
	 "                                    | the directory has been dumped. The flow template specifies\n"
	 "                                    | which columns will be indexed. Its syntax is the same as\n"
	 "                                    | the -T flag. This option requires that fbindex application\n"
	 "                                    | is installed or built. If this flag is not specified, all\n"
	 "                                    | columns will be indexed.\n");
  printf("--fastbit-exec <cmd>                | Execute the specified command after a directory has been\n"
         "                                    | dumped (and optionally indexed). The command must take an\n"
	 "                                    | argument that is the path to the directory just dumped.\n");
#endif
#ifndef WIN32
  printf("--dont-drop-privileges              | Do not drop privileges changing to user nobody\n");
#endif
  printf("--bi-directional                    | Force flows to be bi-directional. This option\n"
	 "                                    | is not supported by NetFlow V5 that by nature\n"
	 "                                    | supports only mono-directional flows\n");
  printf("--account-l2                        | NetFlow accounts IP traffic only, not counting\n"
	 "                                    | L2 headers. Using this option the L2 headers\n"
	 "                                    | are also accounted\n");
  printf("--dump-metadata <file>              | Dump flow metadata into the specified file\n"
	 "                                    | and quit\n");
  printf("--event-log <file>                  | Dump relevant activities into the specified log file\n");

  printf("\nFurther plugin available command line options\n");
  printf("---------------------------------------------------\n");
  initPlugins(0, NULL);
  dumpPluginHelp();

  printf("\n\nNote on interface indexes and (router) MAC/IP addresses\n"
	 "---------------------------------------------------\n"
	 "Flags -u and -Q are used to specify the SNMP interface identifiers for emitted flows.\n"
	 "However using -L it is possible to specify an interface identifier to which a MAC\n"
	 "address or IP network is bound. The syntax of -L is: <MAC|IP/mask>@<interfaceId>\n"
	 "where multiple entries can be separated by a comma (,). Example:\n"
	 "-L \"AA:BB:CC:DD:EE:FF@3,192.168.0.0/24@2\" or -L @<fileaname> where <filename>\n"
	 "is a file path containing the networks specified using the above format.\n");

#ifdef WIN32
  (void)printAvailableInterfaces("-1");
#endif
  printf("\nNetFlow v9/IPFIX format [-T]"
	 "\n----------------"
	 "\nThe following options can be used to specify the format:\n"
	 "\n ID   Flow Label                Description\n"
	 "------------------------------------------------\n");

  printTemplateInfo(ver9_templates, 0);
  dumpPluginTemplates();

  /* ************************************************ */

  printf("\nExample: nprobe -T \"%s\"\n", DEFAULT_V9_IPV4_TEMPLATE);

  printf("\n");
  printf("nProbe shut down\n");
  exit(0);
}

/* ****************************************************** */

static void dumpStats(char *path) {
  FILE *fd = fopen(path, "w");

  if(fd) {
    fprintf(fd,
	    "# time totalPkts totalBytes totFlows\n"
	    "%u %u %u %u\n",
	    (unsigned int)time(NULL),
	    (unsigned int)readWriteGlobals->accumulateStats.pkts,
	    (unsigned int)readWriteGlobals->accumulateStats.bytes,
	    (unsigned int)readWriteGlobals->totFlows);
    fclose(fd);
  } else
    traceEvent(TRACE_WARNING, "Unable to create file %s", path);
}

/* ****************************************************** */

static void printStats(int force) {
  time_t now = time(NULL), nowDiff;
  char pktBuf[32], buf[1024] = { 0 };

  readWriteGlobals->now = now;
  nowDiff = now-readOnlyGlobals.initialSniffTime.tv_sec;

  if(!force) {
    /* Wait at least 5 seconds */
    if((nowDiff < 5)
       /* || (readWriteGlobals->accumulateStats.pkts == 0) */
       )
      return;
  }

  if(readOnlyGlobals.dump_stats_path != NULL)
    dumpStats(readOnlyGlobals.dump_stats_path);

  if(readOnlyGlobals.traceMode) {
    u_int tot_frags, i;

    traceEvent(TRACE_NORMAL, "---------------------------------");
    traceEvent(TRACE_NORMAL, "Average traffic: [%s pps][%s/sec]",
	       formatPackets((float)readWriteGlobals->accumulateStats.pkts/nowDiff, pktBuf),
	       formatTraffic((float)(8*readWriteGlobals->accumulateStats.bytes)/(float)nowDiff, 1, buf));

    nowDiff = now-readWriteGlobals->lastSample;
    traceEvent(TRACE_NORMAL, "Current traffic: [%s pps][%s/sec]",
	       formatPackets((float)readWriteGlobals->currentPkts/nowDiff, pktBuf),
	       formatTraffic((float)(8*readWriteGlobals->currentBytes)/(float)nowDiff, 1, buf));
    readWriteGlobals->lastSample = readWriteGlobals->now;
    readWriteGlobals->currentBytes = readWriteGlobals->currentPkts = 0;

    traceEvent(TRACE_NORMAL, "Current flow export rate: [%.1f flows/sec]",
	       (float)readWriteGlobals->totFlowsRate/nowDiff);

    traceEvent(TRACE_NORMAL, "Drops: [export queue too long=%u][too many flows=%u]",
	       readWriteGlobals->probeStats.totFlowDropped, readWriteGlobals->probeStats.droppedPktsTooManyFlows);
    readWriteGlobals->totFlowsRate = 0;

    for(tot_frags=0, i=0; i<NUM_FRAGMENT_LISTS; i++) tot_frags += readWriteGlobals->fragmentListLen[i];

    traceEvent(TRACE_NORMAL, "Buckets: [active=%u][allocated=%u][toBeExported=%u][frags=%u]",
	       readWriteGlobals->bucketsAllocated-readWriteGlobals->exportBucketsLen,
	       readWriteGlobals->bucketsAllocated,
	       readWriteGlobals->exportBucketsLen, tot_frags);

    for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
      PacketQueue *queue = &readWriteGlobals->packetQueue[i];
      traceEvent(TRACE_NORMAL, "Queue %d: [num_queued_pkts: %u][num_dequeued_pkts: %u][num_drops: %u][queue_len: %u]",
		 i, queue->num_queued_pkts, queue->num_dequeued_pkts, 
		 queue->queue_full_num_drops, queuedPkts(queue));
    }

    buf[0] = '\0';
    for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {     
      if(readWriteGlobals->collectedPkts[i] > 0) {
	u_int len = strlen(buf);

	snprintf(&buf[len], sizeof(buf)-len, "%lu@%d ", 
		 readWriteGlobals->collectedPkts[i], i);
      }
    }

    if(buf[0] != '\0')
      traceEvent(TRACE_NORMAL, "Collector Threads: [ %s]", buf);
 }

  if(readOnlyGlobals.traceMode) {
    u_int num_collected_pkts = 0, i;
    
    for(i=0; i<readOnlyGlobals.numProcessThreads; i++)
      num_collected_pkts += readWriteGlobals->collectedPkts[i];

    traceEvent(TRACE_INFO, "Processed packets: %u (max bucket search: %d)",
	       (unsigned long)readWriteGlobals->accumulateStats.pkts,
	       readWriteGlobals->maxBucketSearch);
    traceEvent(TRACE_INFO, "Flow Collection: [collected pkts: %u][processed flows: %u]",
	       num_collected_pkts, readWriteGlobals->collectionStats.num_flows_processed);
  } else {
    if(readWriteGlobals->maxBucketSearch > readWriteGlobals->lastMaxBucketSearch) {
      traceEvent(TRACE_INFO, "Max bucket search: %d slots (for better "
		 "performance a larger value for -w)",
		 readWriteGlobals->maxBucketSearch);
      readWriteGlobals->lastMaxBucketSearch = readWriteGlobals->maxBucketSearch;
    }
  }

  readWriteGlobals->maxBucketSearch = 0; /* reset */

  if(readOnlyGlobals.pcapPtr)
    printPcapStats(readOnlyGlobals.pcapPtr);
}

/* ****************************************************** */

int resolveIpV4Address(char *addr, int port) {
  struct hostent *hostAddr;
  struct in_addr dstAddr;

  if((hostAddr = gethostbyname(addr)) == NULL) {
    traceEvent(TRACE_ERROR, "Unable to resolve address '%s'\n", addr);
    return(-1);
  }

  memset(&readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors], 0, sizeof(CollectorAddress));
  memcpy(&dstAddr.s_addr, hostAddr->h_addr_list[0], hostAddr->h_length);
  readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd = -1;
  readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].isIPv6 = 0;
  readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v4Address.sin_addr.s_addr = dstAddr.s_addr;
  readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v4Address.sin_family      = AF_INET;
  readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v4Address.sin_port        = (int)htons(port);

  return(0);
}

/* ****************************************************** */

#ifndef IPV4_ONLY

int resolveIpV6Address(char *addr, int port, int *isIpV6Address) {
  int errnum;
  struct addrinfo hints, *res;

  if((readOnlyGlobals.useIpV6 == 0) || !strstr(addr, ":")) {
    (*isIpV6Address) = 0;
    return(resolveIpV4Address(addr, port));
  }

  (*isIpV6Address) = 0;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  errnum = getaddrinfo(addr, NULL, &hints, &res);
  if(errnum != 0) {
    traceEvent(TRACE_INFO, "Unable to resolve address '%s' [error=%d]\n",
	       addr, errnum);
    return(-1);
  }

  if(res->ai_family == PF_INET6) {
    (*isIpV6Address) = 1;
    memset(&readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors], 0, sizeof(CollectorAddress));
    readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].isIPv6 = 1;
    memcpy(&readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v6Address, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v6Address.sin6_port = (int)htons(port);
    return(0);
  } else {
    freeaddrinfo(res);
    (*isIpV6Address) = 0;
    return(resolveIpV4Address(addr, port));
  }
}

#endif

/* ****************************************************** */

#define PROTO_UDP_URL       "udp://"
#define PROTO_TCP_URL       "tcp://"
#define PROTO_SCTP_URL      "sctp://"

int initNetFlow(char* addr, int port) {
  int sockopt = 1, rc, isIpV6Address = 0;
  char *address;
  u_char transport = TRANSPORT_UDP;

  if(readOnlyGlobals.numCollectors >= MAX_NUM_COLLECTORS) {
    traceEvent(TRACE_INFO,
	       "Unable to define further collector address "
	       "(max %d collectors allowed)\n", MAX_NUM_COLLECTORS);
    return(-1);
  }

  if(strncmp(addr, PROTO_UDP_URL, strlen(PROTO_UDP_URL)) == 0)
    transport = TRANSPORT_UDP, address = &addr[strlen(PROTO_UDP_URL)];
  else if(strncmp(addr, PROTO_TCP_URL, strlen(PROTO_TCP_URL)) == 0)
    transport = TRANSPORT_TCP, address = &addr[strlen(PROTO_TCP_URL)];
  else if(strncmp(addr, PROTO_SCTP_URL, strlen(PROTO_SCTP_URL)) == 0) {
#ifdef HAVE_SCTP
    transport = TRANSPORT_SCTP;
#else
    traceEvent(TRACE_ERROR, "SCTP isn't supported on your system. Using UDP.");
    transport = TRANSPORT_UDP;
#endif
    address = &addr[strlen(PROTO_SCTP_URL)];
  } else
    transport = TRANSPORT_UDP, address = addr;

#ifdef IPV4_ONLY
  rc = resolveIpV4Address(address, port);
#else
  if(readOnlyGlobals.useIpV6) {
    rc = resolveIpV6Address(address, port, &isIpV6Address);
    if(!isIpV6Address) readOnlyGlobals.useIpV6 = 0;
  } else
    rc = resolveIpV4Address(address, port);
#endif

  if(rc != 0)  return(-1);

  /* Initialize the socket descriptor, so that it looks like it is not opened yet */
  readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd = -1;

  if(readOnlyGlobals.sockIn.sin_addr.s_addr == 0) {
    if(readOnlyGlobals.useIpV6) {
      if(transport == TRANSPORT_UDP)
	readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd = socket(AF_INET6, SOCK_DGRAM, 0);
      else if(transport == TRANSPORT_TCP)
	readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd = socket(AF_INET6, SOCK_STREAM, 0);
#ifdef HAVE_SCTP
      else if(transport == TRANSPORT_SCTP)
	readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd = socket(AF_INET6, SOCK_SEQPACKET,
						   IPPROTO_SCTP);
#endif
    }
    if(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd == -1) {
      readOnlyGlobals.useIpV6 = 0; /* No IPv6 ? */
      if(transport == TRANSPORT_UDP)
	readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd = socket(AF_INET, SOCK_DGRAM, 0);
      else if(transport == TRANSPORT_TCP)
	readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef HAVE_SCTP
      else if(transport == TRANSPORT_SCTP)
	readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd = socket(AF_INET, SOCK_SEQPACKET,
						   IPPROTO_SCTP);
#endif
    }
  }

#ifdef IP_HDRINCL
  else {
    int tmp = 1;

    if(transport != TRANSPORT_UDP) {
      transport = TRANSPORT_UDP;
      traceEvent(TRACE_WARNING,
		 "Unable to use a transport different from UDP");
      traceEvent(TRACE_WARNING, "when -q is used. Reverting to UDP.");
    }

    readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd == -1) {
      traceEvent(TRACE_ERROR, "Fatal error while creating socket (%s).",
		 strerror(errno));
#ifndef WIN32
      if((getuid() && geteuid()) || setuid (0)) {
	traceEvent(TRACE_ERROR, "You probably need superuser capabilities. "
		   "Please try again.");
      }
#endif

      exit(-1);
    }

    transport = TRANSPORT_UDP_RAW;
    /* Tell that we specify the IP header */
    setsockopt(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd, 0, IP_HDRINCL,
	       &tmp, sizeof(tmp));
  }
#endif

  setsockopt(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd, SOL_SOCKET, SO_REUSEADDR,
	     (char *)&sockopt, sizeof(sockopt));

  if(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd == -1) {
    traceEvent(TRACE_INFO, "Fatal error while creating socket (%s).",
	       strerror(errno));
    exit(-1);
  }

  readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].transport = transport;

  if(transport == TRANSPORT_TCP) {
    int rc;

    traceEvent(TRACE_INFO, "Connecting to %s:%d...", addr, port);

#ifndef IPV4_ONLY
    if(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].isIPv6)
      {
	char col[100];

	inet_ntop(AF_INET6, &readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v6Address, col, sizeof(col));
	rc = connect(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd,
		     (struct sockaddr *)&readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v6Address,
		     sizeof(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v6Address));
      }
    else
#endif
      {
	rc = connect(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd,
		     (struct sockaddr *)&readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v4Address,
		     sizeof(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v4Address));
      }

    if(rc == -1) {
      char msg[256], buf[64];

      snprintf(msg, sizeof(msg), "Connection failed with remote peer %s [%s]. Leaving.",
	       CollectorAddress2Str(&readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors], buf, sizeof(buf)),
	       strerror(errno));

      traceEvent(TRACE_ERROR, "%s", msg);
      dumpLogEvent(collector_connection_error, severity_error, msg);
      close(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd);
      exit(-1);
    } else {
      char buf[64], msg[256];

      snprintf(msg, sizeof(msg), "Succesfully connected with remote collector %s",
	       CollectorAddress2Str(&readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors], buf, sizeof(buf)));

      dumpLogEvent(collector_connected, severity_info, msg);
    }
  } else if(transport == TRANSPORT_UDP) {
    maximize_socket_buffer(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd, SO_SNDBUF);
  }

  readOnlyGlobals.numCollectors++;

  if(strstr(address, ":"))
    traceEvent(TRACE_INFO, "Exporting flows towards [%s]:%d using %s",
	       addr, port,
	       ((transport == TRANSPORT_UDP)
#ifdef IP_HDRINCL
		|| (transport == TRANSPORT_UDP_RAW)
#endif
		) ? "UDP" :
	       (transport == TRANSPORT_TCP ? "TCP" : "SCTP"));
  else
    traceEvent(TRACE_INFO, "Exporting flows towards %s:%d using %s",
	       addr, port,
	       ((transport == TRANSPORT_UDP)
#ifdef IP_HDRINCL
		|| (transport == TRANSPORT_UDP_RAW)
#endif
		) ? "UDP" :
	       (transport == TRANSPORT_TCP ? "TCP" : "SCTP"));

  return(0);
}

/* ****************************************************** */

void printHash(int idx) {
  u_int i;

  for(i = 0; i<readOnlyGlobals.flowHashSize; i++) {
    if(readWriteGlobals->theFlowHash[idx][i] != NULL)
      printf("readWriteGlobals->theFlowHash[%4d]\n", i);
  }
}

/* ****************************************************** */

void dumpBuffer(char *buffer, int bufferLength) {
  int i;

  if(bufferLength > 512) bufferLength = 512;

  for(i=0; i<bufferLength; i++) {
    if(!(i % 8)) printf("\n");
    printf("%3d[%02x] ", i, buffer[i] & 0xFF );
  }

  printf("\n");
}

/* ****************************************************** */

static void checkExportQueuedFlows(int forceExport) {
  checkNetFlowExport(forceExport);
}

/* ****************************************************** */

static void readPcapFileList(const char * filename) {
  char line[512];

  FILE *fd = fopen(filename, "r");

  if(fd != NULL) {
    struct fileList *fl, *prev;

    while(!feof(fd)) {
      if(fgets(line, sizeof(line)-1, fd) == NULL) continue;
      if((line[0] == '#') || (line[0] == '\n')) continue;
      while(strlen(line) && (line[strlen(line)-1] == '\n')) line[strlen(line)-1] = '\0';

      fl = (struct fileList*)malloc(sizeof(struct fileList));

      if(!fl) {
	traceEvent(TRACE_ERROR, "Not enough memory parsing --pcap-file-list argument");
	fclose(fd);
	return;
      }

      fl->path = strdup(line);

      if(!fl->path) {
	free(fl);
        traceEvent(TRACE_ERROR, "Not enough memory parsing --pcap-file-list argument");
        fclose(fd);
        return;
      }

      fl->next = NULL;

      if(readOnlyGlobals.pcapFileList) {
	prev = readOnlyGlobals.pcapFileList;
	while(prev != NULL) {
	  if(prev->next)
	    prev = prev->next;
	  else
	    break;
	}

	prev->next = fl;
      } else
	readOnlyGlobals.pcapFileList = fl;
    }

    fclose(fd);
  } else
    traceEvent(TRACE_ERROR, "Unable to open file %s", optarg);
}

/* ****************************************************** */

static void initDefaults(void) {
  memset(&readOnlyGlobals.sockIn, 0, sizeof(readOnlyGlobals.sockIn));

  /* Set defaults */
  readOnlyGlobals.netFlowVersion = 5; /* NetFlow v5 */
  readOnlyGlobals.bidirectionalFlows = 0;
  readOnlyGlobals.ignorePorts = readOnlyGlobals.ignorePorts = readOnlyGlobals.ignoreProtocol = 0;
  readOnlyGlobals.ignoreIP = readOnlyGlobals.ignoreIP = 0, readOnlyGlobals.ignoreTos = 0;
#ifdef HAVE_GEOIP
  readOnlyGlobals.geo_ip_asn_db = NULL;
#endif
  readOnlyGlobals.numCollectors = 0;
  readOnlyGlobals.flowHashSize = DEFAULT_HASH_SIZE;
  readOnlyGlobals.hostHashSize = readOnlyGlobals.flowHashSize/2;
  readOnlyGlobals.initialSniffTime.tv_sec = 0; /* Set it with the first incoming packet */
  readOnlyGlobals.snaplen = PCAP_DEFAULT_SNAPLEN;
  readOnlyGlobals.pcapFileList = NULL;
  readOnlyGlobals.pcapFile = NULL;
  readOnlyGlobals.reflectorMode = 0;
  readOnlyGlobals.minFlowSize = 0;
  readOnlyGlobals.traceMode = 0;
  readOnlyGlobals.flowExportDelay = 1, readOnlyGlobals.packetFlowGroup = 1;
  readOnlyGlobals.engineType = 0, readOnlyGlobals.engineId = time(NULL) /* dynamic */;
  readOnlyGlobals.useNetFlow = 0xFF;
  readOnlyGlobals.use_vlanId_as_ifId = 0;
  readOnlyGlobals.tcpPayloadExport = 2, readOnlyGlobals.udpPayloadExport
    = readOnlyGlobals.icmpPayloadExport = readOnlyGlobals.otherPayloadExport = 0;
  readOnlyGlobals.stringTemplateV4 = readOnlyGlobals.stringTemplateV6 = NULL;
  readOnlyGlobals.dirPath = NULL;
  readOnlyGlobals.maxPayloadLen = 0;
  readOnlyGlobals.minNumFlowsPerPacket = -1;
  readOnlyGlobals.pktSampleRate = 1;
  readOnlyGlobals.fakePktSampling = 0;
  readOnlyGlobals.flowSampleRate = 1;
  readOnlyGlobals.numInterfaceNetworks = 0;
  readOnlyGlobals.numBlacklistNetworks = 0;
  readOnlyGlobals.roundPacketLenWithIPHeaderLen = 1;

  readWriteGlobals->bufferLenV4 = readWriteGlobals->bufferLenV6 = 0;
  readWriteGlobals->numFlows = 0;
  readWriteGlobals->lastExportTime.tv_sec = 0, readWriteGlobals->lastExportTime.tv_usec = 0;
  readWriteGlobals->num_src_mac_export = 0;

  initAS();
}

/* ****************************************************** */

static int parseOptions(int argc, char* argv[], u_int8_t reparse_options) {
  int _argc, id;
  char *_argv[MAX_NUM_OPTIONS], *theItem;
  char line[2048];
  FILE *fd;
  int opt, i, opt_n = 0;
  u_char mandatoryParamOk=0;

  if(!reparse_options)
    initDefaults();
  
    optind = 0;
#ifdef HAVE_OPTRESET
    optreset = 1; /* Make sure getopt read options again */
#endif

  if((argc == 2) && (argv[1][0] != '-')) {
    char *tok, cont=1;

    fd = fopen(argv[1], "r");

    if(fd == NULL) {
      traceEvent(TRACE_ERROR, "Unable to read config. file %s", argv[1]);
      exit(-1);

    }
    _argc = 0;
    _argv[_argc++] = strdup("nprobe");

    while(cont && fgets(line, sizeof(line), fd)) {
      /* printf("line='%s'\n", line); */

      /*
	Config files accept both
	<option>=<value>
	and
	<option> <value>
      */
      i = 0;
      while(line[i] != '\0') {
	if(line[i] == '=')
	  break;
	else if(line[i] == ' ') {
	  line[i] = '=';
	  break;
	}

	i++;
      }

      tok = strtok(line, "=");

      while(tok != NULL) {
	int len;
	char *argument;

	if(_argc >= MAX_NUM_OPTIONS) {
	  traceEvent(TRACE_ERROR, "Command line too long");
	  cont = 0; break;
	}

	len = strlen(tok)-1;
	if(tok[len] == '\n') tok[len] = '\0';

	if((tok[0] == '\"') && (tok[strlen(tok)-1] == '\"')) {
	  tok[strlen(tok)-1] = '\0';
	  argument = &tok[1];
	} else
	  argument = tok;

	if(argument && (argument[0] != '\0')) {
	  /* traceEvent(TRACE_NORMAL, "_argv[%d]='%s'", _argc, argument); */
	  _argv[_argc++] = strdup(argument);
	}

	tok = strtok(NULL, "\n");
      }
    }

    fclose(fd);
  } else {
    if(reparse_options) {
      traceEvent(TRACE_WARNING, "Command line options can be reloaded only when");
      traceEvent(TRACE_WARNING, "the probe is started from a configuration file");
      traceEvent(TRACE_WARNING, "Please use nprobe <configuration file>");
      return(-1);
    }

    if(argc >= MAX_NUM_OPTIONS)
      _argc = MAX_NUM_OPTIONS-1;
    else
      _argc = argc;

    /* Copy arguments */
    for(i=0; i<_argc; i++) {
      _argv[i] = strdup(argv[i]);
    }
  }

#ifdef IPV4_ONLY
  readOnlyGlobals.useIpV6 = 0;
#else
  readOnlyGlobals.useIpV6 = 1;
#endif
  optarg = NULL;

  while((opt = getopt_long(_argc, _argv,
			   "A:ab:B:c"
			   "C:d:D:e:E:f:F:g:hi:I:l:L:"
#ifdef IP_HDRINCL
			   "q:"
#endif
			   "M:m:Nn:o:O:p:P:Q:rR:s:S:t:T:u:U:w:Wx:vV:z:"
#ifndef WIN32
			   "G"
#endif
#if defined(linux) || defined(__linux__)
			   "X4:"
#endif

			   "1:2:3:a:"
			   "5678:9:!:@"
#if !defined(WIN32)
			   "$:\\"
#endif
			   ,
			   long_options,
			   NULL
			   )) != EOF) {
    if(reparse_options) {
      u_int discard_option;

      switch(opt) {
      case 'b':
      case 'B':
      case 'd':
      case 'e':
      case 'E':
      case 'F':
      case 'l':
      case 'm':
      case 'M':
      case 'o':
      case 'Q':
      case 's':
      case 'S':
      case 'T':
      case 't':
      case 'u':
      case 'U':
      case '5':
      case '7':
      case '8':
      case '^':
      case '{':
      case '}':
      case '+':
	discard_option = 0;
	break;

      default:
	discard_option = 1;
      }

      if(discard_option) {
	traceEvent(TRACE_WARNING, "The %c option cannot be modified at runtime: ignored", opt);
	continue;
      }
    }

    switch (opt) {
    case '1':
      parseInterfaceAddressLists(optarg);
      break;
    case '2':
      readOnlyGlobals.capture_num_packet_and_quit = atoi(optarg);
      break;
    case '3':
      readOnlyGlobals.collectorInPort = atoi(optarg);
      break;
#ifdef linux
    case '4':
      readOnlyGlobals.cpuAffinity = strdup(optarg);
      break;
#endif
    case '5':
      readOnlyGlobals.tunnel_mode = 1;
      break;
    case '6':
      readOnlyGlobals.promisc_mode = 0;
      break;
    case '7':
      readOnlyGlobals.smart_udp_frags_mode = 1;
      break;
    case '8':
      readOnlyGlobals.ipsec_auth_data_len = atoi(optarg);
      break;
    case '9':
      readOnlyGlobals.dump_stats_path = strdup(optarg);
      break;
    case '!':
      parseBlacklistNetworks(optarg);
      break;
    case '@':
      readOnlyGlobals.use_vlanId_as_ifId = 1;
      break;
    case '$':
      readPcapFileList(optarg);
      break;
    case '\\':
      readOnlyGlobals.do_not_drop_privileges = 1;
      break;
    case '^':
      if(readOnlyGlobals.csv_separator) free(readOnlyGlobals.csv_separator);
      readOnlyGlobals.csv_separator = strdup(optarg);
      break;
    case ',':
      readCities(optarg);
      break;
#ifdef HAVE_FASTBIT
    case '[':
      {
	int len;

	if(readOnlyGlobals.fastbit_dump_directory != NULL)
	  free(readOnlyGlobals.fastbit_dump_directory);

	readOnlyGlobals.fastbit_dump_directory = strdup(optarg);
	len = strlen(readOnlyGlobals.fastbit_dump_directory);
	if(readOnlyGlobals.fastbit_dump_directory[len-1] ==
#ifdef WIN32
	   '\\'
#else
	   '/'
#endif
	   )
	  readOnlyGlobals.fastbit_dump_directory[len-1] = '\0';
      }
      break;

    case ']':
      readOnlyGlobals.fastbit_mins_rotation = atoi(optarg);
      if(readOnlyGlobals.fastbit_mins_rotation == 0)
	readOnlyGlobals.fastbit_mins_rotation = 1;
      break;

    case '(':
      readOnlyGlobals.fastbit_dump_template = strdup(optarg);
      break;

#ifndef WIN32
    case ')':
      readOnlyGlobals.fastbit_index_directory = 1;
      readOnlyGlobals.fastbit_index_columns = strdup(optarg);
      break;
#endif

    case '#':
      readOnlyGlobals.fastbit_exec = strdup(optarg);
      break;
#endif

    case '{':
      readOnlyGlobals.bidirectionalFlows = 1;
      break;
    case '}':
      readOnlyGlobals.accountL2Traffic = 1;
      break;
    case '=':
      {
	FILE *fd = fopen(optarg, "w");

	if(fd) {
	  initPlugins(0, NULL);
	  printMetadata(fd);
	  fclose(fd);
	  traceEvent(TRACE_NORMAL, "Dumped metadata on file %s", optarg);
	} else
	  traceEvent(TRACE_ERROR, "Unable to create file %s", optarg);

	exit(0);
      }
      break;

    case '+':
      {
	char *old = readOnlyGlobals.eventLogPath;

	readOnlyGlobals.eventLogPath = strdup(optarg);
	if(old == NULL) free(old);
      }
      break;

    case 'A':
      readASs(optarg);
      break;
    case 'a':
      readOnlyGlobals.reflectorMode = 1;
      break;
    case 'b':
      i = atoi(optarg);
      if(i > 2) i = 2;
      switch(i) {
      case 1:
	readOnlyGlobals.traceMode = 1, readOnlyGlobals.traceLevel = 5;
	break;
      case 2:
	readOnlyGlobals.traceMode = 2, readOnlyGlobals.traceLevel = 5;
	break;
      case 0:
      default:
	readOnlyGlobals.traceMode = 0, readOnlyGlobals.traceLevel = 2;
	break;
      }
      break;
    case 'B':
      readOnlyGlobals.packetFlowGroup = atoi(optarg);
      break;
    case 'c':
      if(readOnlyGlobals.numInterfaceNetworks == 0) {
	traceEvent(TRACE_WARNING, "Ignored -c: it must be specified after -L");
      } else
	readOnlyGlobals.setAllNonLocalHostsToZero = 1;
      break;
    case 'C':
      readOnlyGlobals.flowLockFile = strdup(optarg);
      break;
    case 'P':
      if(optarg[0] != '\0') {
	readOnlyGlobals.dirPath = strdup(optarg);
	if(readOnlyGlobals.dirPath[strlen(readOnlyGlobals.dirPath)-1] == '/') readOnlyGlobals.dirPath[strlen(readOnlyGlobals.dirPath)-1] = '\0';
      }
      break;
    case 'D':
      if(optarg[0] == 't')      readOnlyGlobals.dumpFormat = text_format;
      else if(optarg[0] == 'd') readOnlyGlobals.dumpFormat = sqlite_format;
      else if(optarg[0] == 'b') readOnlyGlobals.dumpFormat = binary_format;
      else traceEvent(TRACE_WARNING, "Invalid -D option '%s': ignored", optarg);
      break;
    case 'd':
      readOnlyGlobals.idleTimeout = atoi(optarg);
      break;
    case 'E':
      theItem = strtok(optarg, ":");
      if(theItem == NULL) {
	traceEvent(TRACE_WARNING, "WARNING: Wrong engine specified (-E flag): see help.");
      } else {
	readOnlyGlobals.engineType = (u_int8_t)atoi(theItem);
	theItem = strtok(NULL, ":");

	if(theItem == NULL) {
	  traceEvent(TRACE_WARNING, "WARNING: Wrong engine specified (-E flag): see help.");
	} else
	  readOnlyGlobals.engineId = (u_int8_t)atoi(theItem);
      }
      break;
    case 'e':
      readOnlyGlobals.flowExportDelay = atoi(optarg);
      if(readOnlyGlobals.flowExportDelay >= 1000) {
	/*
	  NOTE

	  A value of 1000 or more ms will not allow nanosleep to
	  operate properly as 1000 ms = 1 sec and nanosleep does
	  not accept ms sleeps of 1000 or more ms
	*/
	traceEvent(TRACE_WARNING, "Maximum flow export delay is 999 ms");
	readOnlyGlobals.flowExportDelay = 999;
      }
      break;
    case 'g':
      readOnlyGlobals.pidPath = strdup(optarg);
      break;
    case 'O':
      readOnlyGlobals.numProcessThreads = atoi(optarg);
      if(readOnlyGlobals.numProcessThreads > MAX_NUM_PCAP_THREADS) {
	traceEvent(TRACE_ERROR, "You can spawn at most %d threads.",
		   MAX_NUM_PCAP_THREADS);
	readOnlyGlobals.numProcessThreads = MAX_NUM_PCAP_THREADS;
      }

      if(readOnlyGlobals.numProcessThreads <= 0) readOnlyGlobals.numProcessThreads = 1;
      break;
    case 'f':
      if((optarg[0] == '\"') || (optarg[0] == '\'')) {
	readOnlyGlobals.netFilter = strdup(&optarg[1]);
	readOnlyGlobals.netFilter[strlen(readOnlyGlobals.netFilter)-2] = '\0';
      } else {
	readOnlyGlobals.netFilter = strdup(optarg);
      }
      break;
    case 'F':
      readOnlyGlobals.file_dump_timeout = atoi(optarg);
      if(readOnlyGlobals.file_dump_timeout < 60) {
	readOnlyGlobals.file_dump_timeout = 60;
	traceEvent(TRACE_WARNING, "Sorry: -F cannot be set below 60 (sec)");
      }
      break;
    case 'h':
      usage();
      return(-1);
    case 'i':
		{
#ifdef WIN32
	        struct stat statbuf;

			if(stat(optarg, &statbuf) != 0) {
			  readOnlyGlobals.tmpDev = printAvailableInterfaces(optarg);
			} else 
#endif
			{
			  if(readOnlyGlobals.tmpDev != NULL) free(readOnlyGlobals.tmpDev);
			  readOnlyGlobals.tmpDev = strdup(optarg);
			}
		}
      break;
    case 'm':
      readOnlyGlobals.minNumFlowsPerPacket = atoi(optarg);
      break;
    case 'p':
      {
	int a, b, c, d, e, f;

	if(sscanf(optarg, "%d/%d/%d/%d/%d/%d", &a, &b, &c, &d, &e, &f) != 6) {
	  traceEvent(TRACE_WARNING, "Sorry: the -p parameter has an invalid format");
	} else {
	  readOnlyGlobals.ignoreVlan     = (a == 0) ? 1 : 0;
	  readOnlyGlobals.ignoreProtocol = (b == 0) ? 1 : 0;
	  readOnlyGlobals.ignoreIP       = (c == 0) ? 1 : 0;
	  readOnlyGlobals.ignorePorts    = (d == 0) ? 1 : 0;
	  readOnlyGlobals.ignoreTos      = (e == 0) ? 1 : 0;

	  if(f == 0) {
#ifdef HAVE_GEOIP
	    if(readOnlyGlobals.geo_ip_asn_db != NULL)
	      GeoIP_delete(readOnlyGlobals.geo_ip_asn_db);
	    readOnlyGlobals.geo_ip_asn_db = NULL;
#endif
	  }
	}
      }
      break;
    case 'r':
      if(readOnlyGlobals.numInterfaceNetworks == 0) {
	traceEvent(TRACE_WARNING, "Ignored -c: it must be specified after -L");
      } else
	readOnlyGlobals.setLocalTrafficDirection = 1;
      break;
    case 'R':
      readOnlyGlobals.maxPayloadLen = atoi(optarg);
      if(readOnlyGlobals.maxPayloadLen > MAX_PAYLOAD_LEN) {
	readOnlyGlobals.maxPayloadLen = MAX_PAYLOAD_LEN;
	traceEvent(TRACE_WARNING, "WARNING: payload limited to %d bytes",
		   readOnlyGlobals.maxPayloadLen);
      }
      break;
    case 's':
      readOnlyGlobals.scanCycle = atoi(optarg);
      if(readOnlyGlobals.scanCycle <= 0) readOnlyGlobals.scanCycle = 1;
      break;
#ifndef WIN32
    case 'G':
      readOnlyGlobals.becomeDaemon = 1;
      break;
#endif
    case 'l':
      readOnlyGlobals.sendTimeout = atoi(optarg);
      break;
    case 'L':
      parseLocalAddressLists(optarg);
      break;
    case 'M':
      readOnlyGlobals.maxNumActiveFlows = (u_int)atoi(optarg);
      break;
    case 'S':
	{
	  u_int a, b, begin = 0;

	  if(optarg[0] == '@')
	    readOnlyGlobals.fakePktSampling = 1, begin = 1;

	  if(sscanf(&optarg[begin], "%u:%u", &a, &b) == 2) {
	    readOnlyGlobals.pktSampleRate = a;
	    readOnlyGlobals.flowSampleRate = b;
	  } else {
	    traceEvent(TRACE_WARNING, "WARNING: Unable to parse sampling option: discarded");
	    readOnlyGlobals.pktSampleRate = 1;
	    readOnlyGlobals.flowSampleRate = 1;
	  }

	  if(readOnlyGlobals.pktSampleRate > MAX_SAMPLE_RATE) {
	    readOnlyGlobals.pktSampleRate = MAX_SAMPLE_RATE;
	    traceEvent(TRACE_WARNING, "WARNING: packet sample rate set to %d [range 1:%d]",
		       MAX_SAMPLE_RATE, MAX_SAMPLE_RATE);
	  }
	  if(readOnlyGlobals.pktSampleRate == 0) readOnlyGlobals.pktSampleRate = 1;

	  if(readOnlyGlobals.flowSampleRate > MAX_SAMPLE_RATE) {
	    readOnlyGlobals.flowSampleRate = MAX_SAMPLE_RATE;
	    traceEvent(TRACE_WARNING, "WARNING: flow sample rate set to %d [range 1:%d]",
		       MAX_SAMPLE_RATE, MAX_SAMPLE_RATE);
	  }
	  if(readOnlyGlobals.flowSampleRate == 0) readOnlyGlobals.flowSampleRate = 1;
	}
      break;
    case 't':
      readOnlyGlobals.lifetimeTimeout = atoi(optarg);
      if(readOnlyGlobals.lifetimeTimeout == 0) {
	readOnlyGlobals.lifetimeTimeout = 1;
	traceEvent(TRACE_WARNING, "Minimum flow lifetime can't be set to zero: set to %d sec",
		   readOnlyGlobals.lifetimeTimeout);
      }
      break;
    case 'u':
      id = atoi(optarg);
      if(id > (u_int16_t)-1)
	traceEvent(TRACE_WARNING, "The -%c value %s it out of boundaries and it will be truncated", 
		   opt, optarg);
      readOnlyGlobals.inputInterfaceIndex = id;
      break;
    case 'z':
      readOnlyGlobals.minFlowSize = (u_int)atoi(optarg);
      break;
    case 'v':
      probeVersion();
      exit(0);
    case 'w':
      readOnlyGlobals.flowHashSize = atoi(optarg);
      if(readOnlyGlobals.flowHashSize < MIN_HASH_SIZE) {
	readOnlyGlobals.flowHashSize = MIN_HASH_SIZE;
	traceEvent(TRACE_INFO, "Minimum hash size if %d.",
		   readOnlyGlobals.flowHashSize);
      }
      readOnlyGlobals.hostHashSize = readOnlyGlobals.flowHashSize/2;
      break;

    case 'W':
      readOnlyGlobals.disableIPv6 = 1;
      break;

    case 'x':
      if(sscanf(optarg, "%d:%d:%d:%d",
		(int*)&readOnlyGlobals.tcpPayloadExport,
		(int*)&readOnlyGlobals.udpPayloadExport,
		(int*)&readOnlyGlobals.icmpPayloadExport,
		(int*)&readOnlyGlobals.otherPayloadExport)) {
	if(readOnlyGlobals.tcpPayloadExport > 2) {
	  readOnlyGlobals.tcpPayloadExport = 0;
	  traceEvent(TRACE_WARNING,
		     "WARNING: wrong value for -x TCP value [range 0:2]");
	}

	if(readOnlyGlobals.udpPayloadExport > 1) {
	  readOnlyGlobals.udpPayloadExport = 0;
	  traceEvent(TRACE_WARNING,
		     "WARNING: wrong value for -x UDP value [range 0:1]");
	}

	if(readOnlyGlobals.icmpPayloadExport > 1) {
	  readOnlyGlobals.icmpPayloadExport = 0;
	  traceEvent(TRACE_WARNING,
		     "WARNING: wrong value for -x ICMP value [range 0:1]");
	}

	if(readOnlyGlobals.otherPayloadExport > 1) {
	  readOnlyGlobals.otherPayloadExport = 0;
	  traceEvent(TRACE_WARNING,
		     "WARNING: wrong value for -x OTHER value [range 0:1]");
	}
      } else
	traceEvent(TRACE_INFO, "Wrong format for -x. See -h for more info");
      break;

#ifndef WIN32
    case 'I':
      {
	u_int len = strlen(optarg), max_len = sizeof(readOnlyGlobals.nprobeId)-1;

	if(len >= max_len) len = max_len;
	strncpy(readOnlyGlobals.nprobeId, optarg, len);
	readOnlyGlobals.nprobeId[len] = '\0';
	readOnlyGlobals.useSyslog = 1;
      }
      break;
#endif
    case 'n':
      if(strcmp(optarg, "none")) {
	if(readOnlyGlobals.none_specified) {
	  traceEvent(TRACE_WARNING, "-n <host:port> is ignored as '-n none' has beed specified before");
	} else {
	  	  char *port = NULL, *addr = NULL;

	  opt_n = 1;

	  port = strrchr(optarg, ':');

	  if(port != NULL) {
	    port[0] = '\0';
	    port++;
	    addr =  optarg;

	    if(addr[0] == '[') {
	      /*
		IPv6 addresses should be delimited by square brackets
		according to RFC 2732.
	      */
	      addr++;

	      if(strlen(addr) > 0)
		addr[strlen(addr)-1] = '\0';
	    }

	    if(initNetFlow(addr, atoi(port)) == 0)
	      mandatoryParamOk++;
	  } else {
	    usage();
	  }
	}
      } else {
	if(readOnlyGlobals.numCollectors > 0) {
	  traceEvent(TRACE_WARNING, "'-n none' is ignored as '-n <host:port>' has beed specified before");
	} else {
	  readOnlyGlobals.none_specified = 1, mandatoryParamOk++;
	}
      }
      break;
    case 'N':
      readOnlyGlobals.rebuild_hash = 1;
      break;
    case 'o':
      readOnlyGlobals.templatePacketsDelta = (u_short)atoi(optarg);
      break;
#ifdef IP_HDRINCL
    case 'q':
      {
	if(opt_n == 1) {
	  traceEvent(TRACE_ERROR,
		     "You need to specify the --sender-address|-q option before the --collector|-n option."
		     " Please try again.");
	  exit(0);
	}

	readOnlyGlobals.bindAddr = strtok(optarg, ":");
	if(readOnlyGlobals.bindAddr != NULL) {
	  readOnlyGlobals.bindAddr = strdup(readOnlyGlobals.bindAddr);
	  readOnlyGlobals.bindPort = strtok(NULL, ":");
	  if(readOnlyGlobals.bindPort == NULL)
	    usage();
	  else
	    readOnlyGlobals.bindPort = strdup(readOnlyGlobals.bindPort);
	} else
	  usage();

	if(readOnlyGlobals.bindAddr != NULL) {
	  memset(&readOnlyGlobals.sockIn, 0, sizeof(readOnlyGlobals.sockIn));
	  /*
	    FreeBSD only
	    readOnlyGlobals.sockIn.sin_len = sizeof(struct sockaddr_in);
	  */
#ifdef IPV4_ONLY
	  readOnlyGlobals.sockIn.sin_family = AF_INET;
#else
	  readOnlyGlobals.sockIn.sin_family = AF_INET6;
#endif

	  if(readOnlyGlobals.bindPort)
	    readOnlyGlobals.sockIn.sin_port   = (int)htons((unsigned short int)atoi(readOnlyGlobals.bindPort));

	  if(!inet_aton(readOnlyGlobals.bindAddr, &readOnlyGlobals.sockIn.sin_addr)) {
	    traceEvent(TRACE_ERROR, "Unable to convert address '%s'. "
		       "Not binding to a particular interface", readOnlyGlobals.bindAddr);
	    readOnlyGlobals.sockIn.sin_addr.s_addr = INADDR_ANY;
	  }

	  /*
	    If we ask to bind to IPv4 via -q then we
	    implicitly ask to use IPv4
	  */
	  if(strstr(readOnlyGlobals.bindAddr, ":") == NULL)
	    readOnlyGlobals.useIpV6 = 0;
	}
      }
      break;
#endif

    case 'Q':
      id = atoi(optarg);
      if(id > (u_int16_t)-1)
	traceEvent(TRACE_WARNING, "The -%c value %s it out of boundaries and it will be truncated", 
		   opt, optarg);
      readOnlyGlobals.outputInterfaceIndex = (u_int16_t)id;
      break;

    case 'T':
      {
	u_int8_t ignore_template = 1;

	if(reparse_options) {
	  if(strcmp(readOnlyGlobals.stringTemplateV4, optarg) != 0) {
	    /* Template is NOT the same */
	    ignore_template = 0;
	  }
	}

	if((readOnlyGlobals.stringTemplateV4 == NULL) || (!ignore_template)) {
	  readOnlyGlobals.stringTemplateV4 = strdup(optarg);
	  if(readOnlyGlobals.netFlowVersion != 10) readOnlyGlobals.netFlowVersion = 9; /* NetFlow v9 */
	  if(readOnlyGlobals.useNetFlow == 0xFF) readOnlyGlobals.useNetFlow = 1;

	  if(reparse_options)
	    compileTemplates(1);
	}
      }
      break;

    case 'U':
      readOnlyGlobals.idTemplate = atoi(optarg);
      if(readOnlyGlobals.netFlowVersion != 10) readOnlyGlobals.netFlowVersion = 9; /* NetFlow v9 */
      if(readOnlyGlobals.useNetFlow == 0xFF) readOnlyGlobals.useNetFlow = 1;
      break;

    case 'V':
      readOnlyGlobals.netFlowVersion = atoi(optarg);
      if((readOnlyGlobals.netFlowVersion != 5)
	  && (readOnlyGlobals.netFlowVersion != 9)
	  && readOnlyGlobals.netFlowVersion != 10)
	{
	  traceEvent(TRACE_ERROR,
		     "nProbe supports 5 (NetFlow 5), 9 (NetFlow 9) and 10 (IPFIX)");
	  exit(0);
	}
      break;

    default:
      //usage();
      break;
    }
  }

  if(reparse_options) return(0);

#ifdef NETFLOW_DEBUG
  // readOnlyGlobals.numProcessThreads = 1;
#endif

  /*
    This guarantees that the hash size is a multiple of the number of threads
    hence that we do not need locks in the hash when using lockless hash
  */
  readOnlyGlobals.flowHashSize -= (readOnlyGlobals.flowHashSize % readOnlyGlobals.numProcessThreads);

  if((readOnlyGlobals.tmpDev != NULL)
     && (readOnlyGlobals.pcapFileList != NULL)) {
    traceEvent(TRACE_NORMAL, "-i is ignored as --pcap-file-list has been used");
    free(readOnlyGlobals.tmpDev);
    readOnlyGlobals.tmpDev = NULL;
  }

  if(readOnlyGlobals.v9TemplateElementListV4[0] != NULL) {
    readOnlyGlobals.scanCycle = readOnlyGlobals.file_dump_timeout;
    traceEvent(TRACE_INFO, "Scan cycle (-s) set to the -F value: %d",
	       readOnlyGlobals.scanCycle);
  }
  /*
 else {
    if(readOnlyGlobals.rebuild_hash) {
      traceEvent(TRACE_NORMAL, "-N is ignored as -D has not been used");
      readOnlyGlobals.rebuild_hash = 0;
    }
  }
  */

  if(readOnlyGlobals.useNetFlow == 0xFF) readOnlyGlobals.useNetFlow = 1;

  if(readOnlyGlobals.netFlowVersion == 5) {
    if(readOnlyGlobals.minNumFlowsPerPacket == -1)
      readOnlyGlobals.minNumFlowsPerPacket = V5FLOWS_PER_PAK; /* Default */

    if(readOnlyGlobals.minNumFlowsPerPacket > V5FLOWS_PER_PAK) {
      traceEvent(TRACE_WARNING,
		 "Sorry: the min # of flows per packet cannot be set over %d",
		 V5FLOWS_PER_PAK);
      readOnlyGlobals.minNumFlowsPerPacket = V5FLOWS_PER_PAK;
    }
    
    readOnlyGlobals.disableIPv6 = 1;
  }

  traceEvent(TRACE_NORMAL, "Welcome to nprobe v.%s (%s) for %s %s",
	     version, nprobe_revision, osName,
#ifdef HAVE_PF_RING
	     "with native PF_RING acceleration"
#else
	     ""
#endif
	     );

  if(((fd = fopen("nprobe.license", "r")) != NULL)
     || ((fd = fopen("/etc/nprobe.license", "r")) != NULL)) {
    char license[256] = { 0 }, *ret;

    ret = fgets(license, sizeof(license), fd);
    fclose(fd);

    traceEvent(TRACE_NORMAL, "nProbe License: %s", license);
  }

  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "Tracing enabled");

  if(readOnlyGlobals.disableIPv6)
    traceEvent(TRACE_NORMAL, "IPv6 traffic will NOT be exported/accounted by this probe");

  if(readWriteGlobals->num_src_mac_export > 0) {
    int i;

    for(i = 0; i<readWriteGlobals->num_src_mac_export; i++)
      traceEvent(TRACE_INFO,
		 "Using interface idx %d for flows originating from %02X:%02X:%02X:%02X:%02X:%02X",
		 readOnlyGlobals.mac_if_match[i].interface_id,
		 readOnlyGlobals.mac_if_match[i].mac_address[0],
		 readOnlyGlobals.mac_if_match[i].mac_address[1],
		 readOnlyGlobals.mac_if_match[i].mac_address[2],
		 readOnlyGlobals.mac_if_match[i].mac_address[3],
		 readOnlyGlobals.mac_if_match[i].mac_address[4],
		 readOnlyGlobals.mac_if_match[i].mac_address[5]);
  }

  if(readOnlyGlobals.dirPath) {
    struct stat statbuf;

    if((stat(readOnlyGlobals.dirPath, &statbuf) != 0)
       || (!(statbuf.st_mode & S_IFDIR)) /* It's not a directory */
       || (!(statbuf.st_mode & S_IWRITE)) /* It's not writable    */
       ) {
      traceEvent(TRACE_ERROR,
		 "Sorry, the path you specified with -P is invalid.");
      traceEvent(TRACE_ERROR,
		 "Make sure the directory exists and it's writable.");
      exit(-1);
    }

    readWriteGlobals->flowFd = NULL;
    mandatoryParamOk = 1; /* -P can substitute -n */
    traceEvent(TRACE_NORMAL, "Dumping flow files every %d sec into directory %s",
	       readOnlyGlobals.file_dump_timeout, readOnlyGlobals.dirPath);
  }

  if((readOnlyGlobals.numCollectors == 0)
     && (!readOnlyGlobals.none_specified)) {
    traceEvent(TRACE_WARNING, "-n parameter is missing. 127.0.0.1:2055 will be used.\n");
    initNetFlow("127.0.0.1", 2055);
    mandatoryParamOk = 1;
  }

  for(i=0; i<_argc; i++)
    free(_argv[i]);

  if(!mandatoryParamOk) {
      usage();
      return(-1);
  }

#ifdef linux
  setCpuAffinity(readOnlyGlobals.tmpDev, readOnlyGlobals.cpuAffinity);
#endif

  return(0);
}

/* ****************************************************** */

static char *printPayloadValue(u_char payloadExportType) {
  switch(payloadExportType) {
  case 0:
    return("no payload");
    break;
  case 1:
    return("full payload");
    break;
  case 2:
    return("payload only with SYN set");
    break;
  default:
    return("??");
  }
}

/* ****************************************************** */

static void stopCaptureFlushAll(void) {
  u_int i, hash_idx = 0;

  readWriteGlobals->stopPacketCapture = 1;
  traceEvent(TRACE_INFO, "nProbe is shutting down...");

  traceEvent(TRACE_INFO, "Processing queued packets...");
  for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
    PacketQueue *queue = &readWriteGlobals->packetQueue[i];

    while(queuedPkts(queue) > 0)
      ntop_sleep(1);
  }

  traceEvent(TRACE_INFO, "Exporting pending buckets...\n");
  for(hash_idx=0; hash_idx<readOnlyGlobals.numProcessThreads; hash_idx++) {
    walkHash(hash_idx, 1);
  }

  if(readWriteGlobals->exportBucketsLen > 0) {
    traceEvent(TRACE_INFO, "Waiting to export queued buckets... [queue len=%d]",
	       readWriteGlobals->exportBucketsLen);
    while(readWriteGlobals->exportBucketsLen > 0) {
      signalCondvar(&readWriteGlobals->exportQueueCondvar, 0);
      ntop_sleep(1);
    }
  }

  checkNetFlowExport(1);
  traceEvent(TRACE_INFO, "Pending buckets have been exported...\n");
}

/* ****************************************************** */

static void shutdown_nprobe(void) {
  static u_char once = 0;
  FlowHashBucket *list;
  u_int i;

  if(once) return; else once = 1;

  stopCaptureFlushAll();
  readWriteGlobals->shutdownInProgress = 1;

  traceEvent(TRACE_INFO, "Waiting process threads to end...");
  for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
    PacketQueue *queue = &readWriteGlobals->packetQueue[i];

    if(queue != NULL) {
      int j;

      signalCondvar(&queue->queue_condvar, 0);
      signalCondvar(&queue->dequeue_condvar, 0);
      //pthread_join(packetProcessThread[i], NULL);
      traceEvent(TRACE_INFO, "Terminated thread %d/%d...",
		 (1+i), readOnlyGlobals.numProcessThreads);

      for(j=0; j<queue->queue_capacity; j++) {
#ifdef DEBUG
	traceEvent(TRACE_NORMAL, "Freeing slot %d [queue_id=%d][snaplen=%d]=%p",
		   j, i, readOnlyGlobals.snaplen, queue->queue[j].p);
#endif
	free(queue->queue[j].p);
      }

      free(queue->queue);
    }
  }

  signalCondvar(&readWriteGlobals->exportQueueCondvar, 0);
  if(dequeueBucketToExport_up)
    waitCondvar(&readWriteGlobals->termCondvar); /* Wait until dequeueBucketToExport() ends */

  traceEvent(TRACE_INFO, "Flushing queued flows...\n");
  checkExportQueuedFlows(1);

  traceEvent(TRACE_INFO, "Freeing memory...\n");

  for(i = 0; i<readOnlyGlobals.numCollectors; i++)
    close(readOnlyGlobals.netFlowDest[i].sockFd);

  close_dump_file();

  free_bitmask(&readOnlyGlobals.udpProto);
  free_bitmask(&readOnlyGlobals.tcpProto);

  unload_mappings();

  if(readOnlyGlobals.pcapPtr) {
    printPcapStats(readOnlyGlobals.pcapPtr);
    pcap_close(readOnlyGlobals.pcapPtr);
    readOnlyGlobals.pcapPtr = NULL;
  }

  for(i=0; i<readOnlyGlobals.numProcessThreads; i++)
    free(readWriteGlobals->theFlowHash[i]);

  freeHostHash();

  if(readOnlyGlobals.tmpDev != NULL)     free(readOnlyGlobals.tmpDev);
  if(readWriteGlobals->bufferV4 != NULL) free(readWriteGlobals->bufferV4);
  if(readWriteGlobals->bufferV6 != NULL) free(readWriteGlobals->bufferV6);

  list = readWriteGlobals->exportQueue;

  while(list != NULL) {
    FlowHashBucket *nextEntry = list->next;

    if(list->src2dstPayload != NULL) free(list->src2dstPayload);
    if(list->dst2srcPayload != NULL) free(list->dst2srcPayload);
    free(list);
    list = nextEntry;
  }

  for(i=0; i<NUM_FRAGMENT_LISTS; i++) {
    IpV4Fragment *list = readWriteGlobals->fragmentsList[i];

    while(list != NULL) {
      IpV4Fragment *next = list->next;
      free(list);
      list = next;
    }
  }

#ifdef DEBUG
  if(readWriteGlobals->bucketsAllocated > 0)
    traceEvent(TRACE_INFO, "WARNING ===> readWriteGlobals->bucketsAllocated: %d\n",
	       readWriteGlobals->bucketsAllocated);
#endif

#ifdef HAVE_FASTBIT
  term_fastbit(readOnlyGlobals.v9TemplateElementListV4);
#endif

#ifndef WIN32
  if(readOnlyGlobals.useSyslog)
    closelog();
#endif

  termPlugins();

  /* Clean threads */
#if 0
  traceEvent(TRACE_INFO, "Cleaning threads");
  pthread_exit(&readWriteGlobals->walkHashThread);
  pthread_exit(&readWriteGlobals->dequeueThread);
#endif

  traceEvent(TRACE_INFO, "Still allocated %u hash buckets",
	     readWriteGlobals->bucketsAllocated);

  /* Clean globals */
  traceEvent(TRACE_INFO, "Cleaning globals");

  free(readOnlyGlobals.csv_separator);
  free(readOnlyGlobals.dirPath);
  free(packetProcessThread);
  if(readOnlyGlobals.stringTemplateV4) free(readOnlyGlobals.stringTemplateV4);
  if(readOnlyGlobals.stringTemplateV6) free(readOnlyGlobals.stringTemplateV6);

  traceEvent(TRACE_INFO, "nProbe terminated.");
  dumpLogEvent(probe_stopped, severity_info, "nProbe stopped");
  if(readOnlyGlobals.eventLogPath) free(readOnlyGlobals.eventLogPath);

  free(readWriteGlobals); /* Do not move it up as it's needed for logging */

  exit(0);
}

/* ******************************************* */

static int openDevice(char ebuf[], int printErrors, char *pcapFilePath) {
  u_char open_device = 1;

  if(readOnlyGlobals.enableHttpPlugin || readOnlyGlobals.enableDnsPlugin || readOnlyGlobals.enableMySQLPlugin)
    readOnlyGlobals.snaplen = PCAP_LONG_SNAPLEN;

  if((readOnlyGlobals.tmpDev != NULL)
     && (strcmp(readOnlyGlobals.tmpDev, "none") == 0))
    return(0);

  if(readOnlyGlobals.tmpDev != NULL) {
    /* Try if the passed device is instead a dump file */

#ifdef HAVE_PF_RING
    if(strstr(readOnlyGlobals.tmpDev, ".metadata")) {
      if((readOnlyGlobals.metadata_fd = fopen(readOnlyGlobals.tmpDev, "rb")) == NULL) {
	traceEvent(TRACE_ERROR, "Unable to open file %s", readOnlyGlobals.tmpDev);
	return(-1);
      } else {
	traceEvent(TRACE_NORMAL, "Open metadata file %s", readOnlyGlobals.tmpDev);
	goto do_datalink;
      }
    }
#endif

    readOnlyGlobals.pcapPtr = pcap_open_offline(readOnlyGlobals.tmpDev, ebuf);
    if(readOnlyGlobals.pcapPtr != NULL)
      readOnlyGlobals.pcapFile = strdup(readOnlyGlobals.tmpDev);
  } else if(pcapFilePath != NULL) {
    if(readOnlyGlobals.pcapPtr != NULL) {
      pcap_close(readOnlyGlobals.pcapPtr);
      readOnlyGlobals.pcapPtr = NULL;
    }

    readOnlyGlobals.pcapPtr = pcap_open_offline(pcapFilePath, ebuf);
    if(readOnlyGlobals.pcapPtr != NULL) {
      traceEvent(TRACE_NORMAL, "Processing packets from file %s", pcapFilePath);
      readOnlyGlobals.pcapFile = pcapFilePath;
      readOnlyGlobals.snaplen = LONG_SNAPLEN;
    } else
      return(-1);
  } else
    readOnlyGlobals.pcapPtr = NULL;

  if(readOnlyGlobals.pcapPtr == NULL) {
    /* Find the default device if not specified */
    if(readOnlyGlobals.tmpDev == NULL) {
#ifdef WIN32
      readOnlyGlobals.tmpDev = printAvailableInterfaces(NULL);
#else
      readOnlyGlobals.tmpDev = pcap_lookupdev(ebuf);
#endif
      if(readOnlyGlobals.tmpDev == NULL) {
	if(printErrors)
	  traceEvent(TRACE_ERROR,
		     "Unable to locate default interface (%s)\n", ebuf);
	return(-1);
      } else {
	char *_tmpDev = strdup(readOnlyGlobals.tmpDev);
	readOnlyGlobals.tmpDev = _tmpDev;
      }
    }

#ifdef HAVE_PF_RING
    readWriteGlobals->ring = open_ring(readOnlyGlobals.tmpDev, &open_device);
#endif

    if(open_device) {
      readOnlyGlobals.pcapPtr = pcap_open_live(readOnlyGlobals.tmpDev,
					       readOnlyGlobals.snaplen,
					       readOnlyGlobals.promisc_mode /* promiscuous mode */,
					       1000 /* ms */,
					       ebuf);

      if(readOnlyGlobals.pcapPtr == NULL)  {
	if(printErrors)
	  traceEvent(TRACE_ERROR, "Unable to open interface %s.\n", readOnlyGlobals.tmpDev);

#ifndef WIN32
	if((getuid () && geteuid ()) || setuid (0)) {
	  if(printErrors) {
	    traceEvent(TRACE_ERROR, "nProbe opens the network interface "
		       "in promiscuous mode, ");
	    traceEvent(TRACE_ERROR, "so it needs root permission "
		       "to run. Quitting...");
	  }
      }
#endif
	return(-1);
      }
    }
  }

#ifdef HAVE_PF_RING
  if(readWriteGlobals->ring != NULL) {
  do_datalink:
    readOnlyGlobals.datalink = DLT_EN10MB;
  } else
#endif
    readOnlyGlobals.datalink = pcap_datalink(readOnlyGlobals.pcapPtr);

  /* ************************ */

  if(readOnlyGlobals.netFilter != NULL) {
    struct bpf_program fcode;
    struct in_addr netmask;

    netmask.s_addr = htonl(0xFFFFFF00);

    if((pcap_compile(readOnlyGlobals.pcapPtr, &fcode, readOnlyGlobals.netFilter, 1, netmask.s_addr) < 0)
       || (pcap_setfilter(readOnlyGlobals.pcapPtr, &fcode) < 0)) {
      if(printErrors)
	traceEvent(TRACE_ERROR,
		   "Unable to set filter %s. Filter ignored.\n", readOnlyGlobals.netFilter);
      /* return(-1); */
    } else {
      if(printErrors)
	traceEvent(TRACE_INFO, "Packet capture filter set to \"%s\"",
		   readOnlyGlobals.netFilter);
    }

    free(readOnlyGlobals.netFilter);
  }

  return(0);
}

/* ****************************************************** */

static int restoreInterface(char ebuf[]) {
  if(readOnlyGlobals.pcapFile == NULL) {
    int rc = -1;

    traceEvent(TRACE_INFO,
	       "Error while capturing packets: %s",
	       pcap_geterr(readOnlyGlobals.pcapPtr));
    traceEvent(TRACE_INFO, "Waiting until the interface comes back...");

    while(rc == -1) {
      ntop_sleep(1);
      rc = openDevice(ebuf, 0, NULL);
    }

    traceEvent(TRACE_INFO, "The interface is now awailable again.");
    return(rc);
  }

  return(-2);
}

/* ****************************************************** */

#ifndef HAVE_PCAP_NEXT_EX
int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
                 const u_char **pkt_data)
{
  static struct pcap_pkthdr h;

  (*pkt_data) = pcap_next(p, &h);
  (*pkt_header) = &h;
  if(*pkt_data)
    return(1);
  else
    return(0);
}
#endif

/* ****************************************************** */

static void* fetchPackets(void* notUsed) {
  char ebuf[PCAP_ERRBUF_SIZE];
  const u_char *_packet;
  u_char packet[PCAP_LONG_SNAPLEN];
  u_short packetToGo = readOnlyGlobals.fakePktSampling ? 1 : readOnlyGlobals.pktSampleRate;
  struct pcap_pkthdr *_h, h;
  int rc;
  unsigned long thread_id = (unsigned long)notUsed;

  traceEvent(TRACE_INFO, "Fetch packets thread started [thread %lu]", thread_id);

  while(!readWriteGlobals->shutdownInProgress) {
    /* traceEvent(TRACE_INFO, "fetchPackets(%d)", (int)notUsed); */
    if(readOnlyGlobals.fakePktSampling || (readOnlyGlobals.pktSampleRate == 1)) {
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Processing packet");
#endif
      rc = pcap_next_ex(readOnlyGlobals.pcapPtr, &_h, &_packet);
      if((rc > 0) && (_packet != NULL) && (_h->caplen > 0)) {
	_h->caplen = min(_h->caplen, readOnlyGlobals.snaplen);
      } else {
#ifdef DEBUG
	traceEvent(TRACE_INFO, "pcap_next_ex() returned %d", rc);
#endif
      }

#if 0
      if((rc == 0) && (h->caplen == 0)) rc = -2; /* Sanity check */
#endif

      if((rc > 0) && (packet != NULL))
	decodePacket(_h, _packet,
		     readOnlyGlobals.fakePktSampling, readOnlyGlobals.pktSampleRate,
		     NO_INTERFACE_INDEX, NO_INTERFACE_INDEX, 0 /* Unknown sender */);
    } else {
      if(packetToGo > 1) {
	rc = pcap_next_ex(readOnlyGlobals.pcapPtr, &_h, &_packet);

	if((rc == 1) && (packet != NULL)) {
	  packetToGo--;
#ifdef DEBUG
	  traceEvent(TRACE_INFO, "Discarded packet [%d packets to go]", packetToGo-1);
#endif
	} else if(rc == -2) {
	  break; /* Captured file is over */
	}
	continue;
      } else {
#ifdef DEBUG
	traceEvent(TRACE_INFO, "Processing packet");
#endif

	rc = pcap_next_ex(readOnlyGlobals.pcapPtr, &_h, &_packet);
	if((rc > 0) && (packet != NULL)) {
	  _h->caplen = min(_h->caplen, readOnlyGlobals.snaplen);
	  memcpy(&h, _h, sizeof(h)), memcpy(packet, _packet, _h->caplen);
	}

	if((rc == 0) && (h.caplen == 0)) rc = -2; /* Sanity check */
	if((rc >= 0) && (packet != NULL)) {
	  decodePacket(_h, _packet,
		       readOnlyGlobals.fakePktSampling, readOnlyGlobals.pktSampleRate,
		       NO_INTERFACE_INDEX, NO_INTERFACE_INDEX, 0 /* Unknown sender */);
	  packetToGo = readOnlyGlobals.fakePktSampling ? 1 : readOnlyGlobals.pktSampleRate;
	}
      }
    }

    if(rc < 0) {
      if(rc == -2) {
	/* Captured file is over */
	break;
      } else if(rc == -1) {
#ifdef WIN32
	break;
#endif
	if(!readWriteGlobals->shutdownInProgress) {
	  traceEvent(TRACE_ERROR, "Error while reading packets: '%s'",
		     pcap_geterr(readOnlyGlobals.pcapPtr));
	  pcap_close(readOnlyGlobals.pcapPtr);
	  readOnlyGlobals.pcapPtr = NULL;
	  rc = restoreInterface(ebuf);
	  if(rc < 0) break;
	}
      }
    }

    if(readOnlyGlobals.capture_num_packet_and_quit > 1)
      readOnlyGlobals.capture_num_packet_and_quit--;
    else if(readOnlyGlobals.capture_num_packet_and_quit == 1)
      readWriteGlobals->shutdownInProgress = 1;
  } /* while */

  readWriteGlobals->numTerminatedFetchPackets++;

  return(NULL);
}

/* ****************************************************** */

u_short getNumCores(void) {
#ifdef linux
  return(sysconf(_SC_NPROCESSORS_CONF));
#else
  return(ACT_NUM_PCAP_THREADS);
#endif
}

/* ****************************************************** */

void init_globals(void) {
  memset(&readOnlyGlobals, 0, sizeof(readOnlyGlobals));

  readWriteGlobals = (ReadWriteGlobals*)calloc(1, sizeof(ReadWriteGlobals));
  if(!readWriteGlobals){
    traceEvent(TRACE_ERROR, "Not enough memory");
    exit(-1);
  }

  memset(&readOnlyGlobals, 0, sizeof(readOnlyGlobals));
  readOnlyGlobals.tunnel_mode = 0;
  readOnlyGlobals.promisc_mode = 1;
  readOnlyGlobals.maxNumActiveFlows = (u_int)-1;
  readOnlyGlobals.idTemplate = DEFAULT_TEMPLATE_ID;
#ifdef HAVE_FASTBIT
  readOnlyGlobals.fastbit_mins_rotation = DEFAULT_FASTBIT_MINS_ROTATION;
#endif
#ifdef linux
  readOnlyGlobals.cpuAffinity = NULL; /* no affinity */
#endif
  readOnlyGlobals.scanCycle = 30 /* sec */;
  readOnlyGlobals.handleFragments = 1;
  readOnlyGlobals.inputInterfaceIndex = DEFAULT_INPUT_INTERFACE_INDEX;
  readOnlyGlobals.outputInterfaceIndex = DEFAULT_OUTPUT_INTERFACE_INDEX;
  readOnlyGlobals.file_dump_timeout = 60;
  readOnlyGlobals.templatePacketsDelta = TEMPLATE_PACKETS_DELTA;
  readOnlyGlobals.numProcessThreads = getNumCores();
  readOnlyGlobals.enableHostStats = 0;
  readOnlyGlobals.templateBufMaxV4 = readOnlyGlobals.templateBufMaxV6 = NETFLOW_MAX_BUFFER_LEN;
  readOnlyGlobals.optionTemplateBufMax = NETFLOW_MAX_BUFFER_LEN;
  readOnlyGlobals.dumpFormat = text_format;
  readOnlyGlobals.traceLevel = 2;
  readOnlyGlobals.idleTimeout = DUMP_TIMEOUT;
  readOnlyGlobals.deferredHostUpdate = 0; // FIX
  readOnlyGlobals.lifetimeTimeout = 4*DUMP_TIMEOUT;
  readOnlyGlobals.sendTimeout = DUMP_TIMEOUT;
  readWriteGlobals->lastMaxBucketSearch = 5; /* Don't bother with values < 5 */
  readOnlyGlobals.pcapPtr = NULL;
  readOnlyGlobals.csv_separator = strdup("|");
}

/* ****************************************************** */

static void printCopyrights(void) {
#ifdef HAVE_GEOIP
  if(readOnlyGlobals.geo_ip_city_db != NULL)
    traceEvent(TRACE_NORMAL, "%s", GeoIP_database_info(readOnlyGlobals.geo_ip_city_db));
  if(readOnlyGlobals.geo_ip_asn_db != NULL)
    traceEvent(TRACE_NORMAL, "%s", GeoIP_database_info(readOnlyGlobals.geo_ip_asn_db));
#endif
}

/* ****************************************************** */

static void compileTemplates(u_int8_t reloadTemplate) {
  u_int num_runs;

  traceEvent(TRACE_INFO, "Compiling flow templates...");

  if(reloadTemplate) {
    stopCaptureFlushAll();
  }

  if(readOnlyGlobals.netFlowVersion == 5) {
    readOnlyGlobals.stringTemplateV4 = strdup(DEFAULT_V9_IPV4_TEMPLATE);
    compileTemplate(readOnlyGlobals.stringTemplateV4,
		    readOnlyGlobals.v9TemplateElementListV4, TEMPLATE_LIST_LEN);

    if(!reloadTemplate) {
#ifdef HAVE_MYSQL
      init_db_table();
#endif

#ifdef HAVE_FASTBIT
      init_fastbit(readOnlyGlobals.v9TemplateElementListV4, NULL /* No configuration file */);
#endif
    }
  } else if(readOnlyGlobals.netFlowVersion == 9 || readOnlyGlobals.netFlowVersion == 10) {
    u_int i, flowLen;
    char *elem;

    if(readOnlyGlobals.stringTemplateV4 == NULL) {
      traceEvent(TRACE_WARNING, "You choosed v9/IPFIX without specifying a template (-T).");
      traceEvent(TRACE_WARNING, "The default template will be used");

      readOnlyGlobals.stringTemplateV4 = strdup(DEFAULT_V9_IPV4_TEMPLATE);
    } else {
      if(strchr(readOnlyGlobals.stringTemplateV4, '%') == NULL)
	traceEvent(TRACE_WARNING, "The template does not contain any '%%': please check its format");
    }

    if(strstr(readOnlyGlobals.stringTemplateV4, "%FLOW_PROTO_PORT") != NULL)
      loadApplProtocols();

    if((strstr(readOnlyGlobals.stringTemplateV4, "%IN_BYTES")
	&& strstr(readOnlyGlobals.stringTemplateV4, "%OUT_BYTES"))
       || (strstr(readOnlyGlobals.stringTemplateV4, "%IN_PKTS")
	   && strstr(readOnlyGlobals.stringTemplateV4, "%OUT_PKTS")))
      readOnlyGlobals.dontSentBidirectionalV9Flows = 1;
    else
      readOnlyGlobals.dontSentBidirectionalV9Flows = 0;

    if(strstr(readOnlyGlobals.stringTemplateV4, "%JITTER") != NULL)
      readOnlyGlobals.calculateJitter = 1;

    if((strstr(readOnlyGlobals.stringTemplateV4, "%L7_PROTO") != NULL)
       && (readOnlyGlobals.maxPayloadLen == 0))
      readOnlyGlobals.maxPayloadLen = 32; /* Default */

    if((strstr(readOnlyGlobals.stringTemplateV4, "%IN_PAYLOAD") == NULL)
       && (strstr(readOnlyGlobals.stringTemplateV4, "%OUT_PAYLOAD") == NULL)
       && (strstr(readOnlyGlobals.stringTemplateV4, "%L7_PROTO") == NULL)
       ) {
      // traceEvent(TRACE_WARNING, "Neither %%IN_PAYLOAD, %%OUT_PAYLOAD nor %%L7_PROTO were set! Payload length will be set to zero.");
      readOnlyGlobals.maxPayloadLen = 0;
    } else {
      if(readOnlyGlobals.maxPayloadLen == 0) {
	traceEvent(TRACE_WARNING, "Payload set with zero length (see -R): set its length to 8.");
	readOnlyGlobals.maxPayloadLen = 9;
      }

      setPayloadLength(readOnlyGlobals.maxPayloadLen);
    }

#ifdef HAVE_GEOIP
    if(readOnlyGlobals.geo_ip_asn_db == NULL)
      readASs("GeoIPASNum.dat");

    if((strstr(readOnlyGlobals.stringTemplateV4, "_COUNTRY") == NULL)
       && (strstr(readOnlyGlobals.stringTemplateV4, "_CITY") == NULL)) {
      if(readOnlyGlobals.geo_ip_city_db != NULL) {
	GeoIP_delete(readOnlyGlobals.geo_ip_city_db);
	readOnlyGlobals.geo_ip_city_db = NULL;
      }
    } else {
      if(readOnlyGlobals.geo_ip_city_db == NULL)
	readCities("GeoLiteCity.dat");
    }
#endif

    /*
      We need to check if the user has
      1. created a template for both IPv4 and IPv6: in this case we will not change
         the template. This is useful for those situations where both IPv4 and v6 will
	 be mixed into the same packet (e.g. IPv4 tunnel of IPv6 traffic)
      2. if we have a single IPv4-only template we will create a similar IPv6 template
    */

    /* Case 1: both IPv4 and IPv6 template check */
    if(strstr(readOnlyGlobals.stringTemplateV4, "%IPV6") && strstr(readOnlyGlobals.stringTemplateV4, "%IPV4")) {
      compileTemplate(readOnlyGlobals.stringTemplateV4,
		      readOnlyGlobals.v9TemplateElementListV4,
		      TEMPLATE_LIST_LEN);
      readOnlyGlobals.stringTemplateV6 = NULL;
    } else {
      compileTemplate(readOnlyGlobals.stringTemplateV4,
		      readOnlyGlobals.v9TemplateElementListV4,
		      TEMPLATE_LIST_LEN);

      readOnlyGlobals.stringTemplateV6 = strdup(readOnlyGlobals.stringTemplateV4);
      /* Convert IPv4 to IPv6 template */
      while((elem = strstr(readOnlyGlobals.stringTemplateV6, "%IPV4")) != NULL) elem[4] = '6';
      elem = strstr(readOnlyGlobals.stringTemplateV6, "%IPV4_NEXT_HOP");
      if(elem) {
	/* Delete %IPV4_NEXT_HOP */
	for(i=0; i<strlen("%IPV4_NEXT_HOP"); i++)
	  elem[i] = ' ';
      }

      compileTemplate(readOnlyGlobals.stringTemplateV6,
		      readOnlyGlobals.v9TemplateElementListV6,
		      TEMPLATE_LIST_LEN);
    }

    flowPrintf(readOnlyGlobals.v9TemplateElementListV4,
	       1 /* IPv4 */, readOnlyGlobals.templateBufferV4,
	       &readOnlyGlobals.templateBufBeginV4,
	       &readOnlyGlobals.templateBufMaxV4,
	       &readOnlyGlobals.numTemplateFieldElementsV4,
	       1, NULL, 0, 0, 0);

    if(readOnlyGlobals.stringTemplateV6)
      flowPrintf(readOnlyGlobals.v9TemplateElementListV6,
		 0 /* IPv6 */, readOnlyGlobals.templateBufferV6,
		 &readOnlyGlobals.templateBufBeginV6,
		 &readOnlyGlobals.templateBufMaxV6,
		 &readOnlyGlobals.numTemplateFieldElementsV6,
		 1, NULL, 0, 0, 0);
    
    /*
      Optimization for NetFlow v9
      Discard fields that are not needed
    */
    if((strstr(readOnlyGlobals.stringTemplateV4, "%IPV4_SRC_ADDR") == NULL)
       && (strstr(readOnlyGlobals.stringTemplateV4, "%IPV4_DST_ADDR") == NULL)
       && (strstr(readOnlyGlobals.stringTemplateV4, "%IPV6_SRC_ADDR") == NULL)
       && (strstr(readOnlyGlobals.stringTemplateV4, "%IPV6_DST_ADDR") == NULL)
       ) {
      traceEvent(TRACE_WARNING, "IPv4/v6 addresses will be ignored (your template lacks %%IPV4_XXX_ADDR/%%IPV6_XXX_ADDR)");
      readOnlyGlobals.ignoreIP = 1;
    }

    if((strstr(readOnlyGlobals.stringTemplateV4, "%L4_SRC_PORT") == NULL)
       && (strstr(readOnlyGlobals.stringTemplateV4, "%L4_DST_PORT") == NULL)) {
      traceEvent(TRACE_WARNING, "L4 ports will be ignored (your template lacks %%L4_SRC_PORT/%%L4_DST_PORT)");
      readOnlyGlobals.ignorePorts = readOnlyGlobals.ignorePorts = 1;
    }

    if(strstr(readOnlyGlobals.stringTemplateV4, "%PROTOCOL") == NULL) {
      traceEvent(TRACE_WARNING, "Protocol will be ignored (your template lacks %%PROTOCOL)");
      readOnlyGlobals.ignoreProtocol = 1;
    }

    if(strstr(readOnlyGlobals.stringTemplateV4, "%ICMP_TYPE"))
      readOnlyGlobals.usePortsForICMP = 0;
    else {
      readOnlyGlobals.usePortsForICMP = 1;
      traceEvent(TRACE_INFO, "TCP/UDP port will carry ICMP type/code information (your template lacks %%ICMP_TYPE)");
    }

    compileTemplate(V9_OPTION_TEMPLATE, readOnlyGlobals.v9OptionTemplateElementList, TEMPLATE_LIST_LEN);
    flowPrintf(readOnlyGlobals.v9OptionTemplateElementList,
	       1 /* IPv4 */, readOnlyGlobals.optionTemplateBuffer,
	       &readOnlyGlobals.optionTemplateBufBegin, &readOnlyGlobals.optionTemplateBufMax,
	       &readOnlyGlobals.numOptionTemplateFieldElements, 1, NULL, 0, 0, 1);

    flowLen = 0;
    if(readOnlyGlobals.traceMode == 2) traceEvent(TRACE_INFO, "Scanning flow template...");

    for(num_runs = 0; num_runs <= 1; num_runs++) {
      V9V10TemplateElementId **elems;
      u_int tot;

      elems = (num_runs == 0) ? readOnlyGlobals.v9TemplateElementListV4 : readOnlyGlobals.v9TemplateElementListV6;
      if(elems[0] == NULL) continue;

      if(readOnlyGlobals.traceMode == 2)
	traceEvent(TRACE_INFO, "IPv%d Template [id=%u]",
		   (num_runs == 0) ? 4 : 6,
		   (num_runs == 0) ?  readOnlyGlobals.idTemplate : (readOnlyGlobals.idTemplate+1));

      for(i=0, tot = 0; i<TEMPLATE_LIST_LEN; i++) {
	if(elems[i] != NULL) {
	  tot += elems[i]->templateElementLen;
	  if(readOnlyGlobals.traceMode == 2)
	    traceEvent(TRACE_INFO, "Found %20s [id %d][%d bytes][total %d bytes]",
		       elems[i]->templateElementName, 
		       (elems[i]->templateElementEnterpriseId == NTOP_ENTERPRISE_ID) ? elems[i]->templateElementId-NTOP_BASE_ID : elems[i]->templateElementId,
		       elems[i]->templateElementLen, tot);
	} else
	  break;

	if(tot > flowLen) flowLen = tot;
      }
    }

    if((readOnlyGlobals.v9TemplateElementListV4[0] == NULL)
       && (readOnlyGlobals.numCollectors == 0)
       && readOnlyGlobals.none_specified) {
      traceEvent(TRACE_ERROR, "-D is mandatory when '-n none' is specified");
      exit(0);
    }

#ifdef HAVE_MYSQL
    init_db_table();
#endif

#ifdef HAVE_FASTBIT
    init_fastbit(readOnlyGlobals.v9TemplateElementListV4, NULL /* No configuration file */);
#endif

    if(flowLen > 0) {
      if(readOnlyGlobals.traceMode == 2) traceEvent(TRACE_INFO, "Scanning option template...");
      for(i=0; i<readOnlyGlobals.numOptionTemplateFieldElements; i++) {
	if(readOnlyGlobals.v9OptionTemplateElementList[i] != NULL) {
	  readOnlyGlobals.optionTemplateFlowSize += readOnlyGlobals.v9OptionTemplateElementList[i]->templateElementLen;

	  if(readOnlyGlobals.traceMode == 2) {
	    traceEvent(TRACE_INFO, "Found %20s [id %d][%u bytes][total %d bytes]",
		       readOnlyGlobals.v9OptionTemplateElementList[i]->templateElementName,
		       readOnlyGlobals.v9OptionTemplateElementList[i]->templateElementId,
		       readOnlyGlobals.v9OptionTemplateElementList[i]->templateElementLen,
		       (int)readOnlyGlobals.optionTemplateFlowSize);
	  }

	} else
	  break;
      }

      readOnlyGlobals.templateFlowSize = (((8+readOnlyGlobals.templateBufBeginV4+readOnlyGlobals.templateBufBeginV6)
					   + (12+readOnlyGlobals.optionTemplateBufBegin)
					   + (4+readOnlyGlobals.optionTemplateFlowSize)
					   + (flowLen-1) /* Avoid rounding problems */
					   ) / flowLen);

      if(readOnlyGlobals.minNumFlowsPerPacket == -1) {
	/*
	  As with NetFlow v5, we suppose that a UDP packet can fit up to 1440
	  bytes (alias NETFLOW_MAX_BUFFER_LEN) of payload for NetFlow flows.
	*/
	readOnlyGlobals.minNumFlowsPerPacket = (NETFLOW_MAX_BUFFER_LEN/flowLen)-1;
	traceEvent(TRACE_INFO, "Each flow is %d bytes long", flowLen);
	traceEvent(TRACE_INFO, "The # packets per flow has been set to %d",
		   readOnlyGlobals.minNumFlowsPerPacket);
      } else {
	if((readOnlyGlobals.minNumFlowsPerPacket*flowLen) >= NETFLOW_MAX_BUFFER_LEN) {
	  traceEvent(TRACE_WARNING,
		     "Too many flows per packet specified using -m.");
	  readOnlyGlobals.minNumFlowsPerPacket = (NETFLOW_MAX_BUFFER_LEN/flowLen)-1;
	  traceEvent(TRACE_INFO, "The # packets per flow has been set to %d",
		     readOnlyGlobals.minNumFlowsPerPacket);
	}
      }
    } else {
      readOnlyGlobals.netFlowVersion = 5;
      traceEvent(TRACE_INFO, "The flow size is zero. Switching back to v5");
    }
  }

  buildActivePluginsList(readOnlyGlobals.v9TemplateElementListV4);

  if(reloadTemplate) {
    readWriteGlobals->stopPacketCapture = 0;
    traceEvent(TRACE_INFO, "nProbe is now operational...");
  }
}

/* ****************************************************** */

int
#ifdef WIN32
nprobe_main
#else
main
#endif
(int argc, char *argv[]) {
  char ebuf[PCAP_ERRBUF_SIZE] = { '\0' };
  u_int i, idx;

#ifdef HAVE_LICENSE
  /* NOTE
     As the getopt is manipulated this MUST be the
     first function to be called at startup
  */
  {
    extern int optind, opterr, optopt;
    extern int verify_license(char * version, char *license_path, int kind, char *out_buf, int out_buf_len);
    extern int verify_application_instances(char *application_name, char *out_buf, int out_buf_len);
    int t_optind, t_opterr, t_optopt, num_instances;
    char out_buf[8192];

    /* save values of optind, opterr and optopt because license library
     * Calls getopt_long
     */
    t_optind=optind;  t_opterr=opterr;  t_optopt=optopt;

    if((argc == 2) && (!strcmp(argv[1], "-V"))) {
      probeVersion();
      exit(0);
    } else if((argc == 2) && (!strcmp(argv[1], "-h"))) {
      usage();
      exit(0);
    }

    if(verify_license(version, "/etc/nprobe.license", 2, out_buf, sizeof(out_buf)) != 0) {
      if(getuid() == 0)
	traceEvent(TRACE_ERROR, "Invalid or missing license found");
      else
	traceEvent(TRACE_ERROR, "Please start nprobe as root");

      exit(0);
    }

    if((num_instances = verify_application_instances("nprobe", out_buf, sizeof(out_buf))) != 0) {
      traceEvent(TRACE_ERROR, "Too many nProbe instances (%d) running", num_instances);
      exit(-1);
    }

    /* restore values */
    optind=t_optind;  opterr=t_opterr;  optopt=t_optopt;
  }
#endif

#ifdef WIN32
  int optind = 0;

  ptw32_processInitialize();
#endif

  init_globals();

#ifdef DEMO_MODE
  printf("*************************************************************\n");
  printf("* NOTE: This is a DEMO version limited to %d flows export. *\n",
	 MAX_DEMO_FLOWS);
  printf("*************************************************************\n\n");
#endif

#ifdef WIN32
  initWinsock32();
#else
  setprotoent(1); setservent(1); /* Improve protocol/port lookup performance */
#endif

  argc_ = argc;
  argv_ = (char**)argv;
  if(parseOptions(argc, argv, 0) == -1) exit(0);

  // readOnlyGlobals.traceMode = 2, traceLevel = 5; // FIX
  initPlugins(argc, argv);

  traceEvent(TRACE_INFO, "Welcome to nprobe v.%s for %s", version, osName);
  printCopyrights();

#ifndef WIN32
  if(readOnlyGlobals.useSyslog)
    openlog(readOnlyGlobals.nprobeId, LOG_PID ,LOG_DAEMON);
#endif

  memset(&readWriteGlobals->theFlowHash, 0, sizeof(readWriteGlobals->theFlowHash));
  readWriteGlobals->bufferLenV4 = readWriteGlobals->bufferLenV6 = 0;
  readWriteGlobals->shutdownInProgress = 0;
  readWriteGlobals->flowExportStats.totExportedBytes = 0;
  readWriteGlobals->flowExportStats.totExportedPkts = readWriteGlobals->flowExportStats.totExportedFlows = 0;

  createCondvar(&readWriteGlobals->exportQueueCondvar);
  createCondvar(&readWriteGlobals->termCondvar);
  pthread_mutex_init(&readWriteGlobals->exportMutex, NULL);

  for(i=0; i<NUM_FRAGMENT_LISTS; i++)
    pthread_mutex_init(&readWriteGlobals->fragmentMutex[i], NULL);

#ifdef HAVE_GEOIP
  pthread_rwlock_init(&readWriteGlobals->geoipRwLock, NULL);
#endif

  pthread_rwlock_init(&readWriteGlobals->exportRwLock, NULL);
  pthread_rwlock_init(&readWriteGlobals->statsRwLock, NULL);
  pthread_rwlock_init(&readWriteGlobals->rwGlobalsRwLock, NULL);
  pthread_rwlock_init(&readWriteGlobals->collectorRwLock, NULL);
  pthread_rwlock_init(&readWriteGlobals->collectorCounterLock, NULL);

  for(idx=0; idx<readOnlyGlobals.numProcessThreads; idx++) {
    for(i=0; i<MAX_HASH_MUTEXES; i++)
      pthread_rwlock_init(&readWriteGlobals->flowHashRwLock[idx][i], NULL);
  }

  for(i=0; i<MAX_HASH_MUTEXES; i++)
    pthread_mutex_init(&readWriteGlobals->hostHashMutex[idx], NULL);

  if((readWriteGlobals->bufferV4 = (char*)malloc(NETFLOW_MAX_BUFFER_LEN)) == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory [v4] ?");
    return(0);
  }

  if((readWriteGlobals->bufferV6 = (char*)malloc(NETFLOW_MAX_BUFFER_LEN)) == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory [v6] ?");
    return(0);
  }

  /* FIX
     if(textFormat
     && ((strstr(textFormat, "%js") != NULL)
     || (strstr(textFormat, "%jd") != NULL)))
     calculateJitter = 1;
  */

  if(readOnlyGlobals.bidirectionalFlows && (readOnlyGlobals.netFlowVersion == 5)) {
    traceEvent(TRACE_WARNING, "Bi-directional flows are not supported by NetFlowV5: disabled");
    readOnlyGlobals.bidirectionalFlows = 0;
  }

  compileTemplates(0);

  if((readOnlyGlobals.netFlowVersion != 5) && readOnlyGlobals.ignoreIP)
    traceEvent(TRACE_WARNING, "Your template ignores IP addresses: your collector might ignore these flows.");

  if((readOnlyGlobals.dirPath != NULL) && (readOnlyGlobals.v9TemplateElementListV4[0] == NULL)) {
    traceEvent(TRACE_WARNING,
	       "-P can be specified only with -D. Ignoring -P value [%s].",
	       readOnlyGlobals.dirPath);
    free(readOnlyGlobals.dirPath);
    readOnlyGlobals.dirPath = NULL;
  }

  if(readOnlyGlobals.ignorePorts && readOnlyGlobals.ignoreProtocol)
    readOnlyGlobals.handleFragments = 0;

  if((readWriteGlobals->bufferV4 == NULL) || (readWriteGlobals->bufferV6 == NULL)) {
    traceEvent(TRACE_ERROR, "Not enough memory\n");
    exit(-1);
  }

#ifndef WIN32
  signal(SIGTERM, cleanup);
  signal(SIGINT,  cleanup);
  signal(SIGPIPE, brokenPipe);
  signal(SIGHUP,  reloadCLI);
#endif

  /* pcap-based sniffing */
  for(idx=0; idx<readOnlyGlobals.numProcessThreads; idx++)
    allocateFlowHash(idx);

  allocateHostHash();

  if((readOnlyGlobals.collectorInPort == 0) || (readOnlyGlobals.tmpDev != NULL)) {
    if((openDevice(ebuf, 1, (readOnlyGlobals.pcapFileList ? readOnlyGlobals.pcapFileList->path : NULL)) == -1)
       || ((readOnlyGlobals.pcapPtr == NULL)
	   && strcmp(readOnlyGlobals.tmpDev, "none")
#ifdef HAVE_PF_RING
	   && (readWriteGlobals->ring == NULL)
	   && (readOnlyGlobals.metadata_fd == NULL)
#endif
	   )) {
      traceEvent(TRACE_ERROR, "Unable to open interface %s (%s)\n",
		 readOnlyGlobals.tmpDev == NULL ? "<none>" : readOnlyGlobals.tmpDev, ebuf);
      exit(-1);
    }

    if(readOnlyGlobals.pcapFileList != NULL) {
      struct fileList *next = readOnlyGlobals.pcapFileList->next;

      free(readOnlyGlobals.pcapFileList->path);
      free(readOnlyGlobals.pcapFileList);
      readOnlyGlobals.pcapFileList = next;
    }
  }

  readWriteGlobals->accumulateStats.pkts = 0, readWriteGlobals->accumulateStats.bytes = 0,
    readWriteGlobals->accumulateStats.tcpPkts = 0, readWriteGlobals->accumulateStats.tcpBytes = 0;
  readWriteGlobals->accumulateStats.udpPkts = 0, readWriteGlobals->accumulateStats.udpBytes = 0,
    readWriteGlobals->accumulateStats.icmpPkts = 0, readWriteGlobals->accumulateStats.icmpBytes = 0;
  readWriteGlobals->lastSample = time(NULL);

  traceEvent(TRACE_INFO, "The flows hash has %d buckets",
	     readOnlyGlobals.flowHashSize);
  traceEvent(TRACE_INFO, "Flows older than %d seconds will be exported",
	     readOnlyGlobals.lifetimeTimeout);

  if(readOnlyGlobals.rebuild_hash)
    traceEvent(TRACE_INFO, "Flows will be exported at each hash rebuild (--rebuild-hash)\n");
  else
    traceEvent(TRACE_INFO, "Flows inactive for at least %d seconds will be exported",
	       readOnlyGlobals.idleTimeout);

  traceEvent(TRACE_INFO, "Expired flows will be checked every %d seconds",
	     readOnlyGlobals.scanCycle);
  traceEvent(TRACE_INFO, "Expired flows will not be queued for more than %d seconds",
	     readOnlyGlobals.sendTimeout);

  if((readOnlyGlobals.engineType != 0) || (readOnlyGlobals.engineId != 0))
    traceEvent(TRACE_INFO,
	       "Exported flows with engineType %d and engineId %d",
	       readOnlyGlobals.engineType, readOnlyGlobals.engineId);

  if(readOnlyGlobals.minFlowSize != 0)
    traceEvent(TRACE_INFO,
	       "TCP flows shorter than %u bytes will not be emitted",
	       readOnlyGlobals.minFlowSize);

  if(readOnlyGlobals.ignoreVlan)
    traceEvent(TRACE_INFO, "Vlan Ids will be ignored and set to 0.");

  if(readOnlyGlobals.ignoreProtocol)
    traceEvent(TRACE_INFO, "IP Protocol will be ignored and set to 0.");

  if(readOnlyGlobals.ignoreIP)
    traceEvent(TRACE_INFO, "IP addresses will be ignored and set to 0.");

  if(readOnlyGlobals.ignorePorts)
    traceEvent(TRACE_INFO, "UDP/TCP src/dst ports will be ignored and set to 0.");

  if(readOnlyGlobals.ignoreTos)
    traceEvent(TRACE_INFO, "TCP TOS will be ignored and set to 0.");

#ifdef HAVE_GEOIP
  if(readOnlyGlobals.geo_ip_asn_db == NULL)
#endif
    traceEvent(TRACE_INFO, "Flows ASs will not be computed");

  if((readOnlyGlobals.packetFlowGroup > 0) && (readOnlyGlobals.flowExportDelay == 0)) {
    traceEvent(TRACE_INFO, "WARNING: -B requires that you also set -e. Ignored.");
    readWriteGlobals->packetSentCount = 0;
  }

  if((readOnlyGlobals.packetFlowGroup > 0) && (readOnlyGlobals.flowExportDelay > 0))
    traceEvent(TRACE_INFO, "After %d flow packets are sent, we'll delay at least %d ms",
	       readOnlyGlobals.packetFlowGroup, readOnlyGlobals.flowExportDelay);
  else if(readOnlyGlobals.flowExportDelay > 0)
    traceEvent(TRACE_INFO, "The minimum intra-flow delay is of at least %d ms",
	       readOnlyGlobals.flowExportDelay);

  if(readOnlyGlobals.flowLockFile != NULL)
    traceEvent(TRACE_INFO,
	       "No flows will be sent if the lock file '%s' is present",
	       readOnlyGlobals.flowLockFile);

  if(readOnlyGlobals.numCollectors > 1) {
    if(readOnlyGlobals.reflectorMode)
      traceEvent(TRACE_INFO, "All flows will be sent to all defined "
		 "collectors (NetFlow reflector mode)");
    else
      traceEvent(TRACE_INFO, "Flows will be sent to the defined collectors "
		 "in round robin.");
  }

  traceEvent(TRACE_INFO, "Flows will be emitted in %s format",
	     readOnlyGlobals.netFlowVersion == 5 ? "NetFlow 5" :
	     (readOnlyGlobals.netFlowVersion == 9 ? "NetFlow 9" : "IPFIX"));

  if(readOnlyGlobals.maxPayloadLen) {
    traceEvent(TRACE_INFO, "Max payload length set to %d bytes",
	       readOnlyGlobals.maxPayloadLen);
    traceEvent(TRACE_INFO, "Payload export policy (-x) for TCP:   %s",
	       printPayloadValue(readOnlyGlobals.tcpPayloadExport));
    traceEvent(TRACE_INFO, "Payload export policy (-x) for UDP:   %s",
	       printPayloadValue(readOnlyGlobals.udpPayloadExport));
    traceEvent(TRACE_INFO, "Payload export policy (-x) for ICMP:  %s",
	       printPayloadValue(readOnlyGlobals.icmpPayloadExport));
    traceEvent(TRACE_INFO, "Payload export policy (-x) for OTHER: %s",
	       printPayloadValue(readOnlyGlobals.otherPayloadExport));
  }

  if(readOnlyGlobals.pktSampleRate > 1)
    traceEvent(TRACE_INFO, "%sSampling packets at 1:%d rate",
	       readOnlyGlobals.fakePktSampling ? "Fake " : "",
	       readOnlyGlobals.pktSampleRate);

  if(readOnlyGlobals.flowSampleRate > 1) {
    traceEvent(TRACE_INFO, "Sampling flows at 1:%d rate", readOnlyGlobals.flowSampleRate);
    readWriteGlobals->flowsToGo = readOnlyGlobals.flowSampleRate;
  }

  if(readOnlyGlobals.use_vlanId_as_ifId) {
    traceEvent(TRACE_INFO, "Using VLAN Id as NetFlow interface Id");
  } else {
    if(readOnlyGlobals.inputInterfaceIndex == NO_INTERFACE_INDEX)
      traceEvent(TRACE_INFO, "Flow input interface index is dynamic (last two MAC address bytes)");
    else
      traceEvent(TRACE_INFO, "Flow input interface index is set to %d",
		 readOnlyGlobals.inputInterfaceIndex);

    if(readOnlyGlobals.outputInterfaceIndex == NO_INTERFACE_INDEX)
      traceEvent(TRACE_INFO, "Flow output interface index is dynamic (last two MAC address bytes)");
    else
      traceEvent(TRACE_INFO, "Flow output interface index is set to %d",
		 readOnlyGlobals.outputInterfaceIndex);
  }

  if((readOnlyGlobals.pcapFile == NULL)
#ifdef HAVE_PF_RING
     && (readOnlyGlobals.metadata_fd == NULL)
#endif
     && (readOnlyGlobals.tmpDev != NULL)) {
    if((readOnlyGlobals.pcapPtr == NULL)
#ifdef HAVE_PF_RING
       && (readWriteGlobals->ring == NULL)
#endif
       )
      traceEvent(TRACE_NORMAL, "Not capturing packet from interface (collector mode)");
    else
      traceEvent(TRACE_NORMAL, "Capturing packets from interface %s",
		 readOnlyGlobals.tmpDev);
  }

  if(readOnlyGlobals.smart_udp_frags_mode)
    traceEvent(TRACE_NORMAL, "Smart fragment rebuild enabled (no fragments are rebuilt)");

  if(readOnlyGlobals.tunnel_mode)
    traceEvent(TRACE_NORMAL, "Enabled tunnel decoding (e.g. IPSEC/GTP)");

  nprobe_up = 1;
  dumpLogEvent(probe_started, severity_info, "nProbe started");

#ifndef WIN32
  if(readOnlyGlobals.becomeDaemon)
    daemonize();
#endif

#ifndef WIN32
  if(readOnlyGlobals.pidPath) {
    FILE *fd = fopen(readOnlyGlobals.pidPath, "w");
    if(fd != NULL) {
      unsigned long pid = getpid();

      fprintf(fd, "%lu\n", pid);
      fclose(fd);
    } else
      traceEvent(TRACE_ERROR, "Unable to store PID in file %s", readOnlyGlobals.pidPath);
  }
#endif

  if((readOnlyGlobals.pcapFile == NULL)
#ifdef HAVE_PF_RING
     && (readOnlyGlobals.metadata_fd == NULL)
#endif
     ) {
    dropPrivileges();
  }

  enablePlugins();
  load_mappings();
  setupPlugins();

  if((readOnlyGlobals.pcapPtr
#ifdef HAVE_PF_RING
      || (readWriteGlobals->ring != NULL)
      || (readOnlyGlobals.metadata_fd != NULL)
#endif
      || (readOnlyGlobals.collectorInPort > 0)
      )) {
#if !defined(WIN32)
      pthread_attr_t tattr;
      struct sched_param param;

      /* initialized with default attributes */
      if(pthread_attr_init(&tattr) == 0) {
	/* safe to get existing scheduling param */
	if(pthread_attr_getschedparam (&tattr, &param) == 0) {
	  param.sched_priority++; /* Increase priority */

	  /* setting the new scheduling param */
	  pthread_attr_setschedparam (&tattr, &param);
	}
      }
#endif

    /* Start a pool of threads */
    if((packetProcessThread = (pthread_t*)malloc(sizeof(pthread_t)*readOnlyGlobals.numProcessThreads)) == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return(0);
    }

    /* Initialize queues */
    for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
      PacketQueue *queue = &readWriteGlobals->packetQueue[i];
      int j;

      queue->insert_idx = queue->remove_idx = queue->num_queued_pkts = queue->num_dequeued_pkts = 0;
      queue->queue_capacity = DEFAULT_QUEUE_CAPACITY;
      createCondvar(&queue->queue_condvar), createCondvar(&queue->dequeue_condvar);
      queue->queue = (QueuedPacket*)calloc(queue->queue_capacity, sizeof(QueuedPacket));

      if(queue->queue == NULL) {
	traceEvent(TRACE_ERROR, "Not enough memory?");
	return(0);
      }

      for(j=0; j<queue->queue_capacity; j++) {
	queue->queue[j].p = (u_char*)malloc(readOnlyGlobals.snaplen);
	if(queue->queue[j].p == NULL) {
	  traceEvent(TRACE_ERROR, "Not enough memory?");
	  return(0);
	} else {
#ifdef DEBUG
	  traceEvent(TRACE_NORMAL, "Allocated slot %d [queue_id=%d][snaplen=%d]=%p",
		     j, i, readOnlyGlobals.snaplen, queue->queue[j].p);
#endif
	}
      }
    }

    /* Spawn threads */
    for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
      u_long thread_id = i;

      pthread_create(&packetProcessThread[i],
#if !defined(WIN32)
		     &tattr,
#else
		     NULL,
#endif
		     dequeuePackets, (void*)thread_id);

      traceEvent(TRACE_INFO, "Started dequeuePackets() thread %lu", thread_id);
    }

    if(readOnlyGlobals.collectorInPort > 0) {
      createNetFlowListener(readOnlyGlobals.collectorInPort);
    }

#ifdef NETFLOW_DEBUG
    traceEvent(TRACE_WARNING, "*****************************************");
    traceEvent(TRACE_WARNING, "** You're running nprobe in DEBUG mode **");
    traceEvent(TRACE_WARNING, "*****************************************");
#endif

    pthread_create(&readWriteGlobals->walkHashThread, NULL, hashWalker, NULL);
    traceEvent(TRACE_INFO, "Starting %u packet fetch thread(s)", readOnlyGlobals.numProcessThreads);
    pthread_create(&readWriteGlobals->dequeueThread, NULL, dequeueBucketToExport, NULL);

    if(readOnlyGlobals.pcapPtr
#ifdef HAVE_PF_RING
       || readWriteGlobals->ring
       || readOnlyGlobals.metadata_fd
#endif
       ) {
      readWriteGlobals->numTerminatedFetchPackets = 0;

      if(readOnlyGlobals.pcapFileList != NULL) {
	struct fileList *fl = readOnlyGlobals.pcapFileList, *next;

	while(fl != NULL) {
	  if((openDevice(ebuf, 1, fl->path) == -1) || (readOnlyGlobals.pcapPtr == NULL))
	    traceEvent(TRACE_ERROR, "Unable to open file %s (%s)\n", fl->path, ebuf);
	  else {
	    if(readOnlyGlobals.pcapPtr) fetchPackets(NULL);
	  }

	  next = fl->next;
	  free(fl->path);
	  free(fl);
	  fl = next;
	}
      } else {
#ifdef HAVE_PF_RING
	(readWriteGlobals->ring || readOnlyGlobals.metadata_fd) ? fetchPfRingPackets(NULL) : fetchPackets(NULL);
#else
	fetchPackets(NULL);
#endif
      }
    } else {
      while(1) ntop_sleep(999); /* Sleep forever */
    }
  }

  if(readOnlyGlobals.pcapFile) {
    traceEvent(TRACE_INFO, "No more packets to read. Sleeping...\n");
    traceEvent(TRACE_NORMAL, "Processed %d packets", readWriteGlobals->accumulateStats.pkts);

    // while(1) ntop_sleep(999); /* Sleep forever */
  }

  shutdown_nprobe();

  return(0);
}

/* ******************************** */
