/*
 *       Copyright (C) 2002-14 Luca Deri <deri@ntop.org>
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
   7.0    [09/14]        Major improvements with v7

   ************************************************************************ */

#include "nprobe.h"

#define BLANK_SPACES               "                     "

/* #define HASH_DEBUG */

/* #define TIME_PROTECTION  */

#define MAX_SAMPLE_RATE    ((u_short)-1)

#ifdef HAVE_TEMPLATE_EXTENSIONS
#include "hasp_api.h"
#include "hasp_vcode.h"
#endif

/* *************************************** */


/*
  #define OPTION_TEMPLATE "%SYSTEM_ID %SAMPLING_INTERVAL %SAMPLING_ALGORITHM %TOTAL_BYTES_EXP %TOTAL_PKTS_EXP %TOTAL_FLOWS_EXP %FLOW_ACTIVE_TIMEOUT %FLOW_INACTIVE_TIMEOUT"
*/

#define V9_OPTION_TEMPLATE "%TOTAL_FLOWS_EXP %TOTAL_PKTS_EXP"

/* IMPORTANT: when you modify it please also change exportBucketToNetflowV5 */
#define DEFAULT_V9_IPV4_TEMPLATE "%IPV4_SRC_ADDR %IPV4_DST_ADDR %IPV4_NEXT_HOP %INPUT_SNMP %OUTPUT_SNMP %IN_PKTS %IN_BYTES %FIRST_SWITCHED " \
  "%LAST_SWITCHED %L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS %PROTOCOL %SRC_TOS %SRC_AS %DST_AS %IPV4_SRC_MASK %IPV4_DST_MASK"

#define DEFAULT_IPFIX_IPV4_TEMPLATE "%IPV4_SRC_ADDR %IPV4_DST_ADDR %IPV4_NEXT_HOP %INPUT_SNMP %OUTPUT_SNMP %IN_PKTS %IN_BYTES %FLOW_START_MILLISECONDS " \
  "%FLOW_END_MILLISECONDS %L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS %PROTOCOL %SRC_TOS %SRC_AS %DST_AS %IPV4_SRC_MASK %IPV4_DST_MASK"

#define DEFAULT_V9_OPTION_TEMPLATE_ID (DEFAULT_TEMPLATE_ID+1)
#define TEMPLATE_PACKETS_DELTA        10

static void initDefaults(void);

/* *********** Globals ******************* */

#ifdef HAVE_PF_RING
#include "pro/pf_ring.c"
#endif

/* ****************************************************** */

/* Forward */
static void printStats(void);
static int parseOptions(int argc, char* argv[], u_int8_t reparse_options);
static void compileTemplates(u_int8_t reloadTemplate);
static void termL7Discovery(void);

static int argc_;
static char **argv_;

#ifdef HAVE_OPTRESET
extern int optreset; /* defined by BSD, but not others */
#endif

typedef void *(*pthread_start_routine)(void*);

static const struct option _long_options[] = {
  { "all-collectors",                   no_argument,             NULL, 'a' },
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
#ifdef HAVE_ZMQ
  { "zmq",                              required_argument,       NULL, 'H' },
#endif
  { "interface",                        required_argument,       NULL, 'i' },
  { "syslog",                           required_argument,       NULL, 'I' },
  { "queue-timeout",                    required_argument,       NULL, 'l' },
  { "local-networks",                   required_argument,       NULL, 'L' },
  { "min-num-flows",                    required_argument,       NULL, 'm' },
  { "max-num-flows",                    required_argument,       NULL, 'M' },
  { "collector",                        required_argument,       NULL, 'n' },
  { "biflows-export-policy",            required_argument,       NULL, 'N' },
  { "flows-intra-templ",                required_argument,       NULL, 'o' },
  { "num-threads",                      required_argument,       NULL, 'O' },
  { "aggregation",                      required_argument,       NULL, 'p' },
  { "dump-path",                        required_argument,       NULL, 'P' },
#ifdef IP_HDRINCL
  { "sender-address",                   required_argument,       NULL, 'q' },
#endif
  { "out-iface-idx",                    required_argument,       NULL, 'Q' },
  { "local-traffic-direction",          no_argument,             NULL, 'r' },
  { "exec-cmd-dump",                    required_argument,       NULL, 'R' },
  { "snaplen",                          required_argument,       NULL, 's' },
  { "sample-rate",                      required_argument,       NULL, 'S' },
  { "lifetime-timeout",                 required_argument,       NULL, 't' },
  { "flow-templ",                       required_argument,       NULL, 'T' },
  { "in-iface-idx",                     required_argument,       NULL, 'u' },
  { "flow-templ-id",                    required_argument,       NULL, 'U' },
  { "hash-size",                        required_argument,       NULL, 'w' },
#ifdef HAVE_TEMPLATE_EXTENSIONS
  { "nfsender",                         required_argument,       NULL, 'x' },
#endif
  { "no-ipv6",                          no_argument,             NULL, 'W' },
  { "version",                          no_argument,             NULL, 'v' },
  { "flow-version",                     required_argument,       NULL, 'V' },
  { "min-flow-size",                    required_argument,       NULL, 'z' },

#ifdef HAVE_PF_RING
  { "cluster-id",                       required_argument,       NULL, 'Z' },
#endif
  { "max-flow-size",                    required_argument,       NULL, '0' },
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
  { "vlanid-as-iface-idx",              required_argument,       NULL, '@' },
  { "discard-unknown-flows",            required_argument,       NULL, '&' },
  { "pcap-file-list",                   required_argument,       NULL, '$' },
  { "csv-separator",                    required_argument,       NULL, '^' },
  { "city-list",                        required_argument,       NULL, ',' },
  /* Some identifiers are available */
  { "dont-drop-privileges",             no_argument,             NULL, '\\' },
  { "bi-directional",                   no_argument,             NULL, '{' },
  { "account-l2",                       no_argument,             NULL, '}' },
  { "dump-metadata",                    required_argument,       NULL, '=' },
  { "event-log",                        required_argument,       NULL, '+' },
  { "disable-ipv4-deduplication",       no_argument,             NULL, 209 },
#ifdef HAVE_PF_RING
  { "hw-timestamp-mode",                required_argument,       NULL, 210 },
#endif
#ifdef HAVE_VOIP_EXTENSIONS
  { "hep-auth",                         required_argument,       NULL, 211 },
#endif
  { "keep-probes-unmerged",             no_argument,             NULL, 212 },
  { "collector-sample-rate",            required_argument,       NULL, 213 },
  { "aggregate-gtp-tunnels",            no_argument,             NULL, 214 },
  { "skip-packet-header-bytes",         required_argument,       NULL, 215 },
#ifdef HAVE_VOIP_EXTENSIONS
  { "hep",                              required_argument,       NULL, 216 },
#endif
  { "collection-filter",                required_argument,       NULL, 217 },
  { "drop-flow-no-plugin",              no_argument,             NULL, 218 },
#ifdef HAVE_REDIS
  { "account-imsi-traffic",             no_argument,             NULL, 219 },
#endif
  { "tcp",                              required_argument,       NULL, 220 },
  { "json-labels",                      no_argument,             NULL, 221 },
#ifdef HAVE_REDIS
  { "use-redis-proxy",                  no_argument,             NULL, 222 },
#endif
  { "max-log-lines",                    required_argument,       NULL, 223 },
  { "timestamp-format",                 required_argument,       NULL, 224 },
  { "ndpi-proto",                       required_argument,       NULL, 225 },
  { "imsi-aggregation",                 no_argument,             NULL, 226 },
  { "simulate-storage",                 no_argument,             NULL, 227 },
  { "dump-pkts",                        required_argument,       NULL, 228 },

#ifdef HAVE_PTHREAD_SET_AFFINITY
  { "export-thread-affinity",           required_argument,       NULL, 230 },
#endif
  { "dump-bad-packets",                 required_argument,       NULL, 231 },
  { "lru-cache-size",                   required_argument,       NULL, 232 },
  { "enable-throughput-stats",          no_argument,             NULL, 233 },
  { "ndpi-proto-ports",                 required_argument,       NULL, 234 },
  { "dont-reforge-timestamps",          no_argument,             NULL, 235 },
  { "disable-l7-protocol-guess",        no_argument,             NULL, 236 },
  { "original-speed",                   no_argument,             NULL, 237 },
  { "db-engine",                        required_argument,       NULL, 238 },

#ifdef linux
  { "check-boundaries",                 no_argument,             NULL, 239 },
#endif

#ifdef HAVE_REDIS
  { "redis",                            required_argument,       NULL, 240 },
  { "ucloud",                           no_argument,             NULL, 241 },
  { "local-ucloud <port>",              required_argument,       NULL, 242 },
#endif

  { "dont-nest-dump-dirs",              no_argument,             NULL, 243 },
  { "unprivileged-user",                required_argument,       NULL, 244 },
  { "disable-cache",                    no_argument,             NULL, 245 },
  { "fake-capture",                     no_argument,             NULL, 246 },
  /* NOTE: 247 is free */
  { "performance",                      no_argument,             NULL, 248 },
#ifdef HAVE_REDIS
  { "redis-logging",                    required_argument,       NULL, 249 },
#endif
  /*
    Options for plugins. These options are not handled by the main
    program but it's important to have them defined here otherwise we
    get a warning from the probe
  */
  { "nflite",                           required_argument, NULL, 250 /* dummy */ }, /* FIX Remove */
  { "nprobe-version",                   required_argument, NULL, 252 /* dummy */ },

#ifdef HAVE_LICENSE
  { "show-system-id",                   no_argument,       NULL,  252 /* dummy */ },
  { "check-license",                    no_argument,       NULL,  252 /* dummy */ },
#endif
  { "dump-plugin-families",             no_argument,       NULL,  252 /* dummy */ },

  { "interpret-flow-packets",           no_argument,       NULL, 253 },
  { "debug",                            no_argument,       NULL, 254 },
  { "ignore-plugin-version",            no_argument,       NULL, 255 },

  /* End of probe options */
  { NULL,                               no_argument,       NULL,  0 }
};

static struct option long_options[256];

/* ****************************************************** */

void buildCLIoptions() {
  int i = 0, j = 0;

  memset(long_options, 0, sizeof(long_options));

  for(i=0; i<255; i++) {
    if(_long_options[i].name == NULL) break;

    long_options[i].name = _long_options[i].name;
    long_options[i].has_arg = _long_options[i].has_arg;
    long_options[i].flag = _long_options[i].flag;
    long_options[i].val = _long_options[i].val;
  }

  while((j < MAX_NUM_PLUGINS) && (readOnlyGlobals.all_plugins[j] != NULL)) {
    if(readOnlyGlobals.all_plugins[j]->optionsFctn != NULL) {
      const struct option *opt = readOnlyGlobals.all_plugins[j]->optionsFctn();

      if(opt != NULL) {
	int k = 0;

	while(opt[k].name != NULL) {
	  if(i == 255) {

	    traceEvent(TRACE_ERROR, "INTERNAL ERROR: Too many options!");
	    break;
	  }

	  long_options[i].name    = opt[k].name;
	  long_options[i].has_arg = opt[k].has_arg;
	  long_options[i].flag    = opt[k].flag;
	  long_options[i].val     = opt[k].val;
	  i++, k++;
	}
      }

      j++;
    }
  }
}

/* ****************************************************** */

u_int32_t printPcapStats(pcap_t *pcapPtr) {
  struct pcap_stat pcapStat;

  if(readOnlyGlobals.fakePacketCapture) return(0);

  if(pcap_stats(pcapPtr, &pcapStat) >= 0) {
    u_long rcvd_diff, drop_diff;
    char msg[256];

    /* Some pcap implementations reset the stats at each call */
    if(pcapStat.ps_recv >= readWriteGlobals->last_ps_recv) {
      rcvd_diff = pcapStat.ps_recv - readWriteGlobals->last_ps_recv;
      drop_diff = pcapStat.ps_drop - readWriteGlobals->last_ps_drop;
    } else {
      rcvd_diff = pcapStat.ps_recv, drop_diff = pcapStat.ps_drop;
    }

    /* traceEvent(TRACE_ERROR, "[%u][%u]\n", pcapStat.ps_recv, pcapStat.ps_drop); */

    snprintf(msg, sizeof(msg), "Packet stats (pcap): "
	     "%u/%u pkts rcvd/dropped [%.1f%%] [Last %lu/%lu pkts rcvd/dropped]",
	     pcapStat.ps_recv, pcapStat.ps_drop,
	     (pcapStat.ps_recv > 0) ? ((float)(pcapStat.ps_drop*100)/(float)pcapStat.ps_recv) : 0,
	     rcvd_diff, drop_diff);

    // traceEvent(TRACE_INFO, "%s", msg);

    if(readWriteGlobals->shutdownInProgress && (pcapStat.ps_drop > 0)) {
      snprintf(msg, sizeof(msg), "Final capture stats (pcap): "
	       "%u/%u pkts rcvd/dropped [%.1f%%]",
	       pcapStat.ps_recv, pcapStat.ps_drop,
	       (pcapStat.ps_recv > 0) ? ((float)(pcapStat.ps_drop*100)/(float)pcapStat.ps_recv) : 0);
      dumpLogEvent(packet_drop, severity_warning, msg);
    }

    readWriteGlobals->last_ps_recv = pcapStat.ps_recv, readWriteGlobals->last_ps_drop = pcapStat.ps_drop;

    return(drop_diff);
  } else {
#ifdef DEBUG
    traceEvent(TRACE_WARNING, "Unable to read pcap statistics: %s",
	       pcap_geterr(pcapPtr));
#endif

    return(0 /* drop_diff */);
  }
}

/* ****************************************************** */

/* Return the number of dropped packets since last call */
static u_int32_t printCaptureStats(u_int8_t dump_stats_on_screen) {
#ifdef HAVE_PF_RING
  if(!readWriteGlobals->stopPacketCapture)
    return(printPfRingStats(dump_stats_on_screen));
#else
  if(readOnlyGlobals.pcapPtr != NULL)
    return(printPcapStats(readOnlyGlobals.pcapPtr));
#endif
  else
    return(0);
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

  if(!readOnlyGlobals.nprobe_up) exit(0);

  if(!statsPrinted) {
    statsPrinted = 1;
    printCaptureStats(1);
    dumpCacheStats(0);
  }

  readOnlyGlobals.nprobe_up = 0;
  readWriteGlobals->shutdownInProgress = 1;
  traceEvent(TRACE_NORMAL, "Received shutdown request...");

  /* shutdown_nprobe(); */
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

static void closeThroughputStatsDump() {
  if(readWriteGlobals->flowThroughputFd != NULL) {
    int len;
    char newPath[512]; /* same size as dumpFilePath */

    fclose(readWriteGlobals->flowThroughputFd);
    readWriteGlobals->flowThroughputFd = NULL;

    len = strlen(readWriteGlobals->dumpFileThptPath)-strlen(TEMP_PREFIX);
    strncpy(newPath, readWriteGlobals->dumpFileThptPath, len); newPath[len] = '\0';
    rename(readWriteGlobals->dumpFileThptPath, newPath);
    traceEvent(TRACE_INFO, "Throughput file '%s' is now available", newPath);
  }
}

/* ****************************************************** */

void printSingleThroughputTime(time_t theTime) {
  u_int32_t partialPkts, partialBytes;

  if(readWriteGlobals->flowThroughputFd && (theTime % 60) == 0)
    closeThroughputStatsDump();

  if(readWriteGlobals->flowThroughputFd == NULL) {
    char dir_path[256], creation_time[256];
    struct tm *tm;

    tm = localtime(&theTime);
    strftime(creation_time, sizeof(creation_time), "%Y/%m/%d/%H", tm);

    snprintf(dir_path, sizeof(dir_path), "%s%c%s",
	     readOnlyGlobals.dirPath, CONST_DIR_SEP, creation_time);
    mkdir_p(dir_path);

    snprintf(readWriteGlobals->dumpFileThptPath,
	     sizeof(readWriteGlobals->dumpFileThptPath),
	     "%s%c%s%c%02d.%s%s",
	     readOnlyGlobals.dirPath, '/', creation_time, '/',
	     tm->tm_min - (tm->tm_min % ((readOnlyGlobals.file_dump_timeout+59)/60)),
	     "throughput",
	     TEMP_PREFIX);

#ifdef WIN32
    revertSlash(readWriteGlobals->dumpFileThptPath, 0);
#endif

    if((readWriteGlobals->flowThroughputFd = fopen(readWriteGlobals->dumpFileThptPath, "w+b")) == NULL) {
      traceEvent(TRACE_WARNING, "Unable to create file '%s' [errno=%d]",
		 readWriteGlobals->dumpFileThptPath, errno);
    } else {
      fprintf(readWriteGlobals->flowThroughputFd, "# %s\t%s\t%s\n", "epoch", "packets", "bytes");

      traceEvent(TRACE_INFO, "Created file '%s'", readWriteGlobals->dumpFileThptPath);
    }
  }

  pthread_rwlock_wrlock(&readWriteGlobals->trafficThroughputStats.trafficThroughputLock);
  partialPkts = readWriteGlobals->trafficThroughputStats.partialPkts,
    partialBytes = readWriteGlobals->trafficThroughputStats.partialBytes;
  readWriteGlobals->trafficThroughputStats.partialPkts = 0, readWriteGlobals->trafficThroughputStats.partialBytes = 0;
  pthread_rwlock_unlock(&readWriteGlobals->trafficThroughputStats.trafficThroughputLock);

  if(readWriteGlobals->flowThroughputFd) {
    fprintf(readWriteGlobals->flowThroughputFd, "%u\t%u\t%u\n",
	    (unsigned int)theTime, partialPkts, partialBytes);
    readWriteGlobals->lastThroughputDump = theTime;
  }
}

/* ****************************************************** */

static void* printThroughputStats(void* notUsed) {
  traceEvent(TRACE_INFO, "[Throughput] %s() started", __FUNCTION__);

  while(!readWriteGlobals->shutdownInProgress) {
    time_t theTime;

    if(readOnlyGlobals.reforgeTimestamps) readWriteGlobals->now = time(NULL);

    theTime = readWriteGlobals->now;
    printSingleThroughputTime(theTime);
    ntop_sleep(1);
  }

  closeThroughputStatsDump();
  traceEvent(TRACE_INFO, "[Throughput] %s() terminated", __FUNCTION__);

  return(NULL);
}

/* ****************************************************** */

static void updateThreadPacketStats(u_short pktLen, u_short thread_id, struct timeval *ts) {
  pktLen += 24 /* 8 Preamble + 4 CRC + 12 IFG */;

  readWriteGlobals->accumulateStats[thread_id].pkts++, readWriteGlobals->accumulateStats[thread_id].bytes += pktLen;
  readWriteGlobals->currentPkts[thread_id]++, readWriteGlobals->currentBytes[thread_id] += pktLen;

  if(unlikely(readOnlyGlobals.computeTrafficThroughput)) {
    pthread_rwlock_wrlock(&readWriteGlobals->trafficThroughputStats.trafficThroughputLock);
    readWriteGlobals->trafficThroughputStats.partialPkts++, readWriteGlobals->trafficThroughputStats.partialBytes += pktLen;
    readWriteGlobals->trafficThroughputStats.lastPktReceivedSec = ts->tv_sec;
    pthread_rwlock_unlock(&readWriteGlobals->trafficThroughputStats.trafficThroughputLock);
  }
}

/* ****************************************************** */

static void dumpPacket(struct pcap_pkthdr *h, const u_char *p) {
  int i, num;

  traceEvent(TRACE_NORMAL, "%s(len=%u, caplen=%u)", __FUNCTION__, h->len, h->caplen);
  for(i=0, num=0; i<h->caplen; i++) {
    printf("%02X ", p[i] & 0xFF), num++;
    if(num == 32) {
      printf("\n");
      num = 0;
    }
  }

  printf("\n");
}

/* ****************************************************** */

/*
  There are some ports we should not unfragment as the packets are usually
  some leftover and reassembling the payload might not be worth in terms
  of performance loss, and thus it's the plugin that has to do
  the packet reassembly
 */
static u_int8_t portToUnfragment(u_int8_t proto, u_int16_t port) {
  if(proto == IPPROTO_UDP) {
    switch(port) {
    case 5060:
    case 5061:
	return(0);
    }
  }

  return(1);
}

/* ****************************************************** */

static void deepPacketDecode(u_short thread_id,
			     int packet_if_idx /* -1 = unknown */,
			     struct pcap_pkthdr *h, const u_char *p,
			     u_int8_t sampledPacket, u_int8_t direction, /* 1=RX, 0=TX */
			     u_int32_t numPkts, int input_index, int output_index,
			     u_int32_t flow_sender_ip,
			     u_int32_t packet_hash) {
  struct eth_header *ehdr = NULL;
  u_int caplen = h->caplen, length = h->len, offset = 0;
  u_short eth_type, off = 0;
  u_int8_t tcpFlags = 0, proto = 0, dont_defrag = 0;
  u_int8_t icmp_type = 0, icmp_code = 0;
  u_int32_t tunnel_id = 0;
  u_int32_t  tcpSeqNum = 0, tcpAckNum = 0;
  u_int16_t tcpWin = 0, overwrite_packet_lenght = 0 /* must be 16 bit to store the length */;
  struct ip *ip = NULL;
  struct ip6_hdr *ipv6 = NULL;
  struct ip6_ext *ipv6ext = NULL;
  struct tcphdr *tp;
  struct udphdr *up = NULL;
  struct sctphdr *sctph;
  struct icmp_hdr *icmpPkt;
  u_int16_t payload_shift = 0;
  int originalPayloadLen = 0, payloadLen = 0; /* Do not set it to unsigned */
  IpAddress src, dst;
  IpAddress untunneled_src, untunneled_dst;
  u_int16_t untunneled_sport = 0, untunneled_dport = 0, ip_offset = 0, gtp_offset = 0;
  u_int8_t untunneled_proto = 0;
  u_short numFragments = 0;
  u_int ehshift = readOnlyGlobals.initialPacketBytesToSkip;
  ticks when;
  char osi_src[48], osi_dst[48];
  u_int16_t tcpMss = 0;
  u_int8_t tcpWinScale = 0;

#ifdef DEBUG
  traceEvent(TRACE_INFO, ".");
#endif

  /* Zero-out data as with IPv4, the IPv6 fields have random values otherwise */
  memset(&src, 0, sizeof(src)), memset(&dst, 0, sizeof(dst));
  /* dumpPacket(h, p); */

#if 0
  if(h->ts.tv_sec > (time(NULL)+1)) {
    traceEvent(TRACE_WARNING, "BAD time: h->ts.tv_sec=%u/time=%u",
	       (unsigned int)h->ts.tv_sec,
	       (unsigned int)time(NULL));
  }
#endif

  osi_src[0] = '\0', osi_dst[0] = '\0';

  /*
    FIX: when packet_hash > 0 check if the packet isn't fragmented
  */
  if(unlikely(readOnlyGlobals.tracePerformance)) when = getticks();

  if(unlikely(readOnlyGlobals.pcapDumper != NULL))
    pcap_dump((u_char*)readOnlyGlobals.pcapDumper, h, p);

  updateThreadPacketStats(h->len, thread_id, &h->ts);

  if(unlikely(readWriteGlobals->stopPacketCapture)) return;

  if(unlikely(readOnlyGlobals.initialSniffTime.tv_sec == 0)) {
    /* Set it with the first incoming packet */
    memcpy(&readOnlyGlobals.initialSniffTime, &h->ts, sizeof(struct timeval));
  }

  readWriteGlobals->now = h->ts.tv_sec;

  if(likely(caplen >= sizeof(struct eth_header))) {
    u_int plen, hlen = 0, ip_len = 0;
    u_short sport, dport, numMplsLabels = 0, tcp_len;
    u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN];
    u_int32_t null_type, subflow_id = 0;
    struct ppp_header ppphdr;
    u_int16_t vlanId = 0;
    u_int16_t outerVlanId = 0;
    static u_int num_pkts = 0;

    num_pkts++;
    // traceEvent(TRACE_INFO, "Datalink: %d", readOnlyGlobals.datalink);

    switch(readOnlyGlobals.datalink) {
    case DLT_ANY: /* Linux 'any' device */
      eth_type = DLT_ANY;
      break;
    case DLT_RAW: /* Raw packet data */
      if(((p[ehshift] & 0xF0) >> 4) == 4)
	eth_type = ETHERTYPE_IP;
      else
	eth_type = ETHERTYPE_IPV6;
      // ehshift = 0;
      break;
    case DLT_NULL: /* loopaback interface */
      ehshift += 4;
      memcpy(&null_type, &p[ehshift], sizeof(u_int32_t));
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
      break;
    case DLT_PPP:
      memcpy(&ppphdr, &p[ehshift], sizeof(struct ppp_header));
      if(ntohs(ppphdr.protocol) == 0x0021 /* IP */)
	eth_type = ETHERTYPE_IP, ehshift += sizeof(struct ppp_header);
      else
	return;
      break;
    case DLT_ERF: /* Endace */
      ehdr = (struct eth_header*)&p[ehshift+18];
      eth_type = ntohs(ehdr->ether_type);
      ehshift += 18+sizeof(struct eth_header);
      break;
    default:
      ehdr = (struct eth_header*)&p[ehshift];
      ehshift += sizeof(struct eth_header);
      eth_type = ntohs(ehdr->ether_type);
      break;
    }

  analyze_eth_type:
    switch(eth_type) {
    case ETHERTYPE_IP:
    case ETHERTYPE_IPV6:
    case ETHERTYPE_VLAN:
    case ETHERTYPE_MPLS:
    case ETHERTYPE_PPPoE:
    case ETHERTYPE_8021AD:
    case DLT_NULL:
    case DLT_ANY:
    case 16385 /* MacOSX loopback */:
    case 16390 /* MacOSX loopback */:
      {
	u_int estimatedLen = 0;

	if(likely((eth_type == ETHERTYPE_IP) || (eth_type == ETHERTYPE_IPV6))) {
	  if((ehshift == 0) && (readOnlyGlobals.datalink != DLT_RAW)) {
	    /* still not set (used to handle the DLT_NULL case) */
	    ehshift = sizeof(struct eth_header);
	  }
 	} else if(eth_type == ETHERTYPE_MPLS) {
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
	} else if(eth_type == ETHERTYPE_8021AD) {
	  Ether8021ad *ad = (Ether8021ad*)(p+ehshift);

	  eth_type = ntohs(ad->protoType);
	  ehshift += sizeof(Ether8021ad);
	  goto analyze_eth_type;
	} else if(eth_type == ETHERTYPE_PPPoE) {
	  eth_type = ETHERTYPE_IP, ehshift += 8;
	} else if(eth_type == ETHERTYPE_VLAN) {
	  Ether80211q *qType;

	  while(eth_type == ETHERTYPE_VLAN) {
	    qType = (Ether80211q*)(p+ehshift);
	    vlanId = ntohs(qType->vlanId) & 0xFFF;
	    if(outerVlanId == 0) outerVlanId = vlanId;
	    eth_type = ntohs(qType->protoType);
	    ehshift += sizeof(Ether80211q);
	    /* printf("VlanId: %d\n", vlanId); <<<== NOT USED YET */
	  }

	  goto analyze_eth_type;
	} else if(eth_type == DLT_ANY) {
	  ehshift += sizeof(AnyHeader);
	  eth_type = ntohs(((AnyHeader*)p)->protoType);
	} else
	  ehshift += NULL_HDRLEN;

      parse_ip:
	ip_offset = ehshift;
	if(likely(eth_type == ETHERTYPE_IP)) {
	  u_short ip_ip_len;

	  ip = (struct ip*)(p+ehshift);
	  if(ip->ip_v != 4) return; /* IP v4 only */

	  /* blacklist check */
	  if(unlikely(readOnlyGlobals.numBlacklistNetworks > 0)) {
	    if(isBlacklistedAddress(&ip->ip_src)
	       || isBlacklistedAddress(&ip->ip_dst))
	      return;
	  }

	  ip_ip_len = htons(ip->ip_len);

	  ip_len = ((u_short)ip->ip_hl * 4);
	  estimatedLen = ehshift + ip_ip_len;
	  hlen = ip_len;
	  payloadLen = htons(ip->ip_len)-ip_len;

	  if(overwrite_packet_lenght == 1)
	    overwrite_packet_lenght = payloadLen + ip_len + ehshift;

	  if(readOnlyGlobals.roundPacketLenWithIPHeaderLen)
	    length = estimatedLen;

	  if(length < h->caplen)
	    h->caplen = length;

	  src.ipVersion = 4, dst.ipVersion = 4;
	  if(unlikely(readOnlyGlobals.ignoreIP
		      || (readOnlyGlobals.setAllNonLocalHostsToZero
			  && (readOnlyGlobals.numLocalNetworks > 0)
			  && (!isLocalAddress(&ip->ip_src)))))
	    src.ipType.ipv4 = 0, dont_defrag = 1; /* 0.0.0.0 */
	  else
	    src.ipType.ipv4 = ntohl(ip->ip_src.s_addr);

	  if(unlikely(readOnlyGlobals.ignoreIP
		      || (readOnlyGlobals.setAllNonLocalHostsToZero
			  && (readOnlyGlobals.numLocalNetworks > 0)
			  && (!isLocalAddress(&ip->ip_dst)))))
	    dst.ipType.ipv4 = 0, dont_defrag = 1; /* 0.0.0.0 */
	  else
	    dst.ipType.ipv4 = ntohl(ip->ip_dst.s_addr);

	  proto = ip->ip_p;
	  off = ntohs(ip->ip_off) & 0x3fff;
	  numFragments = off ? 1 : 0;

	  /*
	    De-duplicate packets that are physically duplicated by devices and
	    thus that are sequencially duplicated (i.e. retransmissions are not
	    handled)
	   */
	  if(likely(readOnlyGlobals.ipv4_deduplication_enabled)) {
	    u_int16_t checksum;

	    if(proto == IPPROTO_UDP)
	      checksum = ((struct udphdr*)(p+ehshift+hlen))->uh_sum;
	    else if(proto == IPPROTO_TCP)
	      checksum = ((struct tcphdr*)(p+ehshift+hlen))->th_sum;
	    else
	      checksum = 0;

	    if((readWriteGlobals->ipv4_deduplication.last_pkt_len == h->len)
	       && (readWriteGlobals->ipv4_deduplication.last_proto == proto)
	       && (readWriteGlobals->ipv4_deduplication.l4_last_checksum == checksum)
	       && (readWriteGlobals->ipv4_deduplication.last_src == ip->ip_src.s_addr)
	       && (readWriteGlobals->ipv4_deduplication.last_dst == ip->ip_dst.s_addr)
	       && (readWriteGlobals->ipv4_deduplication.last_checksum == ip->ip_sum)
	       && (readWriteGlobals->ipv4_deduplication.last_ip_ttl == ip->ip_ttl)
	       && (readWriteGlobals->ipv4_deduplication.last_ip_id == ip->ip_id)
	       ) {
	      // traceEvent(TRACE_WARNING, "Duplicated packet found [IP id: %04X][checksum: %04X]", ntohs(ip->ip_id), ntohs(checksum));
	      return; /* Duplicated packet found */
	    } else {
	      readWriteGlobals->ipv4_deduplication.last_pkt_len = h->len;
	      readWriteGlobals->ipv4_deduplication.last_proto = proto;
	      readWriteGlobals->ipv4_deduplication.l4_last_checksum = checksum;
	      readWriteGlobals->ipv4_deduplication.last_src = ip->ip_src.s_addr;
	      readWriteGlobals->ipv4_deduplication.last_dst = ip->ip_dst.s_addr;
	      readWriteGlobals->ipv4_deduplication.last_checksum = ip->ip_sum;
	      readWriteGlobals->ipv4_deduplication.last_ip_ttl = ip->ip_ttl;
	      readWriteGlobals->ipv4_deduplication.last_ip_id = ip->ip_id;
	      // traceEvent(TRACE_WARNING, "NON Duplicated packet found [IP id: %04X][checksum: %04X]", ntohs(ip->ip_id), ntohs(checksum));
	    }
	  }
	} else if(eth_type == ETHERTYPE_IPV6) {
	  u_short ipv6_ip_len;

	  if(unlikely(readOnlyGlobals.disableIPv6)) return;

	  ipv6 = (struct ip6_hdr*)(p+ehshift);
	  if(((ipv6->ip6_vfc >> 4) & 0x0f) != 6) return; /* IP v6 only */

	  ipv6_ip_len = htons(ipv6->ip6_plen);
	  estimatedLen = sizeof(struct ip6_hdr)+ehshift+ipv6_ip_len;

	  if(readOnlyGlobals.roundPacketLenWithIPHeaderLen)
	    length = estimatedLen;

	  hlen = sizeof(struct ip6_hdr);
	  src.ipVersion = 6, dst.ipVersion = 6;

	  proto = ipv6->ip6_nxt; /* next header (protocol) */
	  payloadLen = h->caplen - ehshift - hlen;

	  /* FIX: blacklist check for IPv6 */

	  /* FIX: isLocalAddress doesn't work with IPv6 */
	  if(unlikely(readOnlyGlobals.ignoreIP))
	    memset(&src.ipType.ipv6, 0, sizeof(struct in6_addr));
	  else
	    memcpy(&src.ipType.ipv6, &ipv6->ip6_src, sizeof(struct in6_addr));

	  if(unlikely(readOnlyGlobals.ignoreIP))
	    memset(&dst.ipType.ipv6, 0, sizeof(struct in6_addr));
	  else
	    memcpy(&dst.ipType.ipv6, &ipv6->ip6_dst, sizeof(struct in6_addr));

	  if(proto == 0) {
	    /* IPv6 hop-by-hop option */

	    ipv6ext = (struct ip6_ext*)(p+ehshift+40);
	    hlen += (ipv6ext->ip6e_len+1)*8;
	    proto = ipv6ext->ip6e_nxt;
	  }
	} else
	  return; /* Anything else that's not IPv4/v6 */

	originalPayloadLen = payloadLen;
	plen = length-ehshift;
	if(caplen > estimatedLen) caplen = estimatedLen;
	payloadLen -= (estimatedLen-caplen);

	sport = dport = 0; /* default */
	offset = ehshift+hlen;

	/* ************************************************ */

	if(unlikely(readOnlyGlobals.tunnel_mode)) {
	  switch(proto) {
	  case IPPROTO_ESP:
	    /* http://www.unixwiz.net/techtips/iguide-ipsec.html */
	    if((readOnlyGlobals.ipsec_auth_data_len > 0) && (payloadLen > readOnlyGlobals.ipsec_auth_data_len)) {
	      proto = p[offset+payloadLen-readOnlyGlobals.ipsec_auth_data_len-1];
	      offset += 8, payloadLen -= 8;
	    }
	    break;

	  case IPPROTO_GRE:
	    {
	      struct grev1_header *gre;

	      gre = (struct grev1_header*)&p[offset];
	      gre->flags_and_version = ntohs(gre->flags_and_version);
	      gre->proto = ntohs(gre->proto);

	      offset += sizeof(struct grev1_header);
	      if(gre->flags_and_version & (GRE_HEADER_CHECKSUM | GRE_HEADER_ROUTING)) offset += 4;
	      if(gre->flags_and_version & GRE_HEADER_KEY)      offset += 4;
	      if(gre->flags_and_version & GRE_HEADER_SEQ_NUM)  offset += 4;

	      eth_type = gre->proto;

	      if(eth_type == 0x8881 /* CDMA2000 */) {
		offset++; /* PPP in HDLC-Like Framing */
		memcpy(&ppphdr, &p[offset], sizeof(struct ppp_header));
		if(ntohs(ppphdr.protocol) == 0x0021 /* IP */)
		  eth_type = ETHERTYPE_IP;

		ehshift = sizeof(struct ppp_header)+offset;
	      } else if(eth_type == 0x88be /* ERSPAN */) {
		offset += 8 /* ERSPAN header */;
		ehdr = (struct eth_header*)&p[offset];
		eth_type = ntohs(ehdr->ether_type);
		offset += sizeof(struct eth_header);
		ehshift = offset;
		goto analyze_eth_type;
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
	  if(unlikely(plen < (hlen+sizeof(struct tcphdr)))) return; /* packet too short */
	  tp = (struct tcphdr*)(p+offset);
	  if(likely(!readOnlyGlobals.ignorePorts)) sport = ntohs(tp->th_sport), dport = ntohs(tp->th_dport);
	  tcpFlags = tp->th_flags, tcpSeqNum = ntohl(tp->th_seq), tcpAckNum = ntohl(tp->th_ack), tcpWin = ntohs(tp->th_win);
	  tcp_len = (tp->th_off * 4);

	  if(tcpFlags & TH_SYN) {
	    int opt_len = tcp_len - sizeof(struct tcphdr);

	    if(opt_len > 0) {
	      u_int8_t *opt = (u_int8_t*)(p+offset+sizeof(struct tcphdr));
	      int i = 0;

	      while(i < opt_len) {
		switch(opt[i]) {
		case TCPOPT_NOP:
		  i++;
		  break;
		case TCPOPT_MAXSEG:
		  tcpMss = ntohs(*((uint16_t *)&opt[i+2]));
		  i += 4;
		  break;
		case TCPOPT_WSCALE:
		  tcpWinScale = opt[i+2];
		  i += 3;
		  break;
		case TCPOPT_EOL:
		  i = opt_len;
		  break;

		default:
		  if(opt[i+1] == 0) {
		    char buf[256], buf1[256];

		    traceEvent(TRACE_WARNING, "Unknown TCP option %u received: malformed packet ? [%s:%d -> %s:%d][i: %u]",
			       opt[i] & 0xFF, _intoaV4(ip->ip_src.s_addr, buf, sizeof(buf)), sport,
			       _intoaV4(ip->ip_dst.s_addr, buf1, sizeof(buf1)), dport, i);
		    dump_bad_packet(h, p);
		    i = opt_len;
		  } else
		    i += opt[i+1];
		  break;
		}
	      }
	    }
	  }

	  if(0) {
	    char buf[256], buf1[256];

	    traceEvent(TRACE_NORMAL, "%s:%d -> %s:%d [win: %u]",
		       _intoaV4(ip->ip_src.s_addr, buf, sizeof(buf)), sport,
		       _intoaV4(ip->ip_dst.s_addr, buf1, sizeof(buf1)), dport,
		       ntohs(tp->th_win));

	  }

	  payloadLen -= tcp_len, originalPayloadLen -= tcp_len;
	  if(likely(payloadLen > 0))
	    payload_shift = offset+tcp_len;
	  else {
	    payloadLen    = 0;
	    payload_shift = 0;
	  }
	  break;

	case IPPROTO_UDP:
	  if(unlikely(plen < (hlen+sizeof(struct udphdr)))) return; /* packet too short */
	  up = (struct udphdr*)(p+offset);
	  if(likely(!readOnlyGlobals.ignorePorts)) sport = ntohs(up->uh_sport), dport = ntohs(up->uh_dport);
	  originalPayloadLen = payloadLen = min((ntohs(up->uh_ulen)-sizeof(struct udphdr)), caplen - offset-sizeof(struct udphdr));
	  if(likely(payloadLen > 0))
	    payload_shift = offset+sizeof(struct udphdr);
	  else {
	    payloadLen    = 0;
	    payload_shift = 0;
	  }

	  if(unlikely(readOnlyGlobals.tunnel_mode
		      && (sport == L2TP_DATA_PORT)
		      && (dport == L2TP_DATA_PORT))
	     && (payloadLen > sizeof(struct l2tp_header))) {
	    struct l2tp_header *l2tp = (struct l2tp_header*)&p[payload_shift];
	    u_int16_t flags = ntohs(l2tp->flags);

	    if((flags & 0x8002) == 0x02) {
	      /* L2TP v2 Data packet */
	      u_int8_t have_length_bit   = (flags & 0x4000) == 0x4000;
	      u_int8_t have_sequence_bit = (flags & 0x0800) == 0x0800;
	      u_int8_t have_offset_bit   = (flags & 0x0200) == 0x0200;

	      if(unlikely(readOnlyGlobals.enable_debug))
		traceEvent(TRACE_NORMAL, "[L2TP] [TunnelId: %u][SessionId: %u]",
			   ntohs(l2tp->tunnel_id), ntohs(l2tp->session_id));

	      payload_shift += sizeof(struct l2tp_header);
	      if(have_length_bit) payload_shift += 2;
	      if(have_sequence_bit) payload_shift += 2;
	      if(have_offset_bit) payload_shift += 2;

	      if(payloadLen > sizeof(struct ppp_header)) {
		struct ppp_header *ppp = (struct ppp_header*)&p[payload_shift];
		u_int16_t proto = htons(ppp->protocol);

		payload_shift += sizeof(struct ppp_header);

		if(proto == 0x003D /* PPP MultiLink */) {
		  if(payloadLen > sizeof(struct ppp_multilink_header)) {
		    struct ppp_multilink_header *multi = (struct ppp_multilink_header*)&p[payload_shift];
		    u_int8_t first_fragment = (multi->flags & 0x80) ? 1 : 0;
		    u_int8_t last_fragment  = (multi->flags & 0x40) ? 1 : 0;

		    if(unlikely(readOnlyGlobals.enable_debug))
		      traceEvent(TRACE_NORMAL, "[PPP Multilink] [first_fragment: %u][last_fragment: %u]",
				 first_fragment, last_fragment);
		    /*
		      first_fragment = yes, last_fragment = yes -> self-contained packet
		      first_fragment = yes, last_fragment = no  -> first fragment of a longer packet
		      first_fragment = no,  last_fragment = no  -> intermediate fragment of a longer packet
		      first_fragment = no,  last_fragment = yes -> last fragment of a longer packet
		    */

		    if(first_fragment == 0) {
		      /* We ignore packets that are not self-contained or fragments other
			 than the first one */
		      return;
		    } else if(last_fragment == 0) /* && (first_fragment == 1) */ {
		      /* In this case we tell nProbe not to consider as length the one
			 reported in the h header, but rather then one we take from
			 tunneled IP as we do not rebuild fully the packet payload yes */
		      overwrite_packet_lenght = 1;
		    }

		    payload_shift += sizeof(struct ppp_multilink_header);

		    if(payloadLen > 2) {
		      u_int16_t ppp_proto = ntohs(*(u_int16_t*)&p[payload_shift]);

		      if(unlikely(readOnlyGlobals.enable_debug))
			traceEvent(TRACE_NORMAL, "[PPP] [proto: %02X]", ppp_proto);

		      if((ppp_proto == 0x0021) /* IPv4 */ || (ppp_proto == 0x0057) /* IPv6 */) {
			ehshift = payload_shift+2, eth_type = (ppp_proto == 0x0021) ? ETHERTYPE_IP : ETHERTYPE_IPV6;
			goto parse_ip;
		      }
		    }
		  }
		} else if(proto == 0x0021) {
		  /* IPv4 */
		  ehshift = payload_shift, eth_type = ETHERTYPE_IP;
		  goto parse_ip;
		} else if(proto == 0x0057) {
		  /* IPv6 */
		  ehshift = payload_shift, eth_type = ETHERTYPE_IPV6;
		  goto parse_ip;
		}
	      }
	    }
	  } else if(unlikely((readOnlyGlobals.tunnel_mode
			      || readOnlyGlobals.enableGtpPlugin)
			     && (payloadLen >= sizeof(struct gtpv1_header))
			     && (tunnel_id == 0 /* No nested GTP tunnels */))) {
	    if((sport == GTP_DATA_PORT) || (dport == GTP_DATA_PORT)) {
	      struct gtpv1_header *gtp = (struct gtpv1_header*)&p[payload_shift];
	      u_int gtpv1_header_len = 8 /* min size of struct gtpv1_header */;
	      u_int16_t gtp_len = ntohs(gtp->total_length);

	      if(((gtp->flags & 0x30) == 0x30) /* GTPv1 */
		 && (gtp_len >= (payloadLen-gtpv1_header_len))) {
		/* gtp_offset = payload_shift; */ /* <<= do not set it for user-data */
		tunnel_id = ntohl(gtp->tunnel_id);

		/* Now compute gtpv1_header_len precisely */
		if(gtp->flags & 0x04) gtpv1_header_len += 1; /* next_ext_header is present */
		if(gtp->flags & 0x02) gtpv1_header_len += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
		if(gtp->flags & 0x01) gtpv1_header_len += 1; /* pdu_number is present */

		if(readOnlyGlobals.aggregateGtpTunnels) {
		  processGTPFlowPacket(thread_id, tunnel_id, h, gtp_len);
		  return;
		}

		payload_shift += gtpv1_header_len;
		ehshift = payload_shift;

		if(p[payload_shift] == 0x60)
		  eth_type = ETHERTYPE_IPV6;
		else
		  eth_type = ETHERTYPE_IP;

		memcpy(&untunneled_src, &src, sizeof(IpAddress)), memcpy(&untunneled_dst, &dst, sizeof(IpAddress));
		untunneled_proto = proto, untunneled_sport = sport, untunneled_dport = dport;
		goto parse_ip;
	      }
	    } else if((sport == GTPV0_PORT) && (dport == GTPV0_PORT)) {
	      struct gtpv0_header *gtp = (struct gtpv0_header*)&p[payload_shift];
	      u_int16_t gtp_len = ntohs(gtp->total_length);

	      if(((gtp->flags & 0xE0) == 0x00) /* GTPv0 */
		 && (gtp_len <= (payloadLen-sizeof(struct gtpv0_header)))) {
		if(gtp->message_type == 0xFF /* T-PDU */) {
		  if(readOnlyGlobals.aggregateGtpTunnels) {
		    processGTPFlowPacket(thread_id, tunnel_id, h, gtp_len);
		    return;
		  }

		  payload_shift += sizeof(struct gtpv0_header);
		  ehshift = payload_shift, eth_type = ETHERTYPE_IP;
		  memcpy(&untunneled_src, &src, sizeof(IpAddress)), memcpy(&untunneled_dst, &dst, sizeof(IpAddress));
		  untunneled_proto = proto, untunneled_sport = sport, untunneled_dport = dport;
		  goto parse_ip;
		} else /* Signaling */
		  gtp_offset = payload_shift;
	      }

	    } else if((sport == GTP_CONTROL_PORT) || (dport == GTP_CONTROL_PORT)) {
	      struct gtpv1_header *gtp = (struct gtpv1_header*)&p[payload_shift];
	      u_int gtpv1_header_len = 4 /* min size of struct gtpv1_header */;
	      u_int16_t gtp_len = ntohs(gtp->total_length);

	      if(gtp_len <= (payloadLen-gtpv1_header_len)) {
		if((gtp->flags & 0x30) == 0x30) /* GTPv1 */ {
		  subflow_id = ntohs(gtp->sequence_number);
		  gtp_offset = payload_shift;
		} else if((gtp->flags & 0x40) == 0x40) /* GTPv2 */ {
		  subflow_id = ntohs(gtp->sequence_number);
		  gtp_offset = payload_shift;
		}
	      }
	    } else if((sport == MOBILE_IP_PORT) || (dport == MOBILE_IP_PORT)) {
	      struct mobileip_header *mobile_ip = (struct mobileip_header*)&p[payload_shift];

	      if(mobile_ip->message_type == 0x04 /* NAT Traversal Tunnel Data */) {
		if(mobile_ip->next_header == 0x04) {
		  eth_type = ETHERTYPE_IP;
		  payload_shift += sizeof(struct mobileip_header);
		  ehshift = payload_shift;

		  goto parse_ip;
		} else if(mobile_ip->next_header == 0x06) {
		  eth_type = ETHERTYPE_IPV6;
		  payload_shift += sizeof(struct mobileip_header);
		  ehshift = payload_shift;

		  goto parse_ip;
		}
	      }
	    }
	  }

	  if(unlikely((gtp_offset == 0) && readOnlyGlobals.aggregateGtpTunnels)) return;

	  if(unlikely(readOnlyGlobals.interpretFlowPackets)) {
	    if((payloadLen > 0)
	       && (numFragments == 0) && (off == 0) /* Do not process fragmented packets */
	       && ((dport == 2055)
		   || (dport == 2057)
		   || (dport == 6343) || (sport == 6343)
		   || (dport == 9999)
		   || (dport == 3000)
		   || (dport == 6000)
		   || (dport == 9996)
		   || (dport == 15003)
		   )) {
	      /* traceEvent(TRACE_NORMAL, "Dissecting flow packets (%d bytes)", payloadLen); */
#if 0
	      int begin = 70;

	      traceEvent(TRACE_NORMAL, "%02X %02X %02X %02X %02X %02X",
			 p[payload_shift+begin] & 0xFF, p[payload_shift+begin+1] & 0xFF,
			 p[payload_shift+begin+2] & 0xFF, p[payload_shift+begin+3] & 0xFF,
			 p[payload_shift+begin+4] & 0xFF, p[payload_shift+begin+5] & 0xFF);
#endif

	      if((sport == 6343) /* sFlow (we hope) */
		 || (dport == 6343) /* sFlow (we hope) */) {
		struct sockaddr_in fromHostV4;

		dissectSflow((u_char*)&p[payload_shift], payloadLen, &fromHostV4); /* sFlow */
	      } else
		dissectNetFlow(htonl(src.ipType.ipv4), (char*)&p[payload_shift], payloadLen);

	      return;
	    }
	  }

	  break;

	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	  if(plen < (hlen+sizeof(struct icmp_hdr))) return; /* packet too short */
	  icmpPkt = (struct icmp_hdr*)(p+offset); /* ICMPv4 and ICMPv6 headers are alike */
	  if(!(readOnlyGlobals.ignorePorts || readOnlyGlobals.ignorePorts)) {
	    if(readOnlyGlobals.usePortsForICMP)
	      sport = 0, dport = (icmpPkt->icmp_type * 256) + icmpPkt->icmp_code;
	  }

	  icmp_type = icmpPkt->icmp_type, icmp_code = icmpPkt->icmp_code;
	  //traceEvent(TRACE_ERROR, "[icmp_type=%d][icmp_code=%d]", icmpPkt->icmp_type, icmpPkt->icmp_code);
	  payload_shift = 0; /* Who cares of ICMP payload ? */
	  break;

	case IPPROTO_SCTP:
	  if(unlikely(plen < (hlen+sizeof(struct sctphdr)))) return; /* packet too short */
	  sctph = (struct sctphdr*)(p+offset);
	  if(likely(!readOnlyGlobals.ignorePorts))
	    sport = ntohs(sctph->sport), dport = ntohs(sctph->dport);
	  offset += sizeof(struct sctphdr);

	  payload_shift = payloadLen = 0;
	  while(offset < caplen) {
	    struct sctp_chunk *sctp_chunk = (struct sctp_chunk*)(p+offset);
	    u_int16_t chunk_len = ntohs(sctp_chunk->chunk_len);

	    if(chunk_len == 0) {
	      traceEvent(TRACE_WARNING, "SCTP with zero chunk len (malformed packet?) discarded");
	      return;
	    }

	    if(sctp_chunk->chunk_type == 0 /* DATA */) {
	      struct sctp_data_chunk *data;
	      u_int val1, val2;

	      offset += sizeof(struct sctp_chunk);
	      data = (struct sctp_data_chunk*)(p+offset);

	      offset += sizeof(struct sctp_data_chunk);
	      payload_shift = offset;
	      val1 = (chunk_len > (sizeof(struct sctp_chunk)+sizeof(struct sctp_data_chunk))) ? (chunk_len-sizeof(struct sctp_chunk)-sizeof(struct sctp_data_chunk)) : 0;
	      val2 = (caplen > payload_shift) ? (caplen - payload_shift) : 0;

	      payloadLen = min(val1, val2);
	      subflow_id = ntohs(data->stream_id);
	      break;
	    } else
	      offset += chunk_len;
	  } /* while */
	  break;

	default:
	  payloadLen = 0;
	}

	/* ************************************************ */

	/*
	  Is this a fragment ?
	  NOTE: IPv6 doesn't have the concept of fragments
	*/
	if(unlikely(readOnlyGlobals.handleFragments
		    && (numFragments > 0)
		    && (dont_defrag == 0))) {
	  u_short fragmentOffset = (off & 0x1FFF)*8, fragmentId = ntohs(ip->ip_id), num = 0;
	  u_short fragment_list_idx = (src.ipType.ipv4 + dst.ipType.ipv4 + fragmentId) % NUM_FRAGMENT_LISTS;
	  IpV4Fragment *list, *prev = NULL;

	  /*
	    In theory we have fragments also with non-UDP traffic but when smart_udp_frags_mode is used
	    we ignore them too as we believe we do not want to handle fragments at all
	  */
	  if((readOnlyGlobals.smart_udp_frags_mode == 0) /* || (proto != IPPROTO_UDP) */
	     && portToUnfragment(proto, sport) && portToUnfragment(proto, dport)) {
	    pthread_rwlock_wrlock(&readWriteGlobals->fragmentMutex[fragment_list_idx]);
	    list = readWriteGlobals->fragmentsList[fragment_list_idx];

	    while(list != NULL) {
	      if((list->src == src.ipType.ipv4)
		 && (list->dst == dst.ipType.ipv4)
		 && (list->fragmentId == fragmentId)
		 && ((h->ts.tv_sec-list->firstSeen) < 5 /* sec - Discard old fragments/repetitions */))
		break;
	      else {
		if((h->ts.tv_sec-list->firstSeen) > 5 /* sec */) {
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
		  prev = list, num++;
		  list = list->next;
		}
	      }
	    }

	    if(list == NULL) {
	      if(num < MAX_NUM_FRAGMENT_PER_LIST) {
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
		  list = frag, prev = NULL;
		  readWriteGlobals->fragmentListLen[fragment_list_idx]++;
		} else
		  traceEvent(TRACE_ERROR, "Not enough memory?");
	      } else {
		static u_int8_t shown_error = 0;

		if(!shown_error) {
		  traceEvent(TRACE_WARNING, "Too many fragments in queue: expect drops");
		  shown_error = 1;
		}
	      }
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
		pthread_rwlock_unlock(&readWriteGlobals->fragmentMutex[fragment_list_idx]);
		numFragments = numPkts;
	      } else {
		pthread_rwlock_unlock(&readWriteGlobals->fragmentMutex[fragment_list_idx]);
		/* More fragments: we'll handle the packet later */

		/*
		  TODO: defragment onto plugins (e.g. on the SIP plugin)
		*/
#if 0
		if(!(portToUnfragment(proto, list->sport) && portToUnfragment(proto, list->dport)))
		  ;
		else
#endif
		  return;
	      }
	    }
	  } else {
	    if(fragmentOffset > 0) {
	      /*
		Ignore fragments that do not have the initial
		fragmented packet info
	      */
	      if(!(portToUnfragment(proto, sport) && portToUnfragment(proto, dport)))
		return;
	    } else {
	      /*
		We use 2* because we want to be as precise as possible given
		that we have at least two fragments, we account twice the
		IP packt header
	      */
	      if(up)
		plen = ntohs(up->uh_ulen)+2*ip_len, numPkts = 2;
	      else
		plen = h->len*2, numPkts = 2;
	    }
	  }
	}

#ifdef DEBUG
	{
	  char buf[256], buf1[256];

	  printf("%2d) %s:%d -> %s:%d [len=%d][payloadLen=%d]\n",
		 ip->ip_p, _intoaV4(ip->ip_src.s_addr, buf, sizeof(buf)), sport,
		 _intoaV4(ip->ip_dst.s_addr, buf1, sizeof(buf1)), dport,
		 plen, payloadLen);
	}
#endif

	if(unlikely((src.ipVersion == 4) && (src.ipType.ipv4 == 0)
		    && (dst.ipType.ipv4 == 0) && (!(readOnlyGlobals.ignoreIP))))
	  return; /* Flow to skip */

	if(unlikely(readOnlyGlobals.tracePerformance)) {
	  ticks diff = getticks() - when;

	  pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
	  readOnlyGlobals.decodeTicks += diff;
	  pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
	}

	if(unlikely(numPkts == 0)) {
	  traceEvent(TRACE_WARNING, "[%u] Internal error (zero packets)", pthread_self());
	} else {
	  u_int8_t ttl;

	  do_process:
	  /* Use the first VLAN tag we see (the one close to the ethernet) unless inner is used */
	  if(readOnlyGlobals.use_vlanId_as_ifId != inner_vlan)
	    vlanId = outerVlanId;

	  if(ip)
	    ttl = ip->ip_ttl;
	  else if(ipv6)
	    ttl = ipv6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
	  else
	    ttl = 0;

	  /* Check the packet payload boundaries once more */
	  if((payload_shift+payloadLen) > h->caplen) {
	    if(unlikely(readOnlyGlobals.enable_debug))
	      traceEvent(TRACE_WARNING, "Packet shorter than the snaplen [%u vs caplen:%u][proto: %d][num_pkts: %u]",
			 (payload_shift+payloadLen), h->caplen, proto, num_pkts);
	    payloadLen = (h->caplen > payload_shift) ? (h->caplen - payload_shift) : 0;
	  }

	  if(overwrite_packet_lenght)
	    h->len = overwrite_packet_lenght;

	  processFlowPacket(thread_id, packet_if_idx, direction,
			    subflow_id, proto, numFragments, ip_offset, sampledPacket,
			    numPkts,
			    ip ? ip->ip_tos : 0, ttl,
			    vlanId, tunnel_id, gtp_offset,
			    ehdr, &src, sport, &dst, dport,
			    untunneled_proto,
			    &untunneled_src, untunneled_sport,
			    &untunneled_dst, untunneled_dport,
			    unlikely(readOnlyGlobals.accountL2Traffic) ? h->len : plen,
			    tcpWin, tcpFlags, tcpSeqNum, tcpAckNum,
			    tcpMss, tcpWinScale, icmp_type, icmp_code,
			    numMplsLabels, mplsLabels,
			    input_index, output_index,
			    (struct pcap_pkthdr*)h, (u_char*)p,
			    payload_shift, payloadLen,
			    originalPayloadLen, 0,
			    0, 0, 0, 0, flow_sender_ip,
			    packet_hash,
			    readOnlyGlobals.engineType,
			    readOnlyGlobals.engineId,
			    (osi_src[0] == 0) ? NULL : osi_src,
			    (osi_dst[0] == 0) ? NULL : osi_dst,
			    NULL);
	}
      }
      break;

    default:
      if((eth_type != 0) && (eth_type < 1500) /* Max 802.3 lenght */) {
	/* This is a 802.3 frame */
	memset(&src, 0, sizeof(src)), memset(&dst, 0, sizeof(dst));
	// src.ipVersion = 4, src.ipType.ipv4 = 0, dst.ipVersion = 4, dst.ipType.ipv4 = 0, sport = dport = 0;

	/* Check for OSI */
	if((p[14] == 0xFE) && (p[15] == 0xFE /* ISO Network Layer */)
	   && (p[17] == 0x81 /* Network Layer Protocol Identifier */)) {
	  u_int8_t d_len = p[26], s_len = p[27+d_len], len;
	  int i, offset;

	  len = min((sizeof(osi_dst)/2)-1, d_len);
	  for(i=0, offset = 0; i<len; i++) {
	    sprintf(&osi_dst[offset], "%02X", p[27+i] & 0xFF);
	    offset += 2;

	    if(i == 4) {
	      osi_dst[offset] = '.';
	      offset++;
	    }
	  }
	  osi_dst[offset] = '\0';

	  len = min((sizeof(osi_src)/2)-1, s_len);
	  for(i=0, offset = 0; i<len; i++) {
	    sprintf(&osi_src[offset], "%02X", p[28+i+d_len] & 0xFF);
	    offset += 2;

	    if(i == 4) {
	      osi_src[offset] = '.';
	      offset++;
	    }
	  }
	  osi_src[offset] = '\0';
	}

	goto do_process;
      } else {
#ifdef DEBUG
	traceEvent(TRACE_WARNING, "Unknown ethernet type: 0x%X (%d)", eth_type, eth_type);
#endif
	readWriteGlobals->discardedPkts[thread_id]++;

#ifdef HAVE_PF_RING
	if(readOnlyGlobals.enableL7BridgePlugin && (packet_if_idx != -1))
	  forwardPacket(packet_if_idx, (char*)p, h->caplen);
#endif
      }
      break;
    }
  }
}

/* ****************************************************** */

static u_int8_t isPacketQueueFull(ItemsQueue *queue) {
  QueuedPacket *pkt = &((QueuedPacket*)queue->queueSlots)[queue->insert_idx];

  if(pkt->packet_ready && (queue->insert_idx == queue->remove_idx))
    return(1);
  else
    return(0);
}

/* ****************************************************** */

void decodePacket(u_short thread_id,
		  int packet_if_idx /* -1 = unknown */,
		  struct pcap_pkthdr *h, const u_char *p,
		  u_int8_t sampledPacket, u_int8_t direction /* 1=RX, 0=TX */,
		  u_int32_t numPkts, int input_index, int output_index,
		  u_int32_t flow_sender_ip,
		  u_int32_t packet_hash) {

  /* Sanity check */
  if(unlikely((h->ts.tv_sec < 0) || (h->ts.tv_usec < 0))) {
    static u_int8_t shown_msg = 0;

    if(!shown_msg) {
      traceEvent(TRACE_WARNING, "Invalid timestamp: %lu.%lu", h->ts.tv_sec, h->ts.tv_usec);
      shown_msg = 1;
    }

    return; /* We ignore this packet */
  } else if(unlikely(h->caplen > h->len)) {
    static u_int8_t shown_msg = 0;

    if(!shown_msg) {
      traceEvent(TRACE_WARNING, "Invalid packet length: [len=%lu][caplen=%lu][snaplen=%u]",
		 h->len, h->caplen, readOnlyGlobals.snaplen);

      traceEvent(TRACE_WARNING, "Please disable LRO/GRO on your NIC (ethtool -K <NIC> gro off gso off tso off)");
      shown_msg = 1;
    }

    h->len = readOnlyGlobals.snaplen;
    h->caplen = min(h->caplen, h->len);
  }

  if(packet_hash) {
    if(unlikely(readOnlyGlobals.useLocks)) {
      u_int queue_id = packet_hash >> 2; /* shuffle data a bit */
      ItemsQueue *queue = &readWriteGlobals->packetQueues[queue_id % readOnlyGlobals.numProcessThreads];
      QueuedPacket *slot;

      while(isPacketQueueFull(queue)) {
	if(thread_id > 0) traceEvent(TRACE_WARNING, "Queue %d is full [packet_hash=%u]", thread_id, packet_hash);
	if(readWriteGlobals->shutdownInProgress)
	  return;
	else
	  usleep(1);
      }

      /* Copy the packet in queue */
      slot = &((QueuedPacket*)queue->queueSlots)[queue->insert_idx];
      slot->packet_if_idx = packet_if_idx, slot->rx_direction = direction;
      memcpy(&slot->h, h, sizeof(struct pcap_pkthdr)), memcpy(slot->p, p, h->caplen);
      slot->packet_ready = 1, slot->packet_hash = packet_hash;
      queue->insert_idx = (queue->insert_idx + 1) % DEFAULT_QUEUE_CAPACITY, queue->num_insert++;
      signalCondvar(&queue->dequeue_condvar, 0);
      return;
    }
  }

#ifdef linux
  if(unlikely(readOnlyGlobals.checkMemoryBoundaries)) {
    memcpy(readWriteGlobals->protect_mem, (void*)p, h->caplen);
    if(mprotect(readWriteGlobals->protect_mem, h->caplen, PROT_WRITE) != 0)
      traceEvent(TRACE_WARNING, "mprotect(PROT_WRITE) failed [%u/%s]", errno, strerror(errno));

    /* We need to use the default path */
    deepPacketDecode(thread_id, packet_if_idx,
		     h, readWriteGlobals->protect_mem,
		     sampledPacket, direction,
		     numPkts, input_index, output_index,
		     flow_sender_ip, packet_hash);

    if(mprotect(readWriteGlobals->protect_mem, h->caplen, PROT_READ|PROT_WRITE) != 0)
      traceEvent(TRACE_WARNING, "mprotect(PROT_RW) failed [%u/%s]", errno, strerror(errno));

    return;
  }
#endif

  /* We need to use the default path */
  deepPacketDecode(thread_id, packet_if_idx,
		   h, p,
		   sampledPacket, direction,
		   numPkts, input_index, output_index,
		   flow_sender_ip, packet_hash);

  if(unlikely(readOnlyGlobals.computeTrafficThroughput
	      && (readOnlyGlobals.pcapFile != NULL)
	      && (readWriteGlobals->now != readWriteGlobals->lastThroughputDump)))
    printSingleThroughputTime(readWriteGlobals->now);
}

/* ****************************************************** */

void freeHostHash(void) {
  if(readOnlyGlobals.enableHostStats) {
    traceEvent(TRACE_INFO, "MISSING implement freeHostHash()");
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

#if defined(HAVE_LICENSE) || defined(WIN32)
int isGoodLicense(char **rcmsg) {
  extern int verify_license(char * version, char *plugin_name,
			    char *sysId,
			    char *license_path, int kind,
			    char *out_buf, int out_buf_len,
			    time_t *until_then);
  extern char* print_license_code(int rc);
  char out_buf[512];
  char license_path[256], *sysId = getSystemId();
  int rc;
  time_t until_then = 0;

  snprintf(license_path, sizeof(license_path), "%s%s",
#ifdef WIN32
	   readOnlyGlobals.base_installation_path, LICENSE_FILE_NAME
#else
	   "/etc/", LICENSE_FILE_NAME
#endif
	   );

  out_buf[0] = '\0';
  rc = verify_license(version, NULL, sysId, license_path, 2, out_buf, sizeof(out_buf), &until_then);
  free(sysId);
  *rcmsg = print_license_code(rc);

  if(rc != 0) {
#ifdef WIN32
    char msg[512];
    extern VOID AddToMessageLog(LPTSTR lpszMsg);
	wchar_t wtext[512];
	LPWSTR ptr;

    snprintf(msg, sizeof(msg), "Invalid or missing nProbe License file %s [%s]", license_path, *rcmsg);

	mbstowcs(wtext, msg, strlen(msg) + 1);//Plus null
	AddToMessageLog(wtext);
#endif
    // traceEvent(TRACE_NORMAL, "verify_license(%s) returned %d [%d/%s]", license_path, rc, errno, strerror(errno));

    if(until_then != 0) {
      struct tm *l = localtime(&until_then);

      traceEvent(TRACE_ERROR, "Your demo license is expired on %s",
		 asctime((const struct tm*)l));
    }

    return(0);
  } else {
    if(out_buf[0] != '\0') traceEvent(TRACE_NORMAL, "%s", out_buf);

    if(until_then != 0) {
      struct tm *l = localtime(&until_then);

      traceEvent(TRACE_WARNING, "Your demo license will expire on %s",
		 asctime((const struct tm*)l));
    }

    return(1);
  }
}
#endif

/* ****************************************************** */

void probeVersion(void) {
  char *sysId, *msg;

  printf("\nWelcome to nprobe v.%s (r%d) for %s\n"
	 "%s\n"
	 "Copyright 2002-14 ntop.org\n",
	 version, svn_release, osName,
#ifdef HAVE_PF_RING
	 "with native PF_RING acceleration.\n"
#else
	 ""
#endif
	 );

#if defined(HAVE_LICENSE) || defined(WIN32)
  printf("\nSystemID: %s\n", (sysId = getSystemId()));
  free(sysId);

  if(!isGoodLicense(&msg)) {
    printf("WARNING: Invalid nProbe license ("
#ifndef WIN32
	   "/etc/"
#endif
	   LICENSE_FILE_NAME") [%s]\n", msg);
  } else {
    printf("Valid nProbe license found\n");
  }
#endif
}

/* ******************************************************** */

void usage(u_int8_t long_help) {
  char buf[16];

  initDefaults();
  readOnlyGlobals.help_mode = 1;
  probeVersion();

  printf("\nUsage:\n");

  printf("nprobe -n <host:port|none> [-i <interface|dump file>] [-t <lifetime timeout>]\n"
	 "              [-d <idle timeout>] [-l <queue timeout>] [-s <snaplen>]\n"
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
	 "\n              [-x <payload policy>] [-E <engine>] [-C <flow lock file>]"
	 "\n              [-m <min # flows>] [-R <cmd>]"
#ifdef IP_HDRINCL
	 "[-q <host:port>]"
#endif
	 "\n              [-S <sample rate>] [-A <AS list>] [-g <PID file>]"
	 "\n              [-T <flow template>] [-U <flow template id>]"
	 "\n              [-o <v9 templ. export policy>] [-L <local nets>] [-c] [-r]"
	 "\n              [-1 <interface nets>] [-2 <number>] [-3 <port>] "
#ifndef WIN32
	 "[-4] "
#endif
	 "[-5 <port>] [-6]"
	 "\n              [-9 <path>] [--black-list <networks>] [--pcap-file-list <filename>]"
	 "\n              [-N <biflows export policy>]"
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
	 "                                    | the -P parameter is mandatory.\n"
	 "                                    | Note that you can specify the protocol\n"
	 "                                    | used to send packets. Example:\n"
	 "                                    | udp://192.168.0.1:2055,tcp://10.1.2.3:2055\n");
#ifndef WIN32
  printf("[--interface|-i] <iface|pcap>       | Interface name from which packets are\n");
  printf("                                    | captured, or .pcap file (debug only).\n");
#ifdef HAVE_NETFILTER
  printf("                                    | For capturing from netfilter queues specify\n");
  printf("                                    | -i nf:X where X is the netfilter queue id.\n");
#endif
#else
  printf("[--interface|-i] <iface>            | Index or name of the interface from which\n");
  printf("                                    | packets are captured. Type -h to print\n");
  printf("                                    | all the know interfaces.\n");
#endif
  printf("[--lifetime-timeout|-t] <timeout>   | It specifies the maximum (seconds) flow\n"
	 "                                    | lifetime [default=%d]\n",
	 readOnlyGlobals.lifetimeTimeout);
  printf("[--idle-timeout|-d] <timeout>       | It specifies the maximum (seconds) flow\n"
         "                                    | idle lifetime [default=%d]\n", readOnlyGlobals.idleTimeout);
  printf("[--queue-timeout|-l] <timeout>      | It specifies how long expired flows\n"
     	 "                                    | (queued before delivery) are emitted\n"
	 "                                    | [default=%d]\n", readOnlyGlobals.sendTimeout);
  printf("[--snaplen|-s] <snaplen>            | Packet capture snaplen [default %u bytes]\n", readOnlyGlobals.snaplen);
  printf("[--aggregation|-p] <aggregation>    | It specifies the flow aggregation level:\n"
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
  printf("[--exec-cmd-dump|-R] <cmd>          | Execute the specified command for each\n"
	 "                                    | file dump on disk (including plugins).\n");
  printf("[--dump-frequency|-F] <dump timeout>| Dump files dump frequencey (sec).\n"
         "                                    | Default: %d\n", readOnlyGlobals.file_dump_timeout);
  printf("[--dump-format|-D] <format>         | <format>: flows are saved as:\n"
	 "                                    | b       : raw/uncompressed flows\n"
	 "                                    | B       : raw core flow fields (%u bytes)\n"
	 "                                    | t       : text flows\n"
#ifdef HAVE_SQLITE
	 "                                    | d       : SQLite\n"
#endif
	 "                                    | Example: -D b. Note: this flag has no\n"
	 "                                    | effect without -P.\n",
	 (unsigned int)sizeof(FlowHashBucketCoreFields));
  printf("[--in-iface-idx|-u] <in dev idx>    | Index of the input device used in the\n");
  printf("                                    | emitted flows (incoming traffic). Default\n"
	 "                                    | value is %d. Use -1 as value to dynamically\n"
	 "                                    | set to the last two bytes of\n"
	 "                                    | the MAC address of the flow sender.\n",
	 (int16_t)readOnlyGlobals.inputInterfaceIndex);
  printf("[--out-iface-idx|-Q] <out dev idx>  | Index of the output device used in the\n");
  printf("                                    | emitted flows (outgoing traffic). Default\n"
	 "                                    | value is %d. Use -1 as value to dynamically\n"
	 "                                    | set to the last two bytes of\n"
	 "                                    | the MAC address of the flow receiver.\n",
	 (int16_t)readOnlyGlobals.outputInterfaceIndex);
  printf("[--vlanid-as-iface-idx] <mode>      | Use vlanId (0 for untagged traffic)\n"
	 "                                    | as interface index. Mode specifies with\n"
	 "                                    | stacked VLANs which vlanId to choose. Values\n"
	 "                                    | are 'inner', 'outer', 'single', or 'dual':\n"
	 "                                    | inner  = use the most inner VLAN tag\n"
	 "                                    | outer  = use the first (the one close to ether) VLAN tag \n"
	 "                                    | single = for even outer VLAN tags 'E',\n"
	 "                                    |          where E={2,4,6...4094},\n"
	 "                                    |          ifIdx is set to IN='0',OUT='E'.\n"
	 "                                    |          For odd outer VLAN tags 'O',\n"
	 "                                    |          where O={3,5,7...4095},\n"
	 "                                    |          ifIdx is set to IN='O-1',OUT='0'\n"
	 "                                    | double = for even outer VLAN tags 'E',\n"
	 "                                    |          where E={2,4,6...4094}, ifIdx\n"
	 "                                    |          is set to IN='E+1',OUT='E'.\n"
	 "                                    |          For odd outer VLAN tags 'O',\n"
	 "                                    |          where O={3,5,7...4095},\n"
	 "                                    |          ifIdx are set to IN='O-1',OUT='O'\n"
	 "                                    | Note that this option\n"
	 "                                    | superseedes the --in/out-iface-idx options\n");
  printf(
	 "[--discard-unknown-flows] <mode>    | In case you enable L7 proto detection\n"
	 "                                    | (e.g. add %%L7_PROTO to the template)\n"
	 "                                    | this options enables you not to export\n"
	 "                                    | flows for which nDPI has not been able\n"
	 "                                    | to detect the proto. Mode values:\n"
	 "                                    | 0 - Export known/unknown flows (default)\n"
	 "                                    | 1 - Export only known flows (discard\n"
	 "                                    |     flows with unknown protos)\n"
	 "                                    | 2 - Export only unknown flows (discard\n"
	 "                                    |     flows with known protos)\n");
  printf("[--nprobe-version|-v]               | Prints the program version.\n");
  printf("[--flow-lock|-C] <flow lock>        | If the flow lock file is present no flows\n"
	 "                                    | are emitted. This facility is useful to\n"
	 "                                    | implement high availability by means of\n"
	 "                                    | a daemon that can create a lock file\n"
	 "                                    | when this instance is in standby.\n");
  printf("[--help|-h]                         | Prints this help.\n");
  printf("--interpret-flow-packets            | Interpret received packets to see\n"
	     "                                    | if they contain flows (development only).\n");
  printf("--debug                             | Enable debugging (development only).\n");

#ifdef linux
  printf("--check-boundaries                  | Traps code that modifies read-only\n"
	     "                                    | memory (development only).\n");
#endif
  printf("--json-labels                       | In case JSON label is used (e.g. with ZMQ)\n"
	 "                                    | labels instead of numbers are used as keys.\n");
  printf("--fake-capture                      | Fake packet capture (development only).\n");
  printf("--drop-flow-no-plugin               | Drop flows that have not processed by a plugin.\n");
  printf("--dont-nest-dump-dirs               | Dump files won't be saved on nested dirs.\n");
  printf("--performance                       | Enable performance tracing (debug only).\n");
  printf("--disable-ipv4-deduplication        | By default IPv4 frames hw-duplicated are detected\n"
	 "                                    | and discarded. Use this option to disable\n"
	 "                                    | IPv4 hw-deduplication\n");
#ifndef WIN32
  printf("[--syslog|-I] <probe name>          | Log to syslog as <probe name>\n"
	 "                                    | [default=stdout]\n");
#endif
  printf("[--hash-size|-w] <hash size>        | Flows hash size [default=%d]\n",
	 readOnlyGlobals.flowHashSize);
  printf("[--no-ipv6|-W]                      | IPv6 packets will not be accounted.\n");
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
#ifdef HAVE_PF_RING
  printf("--cluster-id <cluster id>           | Specify the PF_RING clusterId on which\n"
	 "                                    | incoming packets will be bound.\n");
#endif

  printf("[--max-num-flows|-M] <max num flows>| Limit the number of active flows. This is\n"
         "                                    | useful if you want to limit the memory\n"
	 "                                    | or CPU allocated to nProbe in case of non\n"
	 "                                    | well-behaved applications such as\n"
	 "                                    | worms or DoS. [default=%u]\n",
	 readOnlyGlobals.maxNumActiveFlows);
  printf("[--netflow-engine|-E] <type:id>     | Specify the engine type and id.\n"
	 "                                    | The format is engineType:engineId.\n"
	 "                                    | [default=%d:%d] where engineId is a\n"
	 "                                    | random number.\n",
	 readOnlyGlobals.engineType, readOnlyGlobals.engineId);
  printf("[--min-num-flows|-m] <min # flows>  | Minimum number of flows per packet\n"
	 "                                    | unless an expired flow is queued\n"
	 "                                    | for too long (see -l) [default=%d\n"
	 "                                    | for v5, dynamic for v9]\n",
	 readOnlyGlobals.num_v5flows_per_packet);
  printf("[--sender-address|-q] <host:port>   | Specifies the address:port of the flow\n"
	 "                                    | sender. This option is useful for hosts\n"
	 "                                    | with multiple interfaces or if flows\n"
	 "                                    | must be emitted from a static port/IP.\n");
  printf("[--sample-rate|-S] <pkt rate>:<flow rate>\n"
	 "                                    | Packet capture sampling rate and flow\n"
	 "                                    | sampling rate. If <pkt rate> starts with\n"
	 "                                    | '@' it means that nprobe will report\n"
	 "                                    | the specified sampling rate but will\n"
	 "                                    | not sample itself as incoming packets\n"
	 "                                    | are already sampled on the specified\n"
	 "                                    | capture device at the specified rate.\n"
	 "                                    | Default: 1:1 [no sampling]\n");
  printf("[--as-list|-A] <AS list>            | GeoIP file containing with known ASs.\n"
	 "                                    | Example: GeoIPASNum.dat\n");
  printf("--city-list <city list>             | GeoIP file containing the city/IP mapping.\n"
	 "                                    | Note that nProbe will load the IPv6 file\n"
	 "                                    | equivalent if present. Example:\n"
	 "                                    | --city-list GeoLiteCity.dat will also\n"
	 "                                    | attempt to load GeoLiteCityv6.dat\n");
  printf("[--pid-file|-g] <PID file>          | Put the PID in the specified file\n");
  printf("[--flow-templ|-T] <flow template>   | Specify the NFv9/IPFIX template (see below).\n");
  printf("[--flow-templ-id|-U] <templ. id>    | Specify the NFv9/IPFIX template identifier\n"
	 "                                    | [default: %d]\n", readOnlyGlobals.idTemplate);
  printf("[--flow-version|-V] <version>       | NetFlow Version: 5=NFv5, 9=NFv9, 10=IPFIX\n");
  printf("[--flows-intra-templ|-o] <num>      | Specify how many flow pkts are exported\n"
	 "                                    | between template exports [default: %d]\n",
	 readOnlyGlobals.templatePacketsDelta);
  printf("[--aggregate-gtp-tunnels]           | Aggregate GTP traffic on tunnel id.\n");
  printf("[--collector-sample-rate] <value>   | Specify the bytes/pkts collection sample rate.\n");
  printf("[--keep-probes-unmerged]            | Don't merge flows rcvd from different probe IPs.\n");
  printf("[--skip-packet-header-bytes] <num>  | Skip <num> bytes from ingress packet header.\n");
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
  printf("[--max-flow-size|-0] <size>         | Specify the maximum flow size. NOTE:\n"
	 "                                    | This parameter has influence on -m.\n");
  printf("[--if-networks|-1] <nets>           | Specify the binding between interfaceId\n"
	 "                                    | and a network (see below).\n");
  printf("[--count|-2] <number>               | Capture a specified number of packets\n"
	 "                                    | and quit (debug only)\n");
  printf("[--collector-port|-3] <port>        | NetFlow/IPFIX/sFlow collector flows port\n");
#ifdef linux
  printf("[--cpu-affinity|-4] <CPU/Core Id>   | Binds this process to the specified CPU/Core\n"
	 "                                    | Note: the first available CPU corresponds to 0.\n");
#endif
#ifdef HAVE_PTHREAD_SET_AFFINITY
  printf("--export-thread-affinity <core>     | Bind the export thread to the specified core (default: no bind)\n");
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
  printf("[--biflows-export-policy|-N] <pol>  | Bi-directional flows export policy:\n"
	 "                                    | 0 - export all flows\n"
	 "                                    | 1 - export bi-directional flows only\n"
	 "                                    | 2 - export mono-directional flows only\n");
  printf("--csv-separator <separator>         | Specify the text files separator (see -P)\n"
	 "                                    | Default is '|' (pipe)\n");
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
	 "                                    | and quit. Useful for knowking the IE handled.\n");
  printf("--dump-pkts <.pcap file>            | Dump incoming packets on the specified dump\n");
  printf("--max-log-lines <num>               | Maximum number of lines on a dump file. Default: %u.\n",
	 readOnlyGlobals.maxLogLines);
  printf("--timestamp-format <mode>           | Specify the timestamp format on dump files. Values:\n"
	 "                                    | 0 - Unix Epoch\n"
	 "                                    | 1 - Unix Epoch with microseconds\n"
	 "                                    | 2 - Human readable timestamp\n");
  printf("--ndpi-proto <proto>                | Comma separated list of nDPI protocols to enable. If\n"
	 "                                    | not specified, all known protocols are detected.\n");
#ifdef HAVE_REDIS
  printf("--account-imsi-traffic              | When used with GTP traffic and --redis, the user traffic\n"
	 "                                    | is accounted per IMSI/NSAPI (mobile traffic only)\n");
#endif
  printf("--event-log <file>                  | Dump relevant activities into the specified log file\n");
#ifdef HAVE_PF_RING
  printf("--hw-timestamp-mode <mode>          | Enable hw timestamping/stripping. Supported TS modes are:\n"
	 "                                    | ixia - Timestamped packets by ixiacom.com hardware devices\n");
  //print("                                    | NOTE: Silicom Hw timestamping NICs are supported automatically.");
#endif

#ifdef HAVE_VOIP_EXTENSIONS
  printf("--hep <host>:<port>                 | Send JSON flows via HEPv3 protocol\n");
  printf("--hep-auth <capture id>:<password>  | Specify the HEP authentication parameters.\n"
	 "                                    | Default: %d:%s\n",
	 readOnlyGlobals.hep.capture_id, readOnlyGlobals.hep.pwd);
#endif
  printf("--collection-filter <filter>        | Filter applied to collected filters only (-3). Filter format:\n"
	 "                                    | [!]<asX | network/mask> (! means discard flows matching filter)\n"
	 "                                    | Example: !as12345, 192.168.0.0/24, !10.0.0.0/8\n");
  printf("--imsi-aggregation                  | Aggregate IMSI traffic (GTP traffic only)\n");
  printf("--simulate-storage                  | Simulate storage to disk (debug only)\n");
#ifdef HAVE_ZMQ
  printf("--zmq <socket>                      | Deliver flows to subscribers connected to the specified endpoint.\n"
	 "                                    | Example tcp://*:5556 or ipc://flows.ipc\n");
#endif
  printf("--tcp <server:port>                 | Deliver flows in JSON format to the specified server via TCP.\n");
#ifdef HAVE_TEMPLATE_EXTENSIONS
  printf("--nfsender <host>:<port>            | Send flows to the nfsender listening at <host>:<port>\n");
#endif
  printf("--dump-bad-packets <file>           | Dump bad/undecodeable packets into the specified pcap file\n");
  printf("--lru-cache-size <size>             | Users and protocol cache size. Default %u\n", DEFAULT_LRU_CACHE_SIZE);
  printf("--enable-throughput-stats           | Compute throughput stats that can be dumped when -P is used\n");
  printf("--ndpi-proto-ports <file>           | Read custom ports definitions for nDPI (see nDPI/example/protos.txt)\n");
  printf("--disable-l7-protocol-guess         | When nDPI is enabled, in case a protocol is not recognized,\n"
	 "                                    | nProbe guesses the protocol based on ports. This option disables\n"
 	 "                                    | this feature and uses only strict payload dissection\n");
  printf("--original-speed                    | When using -i with a pcap file, instead of reading packets\n"
	 "                                    | as fast as possible, the original speed is preserved (debug only)\n");
  printf("--dont-reforge-timestamps           | Disable nProbe to reforge timestamps with -i <pcap file> and \n"
         "                                    | prevent flows from expire until the whole pcap is read (debug only)\n");
  printf("--db-engine <database engine>       | Define the DB engine type (example MyISAM, InfiniDB).\n"
	 "                                    | This information is used by the database plugin.\n"
	 "                                    | Default %s.\n", readOnlyGlobals.dbEngineType);
#ifndef WIN32
  printf("--unprivileged-user <name>          | Use <name> instead of nobody when dropping privileges\n");
#endif
  printf("--disable-cache                     | Disable flow cache for avoid merging flows. This option\n"
	 "                                    | is available only in collector/proxy mode\n"
	 "                                    | (i.e. use -i none)\n");
#ifdef HAVE_REDIS
  printf("--redis <host>[:<port>]             | Connected to the specified redis server\n"
	 "                                    | Example --redis localhost\n");
  printf("--redis-logging <host>[:<port>]     | Log messages/flows to the specified redis instance\n"
	 "                                    | Example --redis-logging localhost\n");
  printf("--use-redis-proxy                   | Use a redis proxy (e.g.\n"
	 "                                    | https://github.com/twitter/twemproxy)\n");
  printf("--ucloud                            | Enable the nProbe micro-cloud\n");
#endif

#ifdef HAVE_LICENSE
  printf("--show-system-id                    | Print the system identifier\n");
  printf("--check-license                     | Checks if the license is present and valid\n");
#endif

  printf("--dump-plugin-families              | Dump all available plugin families\n");

  printf("\nFurther plugin available command line options\n");
  printf("---------------------------------------------------\n");
  initPlugins();
  dumpPluginHelp();

  printf("\n\nNote on interface indexes and (router) MAC/IP addresses\n"
	 "---------------------------------------------------\n"
	 "Flags -u and -Q are used to specify the SNMP interface identifiers for emitted flows.\n"
	 "However using --if-networks it is possible to specify an interface identifier to which\n"
	 "a MAC address or IP network is bound. The syntax of --if-networks is:\n"
	 " <MAC|IP/mask>@<interfaceId> where multiple entries can be separated by a comma (,).\n"
	 "Example: --if-networks \"AA:BB:CC:DD:EE:FF@3,192.168.0.0/24@2\" or\n"
	 "--if-networks @<filename> where <filename> is a file path containing the networks\n"
	 "specified using the above format.\n");

#ifdef WIN32
  (void)printAvailableInterfaces("-1");
#endif


  if(long_help) {
    printf("\nNetFlow v9/IPFIX format [-T]"
	   "\n----------------"
	   "\nThe following options can be used to specify the format:\n"
	   "\n ID   NetFlow Label               IPFIX Label                   Description\n"
	   "-------------------------------------------------------------------------------\n");

    printTemplateInfo(ver9_templates, 0);
    dumpPluginTemplates();

    /* Force L7 initialization for dumping protocols */
    readOnlyGlobals.enable_l7_protocol_discovery = 1;
    initL7Discovery();

    printf("\nMajor protocol (%%L7_PROTO) symbolic mapping 0...%d:\n",
	   ndpi_get_num_supported_protocols(readOnlyGlobals.l7.l7handler)-1);

    ndpi_dump_protocols(readOnlyGlobals.l7.l7handler);
  }

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
    u_int i;
    long unsigned int tot_pkts = 0, tot_bytes = 0;

    for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
      tot_pkts  += (unsigned long)readWriteGlobals->accumulateStats[i].pkts;
      tot_bytes += (unsigned long)readWriteGlobals->accumulateStats[i].bytes;
    }

    fprintf(fd,
	    "# time totalPkts totalBytes totFlows\n"
	    "%u %lu %lu %u\n",
	    (unsigned int)time(NULL),
	    tot_pkts, tot_bytes,
	    (unsigned int)readWriteGlobals->totFlows);
    fclose(fd);
  } else
    traceEvent(TRACE_WARNING, "Unable to create file %s", path);
}

/* ****************************************************** */

static void printFragmentStats() {
  u_int tot_frags, i;

  for(tot_frags=0, i=0; i<NUM_FRAGMENT_LISTS; i++)
    tot_frags += readWriteGlobals->fragmentListLen[i];

  traceEvent(TRACE_NORMAL, "Fragment queue length: %u", tot_frags);
}

/* ****************************************************** */

static void printProcessingStats(void) {
  u_int32_t tot_pkts = 0, tot_bytes = 0;
  u_int num_collected_pkts = 0, i;

  for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
    tot_pkts  += (unsigned long)readWriteGlobals->accumulateStats[i].pkts;
    tot_bytes += (unsigned long)readWriteGlobals->accumulateStats[i].bytes;
  }

  for(i=0; i<readOnlyGlobals.numProcessThreads; i++)
    num_collected_pkts += readWriteGlobals->collectedPkts[i];

  traceEvent(TRACE_NORMAL, "Processed packets: %u (max bucket search: %d)",
	     (unsigned long)tot_pkts, readWriteGlobals->maxBucketSearch);

  printFragmentStats();

  if(readWriteGlobals->maxBucketSearch > 10)
    traceEvent(TRACE_WARNING, "Your bucket search is too slow (%d): expect drops",
	       readWriteGlobals->maxBucketSearch);

  traceEvent(TRACE_NORMAL, "Flow export stats: [%u bytes/%u pkts][%u flows/%u pkts sent]",
	     (unsigned long)readWriteGlobals->flowExportStats.totExportedFlowBytes,
	     (unsigned long)readWriteGlobals->flowExportStats.totExportedFlowPkts,
	     (unsigned long)readWriteGlobals->flowExportStats.totExportedFlows,
	     (unsigned long)readWriteGlobals->flowExportStats.totExportedPkts);

  if(readOnlyGlobals.flowCollection.collectorInPort > 0)
    traceEvent(TRACE_NORMAL, "Flow collection: [collected pkts: %u][processed flows: %u]",
	       num_collected_pkts, readWriteGlobals->collectionStats.num_flows_processed);

  traceEvent(TRACE_NORMAL, "Flow drop stats:   [%u bytes/%u pkts][%u flows]",
	     (unsigned long)readWriteGlobals->probeStats.totFlowBytesDropped,
	     (unsigned long)readWriteGlobals->probeStats.totFlowPktsDropped,
	     (unsigned long)readWriteGlobals->probeStats.totFlowDropped);

  traceEvent(TRACE_NORMAL, "Total flow stats:  [%u bytes/%u pkts][%u flows/%u pkts sent]",
	     (unsigned long)readWriteGlobals->probeStats.totFlowBytesDropped +
	     (unsigned long)readWriteGlobals->flowExportStats.totExportedFlowBytes,
	     (unsigned long)readWriteGlobals->probeStats.totFlowPktsDropped +
	     (unsigned long)readWriteGlobals->flowExportStats.totExportedFlowPkts,
	     (unsigned long)readWriteGlobals->probeStats.totFlowDropped +
	     (unsigned long)readWriteGlobals->flowExportStats.totExportedFlows,
	     (unsigned long)readWriteGlobals->flowExportStats.totExportedPkts);

  if(readOnlyGlobals.tracePerformance && (tot_pkts > 0)) {
    static unsigned long last_pkts = 0;
    ticks tot;

    pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);

    tot = readOnlyGlobals.decodeTicks
      + readOnlyGlobals.processingWithFlowCreationTicks
      + readOnlyGlobals.processingWoFlowCreationTicks;

    if(tot > 0) {
      if(last_pkts == 0) last_pkts = tot_pkts;
      last_pkts = tot_pkts - last_pkts;

      if(last_pkts > 0) {
	traceEvent(TRACE_NORMAL, "---------------------------------");
	traceEvent(TRACE_NORMAL, "Decode ticks:     %.2f ticks/pkt [%.2f %%]",
		   (float)readOnlyGlobals.decodeTicks / (float)last_pkts,
		   (float)(readOnlyGlobals.decodeTicks*100)/(float)tot);

	if(readOnlyGlobals.num_pkts_without_flow_creation == 0) readOnlyGlobals.num_pkts_without_flow_creation = 1;
	traceEvent(TRACE_NORMAL, "Pkt Processing w/o Flow Creation: %.2f ticks/pkt [%.2f %%]",
		   (float)readOnlyGlobals.processingWoFlowCreationTicks / (float)readOnlyGlobals.num_pkts_without_flow_creation,
		   (float)(readOnlyGlobals.processingWoFlowCreationTicks*100) / (float)tot);

	if(readOnlyGlobals.num_pkts_with_flow_creation == 0) readOnlyGlobals.num_pkts_with_flow_creation = 1;
	traceEvent(TRACE_NORMAL, "Pkt Processing with Flow Creation: %.2f ticks/pkt [%.2f %%]",
		   (float)readOnlyGlobals.processingWithFlowCreationTicks / (float)readOnlyGlobals.num_pkts_with_flow_creation,
		   (float)(readOnlyGlobals.processingWithFlowCreationTicks*100) / (float)tot);

	if(readOnlyGlobals.num_allocated_buckets == 0) readOnlyGlobals.num_allocated_buckets = 1;
	traceEvent(TRACE_NORMAL, "Bucket Allocation: %.2f ticks/bkt",
		   (float)readOnlyGlobals.bucketAllocationTicks / (float)readOnlyGlobals.num_allocated_buckets);

	if(readOnlyGlobals.num_malloced_buckets == 0) readOnlyGlobals.num_malloced_buckets = 1;
	traceEvent(TRACE_NORMAL, "Bucket Malloc: %.2f ticks/bkt",
		   (float)readOnlyGlobals.bucketMallocTicks / (float)readOnlyGlobals.num_malloced_buckets);

	if(readOnlyGlobals.num_exported_buckets == 0) readOnlyGlobals.num_exported_buckets = 1;
	traceEvent(TRACE_NORMAL, "Bucket Export: %.2f ticks/bkt",
		   (float)readOnlyGlobals.bucketExportTicks / (float)readOnlyGlobals.num_exported_buckets);

	if(readOnlyGlobals.num_purged_buckets == 0) readOnlyGlobals.num_purged_buckets = 1;
	traceEvent(TRACE_NORMAL, "Bucket Purge: %.2f ticks/bkt",
		   (float)readOnlyGlobals.bucketPurgeTicks / (float)readOnlyGlobals.num_purged_buckets);

	traceEvent(TRACE_NORMAL, "Total ticks:      %.2f ticks/pkt",
		   (float)tot / (float)last_pkts);
	traceEvent(TRACE_NORMAL, "---------------------------------");
      }

    }

    last_pkts = tot_pkts, readOnlyGlobals.decodeTicks = readOnlyGlobals.processingWithFlowCreationTicks
      = readOnlyGlobals.processingWoFlowCreationTicks =
      readOnlyGlobals.bucketAllocationTicks =
      readOnlyGlobals.bucketMallocTicks =
      readOnlyGlobals.bucketPurgeTicks  = readOnlyGlobals.bucketExportTicks = 0;
    readOnlyGlobals.num_exported_buckets = readOnlyGlobals.num_purged_buckets =
      readOnlyGlobals.num_allocated_buckets =
      readOnlyGlobals.num_malloced_buckets =
      readOnlyGlobals.num_pkts_without_flow_creation = readOnlyGlobals.num_pkts_with_flow_creation = 0;

    pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
  }
}

/* ****************************************************** */

static void printStats() {
  time_t now = time(NULL), nowDiff;
  char pktBuf[32], buf[1024] = { 0 };
  u_int i;
  Counter tot_pkts = 0, tot_bytes = 0, current_pkts = 0, current_bytes = 0;

  readWriteGlobals->now = now;
  nowDiff = now-readOnlyGlobals.initialSniffTime.tv_sec;

  if(readOnlyGlobals.traceMode) {
    if(unlikely(readOnlyGlobals.useLocks))
      traceEvent(TRACE_NORMAL, "---------------------------------");
  }

  for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
    tot_pkts      += readWriteGlobals->accumulateStats[i].pkts;
    tot_bytes     += readWriteGlobals->accumulateStats[i].bytes;
    current_pkts  += readWriteGlobals->currentPkts[i];
    current_bytes += readWriteGlobals->currentBytes[i];

    readWriteGlobals->currentPkts[i] = 0, readWriteGlobals->currentBytes[i] = 0;

    if(unlikely(readOnlyGlobals.useLocks))
      traceEvent(TRACE_NORMAL, "Average traffic: [queue %u][%s pps][%s/sec]",
		 i,
		 formatPackets((float)readWriteGlobals->accumulateStats[i].pkts/nowDiff, pktBuf),
		 formatTraffic((float)(8*readWriteGlobals->accumulateStats[i].bytes)/(float)nowDiff, 1, buf));
  }

  if(readOnlyGlobals.traceMode && (nowDiff > 0)) {
    if(readOnlyGlobals.numProcessThreads == 1) traceEvent(TRACE_NORMAL, "---------------------------------");
    traceEvent(TRACE_NORMAL, "Average traffic: [%s pps][%s/sec]",
	       formatPackets((float)(tot_pkts/nowDiff), pktBuf),
	       formatTraffic((float)(8*tot_bytes
				     + 24 /* Preamble/IFG/CRC */ * tot_pkts)/(float)nowDiff, 1, buf));

    nowDiff = now-readWriteGlobals->lastSample;
    if(nowDiff == 0) nowDiff = 1;
    traceEvent(TRACE_NORMAL, "Current traffic: [%s pps][%s/sec]",
	       formatPackets((float)(current_pkts/nowDiff), pktBuf),
	       formatTraffic((float)(8*current_bytes
				     + 24 /* Preamble/IFG/CRC */ * current_pkts)/(float)nowDiff, 1, buf));
    readWriteGlobals->lastSample = readWriteGlobals->now;

    traceEvent(TRACE_NORMAL, "Current flow export rate: [%.1f flows/sec]",
	       (float)readWriteGlobals->totFlowsRate/nowDiff);

    traceEvent(TRACE_NORMAL, "Flow drops: [export queue too long=%u][too many flows=%u]",
	       readWriteGlobals->probeStats.totFlowDropped,
	       readWriteGlobals->probeStats.droppedPktsTooManyFlows);
    readWriteGlobals->totFlowsRate = 0;
    traceEvent(TRACE_NORMAL, "Export Queue: %u/%d [%.1f %%]",
	       readWriteGlobals->exportBucketsLen,
	       readOnlyGlobals.maxExportQueueLen,
	       ((float)(readWriteGlobals->exportBucketsLen * 100))/(float)readOnlyGlobals.maxExportQueueLen);

    traceEvent(TRACE_NORMAL, "Flow Buckets: [active=%u][allocated=%u][toBeExported=%u]",
	       getAtomic(&readWriteGlobals->bucketsAllocated)-readWriteGlobals->exportBucketsLen,
	       getAtomic(&readWriteGlobals->bucketsAllocated), readWriteGlobals->exportBucketsLen);

    dumpCacheStats(nowDiff);
    dumpPluginStats(nowDiff);

    buf[0] = '\0';
    for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
      if(readWriteGlobals->collectedPkts[i] > 0) {
	u_int len = strlen(buf);

	snprintf(&buf[len], sizeof(buf)-len, "[%lu pkts@%d] ",
		 readWriteGlobals->collectedPkts[i], i);
      }
    }

    if(buf[0] != '\0')
      traceEvent(TRACE_NORMAL, "Collector Threads: %s", buf);
  }

  if(readOnlyGlobals.traceMode) {
    printProcessingStats();
  } else {
    if(readWriteGlobals->maxBucketSearch > readWriteGlobals->lastMaxBucketSearch) {
      traceEvent(TRACE_INFO, "Max bucket search: %d slots (for better "
		 "performance a larger value for -w)",
		 readWriteGlobals->maxBucketSearch);
      readWriteGlobals->lastMaxBucketSearch = readWriteGlobals->maxBucketSearch;
    }
  }

  readWriteGlobals->maxBucketSearch = 0; /* reset */

  if(readOnlyGlobals.pcapPtr && (!readOnlyGlobals.traceMode))
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

/* ****************************************************** */

static u_int getMinMTU(void) {
#ifdef linux
  u_int minMTU = JUMBO_MTU;
  char buf[8192] = {0};
  struct ifconf ifc = {0};
  struct ifreq *ifr = NULL;
  int sck = 0;
  int nInterfaces = 0;
  int i = 0;
  struct ifreq *item;
  struct sockaddr *addr;

  /* Get a socket handle. */
  sck = socket(PF_INET, SOCK_DGRAM, 0);
  if(sck < 0)
    return(DEFAULT_MTU);

  /* Query available interfaces. */
  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  if(ioctl(sck, SIOCGIFCONF, &ifc) < 0)
    return(DEFAULT_MTU);

  /* Iterate through the list of interfaces. */
  ifr = ifc.ifc_req;
  nInterfaces = ifc.ifc_len / sizeof(struct ifreq);

  for(i = 0; i < nInterfaces; i++) {
    item = &ifr[i];

    /* Get the MTU */
    if(ioctl(sck, SIOCGIFMTU, item) < 0)
      return(DEFAULT_MTU);

#if 0
    printf("[%s][mtu: %u]\n", item->ifr_ifrn.ifrn_name, item->ifr_ifru.ifru_mtu);
#endif

    /* We assume that interfaces less than 1500 are not ethernet */
    if(item->ifr_ifru.ifru_mtu >= 1500)
      item->ifr_ifru.ifru_mtu += 14; /* Ethernet */

    if(minMTU > item->ifr_ifru.ifru_mtu)
      minMTU = item->ifr_ifru.ifru_mtu;
  }

  return(min(minMTU, DEFAULT_MTU));
#else
  return(DEFAULT_MTU);
#endif
}

/* ****************************************************** */

#define PROTO_UDP_URL       "udp://"
#define PROTO_TCP_URL       "tcp://"
#define PROTO_SCTP_URL      "sctp://"

int initNetFlow(char* addr, int port) {
  int sockopt, rc, isIpV6Address = 0;
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

  if(readOnlyGlobals.useIpV6) {
    rc = resolveIpV6Address(address, port, &isIpV6Address);
    if(!isIpV6Address) readOnlyGlobals.useIpV6 = 0;
  } else
    rc = resolveIpV4Address(address, port);

  if(rc != 0)  return(-1);

  /* Initialize the socket descriptor, so that it looks like it is not opened yet */
  readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd = -1;

#ifdef IP_HDRINCL
  /* Check only if packet reforging is enabled */
  if(!readOnlyGlobals.enableNfLitePlugin)
#endif
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
	if(transport == TRANSPORT_UDP) {
	  readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd = socket(AF_INET, SOCK_DGRAM, 0);

#if defined(IP_DONTFRAG) && 0
	  sockopt = 0;
	  rc = setsockopt(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd, IPPROTO_IP, IP_DONTFRAG,
			  (char *)&sockopt, sizeof(sockopt));
	  if(rc != 0)
	    traceEvent(TRACE_WARNING, "Unable to unset the don't fragment bit on flow packets [%d|%s]",
		       errno, strerror(errno));
#endif

	} else if(transport == TRANSPORT_TCP)
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
    sockopt = 1;
    setsockopt(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd, 0, IP_HDRINCL,
	       &tmp, sizeof(tmp));
  }
#endif

  sockopt = 1;
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

    if(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].isIPv6) {
      char col[100];

      inet_ntop(AF_INET6, &readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v6Address, col, sizeof(col));
      rc = connect(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd,
		   (struct sockaddr *)&readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v6Address,
		   sizeof(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v6Address));
    } else
      rc = connect(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].sockFd,
		   (struct sockaddr *)&readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v4Address,
		   sizeof(readOnlyGlobals.netFlowDest[readOnlyGlobals.numCollectors].u.v4Address));

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

static void readPcapFileList(const char * filename) {
  char line[512];

  FILE *fd = fopen(filename, "r");

  if(fd != NULL) {
    struct fileList *fl, *prev;

    while(!feof(fd)) {
      int i, bad_line;

      if(fgets(line, sizeof(line)-1, fd) == NULL) continue;
      if((line[0] == '#') || (line[0] == '\n')) continue;

      bad_line = 0;

      for(i=0; i<strlen(line); i++) {
	if(!isascii(line[i])) {
	  bad_line = 1;
	  break;
	}
      }

      if(bad_line) {
	traceEvent(TRACE_ERROR, "Your --pcap-file-list %s contains binary data: discarded", filename);
	fclose(fd);
	return;
      }

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

static void setupMTU(void) {
  readOnlyGlobals.maxNetFlowPacketPayloadLen = readOnlyGlobals.minMTU - 42 /* Ethernet+IP+UDP header */;
  readOnlyGlobals.num_v5flows_per_packet = min(DEFAULT_V5FLOWS_PER_PACKET, (readOnlyGlobals.maxNetFlowPacketPayloadLen - sizeof(struct flow_ver5_hdr)) / sizeof(struct flow_ver5_rec));

  readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].templateBufMax =
    readOnlyGlobals.templateBuffers[V6_TEMPLATE_INDEX].templateBufMax = readOnlyGlobals.maxNetFlowPacketPayloadLen;

#if 0
  traceEvent(TRACE_NORMAL, "Min MTU: %u", readOnlyGlobals.minMTU);
  traceEvent(TRACE_NORMAL, "Max NetFlow Packet Payload Len: %u", readOnlyGlobals.maxNetFlowPacketPayloadLen);
  traceEvent(TRACE_NORMAL, "Min Num NetFlow V5 Flows per Packet: %u", readOnlyGlobals.num_v5flows_per_packet);

  // exit(0);
#endif
}

/* ****************************************************** */

static int32_t get_gmt_offset() {
  int dt, dir;
  struct tm *gmt, *loc;
  struct tm sgmt;
  time_t t = time(NULL);

  gmt = &sgmt;
  *gmt = *gmtime(&t);
  loc = localtime(&t);
  dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
    (loc->tm_min - gmt->tm_min) * 60;

  /*
   * If the year or julian day is different, we span 00:00 GMT
   * and must add or subtract a day. Check the year first to
   * avoid problems when the julian day wraps.
   */
  dir = loc->tm_year - gmt->tm_year;
  if (dir == 0)
    dir = loc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;

  return (dt);
}

/* ****************************************************** */

static void initDefaults(void) {
  memset(&readOnlyGlobals.sockIn, 0, sizeof(readOnlyGlobals.sockIn));

  /* Set defaults */
  readOnlyGlobals.netFlowVersion = 5; /* NetFlow v5 */
  readOnlyGlobals.bidirectionalFlows = 0;
  readOnlyGlobals.minMTU = min(getMinMTU(), JUMBO_MTU);
  setupMTU();
  readOnlyGlobals.ignorePorts = readOnlyGlobals.ignorePorts = readOnlyGlobals.ignoreProtocol = 0;
  readOnlyGlobals.ignoreIP = readOnlyGlobals.ignoreIP = 0, readOnlyGlobals.ignoreTos = 1 /* Too many troubles due to TOS */;
#ifdef HAVE_GEOIP
  readOnlyGlobals.geo_ip_asn_db = NULL;
#endif
  readOnlyGlobals.numCollectors = 0;
  readOnlyGlobals.flowHashSize = DEFAULT_HASH_SIZE;
  readOnlyGlobals.hostHashSize = readOnlyGlobals.flowHashSize/2;
  readOnlyGlobals.maxNumActiveFlows = DEFAULT_HASH_SIZE * 4; /* Avoid overflow */
  readOnlyGlobals.initialSniffTime.tv_sec = 0; /* Set it with the first incoming packet */
  readOnlyGlobals.snaplen = PCAP_DEFAULT_SNAPLEN;
  readOnlyGlobals.pcapFileList = NULL;
  readOnlyGlobals.pcapFile = NULL;
  readOnlyGlobals.reflectorMode = 0;
  readOnlyGlobals.minFlowSize = 0;
  readOnlyGlobals.traceMode = 0;
  readOnlyGlobals.flowExportDelay = 1, readOnlyGlobals.packetFlowGroup = 1;
  readOnlyGlobals.engineType = 0, readOnlyGlobals.engineId = (u_int8_t)time(NULL) /* dynamic */;
  readOnlyGlobals.useNetFlow = 0xFF;
  readOnlyGlobals.use_vlanId_as_ifId = vlan_disabled;
  readOnlyGlobals.stringTemplateV4 = readOnlyGlobals.stringTemplateV6 = NULL;
  readOnlyGlobals.dirPath = NULL;
  readOnlyGlobals.minNumFlowsPerPacket = -1;
  readOnlyGlobals.pktSampleRate = 1;
  readOnlyGlobals.fakePktSampling = 0;
  readOnlyGlobals.flowSampleRate = 1;
  readOnlyGlobals.numInterfaceNetworks = 0;
  readOnlyGlobals.numBlacklistNetworks = 0;
  readOnlyGlobals.roundPacketLenWithIPHeaderLen = 1;
  readOnlyGlobals.maxExportQueueLen = MAX_EXPORT_QUEUE_LEN;
  readOnlyGlobals.unprivilegedUser = strdup("nobody");
  readOnlyGlobals.biflowsExportPolicy = export_all_flows;
  readOnlyGlobals.dbEngineType = strdup("MyISAM");
  readOnlyGlobals.max_packet_ordering_queue = min(5, MAX_VARLEN_QUEUE);
  readOnlyGlobals.l7.enable_l7_protocol_guess = 1;
  readOnlyGlobals.pcapDumper = readOnlyGlobals.dumpBadPacketsPcap = NULL;
  readOnlyGlobals.exportThreadAffinity = -1;
  readOnlyGlobals.tcpsender.tcp_socket = -1;
  readOnlyGlobals.tcpsender.tcp_connect = 0;
  readOnlyGlobals.local_timezone = get_gmt_offset();
  readWriteGlobals->numFlows = 0;
  readWriteGlobals->lastExportTime.tv_sec = 0, readWriteGlobals->lastExportTime.tv_usec = 0;
  readWriteGlobals->num_src_mac_export = 0;
#ifdef HAVE_PF_RING
  readOnlyGlobals.cluster_id = -1;
#endif

  initAS();
}

/* ****************************************************** */

static int parseOptions(int argc, char* argv[], u_int8_t reparse_options) {
  int id;
  char *theItem;
  char line[2048];
  FILE *fd;
  int opt, i, opt_n = 0;
  u_int8_t mandatoryParamOk = 0;

  if(!reparse_options)
    initDefaults();

  optind = 0;
#ifdef HAVE_OPTRESET
  optreset = 1; /* Make sure getopt read options again */
#endif

  readOnlyGlobals.argc = 0;
  readOnlyGlobals.argv = (char**)malloc(sizeof(char*)*MAX_NUM_OPTIONS);
  memset(readOnlyGlobals.argv, 0, sizeof(char*)*MAX_NUM_OPTIONS);

  if(readOnlyGlobals.argv == NULL) return(-1);

  if((argc == 2) 
	  && (argv[1][0] != '-')
#ifdef WIN32
	  && (argv[1][0] != '/')
#endif
	  ) {
    char *tok, cont=1;

    fd = fopen(argv[1], "r");

    if(fd == NULL) {
      traceEvent(TRACE_ERROR, "Unable to read config. file %s", argv[1]);
      exit(-1);
    }

    readOnlyGlobals.argv[readOnlyGlobals.argc++] = strdup("nprobe");

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

	if(readOnlyGlobals.argc >= MAX_NUM_OPTIONS) {
	  int i;

	  traceEvent(TRACE_ERROR, "Command line too long [%u arguments]", readOnlyGlobals.argc);

	  for(i=0; i<readOnlyGlobals.argc; i++)
	    traceEvent(TRACE_ERROR, "[%d][%s]", i, readOnlyGlobals.argv[i]);

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
	  /* Skip header spaces */
	  while(argument[0] == ' ') argument++;

	  /* Skip trailer spaces */
	  while(1) {
	    int len = strlen(argument);

	    if(len > 0) {
	      if((argument[len-1] == ' ')
		 || (argument[len-1] == '\t'))
		argument[len-1] = '\0';
	      else
		break;
	    } else
	      break;
	  }

	  /* traceEvent(TRACE_NORMAL, "readOnlyGlobals.argv[%d]='%s'", readOnlyGlobals.argc, argument); */
	  readOnlyGlobals.argv[readOnlyGlobals.argc++] = strdup(argument);
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
      readOnlyGlobals.argc = MAX_NUM_OPTIONS-1;
    else
      readOnlyGlobals.argc = argc;

    /* Copy arguments */
    for(i=0; i<readOnlyGlobals.argc; i++) {
      readOnlyGlobals.argv[i] = strdup(argv[i]);
    }
  }

  readOnlyGlobals.useIpV6 = 1;
  optarg = NULL;

  // readOnlyGlobals.enable_debug = 1;

  if(unlikely(readOnlyGlobals.enable_debug)) {
    traceEvent(TRACE_NORMAL, "argc: %d", readOnlyGlobals.argc);

    for(i=0; i<readOnlyGlobals.argc; i++)
      traceEvent(TRACE_NORMAL, "%2d: %s", i, readOnlyGlobals.argv[i]);
  }

  loadPlugins();
  buildCLIoptions();

  while((opt = getopt_long(readOnlyGlobals.argc, readOnlyGlobals.argv,
			   "A:ab:B:c"
			   "C:d:D:e:E:f:F:g:hi:I:l:L:"
#ifdef IP_HDRINCL
			   "q:"
#endif
			   "M:m:N:n:o:O:p:P:Q:rR:s:S:t:T:u:U:w:Wx:vV:z:"
#ifndef WIN32
			   "G"
#endif
#if defined(linux) || defined(__linux__)
			   "X4:"
#endif
#ifdef HAVE_ZMQ
			   "H:"
#endif
			   "0:1:2:3:a:"
			   "5678:9:!:@"
#if !defined(WIN32)
			   "$:\\"
#endif
			   "\xfc:" /* 252 */

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
	break;
      }

      if(discard_option) {
	traceEvent(TRACE_WARNING, "The %c option cannot be modified at runtime: ignored", opt);
	continue;
      }
    }

    switch(opt) {
    case '0':
      readOnlyGlobals.minMTU = max(min(atoi(optarg)+42 /* Eth+IP+UDP */, JUMBO_MTU), 512 /* min size */);
      setupMTU();
      break;
    case '1':
      parseInterfaceAddressLists(optarg);
      break;
    case '2':
      readOnlyGlobals.capture_num_packet_and_quit = atoi(optarg);
      break;
    case '3':
      readOnlyGlobals.flowCollection.collectorInPort = atoi(optarg);
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
      if(!strcmp(optarg, "inner"))
	readOnlyGlobals.use_vlanId_as_ifId = inner_vlan;
      else if(!strcmp(optarg, "outer"))
	readOnlyGlobals.use_vlanId_as_ifId = outer_vlan;
      else if(!strcmp(optarg, "single"))
	readOnlyGlobals.use_vlanId_as_ifId = single_vlan;
      else if(!strcmp(optarg, "double"))
	readOnlyGlobals.use_vlanId_as_ifId = double_vlan;
      break;
    case '&':
      readOnlyGlobals.l7.discard_unknown_flows = atoi(optarg);
      if(readOnlyGlobals.l7.discard_unknown_flows > 2) {
	traceEvent(TRACE_WARNING, "The mode for --discard-unknown-flows is out of range: ignored.");
	readOnlyGlobals.l7.discard_unknown_flows = 0;
      }
      break;
    case '$':
      readPcapFileList(optarg);
      break;
    case '\\':
      readOnlyGlobals.do_not_drop_privileges = 1;
      break;
    case '^':
      if(readOnlyGlobals.csv_separator) free(readOnlyGlobals.csv_separator);

      if((!strcmp(optarg, "\\t")) || (!strcmp(optarg, "\t"))) {
	char s[8];

	snprintf(s, sizeof(s), "%c", '\t');
	optarg = strdup(s);
      }

      readOnlyGlobals.csv_separator = strdup(optarg);
      break;
    case ',':
      readCities(optarg);
      break;

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
	  initPlugins();
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
      if(readOnlyGlobals.numLocalNetworks == 0) {
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
      else if(optarg[0] == 'B') readOnlyGlobals.dumpFormat = binary_core_flow_format;
      else traceEvent(TRACE_WARNING, "Invalid -D option '%s': ignored", optarg);
      break;

    case 'd':
      readOnlyGlobals.idleTimeout = atoi(optarg);
      break;

    case 'E':
      theItem = strtok(optarg, ":");
      if(theItem == NULL) {
	traceEvent(TRACE_WARNING, "Wrong engine specified (-E flag): see help.");
      } else {
	readOnlyGlobals.engineType = (u_int8_t)atoi(theItem);
	theItem = strtok(NULL, ":");

	if(theItem == NULL) {
	  traceEvent(TRACE_WARNING, "Wrong engine specified (-E flag): see help.");
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
      if(readOnlyGlobals.file_dump_timeout < 10) {
	readOnlyGlobals.file_dump_timeout = 10;
	traceEvent(TRACE_WARNING, "Sorry: -F cannot be set below %u (sec)",
		   readOnlyGlobals.file_dump_timeout);
      }
      break;

    case 'h':
      usage(1);
      return(-1);

    case 'i':
      {
#ifdef WIN32
	struct stat statbuf;

	if(!strcmp(optarg, "none"))
	  readOnlyGlobals.captureDev = strdup(optarg);
	else if(stat(optarg, &statbuf) != 0) {
	  readOnlyGlobals.captureDev = printAvailableInterfaces(optarg);
	} else
#endif

	  if(strcmp(optarg, "sysdig")) {
	    if(readOnlyGlobals.captureDev != NULL) free(readOnlyGlobals.captureDev);
	    readOnlyGlobals.captureDev = strdup(optarg);
	  } else {
	    traceEvent(TRACE_WARNING, "Sorry: you cannot open the sysdig device with -i: ignored");
	    traceEvent(TRACE_WARNING, "The process plugin will handle sysdig");
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
      if(readOnlyGlobals.numLocalNetworks == 0) {
	traceEvent(TRACE_WARNING, "Ignored -r: it must be specified after -L");
      } else
	readOnlyGlobals.setLocalTrafficDirection = 1;
      break;

    case 'R':
      if(access(optarg, F_OK
#ifndef WIN32
		|X_OK
#endif
		) != 0)
	traceEvent(TRACE_WARNING,
		   "The specified command '%s' does not exist or is not executable: ignored",
		   optarg);
      else
	readOnlyGlobals.execCmdDump = strdup(optarg);
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

    case 's':
      i = (u_int)atoi(optarg);

      if(i <= 0) i = (u_int16_t)-1; /* We set it to the maximum snaplen */

      if(i < 64) {
	readOnlyGlobals.snaplen = 64;
	traceEvent(TRACE_WARNING, "The minimum snaplen is %u", readOnlyGlobals.snaplen);
      } else if(i > (u_int16_t)-1) {
	readOnlyGlobals.snaplen = (u_int16_t)-1;
	traceEvent(TRACE_WARNING, "The maximum snaplen is %u", readOnlyGlobals.snaplen);
      } else
	readOnlyGlobals.snaplen = (u_int16_t)i;
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
	  traceEvent(TRACE_WARNING, "Unable to parse sampling option: discarded");
	  readOnlyGlobals.pktSampleRate = 1;
	  readOnlyGlobals.flowSampleRate = 1;
	}

	if(readOnlyGlobals.pktSampleRate > MAX_SAMPLE_RATE) {
	  readOnlyGlobals.pktSampleRate = MAX_SAMPLE_RATE;
	  traceEvent(TRACE_WARNING, "Packet sample rate set to %d [range 1:%d]",
		     MAX_SAMPLE_RATE, MAX_SAMPLE_RATE);
	}
	if(readOnlyGlobals.pktSampleRate == 0) readOnlyGlobals.pktSampleRate = 1;

	if(readOnlyGlobals.flowSampleRate > MAX_SAMPLE_RATE) {
	  readOnlyGlobals.flowSampleRate = MAX_SAMPLE_RATE;
	  traceEvent(TRACE_WARNING, "Flow sample rate set to %d [range 1:%d]",
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
	traceEvent(TRACE_WARNING, "The -%c value %s it out of boundaries (0...%u) and it will be truncated",
		   opt, optarg, (u_int16_t)-1);
      readOnlyGlobals.inputInterfaceIndex = id;
      break;

    case 'z':
      readOnlyGlobals.minFlowSize = (u_int)atoi(optarg);
      break;

#ifdef HAVE_PF_RING
    case 'Z':
      if((readOnlyGlobals.cluster_id = atoi(optarg)) == 0) {
	readOnlyGlobals.cluster_id = 1;
	traceEvent(TRACE_WARNING, "--cluster-id must be a positive number: setting it to %d",
		   readOnlyGlobals.cluster_id);
      }
      break;
#endif

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

      if(readOnlyGlobals.maxNumActiveFlows != (DEFAULT_HASH_SIZE * 4))
	traceEvent(TRACE_WARNING, "As you have specified -w, we also override -M.");
	traceEvent(TRACE_WARNING, "If you want to preserve the -M value, please specify -w before -M");

      readOnlyGlobals.maxNumActiveFlows = readOnlyGlobals.flowHashSize * 4; /* Avoid overflow */
      break;

    case 'W':
      readOnlyGlobals.disableIPv6 = 1;
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
	    usage(0);
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
      readOnlyGlobals.biflowsExportPolicy = atoi(optarg);
      if(readOnlyGlobals.biflowsExportPolicy > export_monodirectional_flows_only) {
	traceEvent(TRACE_WARNING, "'-N %d' is out of range: setting it to %d",
		   readOnlyGlobals.biflowsExportPolicy, export_all_flows);
	readOnlyGlobals.biflowsExportPolicy = export_all_flows;
      }
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
	    usage(0);
	  else
	    readOnlyGlobals.bindPort = strdup(readOnlyGlobals.bindPort);
	} else
	  usage(0);

	if(readOnlyGlobals.bindAddr != NULL) {
	  memset(&readOnlyGlobals.sockIn, 0, sizeof(readOnlyGlobals.sockIn));
	  /*
	    FreeBSD only
	    readOnlyGlobals.sockIn.sin_len = sizeof(struct sockaddr_in);
	  */
	  readOnlyGlobals.sockIn.sin_family = AF_INET6;

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
	  if(strcmp(readOnlyGlobals.baseTemplateBufferV4, optarg) != 0) {
	    /* Template is NOT the same */
	    ignore_template = 0;
	  }
	}

	if((readOnlyGlobals.baseTemplateBufferV4 == NULL) || (!ignore_template)) {
	  readOnlyGlobals.baseTemplateBufferV4 = strdup(optarg);
	  if(readOnlyGlobals.netFlowVersion == 5) readOnlyGlobals.netFlowVersion = 9; /* NetFlow v9 */
	  if(readOnlyGlobals.useNetFlow == 0xFF) readOnlyGlobals.useNetFlow = 1;

	  if(reparse_options)
	    compileTemplates(1);
	}
      }
      break;

    case 'U':
      {
	u_int v = atoi(optarg);

	if(v < 256) {
	  traceEvent(TRACE_WARNING, "Please use templatedId >= 256");
	} else {
	  readOnlyGlobals.idTemplate = v;
	  if(readOnlyGlobals.netFlowVersion != 9) readOnlyGlobals.netFlowVersion = 9; /* NetFlow v9 */
	  if(readOnlyGlobals.useNetFlow == 0xFF) readOnlyGlobals.useNetFlow = 1;
	}
      }
      break;

    case 'V':
      readOnlyGlobals.netFlowVersion = atoi(optarg);
      if((readOnlyGlobals.netFlowVersion != 5)
	 && (readOnlyGlobals.netFlowVersion != 9)
	 && (readOnlyGlobals.netFlowVersion != 10)) {
	traceEvent(TRACE_ERROR, "nProbe supports 5 (NetFlow 5), 9 (NetFlow 9) and 10 (IPFIX)");
	exit(0);
      }
      break;

    case 209:
      readOnlyGlobals.ipv4_deduplication_enabled = 0;
      break;

#ifdef HAVE_PF_RING
    case 210:
      if(strcmp(optarg, "ixia") == 0)
	readOnlyGlobals.enableIxiaTimestamp = 1;
      else
	printf("WARNING: unknown --hw-timestamp-mode mode, it has been ignored\n");
      break;
#endif

#ifdef HAVE_VOIP_EXTENSIONS
    case 211:
      {
	char *hep_capture_id, *hep_pwd;

	if((hep_capture_id = strtok(optarg, ":")) != NULL)
	  hep_pwd = strtok(NULL, ":");
	else
	  hep_pwd = NULL;

	if(hep_capture_id && hep_pwd) {
	  readOnlyGlobals.hep.capture_id = atoi(hep_capture_id);
	  readOnlyGlobals.hep.pwd        = strdup(hep_pwd);
	} else {
	  traceEvent(TRACE_ERROR, "Invalid format for --hep-auth parameter");
	  usage(0);
	}
      }
      break;
#endif

    case 212:
      readOnlyGlobals.flowCollection.keepProbesUnmerged = 1;
      break;

    case 213:
      readOnlyGlobals.flowCollection.sampleRate = atoi(optarg);
      break;

    case 214:
      readOnlyGlobals.aggregateGtpTunnels = 1;
      break;

    case 215:
      readOnlyGlobals.initialPacketBytesToSkip = atoi(optarg);
      break;

#ifdef HAVE_VOIP_EXTENSIONS
    case 216:
      {
	char *hep_ip, *hep_port;

	if((hep_ip = strtok(optarg, ":")) != NULL)
	  hep_port = strtok(NULL, ":");
	else
	  hep_port = NULL;

	if(hep_ip && hep_port) {
	  struct hostent *hostAddr;

	  if((hostAddr = gethostbyname(hep_ip)) == NULL) {
	    traceEvent(TRACE_ERROR, "[HEP] Unable to resolve address '%s'", hep_ip);
	  } else {
	    readOnlyGlobals.hep.sock = socket(AF_INET, SOCK_DGRAM, 0);

	    if(readOnlyGlobals.hep.sock >= 0) {
	      memset(&readOnlyGlobals.hep.server, 0, sizeof(readOnlyGlobals.hep.server));
	      memcpy(&readOnlyGlobals.hep.server.sin_addr.s_addr, hostAddr->h_addr_list[0], hostAddr->h_length);
	      readOnlyGlobals.hep.server.sin_family = AF_INET;
	      readOnlyGlobals.hep.server.sin_port   = (int)htons(atoi(hep_port));

	      traceEvent(TRACE_NORMAL, "[HEP] Sending HEPv3 data to udp://%s:%s [fd: %d]", hep_ip, hep_port, readOnlyGlobals.hep.sock);
	    } else
	      traceEvent(TRACE_ERROR, "[HEP] Unable to create HEP socket: export disabled");
	  }
	} else {
	  traceEvent(TRACE_ERROR, "Invalid format for --hep parameter");
	  usage(0);
	}
      }
      break;
#endif

    case 217:
      handleCollectionFilter(optarg);
      break;

    case 218:
      readOnlyGlobals.drop_flow_no_plugin = 1;
      break;

    case 219:
      readOnlyGlobals.aggregateTrafficPerIMSI = 1;
      break;

    case 220:
      if(set_tcp_client_address(optarg,
				&readOnlyGlobals.tcpsender.tcp_servaddr) == -1)
	traceEvent(TRACE_ERROR, "Invalid address %s with --tcp: ignored", optarg);
      else
	readOnlyGlobals.tcpsender.tcp_connect = 1, readOnlyGlobals.json_symbolic_labels = 1;
      break;

    case 221:
      readOnlyGlobals.json_symbolic_labels = 1;
      break;

    case 223:
      readOnlyGlobals.maxLogLines = atoi(optarg);

      if((readOnlyGlobals.maxLogLines < DEFAULT_MIN_NUM_LINES)
	 || (readOnlyGlobals.maxLogLines > DEFAULT_MAX_NUM_LINES)) {
	traceEvent(TRACE_WARNING, "--max-dump-lines must be in range %u..%u: ignored",
		   DEFAULT_MIN_NUM_LINES, DEFAULT_MAX_NUM_LINES);
	readOnlyGlobals.maxLogLines = DEFAULT_MIN_NUM_LINES;
      }
      break;

    case 224:
      switch(atoi(optarg)) {
      case epoch_ts_format:
      case epoch_with_usec_ts_format:
      case human_readable_ts_format:
	readOnlyGlobals.ts_format = atoi(optarg);
	break;

      default:
	traceEvent(TRACE_ERROR, "Unknown timestamp format: ignored");
	break;
      }
      break;

    case 225:
      /* Start over */
      termL7Discovery();
      readOnlyGlobals.l7.ndpi_protos = strdup(optarg);
      initL7Discovery();
      break;

    case 226:
      readOnlyGlobals.imsi_aggregation_enabled = 1;
      break;

    case 227:
      readOnlyGlobals.simulateStorage = 1;
      break;

    case 228:
      if((readOnlyGlobals.pcapDumper =
	  pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */), optarg)) == NULL) {
        traceEvent(TRACE_ERROR, "Unable to open dump file %s", optarg);
        return(-1);
      } else
	traceEvent(TRACE_NORMAL, "Dumping incoming packets on %s", optarg);
      break;

#ifdef HAVE_TEMPLATE_EXTENSIONS
    case 'x':
      {
        char *host = strtok(optarg, ":");

        if(host != NULL) {
          char *port = strtok(NULL, ":");

          if(port != NULL) {
            char *sourceId = strtok(NULL, ":");

            if(sourceId != NULL) {
              int rc = init_nf_sender(&readOnlyGlobals.nfsender.nf_sender, host, atoi(port), atoi(sourceId));

              if(rc != NFGEN_RC_OK) {
                traceEvent(TRACE_ERROR, "Unable to connect to nf_sender %s:%s\n", host, port);
                exit(-1);
              }
            } else
              traceEvent(TRACE_WARNING, "Invalid format for --nfsender: ignored");
          } else
            traceEvent(TRACE_WARNING, "Invalid format for --nfsender: ignored");
        }
      }
      break;
#else

#ifdef HAVE_ZMQ
    case 'H':
      readOnlyGlobals.zmq.endpoint = strdup(optarg);

      if(readOnlyGlobals.zmq.endpoint != NULL) {
	mandatoryParamOk++;
      } else {
	traceEvent(TRACE_ERROR, "Invalid format for --zmq parameter");
	usage(0);
      }
      break;
#endif
#endif

    case 230:
      readOnlyGlobals.exportThreadAffinity = atoi(optarg);
      break;

    case 231:
      readOnlyGlobals.dumpBadPacketsPcap = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */), optarg);
      if(readOnlyGlobals.dumpBadPacketsPcap == NULL) {
	traceEvent(TRACE_WARNING, "Unable to create pcap file %s: giving up [%s]",
		   optarg, strerror(errno));
	return(-1);
      }
      break;

    case 232:
      readOnlyGlobals.l7LruCacheSize = readOnlyGlobals.flowUsersCacheSize = atoi(optarg);
      if(readOnlyGlobals.l7LruCacheSize > MAX_LRU_CACHE_SIZE) {
	readOnlyGlobals.l7LruCacheSize = readOnlyGlobals.flowUsersCacheSize = MAX_LRU_CACHE_SIZE;
	traceEvent(TRACE_WARNING, "--lru-cache-size set to max value %u", MAX_LRU_CACHE_SIZE);
      }
      break;

    case 233:
      readOnlyGlobals.computeTrafficThroughput = 1;
      break;

    case 234:
      readOnlyGlobals.l7.protocolsFilePath = strdup(optarg);
      break;

    case 235:
      readOnlyGlobals.reforgeTimestamps = 0;
      readOnlyGlobals.dontExportFlowsDuringProcessing = 1;
      break;

    case 236:
      readOnlyGlobals.l7.enable_l7_protocol_guess = 0;
      break;

    case 237:
      readOnlyGlobals.reproduceDumpAtRealSpeed = 1;
      break;

    case 238:
      free(readOnlyGlobals.dbEngineType);
      readOnlyGlobals.dbEngineType = strdup(optarg);
      break;

#ifdef linux
    case 239:
      {
	int pagesize = sysconf(_SC_PAGE_SIZE);

	readOnlyGlobals.checkMemoryBoundaries = 1;

	readWriteGlobals->protect_mem = (void*)memalign(pagesize, pagesize);
	if(readWriteGlobals->protect_mem == NULL) {
	  traceEvent(TRACE_WARNING, "memalign error");
	  exit(-1);
	}
      }
      break;
#endif

#ifdef HAVE_REDIS
    case 222:
      readOnlyGlobals.redis.use_nutcracker = 1;
      break;

    case 240:
      {
	char *dot;

	readOnlyGlobals.redis.remote_redis_host = strdup(optarg);

	dot = strchr(readOnlyGlobals.redis.remote_redis_host, ':');
	if(dot != NULL) {
	dot[0] = '\0';
	readOnlyGlobals.redis.remote_redis_port = atoi(&dot[1]);
	} else
	  readOnlyGlobals.redis.remote_redis_port = 6379;
      }
      break;

    case 241:
      readOnlyGlobals.ucloud_enabled = 1;
      break;

    case 242:
      readOnlyGlobals.redis.local_ucloud_port = atoi(optarg);
      break;
#endif

    case 243:
      readOnlyGlobals.nestDumpDirs = 0;
      break;

    case 244:
      free(readOnlyGlobals.unprivilegedUser);
      readOnlyGlobals.unprivilegedUser = strdup(optarg);
      break;

    case 245:
      readOnlyGlobals.disableFlowCache = 1;
      break;

    case 246:
      readOnlyGlobals.fakePacketCapture = 1;
      break;

      /* NOTE 247 is free */

    case 248:
      readOnlyGlobals.tracePerformance = 1;
      break;

#ifdef HAVE_REDIS
    case 249:
      {
	char *dot;

	readOnlyGlobals.redis.logging_redis_host = strdup(optarg);

	dot = strchr(readOnlyGlobals.redis.logging_redis_host, ':');
	if(dot != NULL) {
	  dot[0] = '\0';
	  readOnlyGlobals.redis.logging_redis_port = atoi(&dot[1]);
	} else
	  readOnlyGlobals.redis.logging_redis_port = 6379;
      }
      break;
  #endif

    case 250: /* --nfLitePlugin <low port>:<num ports> */
      if(sscanf(optarg, "%u:%u", &readOnlyGlobals.nfLitePluginLowPort,
		&readOnlyGlobals.nfLitePluginNumPorts) != 2) {
	readOnlyGlobals.nfLitePluginLowPort = atoi(optarg), readOnlyGlobals.nfLitePluginNumPorts = 1;
      }

      if(readOnlyGlobals.nfLitePluginNumPorts > 32)
	readOnlyGlobals.nfLitePluginNumPorts = 32;
      else if(readOnlyGlobals.nfLitePluginNumPorts == 0)
	readOnlyGlobals.nfLitePluginNumPorts = 1;

#ifdef IP_HDRINCL
      traceEvent(TRACE_NORMAL, "IMPORTANT: Enabling NflitePlugin will also enable IP address forging, thus");
      traceEvent(TRACE_NORMAL, "IMPORTANT: flows appear as they were sent from the NflitePlugin-enabled switch");
#endif
      readOnlyGlobals.enableNfLitePlugin = 1;
      break;

    case 253:
      readOnlyGlobals.interpretFlowPackets = 1;
      break;

    case 254:
      readOnlyGlobals.enable_debug = readOnlyGlobals.interpretFlowPackets = 1;
      break;

    case 255:
      traceEvent(TRACE_WARNING, "Ignoring plugin version (plugins will not be discarded on mismatch)");
      readOnlyGlobals.ignore_plugin_revision_mismatch = 1;
      break;

#if 0
    default:
      usage(0);
      break;
#endif
    }
  }

  if(reparse_options) return(0);

  if(unlikely(readOnlyGlobals.enable_debug)) {
    // readOnlyGlobals.numProcessThreads = 1;
  }

  if(readOnlyGlobals.initialPacketBytesToSkip > 32) {
    /* We setup an upper limit for bytes skipping */
    readOnlyGlobals.initialPacketBytesToSkip = 32;

    traceEvent(TRACE_WARNING, "--skip-packet-header-bytes set to over %u: lowering it",
	       readOnlyGlobals.initialPacketBytesToSkip);
  }

  if(readOnlyGlobals.outputInterfaceIndex == 0)
    traceEvent(TRACE_WARNING, "The output interfaceId is set to 0: did you forget to use -Q perhaps ?");

  if(readOnlyGlobals.inputInterfaceIndex == 0)
    traceEvent(TRACE_WARNING, "The input interfaceId is set to 0: did you forget to use -u perhaps ?");

#ifdef HAVE_ZMQ
  if((readOnlyGlobals.numCollectors == 0) && (readOnlyGlobals.zmq.context != NULL)) {
    traceEvent(TRACE_WARNING, "You have specified --zmq and not specified -n.");
    traceEvent(TRACE_WARNING, "We believe you want to use just ZMQ and no netflow export");
    traceEvent(TRACE_WARNING, "Setting flow export to -n none");
    readOnlyGlobals.none_specified = 1;
  }
#endif

  if(readOnlyGlobals.computeTrafficThroughput
     && (readOnlyGlobals.dirPath == NULL)) {
    traceEvent(TRACE_WARNING, "Disabling --enable-throughput-stats as -P is not used");
    readOnlyGlobals.computeTrafficThroughput = 0;
  }

  /*
    This guarantees that the hash size is a multiple of the number of threads
    hence that we do not need locks in the hash when using lockless hash
  */
  readOnlyGlobals.flowHashSize -= (readOnlyGlobals.flowHashSize % readOnlyGlobals.numProcessThreads);

  readOnlyGlobals.maxExportQueueLen = max(readOnlyGlobals.maxExportQueueLen, readOnlyGlobals.flowHashSize);

  if((readOnlyGlobals.captureDev != NULL)
     && (readOnlyGlobals.pcapFileList != NULL)) {
    traceEvent(TRACE_NORMAL, "-i is ignored as --pcap-file-list has been used");
    free(readOnlyGlobals.captureDev);
    readOnlyGlobals.captureDev = NULL;
  }

  if(readOnlyGlobals.useNetFlow == 0xFF) readOnlyGlobals.useNetFlow = 1;

  if(readOnlyGlobals.netFlowVersion == 5) {
    if(readOnlyGlobals.minNumFlowsPerPacket == (u_short)-1)
      readOnlyGlobals.minNumFlowsPerPacket = readOnlyGlobals.num_v5flows_per_packet; /* Default */

    if(readOnlyGlobals.minNumFlowsPerPacket > readOnlyGlobals.num_v5flows_per_packet) {
      traceEvent(TRACE_WARNING,
		 "Sorry: the min # of flows per packet (%d) cannot be set over %d",
		 readOnlyGlobals.minNumFlowsPerPacket, readOnlyGlobals.num_v5flows_per_packet);
      readOnlyGlobals.minNumFlowsPerPacket = readOnlyGlobals.num_v5flows_per_packet;
    }

    readOnlyGlobals.disableIPv6 = 1;
  }

  if(readOnlyGlobals.disableFlowCache
     && (((readOnlyGlobals.captureDev == NULL) || strcmp(readOnlyGlobals.captureDev, "none"))
	 || (readOnlyGlobals.flowCollection.collectorInPort == 0))) {
    readOnlyGlobals.disableFlowCache = 0;
    traceEvent(TRACE_WARNING, "--disable-cache can be used only in collection mode and with -i none: disabled");
  }

  traceEvent(TRACE_NORMAL, "Welcome to nprobe v.%s (%s) for %s %s",
	     version, nprobe_revision, osName,
#ifdef HAVE_PF_RING
	     "with native PF_RING acceleration"
#else
	     ""
#endif
	     );

  if((readOnlyGlobals.numProcessThreads > 1)
     || ((readOnlyGlobals.flowCollection.collectorInPort > 0)
	 && ((readOnlyGlobals.captureDev == NULL) || strcmp(readOnlyGlobals.captureDev, "none"))))
    readOnlyGlobals.useLocks = 1;

#if defined(HAVE_LICENSE) || defined(WIN32)
  {
    char *sysId = getSystemId();

    traceEvent(TRACE_NORMAL, "nProbe SystemId: %s", sysId);
    free(sysId);
  }
#endif

  if(((fd = fopen("nprobe.license", "r")) != NULL)
     || ((fd = fopen("/etc/nprobe.license", "r")) != NULL)) {
    char license[256] = { 0 }, *ret;

    ret = fgets(license, sizeof(license), fd);
    fclose(fd);

    traceEvent(TRACE_NORMAL, "nProbe License:  %s", license);
  }

  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "Tracing enabled");

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

  if((readOnlyGlobals.numCollectors == 0) && (!readOnlyGlobals.none_specified)) {
    traceEvent(TRACE_WARNING, "-n parameter is missing. 127.0.0.1:2055 will be used.\n");
    initNetFlow("127.0.0.1", 2055);
    mandatoryParamOk = 1;
  }

#if 0
  if(readOnlyGlobals.disableFlowCache
     && ((readOnlyGlobals.numCollectors == 0) || readOnlyGlobals.none_specified)) {
    traceEvent(TRACE_WARNING, "Enabling flow cache as the probe is not used in collector/proxy mode");
    readOnlyGlobals.disableFlowCache = 0;
  }
#endif

  if(!mandatoryParamOk) {
    usage(0);
    return(-1);
  }

  /* Just to make sure we're in good shape */
  checkTemplates();

  if(readOnlyGlobals.netFlowVersion == 10)
    fixTemplatesToIPFIX();

#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.remote_redis_host
     || readOnlyGlobals.redis.logging_redis_host)
    connectToRemoteCache();
#endif

#ifdef linux
  setCpuAffinity(readOnlyGlobals.captureDev, readOnlyGlobals.cpuAffinity);
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
  u_int hash_idx = 0;

  readWriteGlobals->stopPacketCapture = 1;
  traceEvent(TRACE_INFO, "nProbe is shutting down...");

#ifdef HAVE_PF_RING
  if(readWriteGlobals->ring) {
    int num = 0;
    pfring_breakloop(readWriteGlobals->ring);
    traceEvent(TRACE_NORMAL, "Waiting for PF_RING termination");

    while(readWriteGlobals->ring_enabled) {
      if(++num == 3)
	break;
      else
	ntop_sleep(1);
    }

    traceEvent(TRACE_NORMAL, "PF_RING terminated");

    pfring_close(readWriteGlobals->ring);
    readWriteGlobals->ring = NULL;
  }
#endif

#ifdef HAVE_NETFILTER
  if(readOnlyGlobals.nf.h != NULL) {
    traceEvent(TRACE_NORMAL, "Terminating netfilter...");
    nfq_destroy_queue(readOnlyGlobals.nf.qh);
    nfq_close(readOnlyGlobals.nf.h);
    readOnlyGlobals.nf.fd = 0;
  }
#endif

  readWriteGlobals->shutdownInProgress = 1;

  /* Expedite export */
  readOnlyGlobals.flowExportDelay = 0;

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

      if(readWriteGlobals->exportBucketsLen > 0)
	traceEvent(TRACE_NORMAL, "Still %d queued buckets to be exported...",
		   readWriteGlobals->exportBucketsLen);
    }
  }

  checkNetFlowExport(1);
  readWriteGlobals->shutdownInProgress = 2;
  traceEvent(TRACE_INFO, "Pending buckets have been exported...\n");

#ifdef HAVE_VOIP_EXTENSIONS
  if(readOnlyGlobals.hep.sock >= 0)
    close(readOnlyGlobals.hep.sock);
#endif

#ifdef HAVE_ZMQ
  if(readOnlyGlobals.zmq.publisher) {
    if(readOnlyGlobals.zmq.endpoint) free(readOnlyGlobals.zmq.endpoint);
    zmq_close(readOnlyGlobals.zmq.publisher);
    zmq_ctx_destroy(readOnlyGlobals.zmq.context);
  }
#endif

  if(readWriteGlobals->sFlowPoolMap != NULL)
    free(readWriteGlobals->sFlowPoolMap);

  closeThroughputStatsDump();
}

/* ****************************************************** */

void term_pcap(pcap_t **p) {
  if(p == NULL) return;

  if(unlikely(readOnlyGlobals.useLocks))
    pthread_rwlock_wrlock(&readWriteGlobals->pcapLock);

  if(readOnlyGlobals.pcapFile) {
    pcap_close(*p);
    /*
      No clue why sometimes it crashes
      so we free only when reading .pcap dump files
    */
    free(readOnlyGlobals.pcapFile);
    readOnlyGlobals.pcapFile = NULL;
  }

  *p = NULL;

  /* No unlock */
}

/* ****************************************************** */

void shutdown_nprobe(void) {
  static u_char once = 0;
  FlowHashBucket *list;
  u_int i;

  if(once) return; else once = 1;

  stopCaptureFlushAll();

  // ntop_sleep(1);
  signalCondvar(&readWriteGlobals->exportQueueCondvar, 0);

  if(readOnlyGlobals.dequeueBucketToExport_up)
    waitCondvar(&readWriteGlobals->termCondvar); /* Wait until dequeueBucketToExport() ends */

  traceEvent(TRACE_INFO, "Flushing queued flows...\n");
  checkNetFlowExport(1 /* force export */);

  traceEvent(TRACE_INFO, "Freeing memory...\n");

  for(i = 0; i<readOnlyGlobals.numCollectors; i++)
    close(readOnlyGlobals.netFlowDest[i].sockFd);

  close_dump_file();

  free_bitmask(&readOnlyGlobals.udpProto);
  free_bitmask(&readOnlyGlobals.tcpProto);

  unload_mappings();

  if(readOnlyGlobals.pcapPtr) {
    printPcapStats(readOnlyGlobals.pcapPtr);
    term_pcap(&readOnlyGlobals.pcapPtr);
    readOnlyGlobals.pcapPtr = NULL;
  }

  for(i=0; i<readOnlyGlobals.numProcessThreads; i++)
    free(readWriteGlobals->theFlowHash[i]);

  freeHostHash();
  termL7Discovery();

  if(readOnlyGlobals.captureDev != NULL) free(readOnlyGlobals.captureDev);

  for(i=0; i<readOnlyGlobals.numActiveTemplates; i++) {
    if(readOnlyGlobals.templateBuffers[i].buffer)
      free(readOnlyGlobals.templateBuffers[i].buffer);
  }

  list = readWriteGlobals->exportQueue;

  while(list != NULL) {
    FlowHashBucket *nextEntry = list->core.hash.next;

    if(list->ext->extensions != NULL) {
      if(list->ext->extensions->mplsInfo != NULL) free(list->ext->extensions->mplsInfo);
      free(list->ext);
    }

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

#ifndef WIN32
  if(readOnlyGlobals.useSyslog)
    closelog();
#endif

  termPlugins();

  freeCollectionFilters();

  if(readOnlyGlobals.argv) {
    for(i=0; i<readOnlyGlobals.argc; i++)
      free(readOnlyGlobals.argv[i]);

    free(readOnlyGlobals.argv);
  }

#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.read_context != NULL)
    disconnectFromRemoteCache();
#endif

#ifdef linux
  if(readWriteGlobals->protect_mem)
    free(readWriteGlobals->protect_mem);
#endif

  dumpCacheStats(0);
  free_lru_cache(&readWriteGlobals->l7Cache);
  free_lru_cache(&readWriteGlobals->flowUsersCache);

  /* Clean threads */
#if 0
  traceEvent(TRACE_INFO, "Cleaning threads");
  pthread_exit(&readWriteGlobals->walkHashThread);
  pthread_exit(&readWriteGlobals->dequeueThread);
#endif

  traceEvent(TRACE_INFO, "Still allocated %u hash buckets",
	     getAtomic(&readWriteGlobals->bucketsAllocated));

  printProcessingStats();

  if(readOnlyGlobals.pcapDumper != NULL)
    pcap_dump_close(readOnlyGlobals.pcapDumper);

#ifdef HAVE_TEMPLATE_EXTENSIONS
  term_nf_sender(&readOnlyGlobals.nfsender.nf_sender);
#endif

  /* Clean globals */
  traceEvent(TRACE_INFO, "Cleaning globals");

  free(readOnlyGlobals.csv_separator);
  free(readOnlyGlobals.dirPath);
  free(readOnlyGlobals.unprivilegedUser);

  // free(readOnlyGlobals.packetProcessThread);
  if(readOnlyGlobals.baseTemplateBufferV4) free(readOnlyGlobals.baseTemplateBufferV4);
  if(readOnlyGlobals.stringTemplateV4) free(readOnlyGlobals.stringTemplateV4);
  if(readOnlyGlobals.stringTemplateV6) free(readOnlyGlobals.stringTemplateV6);

  if(readOnlyGlobals.tracePerformance)
    printProcessingStats();

#ifndef WIN32
  if(readOnlyGlobals.pidPath) {
    int fd;
    fd  = unlink(readOnlyGlobals.pidPath);
  }
#endif

  traceEvent(TRACE_INFO, "nProbe terminated.");
  dumpLogEvent(probe_stopped, severity_info, "nProbe stopped");
  if(readOnlyGlobals.eventLogPath) free(readOnlyGlobals.eventLogPath);

  if(readOnlyGlobals.dumpBadPacketsPcap)
    pcap_dump_close(readOnlyGlobals.dumpBadPacketsPcap);

  free(readWriteGlobals); /* Do not move it up as it's needed for logging */

#ifndef WIN32
  endpwent();
#endif

  exit(0);
}

/* ******************************************* */

#ifdef HAVE_NETFILTER
static int netfilter_callback(struct nfq_q_handle *qh,
			      struct nfgenmsg *nfmsg,
			      struct nfq_data *nfa,
			      void *data) {
  char *payload;
  u_int payload_len;
  u_int32_t id;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
  int last_rcvd_packet_id, rc;

  last_rcvd_packet_id = ph ? ntohl(ph->packet_id) : 0;
  payload_len = nfq_get_payload(nfa, (unsigned char **)&payload);
  /* Set defaults */
  readWriteGlobals->nf.nf_verdict = NF_ACCEPT, readWriteGlobals->nf.nf_mark = 0;

  if((payload_len > 0) && (payload != NULL)) {
    struct pcap_pkthdr h;

    h.len = h.caplen = payload_len, gettimeofday(&h.ts, NULL);

    decodePacket(readOnlyGlobals.nf.thread_id,
		 -1 /* input interface id */,
		 &h, payload,
		 0 /* readOnlyGlobals.fakePktSampling */,
		 1 /* readOnlyGlobals.pktSampleRate */,
		 1 /* RX */,
		 NO_INTERFACE_INDEX, NO_INTERFACE_INDEX,
		 0 /* Unknown sender */, 0 /* packet hash */);

    idleThreadTask(readOnlyGlobals.nf.thread_id, 9);
  }

  if(unlikely(readOnlyGlobals.enable_debug))
    traceEvent(TRACE_NORMAL, "[NetFilter] [packet len: %u][verdict: %u][nf_mark: %u]",
	       payload_len, readWriteGlobals->nf.nf_verdict, readWriteGlobals->nf.nf_mark);

  rc = nfq_set_verdict_mark(readOnlyGlobals.nf.qh, last_rcvd_packet_id,
			    readWriteGlobals->nf.nf_verdict,
			    htonl(readWriteGlobals->nf.nf_mark), 0, NULL);

  return(rc);
}
#endif

/* ******************************************* */

static int attachToNetFilter(void) {
#ifdef HAVE_NETFILTER
  if(readOnlyGlobals.captureDev
     && (strncmp(readOnlyGlobals.captureDev, "nf:", 3) == 0)) {

    readOnlyGlobals.nf.queueId = atoi(&readOnlyGlobals.captureDev[3]);

    readOnlyGlobals.nf.h = nfq_open();
    if(readOnlyGlobals.nf.h == NULL) {
      traceEvent(TRACE_ERROR, "Error during netfilter initialization");
      exit(1);
    }

    /* Unbinding existing nf_queue handler for AF_INET (if any) */
    if(nfq_unbind_pf(readOnlyGlobals.nf.h, AF_INET) < 0) {
      traceEvent(TRACE_ERROR, "Error during nfq_unbind_pf()");
      exit(1);
    }

    /* Binding nfnetlink_queue as nf_queue handler for AF_INET */
    if(nfq_bind_pf(readOnlyGlobals.nf.h, AF_INET) < 0) {
      traceEvent(TRACE_ERROR, "Error during nfq_bind_pf()");
      exit(1);
    }

#if 0
    /* Binding nfnetlink_queue as nf_queue handler for AF_INET6 */
    if(nfq_bind_pf(readOnlyGlobals.nf.h, AF_INET6) < 0) {
      traceEvent(TRACE_ERROR, "Error during nfq_bind_pf()");
      exit(1);
    }
#endif

    /* Binding this socket to queue 'queueId' */
    readOnlyGlobals.nf.qh = nfq_create_queue(readOnlyGlobals.nf.h,
					     readOnlyGlobals.nf.queueId,
					     &netfilter_callback, NULL);
    if(readOnlyGlobals.nf.qh == NULL) {
      traceEvent(TRACE_ERROR, "Error during attach to queue %d: is it configured?",
		 readOnlyGlobals.nf.queueId);
      exit(1);
    }

    if(nfq_set_mode(readOnlyGlobals.nf.qh, NFQNL_COPY_PACKET,
		    readOnlyGlobals.snaplen /* IP_MAXPACKET */) < 0) {
      traceEvent(TRACE_ERROR, "Can't set packet_copy mode");
      exit(1);
    }

    readOnlyGlobals.nf.fd = nfq_fd(readOnlyGlobals.nf.h);
  } else {
    readOnlyGlobals.nf.fd = -1;
    return(-2);
  }
#else
  return(-1);
#endif
}

/* ******************************************* */

static int openDevice(char ebuf[], int printErrors, char *pcapFilePath) {
  u_char open_device = 1;

  if(readOnlyGlobals.enableHttpPlugin || readOnlyGlobals.enableDnsPlugin
     || readOnlyGlobals.enableMySQLPlugin || readOnlyGlobals.enableSipPlugin
     || readOnlyGlobals.enableProcessPlugin
     || readOnlyGlobals.enableOraclePlugin
     || readOnlyGlobals.enableWhoisPlugin
     || readOnlyGlobals.enableGtpPlugin
     || readOnlyGlobals.enableRadiusPlugin
     || readOnlyGlobals.enableDiameterPlugin
     || readOnlyGlobals.enableSmtpPlugin
     || readOnlyGlobals.enableImapPlugin
     || readOnlyGlobals.enablePopPlugin
     || readOnlyGlobals.enableL7BridgePlugin
     || readOnlyGlobals.enable_l7_protocol_discovery
#ifdef HAVE_PF_RING
     || readOnlyGlobals.enableIxiaTimestamp
#endif
     )
    readOnlyGlobals.snaplen = max(PCAP_LONG_SNAPLEN, readOnlyGlobals.snaplen);

  traceEvent(TRACE_NORMAL, "Using packet capture length %u", readOnlyGlobals.snaplen);

  if((readOnlyGlobals.captureDev != NULL)
     && (strcmp(readOnlyGlobals.captureDev, "none") == 0)) {
    readOnlyGlobals.do_not_drop_privileges = 1;
    return(0);
  }

  if(attachToNetFilter() < 0) {
    if(readOnlyGlobals.captureDev != NULL) {
      /* Try if the passed device is instead a dump file */

      readOnlyGlobals.pcapPtr = pcap_open_offline(readOnlyGlobals.captureDev, ebuf);
      if(readOnlyGlobals.pcapPtr != NULL) {
	readOnlyGlobals.pcapFile = strdup(readOnlyGlobals.captureDev);
	readOnlyGlobals.snaplen = PCAP_LONG_SNAPLEN;
      }
    } else if(pcapFilePath != NULL) {
      if(readOnlyGlobals.pcapPtr != NULL) {
	term_pcap(&readOnlyGlobals.pcapPtr);
	readOnlyGlobals.pcapPtr = NULL;
      }

      readOnlyGlobals.pcapPtr = pcap_open_offline(pcapFilePath, ebuf);
      if(readOnlyGlobals.pcapPtr != NULL) {
	traceEvent(TRACE_NORMAL, "Processing packets from file %s", pcapFilePath);
	readOnlyGlobals.pcapFile = strdup(pcapFilePath);
	readOnlyGlobals.snaplen = PCAP_LONG_SNAPLEN;
      } else
	return(-1);
    } else
      readOnlyGlobals.pcapPtr = NULL;

    if(readOnlyGlobals.pcapPtr == NULL) {
      /* Find the default device if not specified */
      if(readOnlyGlobals.captureDev == NULL) {
#ifdef WIN32
	readOnlyGlobals.captureDev = printAvailableInterfaces(NULL);
#else
	readOnlyGlobals.captureDev = pcap_lookupdev(ebuf);
#endif
	if(readOnlyGlobals.captureDev == NULL) {
	  if(printErrors)
	    traceEvent(TRACE_ERROR,
		       "Unable to locate default interface (%s)\n", ebuf);
	  return(-1);
	} else {
	  char *_captureDev = strdup(readOnlyGlobals.captureDev);
	  readOnlyGlobals.captureDev = _captureDev;
	}
      }

#ifdef HAVE_PF_RING
      open_ring(readOnlyGlobals.captureDev, &open_device, 0);
#endif

      if(open_device) {
	if(readOnlyGlobals.enableIxiaTimestamp)
	  traceEvent(TRACE_WARNING, "Hardware timestamps are supported only on PF_RING capture interfaces");

	readOnlyGlobals.pcapPtr = pcap_open_live(readOnlyGlobals.captureDev,
						 readOnlyGlobals.snaplen,
						 readOnlyGlobals.promisc_mode /* promiscuous mode */,
						 1000 /* ms */,
						 ebuf);

	if(readOnlyGlobals.pcapPtr == NULL)  {
	  if(printErrors)
	    traceEvent(TRACE_ERROR, "Unable to open interface %s.\n", readOnlyGlobals.captureDev);

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
  }

#ifdef HAVE_PF_RING
  if(readWriteGlobals->ring != NULL) readOnlyGlobals.datalink = DLT_EN10MB;
#endif
#ifdef HAVE_NETFILTER
  if(readOnlyGlobals.nf.fd >= 0) {
    readOnlyGlobals.datalink = DLT_RAW;

    if(readOnlyGlobals.netFilter != NULL) {
      free(readOnlyGlobals.netFilter);
      readOnlyGlobals.netFilter = NULL;
    }
  }
#endif

  if(readOnlyGlobals.pcapPtr != NULL)
    readOnlyGlobals.datalink = pcap_datalink(readOnlyGlobals.pcapPtr);

  /* ************************ */

#ifdef HAVE_PF_RING
  if(readWriteGlobals->ring == NULL) {
#endif
    if(readOnlyGlobals.netFilter != NULL) {
      struct bpf_program fcode;
      struct in_addr netmask;

      netmask.s_addr = htonl(0xFFFFFF00);

      if((pcap_compile(readOnlyGlobals.pcapPtr, &fcode,
		       readOnlyGlobals.netFilter, 1, netmask.s_addr) < 0)
	 || (pcap_setfilter(readOnlyGlobals.pcapPtr, &fcode) < 0)) {
	if(printErrors)
	  traceEvent(TRACE_ERROR, "Unable to set filter %s. Filter ignored.\n",
		     readOnlyGlobals.netFilter);
	/* return(-1); */
      } else {
	if(printErrors)
	  traceEvent(TRACE_INFO, "Packet capture filter set to \"%s\"",
		     readOnlyGlobals.netFilter);
      }
    }

#ifdef HAVE_PF_RING
  }
#endif

  return(0);
}

/* ****************************************************** */

static int restoreInterface(char ebuf[]) {
  if(readOnlyGlobals.pcapFile == NULL) {
    int rc = -1;

    if(readOnlyGlobals.pcapPtr != NULL)
      traceEvent(TRACE_INFO, "Error while capturing packets: %s", pcap_geterr(readOnlyGlobals.pcapPtr));
    traceEvent(TRACE_INFO, "Waiting until the interface comes back...");

    while(rc == -1) {
      ntop_sleep(1);
      rc = openDevice(ebuf, 0, NULL);
    }

    traceEvent(TRACE_INFO, "The interface is now available again.");
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

u_int32_t usecdiff(const struct timeval *last, const struct timeval *prev) {
  struct timeval res;

  res.tv_sec = last->tv_sec - prev->tv_sec;
  if(prev->tv_usec > last->tv_usec) {
    res.tv_usec = last->tv_usec + 1000000 - prev->tv_usec;
    res.tv_sec--;
  } else
    res.tv_usec = last->tv_usec - prev->tv_usec;

  return(res.tv_sec*1000000 + res.tv_usec);
}

/* ****************************************************** */

static int next_pcap_packet(pcap_t *p, struct pcap_pkthdr *h, const u_char *pkt_data) {
  int rc;
  u_char *pkt;
  struct pcap_pkthdr *hdr;

  if(unlikely(readOnlyGlobals.useLocks))
    pthread_rwlock_wrlock(&readWriteGlobals->pcapLock);

  // traceEvent(TRACE_NORMAL, "About to call pcap_next_ex()");

  rc = pcap_next_ex(readOnlyGlobals.pcapPtr, &hdr, (const u_char**)&pkt);
  if((rc > 0) && (pkt != NULL) && (hdr->caplen > 0)) {
    hdr->caplen = min(hdr->caplen, readOnlyGlobals.snaplen);
    memcpy(h, hdr, sizeof(struct pcap_pkthdr)),
      memcpy((void*)pkt_data, (const void*)pkt, h->caplen);
  } else
    h->caplen = 0, h->len = 0;


  if(unlikely(readOnlyGlobals.pcapFile != NULL)) {
    u_int32_t warning_threshold = readOnlyGlobals.maxExportQueueLen/2;

    while(readWriteGlobals->exportBucketsLen > warning_threshold) {
      traceEvent(TRACE_INFO, "Sleeping to avoid flow drops during export...");
      ntop_sleep(1);
    }
  }

  if(unlikely(readOnlyGlobals.enable_debug)) {
    if(readWriteGlobals->currentPkts[0] > 0) {
      static struct timeval last;

      if(last.tv_sec != 0) {
	u_int32_t us = usecdiff(&h->ts, &last);

	/* traceEvent(TRACE_INFO, "Sleeping %u usec", us); */
	// usleep(us); FIX
      }

      if(unlikely(readOnlyGlobals.pcapFile != NULL))
	memcpy(&last, &h->ts, sizeof(last));
    }

    /*
       We removed the line below since we introduced
       --dont-reforge-timestamps
    */
    // gettimeofday(&h->ts, NULL); /* Use current time */
  }

  if(unlikely(readOnlyGlobals.useLocks))
    pthread_rwlock_unlock(&readWriteGlobals->pcapLock);

#if 0
  if(rc < 0)
    traceEvent(TRACE_NORMAL, "pcap_next_ex(caplen=%d, len=%d) returned %d [demo_mode=%d][%s]",
	       h->caplen, h->len, rc, readOnlyGlobals.demo_mode, pcap_geterr(readOnlyGlobals.pcapPtr));
#endif

  return(rc);
}

/* ****************************************************** */

static void* processPackets(void* _thid) {
  unsigned long thread_id = (unsigned long)_thid;
  ItemsQueue *queue = &readWriteGlobals->packetQueues[thread_id];
  QueuedPacket *slot;
  u_int num_loops = 0;

  if(readOnlyGlobals.numProcessThreads == 1) {
    /* Sanity check */
    traceEvent(TRACE_WARNING, "Internal error: processPackets() called in single thread");
    return(NULL);
  }

  // setThreadAffinity(thread_id);

  while(!readWriteGlobals->shutdownInProgress) {
    if(queue->num_insert != queue->num_remove) {
      slot = &((QueuedPacket*)queue->queueSlots)[queue->remove_idx];

      if(slot->packet_ready) {
	deepPacketDecode(thread_id,
			 slot->packet_if_idx,
			 &slot->h, slot->p,
			 slot->rx_direction /* Packet direction */,
			 0 /* sampledPacket */,
			 1 /* numPkts */,
			 NO_INTERFACE_INDEX, NO_INTERFACE_INDEX,
			 0 /* flow_sender_ip */,
			 slot->packet_hash);

	slot->packet_ready = 0, queue->remove_idx = (queue->remove_idx + 1) % DEFAULT_QUEUE_CAPACITY, queue->num_remove++;
	num_loops = 0;
	continue;
      }
    }

    // waitCondvar(&queue->dequeue_condvar);
    usleep(1000);
    if(++num_loops == 1000) {
      idleThreadTask(thread_id, 9); /* Run some idle task */
      num_loops = 0;
    }
  }

  return(NULL);
}

/* ****************************************************** */

static void fakeCapture(unsigned long thread_id) {
  struct pcap_pkthdr h;
  u_int8_t a = 0, b = 0;
  u_char pkt[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5,
    0x6, 0x7, 0x8, 0x9, 0x0a, 0x0b,
    0x08, 0x00,
    0x45, 0x0,
    0x0, 0xcc, 0x95, 0x5, 0x40, 0x00, 0x40, 0x06,
    0x6d, 0x21, 0xc0, 0xa8, 0x01, 0x21, 0x4a, 0x7d,
    0x0, 0xc1, 0x00, 0x50, 0x3d, 0xe1,
    0xf0, 0xff, 0x3a, 0xf0, 0xdd, 0x0b, 0x80, 0x18,
    0x00, 0x0<5, 0x38, 0x6d, 0x00, 0x00, 0x01, 0x01,
    0x08, 0x0a, 0x00, 0x09, 0x65, 0xac, 0x98, 0xb7,
    0xc9, 0x3f
  };

  h.len = h.caplen = sizeof(pkt);
  readOnlyGlobals.datalink = DLT_EN10MB;

  while(!readWriteGlobals->shutdownInProgress) {
    h.ts.tv_sec = time(NULL);

    pkt[29] = a++, pkt[30] = b;
    decodePacket(thread_id,
		 -1 /* input interface id */,
		 &h, pkt,
		 readOnlyGlobals.fakePktSampling,
		 readOnlyGlobals.pktSampleRate, 1 /* 1=RX, 0=TX */,
		 NO_INTERFACE_INDEX, NO_INTERFACE_INDEX,
		 0 /* Unknown sender */, 0 /* packet hash */);

    /* Rotating source IP */
    if(a == 0)
      b++;
  }
}

/* ****************************************************** */

#ifdef HAVE_NETFILTER
static void* fetchNetFilterPackets(void* _thid) {
  unsigned long thread_id = (unsigned long)_thid;
  int len;
  char pktBuf[4096] __attribute__ ((aligned));

  readOnlyGlobals.nf.thread_id = thread_id;

  while(!readWriteGlobals->shutdownInProgress) {
    if((len = recv(readOnlyGlobals.nf.fd, pktBuf, sizeof(pktBuf), 0)) > 0) {
      nfq_handle_packet(readOnlyGlobals.nf.h, pktBuf, len);
    } else {

      break;
    }
  }
}
#endif

/* ****************************************************** */

static void* fetchPcapPackets(void* _thid) {
  char ebuf[PCAP_ERRBUF_SIZE];
  const u_char *packet;
  u_short packetToGo = readOnlyGlobals.fakePktSampling ? 1 : readOnlyGlobals.pktSampleRate;
  struct pcap_pkthdr h;
  int rc;
  unsigned long thread_id = (unsigned long)_thid;
  u_int num_read_pkts = 0, num_failures = 0;

  traceEvent(TRACE_INFO, "Fetch packets thread started [thread %lu]", thread_id);

  if(readOnlyGlobals.fakePacketCapture) {
    fakeCapture(thread_id);
    return(NULL);
  }

#if 0
  setThreadAffinity(thread_id % readOnlyGlobals.numProcessThreads);
#endif

  packet = (const u_char*)malloc(readOnlyGlobals.snaplen+1);
  if(packet == NULL) {
    traceEvent(TRACE_WARNING, "Not enough memory: fetchPcapPackets(%d) leaving", thread_id);
    return(NULL);
  }

  while(!readWriteGlobals->shutdownInProgress) {
    /* traceEvent(TRACE_INFO, "fetchPcapPackets(%d)", (int)notUsed); */
    if(readOnlyGlobals.fakePktSampling || (readOnlyGlobals.pktSampleRate == 1)) {
      rc = next_pcap_packet(readOnlyGlobals.pcapPtr, &h, packet);

      if(readOnlyGlobals.pcapFile && readOnlyGlobals.reproduceDumpAtRealSpeed) {
	static struct timeval lastPktProcessed = { 0, 0 }, lastPcapTime;
	struct timeval now;

	gettimeofday(&now, NULL);
	if(lastPktProcessed.tv_sec > 0) {
	  u_int32_t m = msTimeDiff(&h.ts, &lastPcapTime), n;

	  if(m < 100000) { /* Catch wrong timestamps */
	    n = msTimeDiff(&now, &lastPktProcessed);

	    if(n < m) {
	      if(unlikely(readOnlyGlobals.enable_debug))
		traceEvent(TRACE_INFO, "Sleeping %.3f sec @ packet id %u [delta %.3f sec]",
			   ((float)(m-n))/1000, readWriteGlobals->accumulateStats[0].pkts, ((float)m)/1000);

	      usleep((m - n)*1000);
	    }
	  }
	}

	gettimeofday(&now, NULL);
	memcpy(&lastPcapTime, &h.ts, sizeof(struct timeval));
	memcpy(&lastPktProcessed, &now, sizeof(struct timeval));
      }

      if(readOnlyGlobals.reforgeTimestamps)
	gettimeofday(&h.ts, NULL);

      if((rc > 0) && (packet != NULL))
	decodePacket(thread_id,
		     -1 /* input interface id */,
		     &h, packet,
		     readOnlyGlobals.fakePktSampling,
		     readOnlyGlobals.pktSampleRate, 1 /* RX */,
		     NO_INTERFACE_INDEX, NO_INTERFACE_INDEX,
		     0 /* Unknown sender */, 0 /* packet hash */);

      idleThreadTask(thread_id, 5);
    } else {
      if(packetToGo > 1) {
	rc = next_pcap_packet(readOnlyGlobals.pcapPtr, &h, packet);

	if((rc == 1) && (packet != NULL)) {
	  packetToGo--;

	  if(unlikely(readOnlyGlobals.enable_debug))
	    traceEvent(TRACE_INFO, "Discarded packet [%d packets to go]", packetToGo-1);
	} else if(rc == -2) {
	  traceEvent(TRACE_INFO, "%s(): no more packets to read (capture file over?)", __FUNCTION__);
	  break; /* Captured file is over */
	}
	continue;
      } else {
	rc = next_pcap_packet(readOnlyGlobals.pcapPtr, &h, packet);

	if((rc == 0) && (h.caplen == 0)) rc = -2; /* Sanity check */
	if((rc >= 0) && (packet != NULL)) {
	  decodePacket(thread_id,
		       -1 /* input interface id */,
		       &h, packet,
		       readOnlyGlobals.fakePktSampling,
		       readOnlyGlobals.pktSampleRate, 1 /* RX */,
		       NO_INTERFACE_INDEX, NO_INTERFACE_INDEX,
		       0 /* Unknown sender */, 0 /* packet hash */);
	  packetToGo = readOnlyGlobals.fakePktSampling ? 1 : readOnlyGlobals.pktSampleRate;
	}
      }
    }

    if(rc < 0) {
      if(rc == -2) {
	/* Captured file is over */
	traceEvent(TRACE_INFO, "%s(): no more packets to read (capture file over?)", __FUNCTION__);
	break;
      } else if(rc == -1) {
	num_failures++;

	if(num_failures < 10) {
	  /* We hope this is a temporary issue thus we try to recover first and
	     if this is not possible then we have no other choice but to restart
	     the network interface
	  */
	  usleep(100); /* We wanna wait a bit before trying again */
	} else {
	  if(!readWriteGlobals->shutdownInProgress) {
	    traceEvent(TRACE_ERROR, "Error while reading packets: '%s'",
		       pcap_geterr(readOnlyGlobals.pcapPtr));
	    term_pcap(&readOnlyGlobals.pcapPtr);
	    readOnlyGlobals.pcapPtr = NULL;
	    rc = restoreInterface(ebuf);
	    if(rc < 0) {
	      traceEvent(TRACE_INFO, "%s(): no more packets to read", __FUNCTION__);
	      break;
	    }
	  }
	}
      }
    } else if(rc == 0) {
      /* No more packets to read if reading from file */
      if(readOnlyGlobals.pcapFile != NULL) {
	traceEvent(TRACE_INFO, "%s(threadId=%u): no more packets to read",
		   __FUNCTION__, thread_id);
	break;
      }
    } else
      num_failures = 0;

    if(readOnlyGlobals.capture_num_packet_and_quit > 1)
      readOnlyGlobals.capture_num_packet_and_quit--;
    else if(readOnlyGlobals.capture_num_packet_and_quit == 1)
      readWriteGlobals->shutdownInProgress = 1;
  } /* while */

  readWriteGlobals->numTerminatedFetchPackets++;
  free((char*)packet);

  traceEvent(TRACE_INFO, "%s(threadId=%u) terminated",
	     __FUNCTION__, thread_id);

  return(NULL);
}

/* ****************************************************** */

void init_globals(void) {
  /* 1 - Init readWriteGlobals */
  readWriteGlobals = (ReadWriteGlobals*)calloc(1, sizeof(ReadWriteGlobals));
  if(!readWriteGlobals) {
    traceEvent(TRACE_ERROR, "Not enough memory");
    exit(-1);
  }

  readWriteGlobals->flow_serial = 1; /* 0 as flow_serial means no serial */

  /* 2 - Init readOnlyGlobals */
  memset(&readOnlyGlobals, 0, sizeof(readOnlyGlobals));
  readOnlyGlobals.tunnel_mode = 0;
  readOnlyGlobals.promisc_mode = 1;
  readOnlyGlobals.maxNumActiveFlows = (u_int)-1;
  readOnlyGlobals.idTemplate = DEFAULT_TEMPLATE_ID;

#ifdef linux
  readOnlyGlobals.cpuAffinity = NULL; /* no affinity */
#endif
  readOnlyGlobals.handleFragments = 1;
  readOnlyGlobals.inputInterfaceIndex = DEFAULT_INPUT_INTERFACE_INDEX;
  readOnlyGlobals.outputInterfaceIndex = DEFAULT_OUTPUT_INTERFACE_INDEX;
  readOnlyGlobals.file_dump_timeout = 60;
  readOnlyGlobals.templatePacketsDelta = TEMPLATE_PACKETS_DELTA;
  readOnlyGlobals.maxLogLines = DEFAULT_MIN_NUM_LINES;

  /* Resever one core as a thread is used for packet dequeueing */
  readOnlyGlobals.numProcessThreads = 1;

  readOnlyGlobals.enableHostStats = 0;
  readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].templateBufMax =
    readOnlyGlobals.templateBuffers[V6_TEMPLATE_INDEX].templateBufMax = NETFLOW_MAX_BUFFER_LEN;
  readOnlyGlobals.optionTemplateBufMax = NETFLOW_MAX_BUFFER_LEN;
  readOnlyGlobals.dumpFormat = text_format;
  readOnlyGlobals.traceLevel = 2;
  readOnlyGlobals.idleTimeout = DUMP_TIMEOUT;
  readOnlyGlobals.deferredHostUpdate = 0; // FIX
  readOnlyGlobals.lifetimeTimeout = DEFAULT_LIFETIME_TIMEOUT;
  readOnlyGlobals.sendTimeout = DUMP_TIMEOUT;
  readWriteGlobals->lastMaxBucketSearch = 5; /* Don't bother with values < 5 */
  readOnlyGlobals.pcapPtr = NULL;
  readOnlyGlobals.csv_separator = strdup("|");
  readOnlyGlobals.enableNfLitePlugin = 0;
  readOnlyGlobals.nestDumpDirs = 1;
  readOnlyGlobals.reforgeTimestamps = 1;
  readOnlyGlobals.dontExportFlowsDuringProcessing = 0;
  readOnlyGlobals.json_symbolic_labels = 0;
#ifdef DEMO_MODE
  readOnlyGlobals.demo_mode = 1;
#endif
  readOnlyGlobals.useLocks = 0;
  readOnlyGlobals.ipv4_deduplication_enabled = 1;
  readOnlyGlobals.initialPacketBytesToSkip = 0;
  readOnlyGlobals.aggregateGtpTunnels = 0;
  readOnlyGlobals.flowCollection.sampleRate = 1; /* 1:1 */
  readOnlyGlobals.flowCollection.keepProbesUnmerged = 0;

#ifdef HAVE_VOIP_EXTENSIONS
  readOnlyGlobals.hep.sock       = -1;
  readOnlyGlobals.hep.capture_id = 0;
  readOnlyGlobals.hep.pwd        = "nvoice";
#endif

  readOnlyGlobals.l7LruCacheSize = readOnlyGlobals.flowUsersCacheSize = DEFAULT_LRU_CACHE_SIZE;
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
  u_int num_runs, i;
  const u_int templatedBufferLen = 4096;
  char *baseTempleteBufferV4, *baseTempleteBufferV6, *stringBuffer, *option = (char*)V9_OPTION_TEMPLATE;

  if((baseTempleteBufferV4 = calloc(1, templatedBufferLen)) == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory?");
    return;
  }

  if((baseTempleteBufferV6 = calloc(1, templatedBufferLen)) == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory?");
    return;
  }

  if((stringBuffer = calloc(1, templatedBufferLen)) == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory?");
    return;
  }

  traceEvent(TRACE_INFO, "Compiling flow templates...");

  if(reloadTemplate)
    stopCaptureFlushAll();

  if(readOnlyGlobals.netFlowVersion == 5) {
    readOnlyGlobals.stringTemplateV4 = strdup(DEFAULT_V9_IPV4_TEMPLATE);
    readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].templatePlugin =
      compileTemplate(&readOnlyGlobals.stringTemplateV4,
		      readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].v9TemplateElementList,
		      TEMPLATE_LIST_LEN, 0, 0 /* IPv4 */);
    readOnlyGlobals.numActiveTemplates++;

    readOnlyGlobals.userTemplateBuffer.templatePlugin =
      compileTemplate(&readOnlyGlobals.stringTemplateV4,
		      readOnlyGlobals.userTemplateBuffer.v9TemplateElementList,
		      TEMPLATE_LIST_LEN, 0, 0 /* IPv4 */);

    if(!reloadTemplate) {
#ifdef HAVE_MYSQL
      init_db_table();
#endif
    }

    buildActivePluginsList(readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].v9TemplateElementList);
    readOnlyGlobals.computeInterfaceIndexes = 1;
  } else if(readOnlyGlobals.netFlowVersion == 9 || readOnlyGlobals.netFlowVersion == 10) {
    u_int flowLen;

    if(readOnlyGlobals.baseTemplateBufferV4 == NULL) {
      traceEvent(TRACE_WARNING, "You selected v9/IPFIX without specifying a template (-T).");
      traceEvent(TRACE_WARNING, "The default template will be used");
      readOnlyGlobals.baseTemplateBufferV4 = strdup((readOnlyGlobals.netFlowVersion == 9) ?
						    DEFAULT_V9_IPV4_TEMPLATE : DEFAULT_IPFIX_IPV4_TEMPLATE);
    }

    traceEvent(TRACE_NORMAL, "Using NetFlow Packet Payload Len: %u", readOnlyGlobals.maxNetFlowPacketPayloadLen);

    readOnlyGlobals.stringTemplateV4 = strdup(readOnlyGlobals.baseTemplateBufferV4);
    if(strchr(readOnlyGlobals.stringTemplateV4, '%') == NULL)
      traceEvent(TRACE_WARNING, "The template does not contain any '%%': please check its format");

    if(strstr(readOnlyGlobals.stringTemplateV4, "%FLOW_PROTO_PORT") != NULL)
      loadApplProtocols();

    if((strstr(readOnlyGlobals.stringTemplateV4, "%IN_BYTES") && strstr(readOnlyGlobals.stringTemplateV4, "%OUT_BYTES"))
       || (strstr(readOnlyGlobals.stringTemplateV4, "%IN_PKTS") && strstr(readOnlyGlobals.stringTemplateV4, "%OUT_PKTS"))
       || (strstr(readOnlyGlobals.stringTemplateV4, "_IN_") && strstr(readOnlyGlobals.stringTemplateV4, "_OUT_"))
       )
      readOnlyGlobals.dontSentBidirectionalV9Flows = 1, readOnlyGlobals.bidirectionalFlows = 1;
    else
      readOnlyGlobals.dontSentBidirectionalV9Flows = 0, readOnlyGlobals.bidirectionalFlows = 0;

    if(strstr(readOnlyGlobals.stringTemplateV4, "%INPUT_SNMP")
       || strstr(readOnlyGlobals.stringTemplateV4, "%OUTPUT_SNMP"))
      readOnlyGlobals.computeInterfaceIndexes = 1;

    if(strstr(readOnlyGlobals.stringTemplateV4, "%RETRANSMITTED_")
       || strstr(readOnlyGlobals.stringTemplateV4, "%OOORDER")
       || strstr(readOnlyGlobals.stringTemplateV4, "_NW_DELAY_")
       || strstr(readOnlyGlobals.stringTemplateV4, "_OSI_SAP")
       )
      readOnlyGlobals.enableTcpSeqStats = 1, readOnlyGlobals.enableExtBucket = 1,
	readOnlyGlobals.ignoreTos = 1; /* Unless we ignore it, we cannot properly compute bi-directional stats */

    if(strstr(readOnlyGlobals.stringTemplateV4, "%NUM_PKTS_")
       || strstr(readOnlyGlobals.stringTemplateV4, "%PACKET_VARIANCE")
       )
      readOnlyGlobals.enablePacketStats = 1, readOnlyGlobals.enableExtBucket = 1;

    if(strstr(readOnlyGlobals.stringTemplateV4, "%MPLS"))
      readOnlyGlobals.enableExtBucket = 1;

    if(strstr(readOnlyGlobals.stringTemplateV4, "%APPL_LATENCY"))
      readOnlyGlobals.enableLatencyStats = 1, readOnlyGlobals.enableExtBucket = 1;

    if(strstr(readOnlyGlobals.stringTemplateV4, "%JITTER") != NULL)
      readOnlyGlobals.calculateJitter = 1;

    if(strstr(readOnlyGlobals.stringTemplateV4, "%L7_PROTO") != NULL)
      readOnlyGlobals.enable_l7_protocol_discovery = 1;
    else
      readOnlyGlobals.l7.discard_unknown_flows = 0;

    if((!strstr(readOnlyGlobals.stringTemplateV4, "%IPV4_SRC_ADDR"))
       || (!strstr(readOnlyGlobals.stringTemplateV4, "%IPV4_DST_ADDR"))
       || (!strstr(readOnlyGlobals.stringTemplateV4, "%PROTOCOL"))
       || (!strstr(readOnlyGlobals.stringTemplateV4, "%L4_SRC_PORT"))
       || (!strstr(readOnlyGlobals.stringTemplateV4, "%L4_DST_PORT"))) {
      traceEvent(TRACE_WARNING, "Your template lacks some important fields");
      traceEvent(TRACE_WARNING, "Unless you know what you are doing, make sure");
      traceEvent(TRACE_WARNING, "your template (-T) contains at least");
      traceEvent(TRACE_WARNING, "%%IPV4_SRC_ADDR %%IPV4_DST_ADDR %%PROTOCOL");
      traceEvent(TRACE_WARNING, "%%L4_SRC_PORT %%L4_DST_PORT");
    }

    loadApplProtocols();

    switch(readOnlyGlobals.l7.discard_unknown_flows) {
    case 1:
      traceEvent(TRACE_NORMAL, "Flows with unknown L7 protocols will be discarded");
      break;
    case 2:
      traceEvent(TRACE_NORMAL, "Flows with known L7 protocols will be discarded");
      break;
    }

#ifdef HAVE_GEOIP
    if(strstr(readOnlyGlobals.stringTemplateV4, "_COUNTRY")
       || strstr(readOnlyGlobals.stringTemplateV4, "_CITY"))
      readOnlyGlobals.enableGeoIP = 1;
#endif

    /*
      Optimization for NetFlow v9: discard fields that are not needed
    */
    if((strstr(readOnlyGlobals.stringTemplateV4, "%IPV4_SRC_ADDR") == NULL)
       && (strstr(readOnlyGlobals.stringTemplateV4, "%IPV4_DST_ADDR") == NULL)
       && (strstr(readOnlyGlobals.stringTemplateV4, "%IPV6_SRC_ADDR") == NULL)
       && (strstr(readOnlyGlobals.stringTemplateV4, "%IPV6_DST_ADDR") == NULL)
       ) {
      traceEvent(TRACE_WARNING,
		 "IPv4/v6 addresses will be ignored (your template lacks %%IPV4_XXX_ADDR/%%IPV6_XXX_ADDR)");
      readOnlyGlobals.ignoreIP = 1;
    }

    if((strstr(readOnlyGlobals.stringTemplateV4, "%L4_SRC_PORT") == NULL)
       && (strstr(readOnlyGlobals.stringTemplateV4, "%L4_DST_PORT") == NULL)) {
      traceEvent(TRACE_WARNING,
		 "L4 ports will be ignored (your template lacks %%L4_SRC_PORT/%%L4_DST_PORT)");
      readOnlyGlobals.ignorePorts = readOnlyGlobals.ignorePorts = 1;
    }

    if(strstr(readOnlyGlobals.stringTemplateV4, "%IN_SRC_MAC")
       || strstr(readOnlyGlobals.stringTemplateV4, "%OUT_DST_MAC") )
      readOnlyGlobals.handle_l2 = 1;

    if(strstr(readOnlyGlobals.stringTemplateV4, "%FLOW_USER_NAME"))
       readOnlyGlobals.mapUserTraffic = 1;

    if(strstr(readOnlyGlobals.stringTemplateV4, "%SRC_PROC_")
       || strstr(readOnlyGlobals.stringTemplateV4, "%DST_PROC_"))
      readOnlyGlobals.enableProcessPlugin = 1;

    if(strstr(readOnlyGlobals.stringTemplateV4, "%PROTOCOL") == NULL) {
      traceEvent(TRACE_WARNING,
		 "Protocol will be ignored (your template lacks %%PROTOCOL)");
      readOnlyGlobals.ignoreProtocol = 1;
    }

    if(readOnlyGlobals.netFlowVersion == 5) {
      readOnlyGlobals.enableExtBucket = 0;

      if(strstr(readOnlyGlobals.stringTemplateV4, "%ICMP_TYPE"))
	readOnlyGlobals.usePortsForICMP = 0;
      else {
	readOnlyGlobals.usePortsForICMP = 1;
	traceEvent(TRACE_INFO,
		   "TCP/UDP port will carry ICMP type/code information (your template lacks %%ICMP_TYPE)");
      }
    }

    /* Original user-specified template */
    readOnlyGlobals.userStringTemplate = strdup(readOnlyGlobals.baseTemplateBufferV4);
    readOnlyGlobals.userTemplateBuffer.templatePlugin =
      compileTemplate(&readOnlyGlobals.userStringTemplate,
		      readOnlyGlobals.userTemplateBuffer.v9TemplateElementList,
		      TEMPLATE_LIST_LEN, 0, 0 /* IPv4/v6 */);

    /* This is used to enable plugins and set in use to template elements */
    sanitizeV4Template(readOnlyGlobals.stringTemplateV4);
    readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].templatePlugin =
      compileTemplate(&readOnlyGlobals.stringTemplateV4,
		      readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].v9TemplateElementList,
		      TEMPLATE_LIST_LEN, 0, 0 /* IPv4/v6 */);

    /* Dummy code for enabling V6 support */
    v4toV6Template(readOnlyGlobals.stringTemplateV4);
    readOnlyGlobals.templateBuffers[V6_TEMPLATE_INDEX].templatePlugin =
      compileTemplate(&readOnlyGlobals.stringTemplateV4,
		      readOnlyGlobals.templateBuffers[V6_TEMPLATE_INDEX].v9TemplateElementList,
		      TEMPLATE_LIST_LEN, 0, 0 /* IPv4/v6 */);

    i = 0;
    while(ver9_templates[i].netflowElementName != NULL) {
      if(ver9_templates[i].isInUse) {
	switch(ver9_templates[i].protoMode) {
	case BOTH_IPV4_IPV6:
	  snprintf(&baseTempleteBufferV4[strlen(baseTempleteBufferV4)],
		   templatedBufferLen-strlen(baseTempleteBufferV4)," %%%s",
		   ver9_templates[i].netflowElementName);

	  snprintf(&baseTempleteBufferV6[strlen(baseTempleteBufferV6)],
		   templatedBufferLen-strlen(baseTempleteBufferV6)," %%%s",
		   ver9_templates[i].netflowElementName);
	  break;
	case ONLY_IPV4:
	  snprintf(&baseTempleteBufferV4[strlen(baseTempleteBufferV4)],
		   templatedBufferLen-strlen(baseTempleteBufferV4)," %%%s",
		   ver9_templates[i].netflowElementName);
	  break;
	case ONLY_IPV6:
	  snprintf(&baseTempleteBufferV6[strlen(baseTempleteBufferV6)],
		   templatedBufferLen-strlen(baseTempleteBufferV6)," %%%s",
		   ver9_templates[i].netflowElementName);
	  break;
	}
      }

      i++;
    }

    /*
      We need to check if the user has
      1. created a template for both IPv4 and IPv6: in this case we will not change
      the template. This is useful for those situations where both IPv4 and v6 will
      be mixed into the same packet (e.g. IPv4 tunnel of IPv6 traffic)
      2. if we have a single IPv4-only template we will create a similar IPv6 template
    */

    /*
      Dummy calls for enabling all plugins: their values will be overwritten
      but they are functional to nProbe
    */
    readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].templatePlugin =
      compileTemplate(&readOnlyGlobals.stringTemplateV4,
		      readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].v9TemplateElementList,
		      TEMPLATE_LIST_LEN, 0, 0 /* IPv4/v6 */);
    buildActivePluginsList(readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].v9TemplateElementList);

    /* ******** */

    free(readOnlyGlobals.stringTemplateV4); readOnlyGlobals.stringTemplateV4 = strdup(baseTempleteBufferV4);
    readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].templatePlugin =
      compileTemplate(&readOnlyGlobals.stringTemplateV4,
		      readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].v9TemplateElementList,
		      TEMPLATE_LIST_LEN, 0, 0 /* IPv4/v6 */);
    readOnlyGlobals.stringTemplateV6 = NULL;

    flowPrintf(readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].v9TemplateElementList,
	       readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].templatePlugin,
	       1 /* IPv4 */, readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].templateBuffer,
	       &readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].templateBufBegin,
	       &readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].templateBufMax,
	       &readOnlyGlobals.templateBuffers[V4_TEMPLATE_INDEX].numTemplateFieldElements,
	       1, NULL, 0, 0, 0, 0 /* No JSON */);
    readOnlyGlobals.numActiveTemplates++;

    /* ******* */

    /* Do the check below before we deallocate the string */
    if(!readOnlyGlobals.disableIPv6) {
      readOnlyGlobals.stringTemplateV6 = strdup(baseTempleteBufferV6);
      readOnlyGlobals.templateBuffers[V6_TEMPLATE_INDEX].templatePlugin =
	compileTemplate(&readOnlyGlobals.stringTemplateV6,
			readOnlyGlobals.templateBuffers[V6_TEMPLATE_INDEX].v9TemplateElementList,
			TEMPLATE_LIST_LEN, 0, 1 /* IPv6 ONLY template */);
      flowPrintf(readOnlyGlobals.templateBuffers[V6_TEMPLATE_INDEX].v9TemplateElementList,
		 readOnlyGlobals.templateBuffers[V6_TEMPLATE_INDEX].templatePlugin,
		 0 /* IPv6 */, readOnlyGlobals.templateBuffers[V6_TEMPLATE_INDEX].templateBuffer,
		 &readOnlyGlobals.templateBuffers[V6_TEMPLATE_INDEX].templateBufBegin,
		 &readOnlyGlobals.templateBuffers[V6_TEMPLATE_INDEX].templateBufMax,
		 &readOnlyGlobals.templateBuffers[V6_TEMPLATE_INDEX].numTemplateFieldElements,
		 1, NULL, 0, 0, 0, 0 /* No JSON */);
      readOnlyGlobals.numActiveTemplates++;
    }

    /* ******** */

    for(i=0; i<readOnlyGlobals.num_active_plugins; i++) {
      int j;
      V9V10TemplateElementId *el = readOnlyGlobals.all_active_plugins[i]->pluginFlowConf();

      strcpy(stringBuffer, baseTempleteBufferV4);

      j = 0;
      while(el[j].netflowElementName != NULL) {
	if(el[j].isInUse && (el[j].protoMode != ONLY_IPV6))
	  snprintf(&stringBuffer[strlen(stringBuffer)],
		   templatedBufferLen-strlen(stringBuffer),
		   " %%%s", el[j].netflowElementName);

	j++;
      }

      readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].templatePlugin =
	compileTemplate(&stringBuffer,
			readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].v9TemplateElementList,
			TEMPLATE_LIST_LEN, 0, 0 /* IPv4 */);
      readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].templateBufMax = readOnlyGlobals.maxNetFlowPacketPayloadLen;
      flowPrintf(readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].v9TemplateElementList,
		 readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].templatePlugin,
		 1 /* IPv4 */, readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].templateBuffer,
		 &readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].templateBufBegin,
		 &readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].templateBufMax,
		 &readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].numTemplateFieldElements,
		 1, NULL, 0, 0, 0, 0 /* No JSON */);

      readOnlyGlobals.all_active_plugins[i]->v4TemplateIdx = readOnlyGlobals.numActiveTemplates;

      readOnlyGlobals.numActiveTemplates++;

      if(readOnlyGlobals.stringTemplateV6) {
	u_int num_added;

	strcpy(stringBuffer, baseTempleteBufferV6);

	j = 0, num_added = 0;
	while(el[j].netflowElementName != NULL) {
	  if(el[j].isInUse && (el[j].protoMode != ONLY_IPV4)) {
	    snprintf(&stringBuffer[strlen(stringBuffer)],
		     templatedBufferLen-strlen(stringBuffer),
		     " %%%s", el[j].netflowElementName);
	    num_added++;
	  }

	  j++;
	}

	if(num_added > 0) {
	  if(!readOnlyGlobals.disableIPv6) {
	    readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].templatePlugin =
	      compileTemplate(&stringBuffer,
			      readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].v9TemplateElementList,
			      TEMPLATE_LIST_LEN, 0, 1 /* IPv6 */);
	    readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].templateBufMax = readOnlyGlobals.maxNetFlowPacketPayloadLen;
	    flowPrintf(readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].v9TemplateElementList,
		       readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].templatePlugin,
		       0 /* IPv6 */, readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].templateBuffer,
		       &readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].templateBufBegin,
		       &readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].templateBufMax,
		       &readOnlyGlobals.templateBuffers[readOnlyGlobals.numActiveTemplates].numTemplateFieldElements,
		       1, NULL, 0, 0, 0, 0 /* No JSON */);
	    readOnlyGlobals.all_active_plugins[i]->v6TemplateIdx = readOnlyGlobals.numActiveTemplates;
	    readOnlyGlobals.numActiveTemplates++;
	  }
	}
      }
    } /* for */

    /* Option template */
    compileTemplate(&option, readOnlyGlobals.v9OptionTemplateElementList,
		    TEMPLATE_LIST_LEN, 1, 0 /* IPv4/v6 */);
    flowPrintf(readOnlyGlobals.v9OptionTemplateElementList, NULL,
	       1 /* IPv4 */, readOnlyGlobals.optionTemplateBuffer,
	       &readOnlyGlobals.optionTemplateBufBegin, &readOnlyGlobals.optionTemplateBufMax,
	       &readOnlyGlobals.numOptionTemplateFieldElements, 1, NULL, 0, 0, 1,
	       0 /* No JSON */);

    flowLen = 0;
    if(readOnlyGlobals.traceMode == 2) traceEvent(TRACE_INFO, "Scanning flow template...");

    for(num_runs = 0; num_runs < readOnlyGlobals.numActiveTemplates; num_runs++) {
      V9V10TemplateElementId **elems;
      u_int tot, elId;

      elems = readOnlyGlobals.templateBuffers[num_runs].v9TemplateElementList;
      if(elems[0] == NULL) continue;

      if(readOnlyGlobals.traceMode == 2)
	traceEvent(TRACE_INFO, "Template [id=%u]", readOnlyGlobals.idTemplate + num_runs);

      for(i=0, tot = 0, elId = 0; i<TEMPLATE_LIST_LEN; i++) {
	if(elems[i] != NULL) {
	  tot += elems[i]->templateElementLen;
	  if(readOnlyGlobals.traceMode == 2)
	    traceEvent(TRACE_INFO, "Found %20s [num %d][id %d][%d bytes][total %d bytes]",
		       elems[i]->netflowElementName, ++elId,
		       (elems[i]->templateElementEnterpriseId == NTOP_ENTERPRISE_ID)
		       ? elems[i]->templateElementId-NTOP_BASE_ID : elems[i]->templateElementId,
		       elems[i]->templateElementLen, tot);
	} else
	  break;

	if(tot > flowLen) flowLen = tot;
      }
    }

    if((readOnlyGlobals.userTemplateBuffer.v9TemplateElementList[0] == NULL)
       && (readOnlyGlobals.numCollectors == 0)
       && readOnlyGlobals.none_specified) {
      traceEvent(TRACE_ERROR, "-D is mandatory when '-n none' is specified");
      exit(0);
    }

#ifdef HAVE_MYSQL
    init_db_table();
#endif

    if(flowLen > 0) {
      if(readOnlyGlobals.traceMode == 2) traceEvent(TRACE_INFO, "Scanning option template...");
      for(i=0; i<readOnlyGlobals.numOptionTemplateFieldElements; i++) {
	if(readOnlyGlobals.v9OptionTemplateElementList[i] != NULL) {
	  readOnlyGlobals.optionTemplateFlowSize += readOnlyGlobals.v9OptionTemplateElementList[i]->templateElementLen;

	  if(readOnlyGlobals.traceMode == 2) {
	    traceEvent(TRACE_INFO, "Found %20s [id %d][%u bytes][total %d bytes]",
		       readOnlyGlobals.v9OptionTemplateElementList[i]->netflowElementName,
		       readOnlyGlobals.v9OptionTemplateElementList[i]->templateElementId,
		       readOnlyGlobals.v9OptionTemplateElementList[i]->templateElementLen,
		       (int)readOnlyGlobals.optionTemplateFlowSize);
	  }
	} else
	  break;
      }

      readOnlyGlobals.templateFlowSize = 8;

      for(i=0; i<readOnlyGlobals.numActiveTemplates; i++)
	readOnlyGlobals.templateFlowSize += readOnlyGlobals.templateBuffers[i].templateBufBegin;

      readOnlyGlobals.templateFlowSize += ((12 + readOnlyGlobals.optionTemplateBufBegin)
					   + (4 + readOnlyGlobals.optionTemplateFlowSize)
					   + (flowLen - 1) /* Avoid rounding problems */
					   );

      readOnlyGlobals.templateFlowSize /= flowLen;

      if(readOnlyGlobals.minNumFlowsPerPacket == (u_short)-1) {
	/*
	  As with NetFlow v5, we suppose that a UDP packet can fit up to 1440
	  bytes (alias NETFLOW_MAX_BUFFER_LEN) of payload for NetFlow flows.
	*/
	readOnlyGlobals.minNumFlowsPerPacket = max(1, (readOnlyGlobals.maxNetFlowPacketPayloadLen/flowLen)-1);
	traceEvent(TRACE_NORMAL, "Each flow is %d bytes long", flowLen);
	traceEvent(TRACE_NORMAL, "The # packets per flow has been set to %d",
		   readOnlyGlobals.minNumFlowsPerPacket);
      } else {
	if((readOnlyGlobals.minNumFlowsPerPacket*flowLen) >= readOnlyGlobals.maxNetFlowPacketPayloadLen) {
	  traceEvent(TRACE_WARNING,
		     "Too many flows (%d) per packet specified using -m.",
		     readOnlyGlobals.minNumFlowsPerPacket);
	  readOnlyGlobals.minNumFlowsPerPacket = max(1, (readOnlyGlobals.maxNetFlowPacketPayloadLen/flowLen)-1);
	  traceEvent(TRACE_INFO, "The # packets per flow has been set to %d",
		     readOnlyGlobals.minNumFlowsPerPacket);
	}
      }
    } else {
      readOnlyGlobals.netFlowVersion = 5;
      traceEvent(TRACE_INFO, "The flow size is zero. Switching back to v5");
    }
  }

  /* All NetFlow/IPFIX versions */
  if(readOnlyGlobals.enableGtpPlugin || readOnlyGlobals.enableHttpPlugin)
    readOnlyGlobals.mapUserTraffic = 1;

#ifdef HAVE_GEOIP
  if(readOnlyGlobals.geo_ip_asn_db == NULL)
    readASs("GeoIPASNum.dat");

  if(!readOnlyGlobals.enableGeoIP) {
    if(readOnlyGlobals.geo_ip_city_db != NULL) {
      GeoIP_delete(readOnlyGlobals.geo_ip_city_db);
      readOnlyGlobals.geo_ip_city_db = NULL;
    }
  } else {
    if(readOnlyGlobals.geo_ip_city_db == NULL)
      readCities("GeoLiteCity.dat");
  }
#endif

  /* Allocate memory for template buffers */
  for(i=0; i<readOnlyGlobals.numActiveTemplates; i++) {
    if((readOnlyGlobals.templateBuffers[i].buffer = (char*)malloc(JUMBO_MTU)) == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory ?");
      exit(0); /* If we don't have enough memory now, we better quit */
    }
  }

  if(reloadTemplate) {
    readWriteGlobals->stopPacketCapture = 0;
    traceEvent(TRACE_INFO, "nProbe is now operational...");
  }

  free(baseTempleteBufferV4);
  free(baseTempleteBufferV6);
  free(stringBuffer);
}

/* ****************************************************** */

static void debug_printf(u_int32_t protocol, void *id_struct, ndpi_log_level_t log_level, const char *format, ...) { ; }
static void *malloc_wrapper(unsigned long size) { return malloc(size); }
static void free_wrapper(void *ptr) { free(ptr); }

/* ****************************************************** */

void initL7Discovery(void) {
  NDPI_PROTOCOL_BITMASK enabled_l7_protos;
  u_int32_t detection_tick_resolution = 1000;

  if(readOnlyGlobals.l7.l7handler != NULL) {
    // traceEvent(TRACE_WARNING, "Double nDPI initialization");
    return;
  }

  // if(!readOnlyGlobals.enable_l7_protocol_discovery) return;

  readOnlyGlobals.l7.l7handler = ndpi_init_detection_module(detection_tick_resolution,
							    malloc_wrapper, free_wrapper, debug_printf);
  if(readOnlyGlobals.l7.l7handler == NULL) {
    traceEvent(TRACE_ERROR, "Unable to initialize L7 engine: disabling L7 discovery");
    readOnlyGlobals.enable_l7_protocol_discovery = 0;
    return;
  }

  if(readOnlyGlobals.l7.ndpi_protos == NULL) {
    NDPI_BITMASK_SET_ALL(enabled_l7_protos); /* Enable all protocols */
  } else {
    char *p = strtok(readOnlyGlobals.l7.ndpi_protos, ",");

    while(p != NULL) {
      int id = ndpi_get_protocol_id(readOnlyGlobals.l7.l7handler, p);

      if(id == -1)
	traceEvent(TRACE_ERROR, "[L7] Discarded unknown protocol %s", p);
      else {
	NDPI_ADD_PROTOCOL_TO_BITMASK(enabled_l7_protos, id);
	traceEvent(TRACE_INFO, "[L7] Enabling nDPI protocol %s", p);
      }

      p = strtok(NULL, ",");
    }
  }

  ndpi_set_protocol_detection_bitmask2(readOnlyGlobals.l7.l7handler, &enabled_l7_protos);

  readOnlyGlobals.l7.proto_size = ndpi_detection_get_sizeof_ndpi_id_struct();
  readOnlyGlobals.l7.flow_struct_size = ndpi_detection_get_sizeof_ndpi_flow_struct();

#ifdef linux
  /* The statement below is used to trap nDPI reentrancy bugs */
  mprotect(readOnlyGlobals.l7.l7handler, sizeof(struct ndpi_detection_module_struct), PROT_WRITE);
#endif

  if(readOnlyGlobals.l7.protocolsFilePath) {
    traceEvent(TRACE_NORMAL, "Loading nDPI custom protocol ports from %s",
	       readOnlyGlobals.l7.protocolsFilePath);
    ndpi_load_protocols_file(readOnlyGlobals.l7.l7handler, readOnlyGlobals.l7.protocolsFilePath);
  }
}

/* ****************************************************** */

static void termL7Discovery(void) {
  if(readOnlyGlobals.l7.l7handler)
    ndpi_exit_detection_module(readOnlyGlobals.l7.l7handler, free_wrapper);

  if(readOnlyGlobals.l7.ndpi_protos != NULL)
    free(readOnlyGlobals.l7.ndpi_protos);

  readOnlyGlobals.l7.l7handler = NULL;
  readOnlyGlobals.l7.ndpi_protos = NULL;
}

/* ****************************************************** */

static void checkIntefaceDrops(u_int8_t dump_stats_on_screen) {
  u_int32_t drop_diff = printCaptureStats(dump_stats_on_screen);

  if(drop_diff > 0) {
    char msg[256];

    if(dump_stats_on_screen) {
      snprintf(msg, sizeof(msg), "%u packets dropped since last check", drop_diff);
      dumpLogEvent(packet_drop, severity_warning, msg);
    }
  }
}

/* ****************************************************** */

static void* printPeriodicStats(void* notUsed) {
  u_int sleep_duration = 60, to_sleep, rc;
#ifdef HAVE_TEMPLATE_EXTENSIONS
  u_int hasp_to_sleep = sleep_duration;
#endif

  sleep_duration = min(sleep_duration, readOnlyGlobals.lifetimeTimeout);
  sleep_duration = min(sleep_duration, readOnlyGlobals.idleTimeout);

  if(sleep_duration == 0) sleep_duration = 1;
  to_sleep = sleep_duration;

  while(!readWriteGlobals->shutdownInProgress) {
    ntop_sleep(1);

    if(to_sleep == sleep_duration) {
#ifdef HAVE_REDIS
      pingRedisConnections();
#endif

#ifdef HAVE_TEMPLATE_EXTENSIONS
    if(hasp_to_sleep == sleep_duration) {
      hasp_status_t   status;
      hasp_handle_t   handle;

      status = hasp_login(HASP_DEFAULT_FID,
			  (hasp_vendor_code_t *)vendor_code,
			  &handle);

      if (status != HASP_STATUS_OK) exit(1);

      status = hasp_logout(handle);

      if (status != HASP_STATUS_OK) exit(1);
    }

    if(--hasp_to_sleep == 0) hasp_to_sleep = sleep_duration;
#endif

      if((readOnlyGlobals.traceMode == 1)
	 || (readOnlyGlobals.eventLogPath != NULL))
	printStats();

      if(readOnlyGlobals.dump_stats_path != NULL)
	dumpStats(readOnlyGlobals.dump_stats_path);
      rc = 1;
    } else
      rc = 0;

    checkIntefaceDrops(rc);
    if(--to_sleep == 0) to_sleep = sleep_duration;
  }

  return(NULL);
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
  u_int i, idx, demo_mode = readOnlyGlobals.demo_mode;
#ifdef WIN32
  int optind = 0;

 // ptw32_processInitialize();
#endif

  /* Initialize to a valid value */
  readOnlyGlobals.traceLevel = 2;

#if defined(HAVE_LICENSE) || defined(WIN32)
  /* NOTE
     As the getopt is manipulated this MUST be the
     first function to be called at startup
  */
  if(!readOnlyGlobals.demo_mode) {
    extern int optind, opterr, optopt;
    extern int verify_application_instances(char *application_name, char *out_buf, int out_buf_len);
    int t_optind, t_opterr, t_optopt, num_instances;
    char out_buf[8192], *msg;

    /* save values of optind, opterr and optopt because license library
     * Calls getopt_long
     */
    t_optind = optind,  t_opterr = opterr, t_optopt = optopt;

    if((argc == 2) && (!strcmp(argv[1], "-v"))) {
      probeVersion();
      exit(0);
    } else if((argc == 2) && (!strcmp(argv[1], "--show-system-id"))) {
      printf("%s\n", getSystemId());
      exit(0);
    } else if((argc == 2) && (!strcmp(argv[1], "--nprobe-version"))) {
      printf("%s\n", version);
      exit(0);
    } else if((argc == 2) && (!strcmp(argv[1], "--dump-plugin-families"))) {
      init_globals();
      initDefaults();
      readOnlyGlobals.demo_mode = 1;
      initPlugins();
      dumpPluginFamilies();
      exit(0);
    } else if((argc == 2) && (!strcmp(argv[1], "-h"))) {
      init_globals();
      usage(1);
      exit(0);
    }

    if(!isGoodLicense(&msg)) {
      readOnlyGlobals.demo_mode = 1;
    } else {
#if 0
      if((num_instances = verify_application_instances("nprobe", out_buf, sizeof(out_buf))) != 0) {
	traceEvent(TRACE_ERROR, "Too many nProbe instances (%d) running", num_instances);
	/* exit(-1); */
	readOnlyGlobals.demo_mode = 1;
      }
#endif
    }

    if((argc == 2) && (!strcmp(argv[1], "--check-license"))) {
      printf("%s\n", (readOnlyGlobals.demo_mode == 0) ? "License Ok" : "Invalid license");
      exit(0);
    }

    if(readOnlyGlobals.demo_mode) {
      char *sysId;

      traceEvent(TRACE_ERROR, "Invalid nProbe license"
		 " ("
#ifndef WIN32
		 "/etc/"
#endif
		 LICENSE_FILE_NAME") [%s]", msg);

      traceEvent(TRACE_ERROR, "for %s", (sysId = getSystemId()));
      /* exit(0); */
      free(sysId);

      traceEvent(TRACE_ERROR, "***************************************************");
      traceEvent(TRACE_ERROR, "**                                               **");
      traceEvent(TRACE_ERROR, "**  Switching to DEMO MODE due to license error  **");
      traceEvent(TRACE_ERROR, "**                                               **");
      traceEvent(TRACE_ERROR, "**  Create your nProbe license at                **");
      traceEvent(TRACE_ERROR, "**       http://www.nmon.net/mklicense/          **");
      traceEvent(TRACE_ERROR, "**                                               **");
      traceEvent(TRACE_ERROR, "***************************************************");
    } else
      traceEvent(TRACE_NORMAL, "Valid nProbe license found");

    /* restore values */
    optind=t_optind, opterr=t_opterr, optopt=t_optopt;

    demo_mode = readOnlyGlobals.demo_mode;
  }
#else
  if((argc == 2) && (!strcmp(argv[1], "--nprobe-version"))) {
    printf("%s\n", version);
    exit(0);
  }
#endif

  init_globals();
  readOnlyGlobals.demo_mode = demo_mode;

  if(readOnlyGlobals.demo_mode) {
    traceEvent(TRACE_ERROR, "***************************************************************\n");
    traceEvent(TRACE_ERROR, "* NOTE: This is a DEMO version limited to %d flows export.  *\n", MAX_DEMO_FLOWS);
    traceEvent(TRACE_ERROR, "***************************************************************\n\n");
  }

#ifdef WIN32
  initWinsock32();
#else
  setprotoent(1); setservent(1); /* Improve protocol/port lookup performance */
#endif

  argc_ = argc;
  argv_ = (char**)argv;
  if(parseOptions(argc, argv, 0) == -1) exit(0);

  // readOnlyGlobals.traceMode = 2, traceLevel = 5; // FIX
  initPlugins();

  traceEvent(TRACE_NORMAL, "Welcome to nprobe v.%s for %s", version, osName);
  printCopyrights();

#ifndef WIN32
  if(readOnlyGlobals.useSyslog)
    openlog(readOnlyGlobals.nprobeId, LOG_PID ,LOG_DAEMON);
#endif

  memset(&readWriteGlobals->theFlowHash, 0, sizeof(readWriteGlobals->theFlowHash));
  readWriteGlobals->shutdownInProgress = 0;
  readWriteGlobals->flowExportStats.totExportedBytes = 0;
  readWriteGlobals->flowExportStats.totExportedPkts = readWriteGlobals->flowExportStats.totExportedFlows = 0;
  initAtomic(&readWriteGlobals->bucketsAllocated);
  createCondvar(&readWriteGlobals->exportQueueCondvar);
  createCondvar(&readWriteGlobals->termCondvar);
  pthread_rwlock_init(&readWriteGlobals->exportMutex, NULL);

  for(i=0; i<NUM_FRAGMENT_LISTS; i++)
    pthread_rwlock_init(&readWriteGlobals->fragmentMutex[i], NULL);

#ifdef HAVE_GEOIP
  pthread_rwlock_init(&readWriteGlobals->geoipRwLock, NULL);
#endif

  pthread_rwlock_init(&readOnlyGlobals.ticksLock, NULL);
  pthread_rwlock_init(&readWriteGlobals->exportRwLock, NULL);
  pthread_rwlock_init(&readWriteGlobals->rwGlobalsRwLock, NULL);
  pthread_rwlock_init(&readWriteGlobals->collectorRwLock, NULL);
  pthread_rwlock_init(&readWriteGlobals->collectorCounterLock, NULL);
  pthread_rwlock_init(&readWriteGlobals->pcapLock, NULL);
  pthread_rwlock_init(&readWriteGlobals->checkExportLock, NULL);
  pthread_rwlock_init(&readWriteGlobals->expireListLock, NULL);
  pthread_rwlock_init(&readWriteGlobals->trafficThroughputStats.trafficThroughputLock, NULL);
  pthread_rwlock_init(&readWriteGlobals->dumpFileLock, NULL);

  init_lru_cache(&readWriteGlobals->l7Cache, readOnlyGlobals.l7LruCacheSize);
  init_lru_cache(&readWriteGlobals->flowUsersCache, readOnlyGlobals.flowUsersCacheSize);

  /* FIX
     if(textFormat
     && ((strstr(textFormat, "%js") != NULL)
     || (strstr(textFormat, "%jd") != NULL)))
     calculateJitter = 1;
  */

  if(readOnlyGlobals.bidirectionalFlows && (readOnlyGlobals.netFlowVersion == 5)) {
    traceEvent(TRACE_WARNING, "Bi-directional flows are not supported by NetFlow v5: disabled");
    readOnlyGlobals.bidirectionalFlows = 0;
  }

  compileTemplates(0);

  if((readOnlyGlobals.netFlowVersion != 5) && readOnlyGlobals.ignoreIP)
    traceEvent(TRACE_WARNING, "Your template ignores IP addresses: your collector might ignore these flows.");

  if((readOnlyGlobals.dirPath != NULL)
     && (readOnlyGlobals.userTemplateBuffer.v9TemplateElementList[0] == NULL)) {
    traceEvent(TRACE_WARNING,
	       "-P can be specified only with -D. Ignoring -P value [%s].",
	       readOnlyGlobals.dirPath);
    free(readOnlyGlobals.dirPath);
    readOnlyGlobals.dirPath = NULL;
  }

  if(readOnlyGlobals.ignorePorts && readOnlyGlobals.ignoreProtocol)
    readOnlyGlobals.handleFragments = 0;

#ifndef WIN32
  signal(SIGTERM, cleanup);
  signal(SIGINT,  cleanup);
  signal(SIGPIPE, brokenPipe);
  signal(SIGHUP,  reloadCLI);
#endif

  /* pcap-based sniffing */
  memset(readWriteGlobals->theFlowHash, 0, sizeof(readWriteGlobals->theFlowHash));

  if((readOnlyGlobals.flowCollection.collectorInPort > 0) && (readOnlyGlobals.netFilter != NULL)) {
    traceEvent(TRACE_WARNING, "You cannot use BPF filters (%s) in collector/proxy mode: BPF filter disabled",
	       readOnlyGlobals.netFilter);

    free(readOnlyGlobals.netFilter);
    readOnlyGlobals.netFilter = NULL;
  }

  if((readOnlyGlobals.flowCollection.collectorInPort == 0) || (readOnlyGlobals.captureDev != NULL)) {
    if((openDevice(ebuf, 1, (readOnlyGlobals.pcapFileList ? readOnlyGlobals.pcapFileList->path : NULL)) == -1)
       || ((readOnlyGlobals.pcapPtr == NULL)
	   && strcmp(readOnlyGlobals.captureDev, "none")
#ifdef HAVE_PF_RING
	   && (readWriteGlobals->ring == NULL)
#endif
#ifdef HAVE_NETFILTER
	   && (readOnlyGlobals.nf.h == NULL)
#endif
	   )) {
      traceEvent(TRACE_ERROR, "Unable to open interface %s (%s)\n",
		 readOnlyGlobals.captureDev == NULL ? "<unknown>" : readOnlyGlobals.captureDev, ebuf);
      traceEvent(TRACE_ERROR, "Try using -i none if you do not want capture from a NIC");
      exit(-1);
    }
  }

  if(unlikely(readOnlyGlobals.useLocks)) {
    u_int8_t have_pf_ring = 0;

    /*
      In order to support multithreaded packet processing
      we need to use PF_RING natively
    */
#ifdef HAVE_PF_RING
    if(readWriteGlobals->ring != NULL)
      have_pf_ring = 1;
#endif

    /* Use multiprocessing also outside PF_RING */
    if(1 || have_pf_ring) {
      /* We need to allocate per-thread packet queues */
      for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
	ItemsQueue *queue = &readWriteGlobals->packetQueues[i];
	int j;

	initQueue(queue);

	queue->queueSlots = (QueuedPacket*)calloc(sizeof(QueuedPacket), DEFAULT_QUEUE_CAPACITY);
	if(queue->queueSlots == NULL) {
	  traceEvent(TRACE_ERROR, "Not enough memory");
	  exit(-1);
	}

	for(j=0; j<DEFAULT_QUEUE_CAPACITY; j++) {
	  QueuedPacket *pkt = &((QueuedPacket*)queue->queueSlots)[j];

	  if((pkt->p = malloc(readOnlyGlobals.snaplen)) == NULL) {
	    traceEvent(TRACE_ERROR, "Not enough memory");
	    exit(-1);
	  }
	}
      }
    } else {
      traceEvent(TRACE_WARNING, "Multithreaded processing is supported only with PF_RING");
      traceEvent(TRACE_WARNING, "Switching back to single thread processing");
      readOnlyGlobals.numProcessThreads = 1;
    }
  }

  memset(readWriteGlobals->flowHashRwLock, 0, sizeof(readWriteGlobals->flowHashRwLock));
  for(idx=0; idx<readOnlyGlobals.numProcessThreads; idx++) {
    for(i=0; i<MAX_HASH_MUTEXES; i++)
      pthread_rwlock_init(&readWriteGlobals->flowHashRwLock[idx][i], NULL);
  }

  for(idx=0; idx<readOnlyGlobals.numProcessThreads; idx++)
    allocateFlowHash(idx);

  for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
    readWriteGlobals->accumulateStats[i].pkts = 0, readWriteGlobals->accumulateStats[i].bytes = 0,
      readWriteGlobals->accumulateStats[i].tcpFlows = 0, readWriteGlobals->accumulateStats[i].udpFlows = 0;
    readWriteGlobals->accumulateStats[i].icmpFlows = 0;
  }

  readWriteGlobals->lastSample = time(NULL);

  if(readOnlyGlobals.enableHttpPlugin
     || readOnlyGlobals.enableDnsPlugin)
    readOnlyGlobals.disableIPv6 = 0;

  if(readOnlyGlobals.disableIPv6) {
    traceEvent(TRACE_NORMAL, "IPv6 traffic will NOT be exported/accounted by this probe");
    traceEvent(TRACE_NORMAL, "due to configuration options (e.g. use NetFlow v9)");
  }

  traceEvent(TRACE_INFO, "The flows hash has %d buckets",
	     readOnlyGlobals.flowHashSize);
  traceEvent(TRACE_INFO, "Flows older than %d seconds will be exported",
	     readOnlyGlobals.lifetimeTimeout);

  traceEvent(TRACE_INFO, "Flows inactive for at least %d seconds will be exported",
	     readOnlyGlobals.idleTimeout);

  traceEvent(TRACE_INFO, "Expired flows will not be queued for more than %d seconds",
	     readOnlyGlobals.sendTimeout);

  if(readOnlyGlobals.dump_stats_path)
    traceEvent(TRACE_INFO, "Events will be logged on file %s", readOnlyGlobals.dump_stats_path);

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

  if(unlikely(readOnlyGlobals.ignoreIP))
    traceEvent(TRACE_INFO, "IP addresses will be ignored and set to 0.");

  if(readOnlyGlobals.ignorePorts)
    traceEvent(TRACE_INFO, "UDP/TCP src/dst ports will be ignored and set to 0.");

  if(readOnlyGlobals.ignoreTos)
    traceEvent(TRACE_INFO, "TCP TOS will be ignored and set to 0.");

#ifdef HAVE_GEOIP
  if(readOnlyGlobals.geo_ip_asn_db == NULL)
#endif
    traceEvent(TRACE_NORMAL, "Flows ASs will not be computed "
#ifndef HAVE_GEOIP
	       "(missing GeoIP support)"
#endif
	       );

  if((readOnlyGlobals.packetFlowGroup > 1) && (readOnlyGlobals.flowExportDelay == 0)) {
    traceEvent(TRACE_INFO, "WARNING: -B (%u) requires that you also set -e. Ignored.",
	       readOnlyGlobals.packetFlowGroup);
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

  if(readOnlyGlobals.pktSampleRate > 1)
    traceEvent(TRACE_INFO, "%sSampling packets at 1:%d rate",
	       readOnlyGlobals.fakePktSampling ? "Fake " : "",
	       readOnlyGlobals.pktSampleRate);

  if(readOnlyGlobals.flowSampleRate > 1) {
    traceEvent(TRACE_INFO, "Sampling flows at 1:%d rate", readOnlyGlobals.flowSampleRate);
    readWriteGlobals->flowsToGo = readOnlyGlobals.flowSampleRate;
  }

  if(readOnlyGlobals.use_vlanId_as_ifId != vlan_disabled) {
    char *label = "";

    switch(readOnlyGlobals.use_vlanId_as_ifId) {
    case inner_vlan:  label = "inner"; break;
    case outer_vlan:  label = "outer"; break;
    case single_vlan: label = "single"; break;
    case double_vlan: label = "double"; break;
    case vlan_disabled: label = "disabled"; break;
    }

    traceEvent(TRACE_INFO, "Using %s VLAN Id as NetFlow interface Id", label);
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

  if((readOnlyGlobals.pcapFile == NULL) && (readOnlyGlobals.captureDev != NULL)) {
#ifdef HAVE_PF_RING
    if(readWriteGlobals->ring == NULL)
#endif

#ifdef HAVE_NETFILTER
      if(readOnlyGlobals.nf.h == NULL)
#endif

	if(readOnlyGlobals.pcapPtr == NULL)
	  traceEvent(TRACE_NORMAL, "Not capturing packet from interface (collector mode)");
	else
	  traceEvent(TRACE_NORMAL, "Capturing packets from interface %s [snaplen: %u bytes]",
		     readOnlyGlobals.captureDev, readOnlyGlobals.snaplen);
  }

  if(readOnlyGlobals.smart_udp_frags_mode)
    traceEvent(TRACE_NORMAL, "Smart fragment rebuild enabled (no fragments are rebuilt)");

  if(readOnlyGlobals.tunnel_mode)
    traceEvent(TRACE_NORMAL, "Enabled tunnel decoding (e.g. IPSEC/GTP)");

  readOnlyGlobals.nprobe_up = 1;

#ifdef HAVE_ZMQ
#ifndef WIN32
  if(readOnlyGlobals.zmq.endpoint != NULL) {
    readOnlyGlobals.zmq.daemon = readOnlyGlobals.becomeDaemon;

    /* If nprobe will be daemon, the zmq socket must be initialize after that the daemon process will be finished. */
    if(!readOnlyGlobals.becomeDaemon)
      initZMQ();
  }
#endif
#endif

#ifndef WIN32
  if(readOnlyGlobals.becomeDaemon)
    daemonize();
#endif

  if((readOnlyGlobals.pcapFile == NULL) && (!readOnlyGlobals.enableNfLitePlugin)) {
    /* Change user-id then save the pid path */
#ifndef WIN32
    readOnlyGlobals.nprobePid = getpid();

    if(readOnlyGlobals.pidPath) {
      FILE *fd = fopen(readOnlyGlobals.pidPath, "w");
      if(fd != NULL) {
	fprintf(fd, "%lu\n", readOnlyGlobals.nprobePid);
	fclose(fd);
      } else
	traceEvent(TRACE_ERROR, "Unable to store PID in file %s",
		   readOnlyGlobals.pidPath);
    }
#endif
    dropPrivileges();
  }

  load_mappings();
  enablePlugins();
  setupPlugins();

  if(readOnlyGlobals.enable_l7_protocol_discovery)
   initL7Discovery();

  if((readOnlyGlobals.pcapPtr
#ifdef HAVE_PF_RING
      || (readWriteGlobals->ring != NULL)
#endif
#ifdef HAVE_NETFILTER
      || (readOnlyGlobals.nf.h != NULL)
#endif
      || (readOnlyGlobals.flowCollection.collectorInPort > 0)
      || readOnlyGlobals.enableNfLitePlugin
      || readOnlyGlobals.tracePerformance
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
    if((readOnlyGlobals.packetProcessThread = (pthread_t*)malloc(sizeof(pthread_t)*readOnlyGlobals.numProcessThreads)) == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return(0);
    }

    if(readOnlyGlobals.flowCollection.collectorInPort > 0)
      createNetFlowListener(readOnlyGlobals.flowCollection.collectorInPort);

    if(unlikely(readOnlyGlobals.enable_debug)) {
      traceEvent(TRACE_WARNING, "*****************************************");
      traceEvent(TRACE_WARNING, "** You're running nprobe in DEBUG mode **");
      traceEvent(TRACE_WARNING, "*****************************************");
    }

    /*
      We need to figure out when lock/not lock the hash table
     */
    if(((readOnlyGlobals.pcapPtr
#ifdef HAVE_PF_RING
	|| readWriteGlobals->ring
#endif
       )
      && readOnlyGlobals.flowCollection.collectorInPort)
       || (readOnlyGlobals.useLocks))
      readOnlyGlobals.needHashLock = 1;
    else
      readOnlyGlobals.needHashLock = 0;

    traceEvent(TRACE_INFO, "Starting %u packet fetch thread(s)", readOnlyGlobals.numProcessThreads);
    pthread_create(&readWriteGlobals->dequeueThread, NULL, dequeueBucketToExport, NULL);

    pthread_create(&readWriteGlobals->statsThread, NULL, printPeriodicStats, NULL);

    if(readOnlyGlobals.computeTrafficThroughput) {
      if(readOnlyGlobals.pcapFile == NULL)
	pthread_create(&readWriteGlobals->statsThread, NULL, printThroughputStats, NULL);
      else
	readOnlyGlobals.reforgeTimestamps = 0;
    }

    if(readOnlyGlobals.pcapPtr
#ifdef HAVE_PF_RING
       || readWriteGlobals->ring
#endif
#ifdef HAVE_NETFILTER
       || readOnlyGlobals.nf.h
#endif
       || readOnlyGlobals.tracePerformance
       ) {
      readWriteGlobals->numTerminatedFetchPackets = 0;

      if(readOnlyGlobals.pcapFileList != NULL) {
	struct fileList *fl = readOnlyGlobals.pcapFileList, *next;

	while(fl != NULL) {
	  if((openDevice(ebuf, 1, fl->path) == -1) || (readOnlyGlobals.pcapPtr == NULL))
	    traceEvent(TRACE_ERROR, "Unable to open file '%s' (%s)\n", fl->path, ebuf);
	  else {
	    if(readOnlyGlobals.pcapPtr)
	      fetchPcapPackets(NULL);
	  }

	  next = fl->next;
	  free(fl->path);
	  free(fl);
	  fl = next;
	}
      } else {
	if(readOnlyGlobals.pcapFile != NULL) {
	  fetchPcapPackets(NULL);
	} else {
	  /* Spawn idleThreadTaskfetcher thread */
	  u_long thread_id = 0;
	  pthread_start_routine fetcher = NULL;

#ifdef HAVE_NETFILTER
	  if(readOnlyGlobals.nf.fd >= 0) fetcher = fetchNetFilterPackets;
#endif

	  if(fetcher == NULL) {
#ifdef HAVE_PF_RING
	    fetcher = readWriteGlobals->ring ? fetchPfRingPackets : fetchPcapPackets;
#else
	    fetcher = fetchPcapPackets;
#endif
	  }

	  /* 1 receive thread */
	  pthread_create(&readOnlyGlobals.packetProcessThread[i],
#if !defined(WIN32)
			 &tattr,
#else
			 NULL,
#endif
			 fetcher, (void*)thread_id);

	  /* n process threads */
	  if(unlikely(readOnlyGlobals.useLocks)) {
	    for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
	      thread_id = i;

	      pthread_create(&readOnlyGlobals.packetProcessThread[i],
#if !defined(WIN32)
			     &tattr,
#else
			     NULL,
#endif
			     processPackets, (void*)thread_id);
	    }
	  }
	}
      }
    }
  }

  readWriteGlobals->nprobeStarted = 1;
  traceEvent(TRACE_NORMAL, "nProbe started successfully");
  dumpLogEvent(probe_started, severity_info, "nProbe started");

  if(readOnlyGlobals.pcapFile) {
    u_int32_t i, tot_pkts = 0, tot_bytes = 0;

    for(i=0; i<readOnlyGlobals.numProcessThreads; i++)
      tot_pkts += readWriteGlobals->accumulateStats[i].pkts;

    traceEvent(TRACE_INFO, "No more packets to read. Sleeping...\n");

    // while(1) ntop_sleep(999); /* Sleep forever */
  } else {
    while(readOnlyGlobals.nprobe_up) {
      // sleep(5); break;
      ntop_sleep(1);
    }
  }

  shutdown_nprobe();

  return(0);
}

/* ******************************** */
