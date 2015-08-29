/*
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6
 *
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


#ifndef _NPROBE_H_
#define _NPROBE_H_

/* *************************** */

//#define DEMO

#define MAX_DEMO_FLOWS    25000
#ifdef DEMO
#define DEMO_MODE
//#define MAKE_STATIC_PLUGINS
#endif

/* *************************** */

#include "config.h"

#ifdef MAKE_STATIC_PLUGINS
#undef HAVE_VOIP_EXTENSIONS
#undef HAVE_NETFILTER
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* See http://www.redhat.com/magazine/009jul05/features/execshield/ */
#ifdef  __OPTIMIZE__
#ifndef _FORTIFY_SOURCE
#define _FORTIFY_SOURCE 2
#endif
#endif

#if defined(linux) || defined(__linux__)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/*
 * This allows to hide the (minimal) differences between Linux and BSD
 */
#include <features.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#endif /* linux || __linux__ */

#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#include <process.h> /* for getpid() and the exec..() family */

#define srandom srand
#define random rand
#define in_addr_t unsigned long

#define nprobe_strdup(a)  _strdup(a)
#ifndef localtime
#define localtime_r(a,b)	localtime(a)
#endif

/* Values for the second argument to access.
   These may be OR'd together.  */
#define R_OK    4       /* Test for read permission.  */
#define W_OK    2       /* Test for write permission.  */
//#define   X_OK    1       /* execute permission - unsupported in windows*/
#define F_OK    0       /* Test for existence.  */

#define access _access
#define ftruncate _chsize


/* WIN32 Memory Debugger */
//#include "vld.h"

#include "dirent.h"
#else
#define nprobe_strdup(a)  strdup(a)
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#ifndef WIN32
#include <strings.h>
#include <pwd.h>
#include <fstab.h>
#endif
#include <limits.h>
#include <float.h>
#include <math.h>
#include <sys/types.h>
#ifdef linux
/* #include <sys/sysinfo.h> */
#include <malloc.h>
#endif

#ifdef HAVE_SCHED_H
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <sched.h>
#endif

#define MAX_NUM_RECYCLED_BUFFERS 16384

#include <getopt.h> /* getopt from: http://www.pwilson.net/sample.html. */

#ifndef WIN32
#include <sys/mman.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>

#define PERFORMANCE

#if defined(PERFORMANCE) \
  && defined(__GNUC__)	 \
  && (defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4) \
      || defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8))
#define HAVE_COMPARE_AND_SWAP
#endif

#ifdef HAVE_GDBM
#include <gdbm.h>
#endif

#ifdef __arm__
#pragma pack(1)
#endif

#ifdef __NetBSD__
#include <net/if_ether.h>
#endif
#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#include <netinet/in_systm.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#endif

#ifdef __arm__
#pragma pack()
#endif

#include <sys/stat.h>
#include "pcap.h"

#ifdef HAVE_DL_H
#include <dl.h>
#endif

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#ifdef WIN32
#define HAVE_MYSQL
//#define HAVE_SQLITE
#define HAVE_ZMQ
#endif

#ifdef HAVE_MYSQL
#include <mysql.h>
#define MYSQL_OPT              "--mysql"
#define MYSQL_SKIP_DB_CREATION "--mysql-skip-db-creation"
#endif

#ifdef HAVE_LIBSQLITE3
#define HAVE_SQLITE
#endif

#ifdef HAVE_SQLITE
#include <sqlite3.h>
#endif

/* GeoIP */
#ifdef HAVE_GEOIP
#include "GeoIP.h"
#include "GeoIPCity.h"
#endif

/* Redis - http://www.redis.io/ */
#ifdef HAVE_REDIS
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#endif

#ifdef HAVE_NETFILTER
#include <linux/types.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#endif

#include "version.h"

#ifdef HAVE_ZMQ
#include "zmq.h"

struct zmq_msg_hdr {
  char url[32];
  u_int32_t version;
  u_int32_t size;
};
#endif

#ifdef HAVE_TEMPLATE_EXTENSIONS
#include "templates.h"
#endif

#include "patricia.h"

#include "ndpi_main.h"
#include "template.h"

/* CysSSL Sniffer Interface */
//#ifdef HAVE_YASSL
//#define FILETYPE_PEM 1
//#define FILETYPE_DER 2
//
//extern int  ssl_SetPrivateKey(const char* address, int port, const char* keyFile, int keyType, const char* password, char* error);
//extern int  ssl_DecodePacket(const unsigned char* packet, int length, unsigned char* data, char* error);
//extern void ssl_InitSniffer(void);
//extern void ssl_FreeSniffer(void);
//#endif

#define TEMPLATE_LIST_LEN   64

#define DEFAULT_MIN_NUM_LINES    10000
#define DEFAULT_MAX_NUM_LINES  1000000

#ifndef TH_FIN
#define	TH_FIN	0x01
#endif
#ifndef TH_SYN
#define	TH_SYN	0x02
#endif
#ifndef TH_RST
#define	TH_RST	0x04
#endif
#ifndef TH_PUSH
#define	TH_PUSH	0x08
#endif
#ifndef TH_ACK
#define	TH_ACK	0x10
#endif
#ifndef TH_URG
#define	TH_URG	0x20
#endif

#define DEFAULT_MTU      1514
#define JUMBO_MTU        9000

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct eth_header {
  u_char	ether_dhost[6];
  u_char	ether_shost[6];
  u_short	ether_type;
};


/* http://en.wikipedia.org/wiki/Stdint.h */
/* On various systems there's u_int64_t but not u_int64_t */

#ifndef WIN32
#include <pthread.h>
#include <stdarg.h>
#include <syslog.h>

#ifndef PTHREAD_RWLOCK_INITIALIZER
#undef HAVE_RW_LOCK
#endif

#ifndef HAVE_RW_LOCK
#define pthread_rwlock_t       pthread_mutex_t
#define pthread_rwlock_init    pthread_mutex_init
#define pthread_rwlock_rdlock  pthread_mutex_lock
#define pthread_rwlock_wrlock  pthread_mutex_lock
#define pthread_rwlock_unlock  pthread_mutex_unlock
#define pthread_rwlock_destroy pthread_mutex_destroy
#endif

#else /* WIN32 */

#define usleep(a) Sleep(a/1000)

#ifdef WIN32_THREADS
#define pthread_t              HANDLE
#define pthread_mutex_t        HANDLE
#define pthread_rwlock_t       HANDLE
#endif

#if !defined (__GNUC__)
typedef	u_int32_t	tcp_seq;
#endif

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
  u_int16_t	th_sport;		/* source port */
  u_int16_t	th_dport;		/* destination port */
  tcp_seq	th_seq;			/* sequence number */
  tcp_seq	th_ack;			/* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
  u_char	th_x2:4,		/* (unused) */
    th_off:4;		/* data offset */
#else
  u_char	th_off:4,		/* data offset */
    th_x2:4;		/* (unused) */
#endif
  u_int8_t	th_flags;
  u_int16_t	th_win;			/* window */
  u_int16_t	th_sum;			/* checksum */
  u_int16_t	th_urp;			/* urgent pointer */
};

/* ********************************************* */

struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
  u_int8_t	ip_hl:4,		/* header length */
    ip_v:4;			/* version */
#else
  u_int8_t	ip_v:4,			/* version */
    ip_hl:4;		/* header length */
#endif
  u_int8_t	ip_tos;			/* type of service */
  int16_t	ip_len;			/* total length */
  u_int16_t	ip_id;			/* identification */
  int16_t	ip_off;			/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
  u_int8_t	ip_ttl;			/* time to live */
  u_int8_t	ip_p;			/* protocol */
  u_int16_t	ip_sum;			/* checksum */
  struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

/* ********************************************* */

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udphdr {
  u_int16_t	uh_sport;		/* source port */
  u_int16_t	uh_dport;		/* destination port */
  int16_t	uh_ulen;		/* udp length */
  u_int16_t	uh_sum;			/* udp checksum */
};

/* ********************************************* */

extern int gettimeofday(struct timeval *tv, struct timezone *tz);

#ifndef WIN32
extern char *strtok_r(char *s, const char *delim, char **save_ptr);
#else
#define strcasecmp(a, b) lstrcmpiA(a, b)
extern const char *strcasestr(const char *haystack, const char *needle);
extern int ptw32_processInitialize (void);
#endif
extern int nprobe_sleep(int secToSleep);

#ifdef WIN32_THREADS
extern int pthread_create(pthread_t *threadId, void* notUsed, void *(*__start_routine) (void *), char* userParm);
extern void pthread_detach(pthread_t *threadId);
extern int pthread_mutex_init(pthread_mutex_t *mutex, char* notused);
extern void pthread_mutex_destroy(pthread_mutex_t *mutex);
extern int pthread_mutex_lock(pthread_mutex_t *mutex);
extern int pthread_mutex_trylock(pthread_mutex_t *mutex);
extern int pthread_mutex_unlock(pthread_mutex_t *mutex);

#define pthread_rwlock_init			pthread_mutex_init
#define pthread_rwlock_wrlock			pthread_mutex_lock
#define pthread_rwlock_unlock			pthread_mutex_unlock
#endif

#endif /* WIN32 */

#ifdef HAVE_JSON_C
#include <json-c/json.h>
#endif

/* http://en.wikipedia.org/wiki/SCTP_packet_structure */
struct sctphdr {
  /* Common Header */
  u_int16_t sport, dport;
  u_int32_t verification_tag; /* A 32-bit random value created during initialization to distinguish stale packets from a previous connection. */
  u_int32_t checksum; /*  CRC32c algorithm */
};

struct sctp_chunk {
  /* Chunk Info */
  u_int8_t chunk_type, chunk_flags;
  u_int16_t chunk_len;
};

struct sctp_data_chunk {
  /* Data Header */
  u_int32_t tsn; /* Transmission sequence number (TSN) */
  u_int16_t stream_id; /* Stream identifier */
  u_int16_t stream_sequence; /* Stream sequence number */
  u_int32_t payload_id; /* Payload protocol identifier */
};

#ifdef WIN32
#define CONST_DIR_SEP '\\'
#else
#define CONST_DIR_SEP '/'
#endif

#define PREFIX             "/usr/local"
#define LICENSE_FILE_NAME  "nprobe.license"

/*
  2^32 minus a large value so that we won't wrap for sure
  Note that nProbe can work as sFlow collector and thus
  we cannot expect packets to be 1500 bytes but they can
  very well be 3072000 or more. Thus better set a high
  threshold but not too high to risk missing the wrap
 */
#define BYTES_WRAP_THRESHOLD 0xFF000000

#include "bucket.h"
#include "collect.h"

typedef struct ether80211q {
  u_int16_t vlanId;
  u_int16_t protoType;
} Ether80211q;

typedef struct ether8021ad {
  u_int16_t flags;
  u_int16_t protoType;
} Ether8021ad;


/* GRE (Generic Route Encapsulation) */

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

#define GRE_HEADER_CHECKSUM      0x8000 /* 32 bit */
#define GRE_HEADER_ROUTING       0x4000 /* 32 bit */
#define GRE_HEADER_KEY           0x2000 /* 32 bit */
#define GRE_HEADER_SEQ_NUM       0x1000 /* 32 bit */

struct grev1_header {
  u_int16_t flags_and_version;
  u_int16_t proto;
};

/* GPRS Tunneling Protocol */
struct gtpv0_header {
  u_int8_t flags, message_type;
  u_int16_t total_length, sequence_number, flow_label;
  u_int8_t sndcp_number, padding[3];
  u_int64_t tunnel_id;
} __attribute__((__packed__));

struct gtpv1_header {
  u_int8_t flags, message_type;
  u_int16_t total_length;
  u_int32_t tunnel_id;
  u_int16_t sequence_number;
  u_int8_t pdu_nuber, next_ext_header;
} __attribute__((__packed__));

struct gtpv2_header {
  u_int8_t flags, message_type;
  u_int16_t message_len;
  u_int32_t teid;
  u_int8_t sequence_number[3], spare;
} __attribute__((__packed__));

struct l2tp_header {
  u_int16_t flags, tunnel_id, session_id;
} __attribute__((__packed__));

struct ppp_header {
  u_int8_t address, control;
  u_int16_t protocol;
} __attribute__((__packed__));

struct ppp_multilink_header {
  u_int8_t flags, sequence_number[3];
} __attribute__((__packed__));

struct mobileip_header {
  u_int8_t message_type, next_header;
  u_int16_t reserved;
};

extern char nprobe_revision[];

typedef enum {
  text_format = 0,
  sqlite_format,
  binary_format,
  binary_core_flow_format,
} DumpFormat;

typedef enum {
  epoch_ts_format = 0,
  epoch_with_usec_ts_format,
  human_readable_ts_format
} TimestampFormat;

typedef enum {
  export_all_flows = 0,
  export_bidirectional_flows_only,
  export_monodirectional_flows_only
} BiflowsExportPolicy;
/* Update LogEventSeverity2Str in util.c when changing the structure below */
typedef enum {
  severity_error = 0,
  severity_warning,
  severity_info
} LogEventSeverity;

/* Update LogEventType2Str in util.c when changing the structure below */
typedef enum {
  probe_started = 0,
  probe_stopped,
  packet_drop,
  flow_export_error,
  collector_connection_error,
  collector_connected,
  collector_disconnected,
  collector_too_slow
} LogEventType;

extern void allocateHash(void);

#ifdef ETHER_HEADER_HAS_EA
#  define ESRC(ep) ((ep)->ether_shost.ether_addr_octet)
#  define EDST(ep) ((ep)->ether_dhost.ether_addr_octet)
#else
#  define ESRC(ep) ((ep)->ether_shost)
#  define EDST(ep) ((ep)->ether_dhost)
#endif

/* BSD AF_ values. */
#define BSD_AF_INET             2
#define BSD_AF_INET6_BSD        24      /* OpenBSD (and probably NetBSD), BSD/OS */
#define BSD_AF_INET6_FREEBSD    28
#define BSD_AF_INET6_DARWIN     30

#define PLUGIN_EXTENSION        ".so"

/*
  Courtesy of http://ettercap.sourceforge.net/
*/
#ifndef CFG_LITTLE_ENDIAN
#define ptohs(x) ( (u_int16_t)				\
		   ((u_int16_t)*((u_int8_t *)x+1)<<8|	\
		    (u_int16_t)*((u_int8_t *)x+0)<<0)   \
		   )

#define ptohl(x) ( (u_int32)*((u_int8_t *)x+3)<<24|	\
		   (u_int32)*((u_int8_t *)x+2)<<16|	\
		   (u_int32)*((u_int8_t *)x+1)<<8|	\
		   (u_int32)*((u_int8_t *)x+0)<<0	\
		   )
#else
#define ptohs(x) *(u_int16_t *)(x)
#define ptohl(x) *(u_int32 *)(x)
#endif

#define TCPOPT_EOL              0
#define TCPOPT_NOP              1
#define TCPOPT_MAXSEG           2
#define TCPOPT_WSCALE           3
#define TCPOPT_SACKOK           4
#define TCPOPT_TIMESTAMP        8

#define MAX_AS_PATH_LEN         10

/* ************************************ */

#ifndef ETHERTYPE_IP
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#endif

#ifndef ETHERTYPE_IPV6
#define	ETHERTYPE_IPV6		0x86DD	/* IPv6 protocol */
#endif

#ifndef ETHERTYPE_MPLS
#define	ETHERTYPE_MPLS		0x8847	/* MPLS protocol */
#endif

#ifndef ETHERTYPE_MPLS_MULTI
#define ETHERTYPE_MPLS_MULTI	0x8848	/* MPLS multicast packet */
#endif

#ifndef ETHERTYPE_PPPoE
#define	ETHERTYPE_PPPoE		0x8864	/* PPP over Ethernet */
#endif

struct ether_mpls_header {
  u_int8_t label, exp, bos;
  u_int8_t ttl;
};

#define NULL_HDRLEN             4

#ifndef SOLARIS
/* VLAN support - Courtesy of  Mikael Cam <mca@mgn.net> - 2002/08/28 */
#ifndef ETHER_ADDR_LEN
#define	ETHER_ADDR_LEN	6
#endif

struct	ether_vlan_header {
  u_int8_t    evl_dhost[ETHER_ADDR_LEN];
  u_int8_t    evl_shost[ETHER_ADDR_LEN];
  u_int16_t evl_encap_proto;
  u_int16_t evl_tag;
  u_int16_t evl_proto;
};
#endif

#ifdef SOLARIS
struct  ip6_ext {
  u_int8_t ip6e_nxt;
  u_int8_t ip6e_len;
} __attribute__((__packed__));
#endif

#define NO_VLAN       (u_int16_t)-1
#define MAX_VLAN      4096

#ifndef ETHERTYPE_VLAN
#define	ETHERTYPE_VLAN		0x08100
#endif

#ifndef ETHERTYPE_8021AD
#define	ETHERTYPE_8021AD	0x088A8
#endif

typedef struct ipV4Fragment {
  u_int32_t src, dst;
  u_short fragmentId, numPkts, len, sport, dport;
  time_t firstSeen;
  struct ipV4Fragment *next;
} IpV4Fragment;

/* ************************************ */

#ifndef linux
#undef IP_HDRINCL
#endif

#define TRANSPORT_UDP          1
#define TRANSPORT_TCP          2
#define TRANSPORT_SCTP         3
#ifdef IP_HDRINCL
#define TRANSPORT_UDP_RAW      4
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP         132
#endif

typedef struct collectorAddress {
  u_int8_t isIPv6; /* 0=IPv4, 1=IPv6 or anything else (generic addrinfo) */
  u_int8_t transport; /* TRANSPORT_XXXX */
  u_int  flowSequence;

  union {
    struct sockaddr_in v4Address;
    struct sockaddr_in6 v6Address;
  } u;

  int sockFd; /* Socket file descriptor */
  struct timeval lastExportTime; /* Time when last packet was exported [Set only with -e] */
} CollectorAddress;

/* ************************************ */

#ifndef WIN32
#include <pthread.h>

typedef struct conditionalVariable {
  pthread_mutex_t mutex;
  pthread_cond_t  condvar;
  int predicate;
} ConditionalVariable;

#else

typedef struct conditionalVariable {
  HANDLE condVar;
  CRITICAL_SECTION criticalSection;
} ConditionalVariable;

#endif

extern int createCondvar(ConditionalVariable *condvarId);
extern void deleteCondvar(ConditionalVariable *condvarId);
extern int waitCondvar(ConditionalVariable *condvarId);
extern int signalCondvar(ConditionalVariable *condvarId, int broadcast);

#define TEMP_PREFIX        ".temp"
#define BUF_SIZE           512

#define NO_INTERFACE_INDEX ((u_int16_t)-1)

#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__

/* ************************************************ */

extern char *optarg;

/* ********** ICMP ******************** */

#ifdef WIN32

struct icmp_ra_addr
{
  u_int32_t ira_addr;
  u_int32_t ira_preference;
};
#endif /* WIN32 */

struct icmp_hdr
{
  u_int8_t  icmp_type;	 /* type of message, see below */
  u_int8_t  icmp_code;	 /* type sub code */
  u_int16_t icmp_cksum;	 /* ones complement checksum of struct */
  u_int16_t icmp_identifier, icmp_seqnum;
};

struct icmp6_hdr {
  u_int8_t icmp6_type;/* type field */
  u_int8_t icmp6_code;/* code field */
  u_int16_t icmp6_cksum;/* checksum field */
  union {
    u_int32_t icmp6_un_data32[1]; /* type-specific field */
    u_int16_t icmp6_un_data16[2]; /* type-specific field */
    u_int8_t icmp6_un_data8[4];  /* type-specific field */
  } icmp6_dataun;
};

/*
 * Definition of ICMP types and code field values.
 */
#define	NPROBE_ICMP_ECHOREPLY		0		/* echo reply */
#define	NPROBE_ICMP_UNREACH		3		/* dest unreachable, codes: */
#define	NPROBE_ICMP_UNREACH_NET	        0		/* bad net */
#define	NPROBE_ICMP_UNREACH_HOST	1		/* bad host */
#define	NPROBE_ICMP_UNREACH_PROTOCOL	2		/* bad protocol */
#define	NPROBE_ICMP_UNREACH_PORT	3		/* bad port */
#define	NPROBE_ICMP_UNREACH_NEEDFRAG	4		/* IP_DF caused drop */
#define	NPROBE_ICMP_UNREACH_SRCFAIL	5		/* src route failed */
#define	NPROBE_ICMP_UNREACH_NET_UNKNOWN 6		/* unknown net */
#define	NPROBE_ICMP_UNREACH_HOST_UNKNOWN 7		/* unknown host */
#define	NPROBE_ICMP_UNREACH_ISOLATED	8		/* src host isolated */
#define	NPROBE_ICMP_UNREACH_NET_PROHIB	9		/* prohibited access */
#define	NPROBE_ICMP_UNREACH_HOST_PROHIB 10		/* ditto */
#define	NPROBE_ICMP_UNREACH_TOSNET	11		/* bad tos for net */
#define	NPROBE_ICMP_UNREACH_TOSHOST	12		/* bad tos for host */
#define	NPROBE_ICMP_UNREACH_FILTER_PROHIB 13		/* admin prohib */
#define	NPROBE_ICMP_UNREACH_HOST_PRECEDENCE 14		/* host prec vio. */
#define	NPROBE_ICMP_UNREACH_PRECEDENCE_CUTOFF 15	/* prec cutoff */
#define	NPROBE_ICMP_SOURCEQUENCH	 4		/* packet lost, slow down */
#define	NPROBE_ICMP_REDIRECT		 5		/* shorter route, codes: */
#define	NPROBE_ICMP_REDIRECT_NET	 0		/* for network */
#define	NPROBE_ICMP_REDIRECT_HOST	 1		/* for host */
#define	NPROBE_ICMP_REDIRECT_TOSNET	 2		/* for tos and net */
#define	NPROBE_ICMP_REDIRECT_TOSHOST	 3		/* for tos and host */
#define	NPROBE_ICMP_ECHO		 8		/* echo service */
#define	NPROBE_ICMP_ROUTERADVERT	 9		/* router advertisement */
#define	NPROBE_ICMP_ROUTERSOLICIT	10		/* router solicitation */
#define	NPROBE_ICMP_TIMXCEED		11		/* time exceeded, code: */
#define	NPROBE_ICMP_TIMXCEED_INTRANS	 0		/* ttl==0 in transit */
#define	NPROBE_ICMP_TIMXCEED_REASS	 1		/* ttl==0 in reass */
#define	NPROBE_ICMP_PARAMPROB		12		/* ip header bad */
#define	NPROBE_ICMP_PARAMPROB_ERRATPTR   0		/* error at param ptr */
#define	NPROBE_ICMP_PARAMPROB_OPTABSENT  1		/* req. opt. absent */
#define	NPROBE_ICMP_PARAMPROB_LENGTH     2			/* bad length */
#define	NPROBE_ICMP_TSTAMP		13		/* timestamp request */
#define	NPROBE_ICMP_TSTAMPREPLY	        14		/* timestamp reply */
#define	NPROBE_ICMP_IREQ		15		/* information request */
#define	NPROBE_ICMP_IREQREPLY		16		/* information reply */
#define	NPROBE_ICMP_MASKREQ		17		/* address mask request */
#define	NPROBE_ICMP_MASKREPLY		18		/* address mask reply */

#define	NPROBE_ICMP_MAXTYPE		18

/* ********* NETFLOW ****************** */

/*
  For more info see:

  http://www.cisco.com/warp/public/cc/pd/iosw/ioft/neflct/tech/napps_wp.htm

  ftp://ftp.net.ohio-state.edu/users/maf/cisco/
*/

/* ********************************* */

#define FLOW_VERSION_1		     1
#define DEFAULT_V1FLOWS_PER_PACKET   30

struct flow_ver1_hdr {
  u_int16_t version;         /* Current version = 1*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
};

struct flow_ver1_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration */
  u_int32_t dOctets;    /* Octets sent in Duration */
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t pad;        /* pad to word boundary */
  u_int8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int8_t  pad2[7];    /* pad to word boundary */
};

typedef struct single_flow_ver1_rec {
  struct flow_ver1_hdr flowHeader;
  struct flow_ver1_rec flowRecord[DEFAULT_V1FLOWS_PER_PACKET+1 /* safe against buffer overflows */];
} NetFlow1Record;

/* ***************************************** */

#define FLOW_VERSION_5		        5
#define DEFAULT_V5FLOWS_PER_PACKET	30

struct flow_ver5_hdr {
  u_int16_t version;         /* Current version=5*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int8_t  engine_type;     /* Type of flow switching engine (RP,VIP,etc.)*/
  u_int8_t  engine_id;       /* Slot number of the flow switching engine */
  u_int16_t sampleRate;      /* Packet capture sample rate */
};

struct flow_ver5_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration (milliseconds between 1st
			   & last packet in this flow)*/
  u_int32_t dOctets;    /* Octets sent in Duration (milliseconds between 1st
			   & last packet in  this flow)*/
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t pad1;        /* pad to word boundary */
  u_int8_t tcp_flags;   /* Cumulative OR of tcp flags */
  u_int8_t proto;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t tos;         /* IP Type-of-Service */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int8_t src_mask;    /* source route's mask bits */
  u_int8_t dst_mask;    /* destination route's mask bits */
  u_int16_t pad2;       /* pad to word boundary */
};

typedef struct single_flow_ver5_rec {
  struct flow_ver5_hdr flowHeader;
  struct flow_ver5_rec flowRecord[DEFAULT_V5FLOWS_PER_PACKET+1 /* safe against buffer overflows */];
} NetFlow5Record;

/* ************************************ */

#define FLOW_VERSION_7		     7
#define DEFAULT_V7FLOWS_PER_PACKET  28

/* ********************************* */

struct flow_ver7_hdr {
  u_int16_t version;         /* Current version=7*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int32_t reserved;
};

struct flow_ver7_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration */
  u_int32_t dOctets;    /* Octets sent in Duration */
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t  flags;      /* Shortcut mode(dest only,src only,full flows*/
  u_int8_t  tcp_flags;  /* Cumulative OR of tcp flags */
  u_int8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int8_t  dst_mask;   /* destination route's mask bits */
  u_int8_t  src_mask;   /* source route's mask bits */
  u_int16_t pad2;       /* pad to word boundary */
  u_int32_t router_sc;  /* Router which is shortcut by switch */
};

typedef struct single_flow_ver7_rec {
  struct flow_ver7_hdr flowHeader;
  struct flow_ver7_rec flowRecord[DEFAULT_V7FLOWS_PER_PACKET+1 /* safe against buffer overflows */];
} NetFlow7Record;

/* ************************************ */

/* NetFlow v9/IPFIX */

typedef struct flow_ver9_hdr {
  u_int16_t version;         /* Current version=9*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int32_t sourceId;        /* Source id */
} V9FlowHeader;

typedef struct flow_ver9_template_field {
  u_int16_t fieldId;
  u_int16_t fieldLen;
  u_int8_t  isPenField;
  u_int32_t enterpriseId;
} V9V10TemplateField;

typedef struct flow_ver9_template_header {
  u_int16_t templateFlowset; /* = 0 */
  u_int16_t flowsetLen;
} V9TemplateHeader;

typedef struct flow_ver9_template_def {
  u_int16_t templateId;
  u_int16_t fieldCount;
} V9TemplateDef;

typedef struct flow_ver9_ipfix_simple_template {
  /* V9TemplateHeader */
  u_int16_t flowsetLen;
  /* V9TemplateDef */
  u_int8_t flowVersion;
  u_int16_t templateId;
  u_int16_t fieldCount, scopeFieldCount, v9ScopeLen;
  u_int32_t netflow_device_ip, observation_domain_id_source_id; /* IPFIX: observation_domain_id, v9: source_id */
  u_int8_t isOptionTemplate;
} V9IpfixSimpleTemplate;

typedef struct flow_ver9_option_template {
  u_int16_t templateFlowset; /* = 0 */
  u_int16_t flowsetLen;
  u_int16_t templateId;
  u_int16_t optionScopeLen;
  u_int16_t optionLen;
} V9OptionTemplate;

typedef struct flow_ver9_flow_set {
  u_int16_t templateId;
  u_int16_t flowsetLen;
} V9FlowSet;

typedef struct flow_set {
  u_int16_t templateId;
  u_int16_t fieldCount;
} FlowSet;

typedef struct flowSetV9Ipfix {
  V9IpfixSimpleTemplate templateInfo;
  u_int16_t flowLen; /* Real flow length */
  V9V10TemplateField *fields;
  struct flowSetV9Ipfix *next;
} FlowSetV9Ipfix;

#define STANDARD_ENTERPRISE_ID                0
#define NTOP_ENTERPRISE_ID           0x00008B30 /* IANA assignment for ntop */

typedef enum {
  ascii_format = 0,
  hex_format,
  numeric_format,
  ipv6_address_format
} ElementFormat;

typedef enum {
  /*
    NOTE

    whenever this datastructure is updated
    you ought to also update
    dumpformat2ascii and printMetadata (plugin.c)
  */
  dump_as_uint = 0, /* 1234567890 */
  dump_as_formatted_uint, /* 123'456 */
  dump_as_ip_port,
  dump_as_ip_proto,
  dump_as_ipv4_address,
  dump_as_ipv6_address,
  dump_as_mac_address,
  dump_as_epoch,
  dump_as_bool,
  dump_as_tcp_flags,
  dump_as_hex,
  dump_as_ascii
} ElementDumpFormat;

#define FLOW_TEMPLATE       0
#define OPTION_TEMPLATE     1

#define SHORT_SNAPLEN       0
#define LONG_SNAPLEN        1

#define STATIC_FIELD_LEN    1
#define VARIABLE_FIELD_LEN  2

#define BOTH_IPV4_IPV6      1
#define ONLY_IPV4           2
#define ONLY_IPV6           3

typedef struct flow_ver9_ipfix_template_elementids {
  u_int8_t isInUse; /* 1=used by the template, 0=not in use */
  u_int8_t protoMode; /* BOTH_IPV4_IPV6, ONLY_IPV4, ONLY_IPV6 */
  const u_int8_t  isOptionTemplate; /* 0=flow template, 1=option template */
  const u_int8_t  useLongSnaplen;
  const u_int32_t templateElementEnterpriseId;
  const u_int16_t templateElementId;
  u_int8_t variableFieldLength; /* This is not a const as it can be set */
  u_int16_t templateElementLen; /* This is not a const as it can be set */
  const ElementFormat elementFormat; /* Only for elements longer than 4 bytes */
  const ElementDumpFormat fileDumpFormat; /* Hint when data has to be printed on
					     a human readable form */
  const char *netflowElementName, *ipfixElementName, *templateElementDescr;
} V9V10TemplateElementId;

/* ******************************************* */

/*
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |       Version Number          |            Length             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                           Export Time                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                       Sequence Number                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Observation Domain ID                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

typedef struct flow_ipfix_hdr {
  u_int16_t version;             /* Current version = 10 */
  u_int16_t len;                 /* The length of the IPFIX PDU */
  u_int32_t sysUptime;           /* Current time in msecs since router booted */
  u_int32_t flow_sequence;       /* Sequence number of total flows seen */
  u_int32_t observationDomainId; /* Source id */
} IPFIXFlowHeader;

typedef struct flow_ipfix_set {
  u_int16_t set_id, set_len;
} IPFIXSet;

typedef struct flow_ipfix_field {
  u_int16_t field_id, field_len;
  u_int32_t enterprise_number;
} IPFIXField;

/* Bitmask */
typedef struct {
  u_int32_t num_bits;
  void *bits_memory;
} bitmask_selector;

/* ******************************************* */

#define NETFLOW_MAX_BUFFER_LEN    1440
#define MAX_EXPORT_QUEUE_LEN    512000

#define ACT_NUM_PCAP_THREADS      2
#define MAX_NUM_PCAP_THREADS     32

#define DEFAULT_INPUT_INTERFACE_INDEX  0 /* NO_INTERFACE_INDEX */
#define DEFAULT_OUTPUT_INTERFACE_INDEX 0 /* NO_INTERFACE_INDEX */

typedef unsigned long long ticks;

/* It must stay here as it needs the definition of v9 types */
#include "engine.h"
#include "util.h"

#ifdef HAVE_PF_RING
#include "pro/pf_ring.h"
#define CHECKSUM
#endif

/* ************************************ */

#define MAX_PAYLOAD_LEN         1400
#define MAX_HASH_MUTEXES         128 /* Must be a power of 2 */

/* ************************************ */

struct mypcap {
  int fd, snapshot, linktype, tzoff, offset;
  FILE *rfile;

  /* Other fields have been skipped. Please refer
     to pcap-int.h for the full datatype.
  */
};

/* ******** ANY (Linux) ************ */

#ifndef DLT_ANY
#define DLT_ANY 113
#endif

typedef struct anyHeader {
  u_int16_t  pktType;
  u_int16_t  llcAddressType;
  u_int16_t  llcAddressLen;
  u_int8_t   ethAddress[6];
  u_int16_t  pad;
  u_int16_t  protoType;
} AnyHeader;

/* ************************************ */

#define DUMP_TIMEOUT             30 /* seconds */
#define DEFAULT_LIFETIME_TIMEOUT 4*DUMP_TIMEOUT

/* #define DEBUG  */

#define MIN_HASH_SIZE         512 /* buckets */
#define DEFAULT_HASH_SIZE  131072 /* buckets */

/* *************************** */

/* version.c */
extern char *version, *osName;
extern unsigned int compile_time;
extern unsigned int svn_release;

/* **************************************************************** */

struct ip_header {
#if BYTE_ORDER == LITTLE_ENDIAN
  uint	ihl:4,		/* header length */
    version:4;			/* version */
#else
  uint	version:4,			/* version */
    ihl:4;		/* header length */
#endif
  u_char	tos;			/* type of service */
  u_short	tot_len;			/* total length */
  u_short	id;			/* identification */
  u_short	frag_off;			/* fragment offset field */
  u_char	ttl;			/* time to live */
  u_char	protocol;			/* protocol */
  u_short	check;			/* checksum */
  u_int32_t saddr, daddr;	/* source and dest address */
};

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udp_header {
  u_short	source;		/* source port */
  u_short	dest;		/* destination port */
  u_short	len;		/* udp length */
  u_short	check;		/* udp checksum */
};

/* ************************************* */

#define MAX_NUM_COLLECTORS            8
#define MAX_NUM_COLLECTOR_THREADS  MAX_NUM_PCAP_THREADS
#define MAX_NUM_OPTIONS             128
#define DISPLAY_TIME                 30
#define DEFAULT_TEMPLATE_ID         257
#define NUM_MAC_INTERFACES            8
#define TCP_PROTOCOL               0x06
#define NUM_FRAGMENT_LISTS         4096
#define MAX_NUM_FRAGMENT_PER_LIST    32
#define GTP_DATA_PORT              2152
#define GTP_CONTROL_PORT           2123
#define GTPV0_PORT                 3386
#define L2TP_DATA_PORT             1701
#define MOBILE_IP_PORT              434

#ifdef WIN32
typedef float Counter;
#else
typedef unsigned long long Counter;
#endif

/* ********************************************* */

/* Least recently used cache */

struct LruCacheNumEntry {
  u_int64_t key;
  u_int32_t value;
};

struct LruCacheStrEntry {
  char *key, *value;
  time_t expire_time;
};

struct LruCacheEntry {
  u_int8_t numeric_node;

  union {
    struct LruCacheNumEntry num; /* numeric_node == 1 */
    struct LruCacheStrEntry str; /* numeric_node == 0 */
  } u;

  struct LruCacheEntry *next; /* Hash collision list */
};

struct LruCache {
  pthread_rwlock_t lruLock;
  u_int32_t max_cache_node_len, hash_size, mem_size;
  u_int32_t num_cache_add, num_cache_find, num_cache_misses;
  u_int32_t last_num_cache_add, last_num_cache_find, last_num_cache_misses;
  u_int32_t *current_hash_size; /* Allocated dynamically */
  struct LruCacheEntry **hash;   /* Allocated dynamically */
};

/* ********************************************* */

struct mac_export_if {
  u_char mac_address[6];
  u_int16_t interface_id;
};

struct fileList {
  char *path;
  struct fileList *next;
};

typedef struct {
  u_int32_t network, netmask, broadcast, netmask_v6;
  u_int16_t interface_id;
} NetworkInfo;

typedef enum {
  vlan_disabled = 0,
  inner_vlan,
  outer_vlan,
  single_vlan,
  double_vlan
} vlan_iface_mode;

#define V4_TEMPLATE_INDEX     0
#define V6_TEMPLATE_INDEX     1

#define MAX_NUM_TEMPLATES   2 /* v4 + v6 */ + MAX_NUM_PLUGINS

typedef struct {
  V9V10TemplateElementId *v9TemplateElementList[TEMPLATE_LIST_LEN];
  char templateBuffer[NETFLOW_MAX_BUFFER_LEN];
  u_int templateBufBegin, templateBufMax;
  int numTemplateFieldElements;
  char *buffer;
  u_int32_t bufferLen;
  PluginEntryPoint *templatePlugin; /*
				       Pointer to the plugin (if any) that handles
				       fields not part of the base nProbe
				    */
} TemplateBufferInfo;

typedef struct asList {
  u_int32_t asn;
  struct asList *next;
} ASlist;

typedef struct netList {
  u_int32_t net;
  u_int32_t mask;
  struct netList *next;
} NetList;

#define MAX_NUM_REDIS_CONNECTIONS        4
#define DEFAULT_LRU_CACHE_SIZE       16384
#define MAX_LRU_CACHE_SIZE          128000
typedef struct {
#ifdef WIN32
  char base_installation_path[MAX_PATH];
#else
  u_char becomeDaemon;
#endif

  /* Expanded copy of CLI arguments */
  int argc;
  char **argv;

  u_int pktSampleRate, flowSampleRate, capture_num_packet_and_quit, fakePktSampling;
  u_int8_t setAllNonLocalHostsToZero, setLocalTrafficDirection,
    none_specified, promisc_mode, tunnel_mode, smart_udp_frags_mode,
    enableGeoIP, enableExtBucket;

  /* Plugins */
  u_int    nfLitePluginLowPort, nfLitePluginNumPorts, logPluginLowPort, logPluginNumPorts;
  u_int8_t disableFlowCache;

  char *unprivilegedUser;
  u_int8_t db_initialized, skip_db_creation, computeTrafficThroughput, needHashLock;
  u_int16_t ipsec_auth_data_len;
  u_int maxNumActiveFlows;
  u_int idTemplate;
  char *dump_stats_path;

  struct {
    int collectorInPort;
    u_int sampleRate;
    u_int8_t keepProbesUnmerged;
    NetList *prefix_list, *not_prefix_list;
    ASlist *as_list, *not_as_list;
  } flowCollection;

#ifdef linux
  char *cpuAffinity; /* NULL means no affinity */
#endif
  struct timeval initialSniffTime;
  u_int16_t flowExportDelay;
  /* -B support courtesy of Mark Notarus <notarus@uiuc.edu> */
  u_short packetFlowGroup; /* # packets to send before we delay */
#ifndef WIN32
  char nprobeId[255+1];
#endif
  struct fileList *pcapFileList;
  char *pcapFile, *flowLockFile, *pidPath;
  u_char ignoreVlan, ignoreProtocol, ignoreIP, handle_l2,
    ignorePorts, ignoreTos, usePortsForICMP, disableIPv6,
    mapUserTraffic;
  u_char reflectorMode, calculateJitter, handleFragments;
  pcap_t *pcapPtr;
#ifdef HAVE_NETFILTER
  struct {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int queueId, fd;
    unsigned long thread_id;
  } nf;
#endif
#ifdef HAVE_PF_RING
  int cluster_id;
#endif
  int datalink;
  char *captureDev, *netFilter, *flowDumpFormat;
  char *addr, *port;
  char *bindAddr, *bindPort;
  u_int8_t enableIxiaTimestamp:1;
  u_int16_t inputInterfaceIndex, outputInterfaceIndex, snaplen;
  char *dirPath;
  time_t flowFd_close_time;
  u_char useNetFlow, dontSentBidirectionalV9Flows, do_not_drop_privileges;
  vlan_iface_mode use_vlanId_as_ifId;
  int exportThreadAffinity;
  char *userStringTemplate, *stringTemplateV4, *baseTemplateBufferV4, *stringTemplateV6;
  u_int file_dump_timeout;

  /* MAC Export */
  struct mac_export_if mac_if_match[NUM_MAC_INTERFACES];

  /* Logging */
  char *eventLogPath;

  /* Exec */
  char *execCmdDump;

  /* Export Options */
  u_int8_t netFlowVersion, bidirectionalFlows, aggregateGtpTunnels;
  u_short templatePacketsDelta, minNumFlowsPerPacket, initialPacketBytesToSkip;
  struct sockaddr_in sockIn;
  u_short packetsBeforeSendingTemplates;
  u_int8_t num_v5flows_per_packet, useLocks;
  u_short numProcessThreads, minMTU, maxNetFlowPacketPayloadLen;
  u_int8_t enableHostStats, enableTcpSeqStats, enableLatencyStats, enablePacketStats;

  /* V9 Templates */
  u_short numActiveTemplates;
  TemplateBufferInfo userTemplateBuffer, templateBuffers[MAX_NUM_TEMPLATES];

  u_int minFlowSize;
  /* approximate # of flows that the template takes up */
  u_short templateFlowSize;

  /* V9 Options */
  V9V10TemplateElementId *v9OptionTemplateElementList[TEMPLATE_LIST_LEN];
  char optionTemplateBuffer[NETFLOW_MAX_BUFFER_LEN];
  u_int optionTemplateBufBegin, optionTemplateBufMax, flowHashSize;
  int numOptionTemplateFieldElements;
  /* approximate # of flows that the template takes up */
  u_short optionTemplateFlowSize;

  /* Hosts Hash */
  u_int hostHashSize;

  /* Collectors addresses */
  u_char useIpV6;
  CollectorAddress netFlowDest[MAX_NUM_COLLECTORS];
  u_int8_t numCollectors;
  DumpFormat dumpFormat;
  u_char traceMode;
#ifndef WIN32
  int useSyslog;
#endif
  int traceLevel;
  u_int8_t deferredHostUpdate, roundPacketLenWithIPHeaderLen;
  u_int16_t idleTimeout, sendTimeout;
  u_int32_t lifetimeTimeout;
  u_int8_t engineType, engineId, accountL2Traffic;

  /* Networks mapping */
  u_int32_t numInterfaceNetworks, numLocalNetworks;
  NetworkInfo interfaceNetworks[MAX_NUM_NETWORKS], blacklistNetworks[MAX_NUM_NETWORKS],
    localNetworks[MAX_NUM_NETWORKS];
  u_char hasSrcMacExport, srcMacExport[6];
  u_int32_t numBlacklistNetworks, maxExportQueueLen;
  char *csv_separator;
  pthread_t *packetProcessThread;

  /* Database */
  char *dbEngineType;

  u_int8_t enable_l7_protocol_discovery;
  TimestampFormat ts_format;

  struct {
    u_int proto_size, flow_struct_size;
    struct ndpi_detection_module_struct *l7handler;
    u_int8_t discard_unknown_flows, enable_l7_protocol_guess;
    char *protocolsFilePath;
    char *ndpi_protos;
  } l7;

#ifdef HAVE_GEOIP
  /* GeoIP */
  GeoIP *geo_ip_asn_db, *geo_ip_asn_db_v6;
  GeoIP *geo_ip_city_db, *geo_ip_city_db_v6;
#endif

  /* Protocols bitmask */
  bitmask_selector udpProto, tcpProto;

  /* Plugins */
  u_int32_t enableHttpPlugin:1, enableDnsPlugin:1,
    enableMySQLPlugin:1, enableSipPlugin:1, enableOraclePlugin:1,
    enableGtpPlugin:1, enableL7BridgePlugin:1, enableRadiusPlugin:1,
    enableSmtpPlugin:1, enableImapPlugin:1, enablePopPlugin:1,
    enableDiameterPlugin:1, enableWhoisPlugin:1,
    enableDhcpPlugin:1, enableNfLitePlugin:1,
    enableFtpPlugin:1, enableProcessPlugin:1;
  u_int8_t nestDumpDirs, computeInterfaceIndexes;
  u_int8_t ignore_plugin_revision_mismatch, ipv4_deduplication_enabled;
  u_int32_t l7LruCacheSize, flowUsersCacheSize;
  u_short numDeleteFlowFctn, numPacketFlowFctn, num_plugins;
  PluginEntryPoint *all_plugins[MAX_NUM_PLUGINS+1], *all_active_plugins[MAX_NUM_PLUGINS+1];
  void *pluginDlopenHandle[MAX_NUM_PLUGINS+1];

  /* Collector */
  int collectorInSocketv4, collectorInSocketv6, collectorInSctpSocket;
  pthread_t collectThread[MAX_NUM_COLLECTOR_THREADS];

  /* SSL */
#ifdef HAVE_YASSL
  u_int8_t sslDecodingEnabled;
  u_int8_t sslDebug;
#endif

  /* Status */
  u_int8_t nprobe_up, dequeueBucketToExport_up, num_active_plugins;
  u_int8_t fakePacketCapture, checkMemoryBoundaries, max_packet_ordering_queue;
  u_int32_t maxLogLines;

  /* Performance test */
  u_int8_t tracePerformance;
  pthread_rwlock_t ticksLock;
  ticks decodeTicks, allInclusiveTicks,
    processingWithFlowCreationTicks, processingWoFlowCreationTicks, bucketExportTicks,
    bucketPurgeTicks, bucketAllocationTicks, bucketMallocTicks;
  u_int64_t num_pkts_with_flow_creation, num_pkts_without_flow_creation, num_exported_buckets,
    num_purged_buckets, num_allocated_buckets, num_malloced_buckets;

  unsigned long nprobePid; /* 0 on Windows */
  BiflowsExportPolicy biflowsExportPolicy; /* default: export_all_flows */

  /* Cache */
#ifdef HAVE_REDIS
  struct {
    int local_server_socket;
    char *remote_redis_host, *logging_redis_host;
    u_int16_t remote_redis_port, local_ucloud_port, logging_redis_port;

    struct event_base *base;
    redisContext *read_context, *write_context[MAX_NUM_REDIS_CONNECTIONS], *logging_context[MAX_NUM_REDIS_CONNECTIONS];
    pthread_rwlock_t lock_set_delete[MAX_NUM_REDIS_CONNECTIONS], lock_logging[MAX_NUM_REDIS_CONNECTIONS], lock_get;
    pthread_t reply_loop, local_server_loop;
    u_int8_t queue_thread_running[MAX_NUM_REDIS_CONNECTIONS], local_server_running, use_nutcracker;
  } redis;
#endif

#ifdef HAVE_MYSQL
  struct {
    MYSQL mysql;
    char *table_prefix;
  } db;
#endif

  /* Microcloud */
  u_int8_t ucloud_enabled:1, imsi_aggregation_enabled:1;

  /* Debug/Demo */
  u_int8_t enable_debug, help_mode, demo_mode, demo_expired,
    interpretFlowPackets, reproduceDumpAtRealSpeed,
    reforgeTimestamps, simulateStorage, json_symbolic_labels,
    aggregateTrafficPerIMSI, drop_flow_no_plugin,
    dontExportFlowsDuringProcessing;

  u_int16_t local_timezone;
  pcap_dumper_t *dumpBadPacketsPcap, *pcapDumper;

#ifdef HAVE_ZMQ
  struct {
    u_int8_t daemon;
    char *endpoint;
    void *context;
    void *publisher;
  } zmq;
#endif

  struct {
    u_int8_t tcp_connect;
    int tcp_socket;
    struct sockaddr_in tcp_servaddr;
  } tcpsender;

  u_int8_t computeMos;

  struct {
    int sock, capture_id;
    struct sockaddr_in server;
    char *pwd;
} hep;

#ifdef HAVE_TEMPLATE_EXTENSIONS
  struct {
    u_int8_t use_nf_sender;
    nfsender_t nf_sender;
  } nfsender;
#endif

#ifdef HAVE_PF_RING
  struct {
    pfring *h;
#if 0
    scap_dumper_t* dumper;
    char *dump_file_path, *scap_dump_path;
#endif
    patricia_tree_t *local_interface_addresses;
  } sysdig;
#endif
} ReadOnlyGlobals;

typedef struct {
  Counter pkts, bytes;
  Counter tcpFlows, udpFlows, icmpFlows;
} ProbeStats;

typedef struct selectorsList {
  u_int16_t selectorId, packet_offset;
  u_int32_t samplingPopulation;
  u_int32_t netflow_device_ip;
  struct selectorsList *next;
} SelectorsList;

typedef struct {
  time_t nextFlowProcessTime;
  FlowHashBucket *flowListHead[MAX_NUM_PCAP_THREADS][MAX_HASH_MUTEXES], *flowListTail[MAX_NUM_PCAP_THREADS][MAX_HASH_MUTEXES];
} FlowExpire;

#ifdef HAVE_PF_RING
struct forward_out_devs {
  pfring *ring;
  int deviceId;
};
#endif

#define MAX_NUM_CPUS   64

typedef struct {
  time_t now;
  struct timeval lastExportTime;
  FILE *flowFd, *flowThroughputFd;
  u_int totFlows, totFlowsRate, totFlowsSinceLastExport, queuedDataToExport;
  u_int64_t totExports;
  u_int8_t shutdownInProgress:2, stopPacketCapture:1, nprobeStarted:1;
  u_int32_t flow_serial;
  FlowHashBucket *exportQueue;
  /* Export Options */
  NetFlow5Record theV5Flow;
  V9FlowHeader theV9Header;
  IPFIXFlowHeader theIPFIXHeader;
  int numFlows;
  IpV4Fragment *fragmentsList[NUM_FRAGMENT_LISTS];
  atomic_u_int32_t bucketsAllocated; /* We need to protect it as purgeBucket() decrements it,
					and threads increment it as new buckets are allocated.
					A sparse counter won't help as purgeBucket() asyncronously
					decrements it
				     */

  u_int32_t exportBucketsLen, fragmentListLen[NUM_FRAGMENT_LISTS];
  u_short packetSentCount; /* packets sent before a delay */
  u_char num_src_mac_export;

  /* Flow Sampling */
  u_int flowsToGo;

  /* Packet de-duplication */
  struct {
    u_int32_t last_src, last_dst;
    u_int16_t last_pkt_len, last_checksum, last_ip_ttl, last_ip_id, l4_last_checksum;
    u_int8_t last_proto;
} ipv4_deduplication;

  /* Threads */
  pthread_rwlock_t exportMutex, fragmentMutex[NUM_FRAGMENT_LISTS];
  pthread_rwlock_t rwGlobalsRwLock, exportRwLock, pcapLock, checkExportLock;
  pthread_rwlock_t collectorRwLock, collectorCounterLock;
#ifdef HAVE_GEOIP
  pthread_rwlock_t geoipRwLock;
#endif
  pthread_rwlock_t flowHashRwLock[MAX_NUM_PCAP_THREADS][MAX_HASH_MUTEXES], expireListLock, dumpFileLock;
  ConditionalVariable exportQueueCondvar, termCondvar;
  pthread_t dequeueThread, walkHashThread, statsThread;

  /* Stats */
  time_t lastSample;
  Counter currentPkts[MAX_NUM_PCAP_THREADS], discardedPkts[MAX_NUM_PCAP_THREADS], currentBytes[MAX_NUM_PCAP_THREADS];
  ProbeStats accumulateStats[MAX_NUM_PCAP_THREADS], lastMinStats;

  /* Collector */
  struct {
    u_int32_t num_dissected_flow_packets, num_flows_unknown_template,
      num_flows_processed, num_good_templates_received,
      num_known_templates, num_bad_templates_received;
  } collectionStats;

  /* Probe */
  struct {
    u_int32_t totFlowDropped, totFlowBytesDropped, totFlowPktsDropped, droppedPktsTooManyFlows;
  } probeStats;

  /* Export */
  struct {
    u_int32_t totExportedBytes, totExportedPkts, totExportedFlows,
      totExportedFlowPkts, totExportedFlowBytes, totJSONExports;
  } flowExportStats;

  FlowSetV9Ipfix *v9_ipfix_templates;  /* Linked List */
  SelectorsList *selectors;

#ifdef HAVE_SQLITE
  sqlite3 *sqlite3Handler;
#endif

  u_int sql_row_idx;
  time_t idleTaskNextUpdate[MAX_NUM_PCAP_THREADS];
  FlowHashBucket **theFlowHash[MAX_NUM_PCAP_THREADS];
  ItemsQueue packetQueues[MAX_NUM_PCAP_THREADS]; /* Packets waiting to be processed */

  /* Expire List */
  FlowHashBucket *expireFlowListHead[MAX_NUM_PCAP_THREADS], *expireFlowListTail[MAX_NUM_PCAP_THREADS];
  FlowHashBucket *idleFlowListHead[MAX_NUM_PCAP_THREADS], *idleFlowListTail[MAX_NUM_PCAP_THREADS];

  u_int maxBucketSearch;
  struct timeval actTime;
  char dumpFilePath[512], dumpFileThptPath[512];
  u_int lastMaxBucketSearch, numTerminatedFetchPackets;

  struct {
    u_int32_t lastPktReceivedSec, lastThroughputDump;
    u_int32_t partialPkts, partialBytes;
    pthread_rwlock_t trafficThroughputLock;
  } trafficThroughputStats;

#ifdef linux
  void *protect_mem; /* Debug only */
#endif

#ifndef WIN32
  u_char syslog_opened;
#ifdef HAVE_PF_RING
  u_int8_t ring_enabled;
  pfring *ring, *twin_ring /* used for L7Bridging only */;
  pfring_bundle ring_bundle;
#endif
#endif

#ifdef HAVE_FASTBIT
  time_t next_fastbit_rotation;
  char fastbit_actual_dump_dir[256];
  u_int8_t fastbit_dump_switch[TEMPLATE_LIST_LEN];
#endif

  /* Stats */
  u_long last_ps_recv, last_ps_drop, collectedPkts[MAX_NUM_COLLECTOR_THREADS];
  time_t lastThroughputDump;

#ifdef HAVE_PF_RING
  /* L7 Packet Forward */
  struct forward_out_devs out_devices[2];
#endif

#ifdef HAVE_REDIS
  struct {
    u_int32_t queuedSetDeleteCommands[MAX_NUM_REDIS_CONNECTIONS],
      maxQueuedSetDeleteCommands[MAX_NUM_REDIS_CONNECTIONS],
      queuedLoggingCommands[MAX_NUM_REDIS_CONNECTIONS],
      maxQueuedLoggingCommands[MAX_NUM_REDIS_CONNECTIONS],
      numGetCommands[MAX_NUM_REDIS_CONNECTIONS],
      numSetCommands[MAX_NUM_REDIS_CONNECTIONS],
      numLoggingCommands[MAX_NUM_REDIS_CONNECTIONS],
      numLastGetCommands[MAX_NUM_REDIS_CONNECTIONS],
      numLastSetCommands[MAX_NUM_REDIS_CONNECTIONS],
      numLastLoggingCommands[MAX_NUM_REDIS_CONNECTIONS];
  } redis;
#endif

  /* sFlow sampling */
  u_int32_t *sFlowPoolMap;

  /* LRU Cache for L7 */
  struct LruCache l7Cache;

  /* Flow User's Cache */
  struct LruCache flowUsersCache;
#ifdef HAVE_NETFILTER
  struct {
    u_int32_t nf_verdict, nf_mark;
  } nf;
#endif

#ifdef HAVE_PF_RING
  u_int8_t l7_plugin_fwd_packet_verdict:1;

  struct {
    struct port_inode *currently_open_ports;
    struct tid_pid_exe *tid2pid;
    struct fd_type *fd2type;
    struct fd_pid *active_fd_pid;
    struct port_exe *port_bound_to_exe_udp4, *port_bound_to_exe_tcp4;
    struct port_exe *port_bound_to_exe_udp6, *port_bound_to_exe_tcp6;
    struct uid_name *uid_to_name;
    int       last_fd[MAX_NUM_CPUS], last_socket_domain[MAX_NUM_CPUS],
      last_socket_type[MAX_NUM_CPUS], last_socket_proto[MAX_NUM_CPUS];
    u_int64_t last_ts;
  } sysdig;
#endif
} ReadWriteGlobals;

#include "globals.h"
#include "export.h"

/* ********************************************* */

/* Shortest time for which we check idle task */
#define IDLE_TASK_UPDATE_FREQUENCY  3 /* sec */

/* ********************************************* */

#ifdef WIN32
#define likely(x)       (x)
#define unlikely(x)     (x)
#else
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#endif

/* ********************************************* */

extern void exportBucket(FlowHashBucket *myBucket, u_char free_memory);
extern void close_dump_file(void);

/* nprobe.c */
extern void decodePacket(u_short thread_id,
			 int packet_if_idx /* -1 = unknown */,
			 struct pcap_pkthdr *h, const u_char *p,
			 u_int8_t sampledPacket,
			 u_int8_t direction /* 1=RX, 0=TX */,
			 u_int32_t numPkts,
			 int input_index, int output_index,
			 u_int32_t flow_sender_ip,
			 u_int32_t packet_hash);
extern void recycleBucket(FlowHashBucket *myBucket);
extern void shutdown_nprobe(void);
extern void initL7Discovery(void);

/* database.c */
extern int exec_sql_query(char *sql, u_char dump_error_if_any);
extern char* get_last_db_error(void);
extern int init_database(char *db_host, u_int db_port,
			 char* user, char *pw,
			 char *db_name, char *tp);
extern int init_db_table(void);
extern void dump_flow2db(V9V10TemplateElementId **template_name, char *buffer, u_int32_t buffer_len);
extern char* get_db_table_prefix(void);

/* Win32 */
extern void revertSlash(char *str, int mode);

/* engine.c */
extern void allocateFlowHash(int idx);
extern void allocateHostHash(void);
extern void tellProbeToExportFlow(u_int32_t thread_id, FlowHashBucket *myBucket);
extern FlowHashBucket* getHashBucket(u_int32_t packet_hash, u_short thread_id);
extern void idleThreadTask(u_int8_t thread_id, u_int8_t context_type);
extern void oomTask(u_int8_t thread_id);
extern void freenDPI(FlowHashBucket *myBucket);

#ifdef HAVE_GEOIP
extern void geoLocate(IpAddress *addr, HostInfo *bkt);
#endif
extern void timeval_diff(struct timeval *begin, struct timeval *end,
			 struct timeval *result, u_short divide_by_two);

/* collect.c */
extern int createNetFlowListener(u_short collectorInPort);
extern void closeNetFlowListener(void);
extern void dissectNetFlow(u_int32_t netflow_device_ip, char *buffer, int bufferLen);

/* sflow_collect.c */
extern void dissectSflow(u_char *buffer, u_int buffer_len, struct sockaddr_in *fromHost);

/* util.c */
typedef u_int32_t (*ip_to_AS)(IpAddress ip);
extern void setIp2AS(ip_to_AS ptr);
typedef void (*fillASinfo)(FlowHashBucket *bkt);
extern void setFillASInfo(fillASinfo ptr);
extern void fillASInfo(FlowHashBucket *bkt);
extern u_int32_t getAS(IpAddress *addr, HostInfo *bkt);
extern void setThreadAffinity(u_int core_id);
extern u_short getNumCores(void);
extern char *getProtoName(u_short protoId);
extern char* port2name(u_int16_t port, u_int8_t proto);
extern u_int16_t getServerPort(FlowHashBucket *theFlow);
#ifdef HAVE_PF_RING
extern int forwardPacket(int rx_device_id, char *p, int p_len);
#endif

/* cache.c */
extern void logCacheKeyValueString(const char *prefix, u_int16_t id, const char *value);
extern void queueCacheKeyValueString(const char *prefix, u_int16_t id, const char *queue_name, const char *value);
extern void setCacheKeyValueString(const char *prefix, u_int16_t id, const char *key, const char *value);
extern void publishKeyValueString(const char *prefix, u_int16_t id, const char *key, const char *value);
extern void setCacheKeyValueNumber(const char *prefix, u_int16_t id, const char *key, const u_int64_t value);
extern void setCacheKeyValueNumberNumber(const char *prefix, u_int16_t id, const u_int32_t key, const u_int32_t value);
extern void setCacheKeyValueNumberString(const char *prefix, u_int16_t id, const u_int32_t key, const char *value);
extern void incrCacheKeyValueNumber(const char *prefix, u_int16_t id, const char *key, u_int64_t value);
extern void incrHashCacheKeyValueNumber(const char *element, u_int16_t id, const char *key, u_int64_t value);
extern void expireCacheKey(const char *prefix, u_int16_t id, const char *key, u_int32_t duration_sec);
extern void setCacheHashKeyValueString(const char *element, u_int16_t id, const char *key, const char *value);
extern void setCacheHashKeyValueNumber(const char *element, u_int16_t id, const char *key, const u_int64_t value);
extern void incrCacheHashKeyValueNumber(const char *element,
					u_int16_t id, const char *key, const u_int64_t value);
extern void setCacheNumKeyMixedValueDual(const char *prefix, u_int16_t id,
					 const u_int32_t key0, const char* value0,
					 const u_int32_t key1, const char* value1);
extern void setCacheHashNumKeyMixedValueDual(const char *master_key, u_int16_t id,
					     const u_int32_t key0, const char* value0,
					     const u_int32_t key1, const char* value1);
extern void zIncrCacheHashKeyValueNumber(const char *set_name, u_int16_t id, const char *key, const u_int64_t value);
extern void setCacheNumKeyNumValueQuad(const u_int32_t key0, const u_int32_t value0,
				       const u_int32_t key1, const u_int32_t value1,
				       const u_int32_t key2, const u_int32_t value2,
				       const u_int32_t key3, const u_int32_t value3);
extern void setCacheNumKeyMixedValueQuad(const char *prefix, u_int16_t id,
					 const u_int32_t key0, const char* value0,
					 const u_int32_t key1, const char* value1,
					 const u_int32_t key2, const u_int32_t value2,
					 const u_int32_t key3, const u_int32_t value3);
extern void setCacheHashNumKeyMixedValueQuad(const char *master_key, u_int16_t id,
					     const u_int32_t key0, const char* value0,
					     const u_int32_t key1, const char* value1,
					     const u_int32_t key2, const u_int32_t value2,
					     const u_int32_t key3, const u_int32_t value3);
extern void incrCacheHashKeyValueNumber(const char *element, u_int16_t id, const char *key, const u_int64_t value);
extern char* getCacheDataNumKey(const char *prefix, u_int16_t id, const u_int32_t key);
extern void getCacheDataNumKeyTwin(const char *prefix, u_int16_t id, const u_int32_t key1, const u_int32_t key2, char **rsp1, char **rsp2);
extern char* getCacheDataStrKey(const char *prefix, u_int16_t id, const char *key);
extern void getCacheDataStrKeyTwin(const char *prefix, u_int16_t id, const char *key1, const char *key2, char **rsp1, char **rsp2);
extern char* getHashCacheDataStrKey(const char *prefix, u_int16_t id, const char *element, const char *key);
extern int deleteCacheStrKey(const char *prefix, u_int16_t id, const char *key, const u_int32_t delete_delay_sec);
extern int deleteCacheNumKey(const char *prefix, u_int16_t id, const u_int32_t key, const u_int32_t delete_delay_sec);
extern int deleteCacheNumKeyTwin(const char *prefix, u_int16_t id, const u_int32_t key1, const u_int32_t key2);
extern int deleteCacheStrKeyTwin(const char *prefix, u_int16_t id, const char *key1, const char *key2);
extern int connectToRemoteCache(void);
extern void disconnectFromRemoteCache(void);
extern int createLocalCacheServer();
extern void pingRedisConnections();
extern void dumpCacheStats(u_int timeDifference);
extern void dumpLruCacheStats(u_int timeDifference);

extern int init_lru_cache(struct LruCache *cache, u_int32_t max_size);
extern void free_lru_cache(struct LruCache *cache);
extern int add_to_lru_cache_num(struct LruCache *cache, u_int64_t key, u_int32_t value);
extern int add_to_lru_cache_str(struct LruCache *cache, char *key, char *value);
extern char* find_lru_cache_str(struct LruCache *cache, char *key);
extern int add_to_lru_cache_str_timeout(struct LruCache *cache, char *key, char *value, u_int32_t timeout);
extern u_int32_t find_lru_cache_num(struct LruCache *cache, u_int64_t key);
extern void test_lru_cache(struct LruCache *cache);

/* template.c */
extern void printTemplateInfo(V9V10TemplateElementId *templates,
			      u_char show_private_elements);
extern char* getStandardFieldId(u_int id);
extern void fixTemplatesToIPFIX(void);
extern void checkTemplates(void);
extern void sanitizeV4Template(char *str);
extern void v4toV6Template(char *str);
extern PluginEntryPoint* compileTemplate(char **_fmt, V9V10TemplateElementId **templateList,
					 int templateElements, u_int8_t isOptionTemplate,
					 u_int8_t isIPv6OnlyTemplate);
extern void copyVariableLenString(V9V10TemplateElementId *theTemplateElement,
				  char *name, char *outBuffer,
				  u_int *outBufferBegin, u_int *outBufferMax);
extern void flowPrintf(V9V10TemplateElementId **templateList,
		       PluginEntryPoint *pluginEntryPoint,
		       u_int8_t ipv4_template, char *outBuffer,
		       uint *outBufferBegin, uint *outBufferMax,
		       int *numElements, char buildTemplate,
		       FlowHashBucket *theFlow, FlowDirection direction,
		       int addTypeLen, int optionTemplate,
		       u_int8_t json_mode);

#ifdef WIN32
extern char* nprobe_strdup(const char *str);
extern int nprobe_inet_pton(int af, const char *src, void *dst);

#define strdup(a)       nprobe_strdup(a) /* _strdup(a) */
#define stricmp(a,b)    _stricmp(a,b)
#define snprintf	_snprintf
#define inet_pton(a, b, c) nprobe_inet_pton(a, b, c)

#endif

#endif /* _NPROBE_H_ */


/* Don't move this #define above */
#define DUMMY_SYSTEM_ID "1234567890"

