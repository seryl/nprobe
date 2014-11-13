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


/* ********************** */

#define MAX_NUM_NETWORKS                   128
#define CONST_INVALIDNETMASK                -1

/* ********************************************** */

#ifdef linux
#include <sys/time.h>
#endif

#define MAX_VARLEN_STR_LEN    4096 /* Headers might be long */
#define MAX_VARLEN_QUEUE        10  /* Number of elements */

typedef struct {
  char *str;
  u_int32_t str_len, seq_id;
} varlen_string_elem;

typedef struct {
  char *str;
  u_int32_t str_len;

  /* Sequence reordering */
  varlen_string_elem partial[MAX_VARLEN_QUEUE];
} varlen_string;

struct rfc822_info {
  varlen_string from, to, cc, subject, message_id, reply_to;
  varlen_string email_header;
  u_int8_t begin_data_cmd, email_header_processed, email_header_full;
};

typedef struct {
  u_int8_t packet_ready, rx_direction;
  u_int32_t packet_hash;
  struct pcap_pkthdr h;
  u_char *p;
  int packet_if_idx /* -1 = unknown */;
} QueuedPacket;

#define DEFAULT_QUEUE_CAPACITY  1024

typedef struct {
  u_int16_t insert_idx, remove_idx;
  u_int32_t num_insert, num_remove;
  ConditionalVariable dequeue_condvar;
  void *queueSlots;
} ItemsQueue;

typedef struct {
  u_int32_t value;
#ifndef HAVE_BUILTIN_ATOMIC
  pthread_rwlock_t lock;
#endif
} atomic_u_int32_t;

void freeRfc822Info(struct rfc822_info *info);
void processEmailHeader(struct rfc822_info *info);
void dumpRfc822Info(struct rfc822_info *info);

#ifdef WIN32
#define nprobe_sleep(a /* sec */) { waitForNextEvent(1000*a /* ms */); }
extern unsigned long waitForNextEvent(unsigned long ulDelay /* ms */);
extern void initWinsock32();
extern short isWinNT();
#define close(fd) closesocket(fd)
#else
int nprobe_sleep(int secs);
#endif

extern void traceEvent(const int eventTraceLevel, const char* file, const int line, const char * format, ...);
extern void daemonize(void);
/*
#ifndef WIN32
extern int snprintf(char *string, size_t maxlen, const char *format, ...);
#endif
*/
extern u_int8_t ip2mask(IpAddress *addr, HostInfo *ip);
extern void readASs(char *path);
extern void readCities(char *path);
extern V9V10TemplateElementId ver9_templates[];
extern void printTemplateInfo(V9V10TemplateElementId *templates, u_char show_private_elements);
extern void dumpPluginHelp(void);
extern void dumpPluginFamilies(void);
extern void dumpPluginStats(u_int timeDifference);
extern void dumpPluginTemplates(void);
extern void enablePlugins(void);
extern void setupPlugins(void);
extern void initAS(void);
extern void flowFilePrintf(V9V10TemplateElementId **templateList, 
			   PluginEntryPoint *pluginEntryPoint,
			   FILE *stream, FlowHashBucket *theFlow, 
			   FlowDirection direction);
extern void flowBufferPrintf(V9V10TemplateElementId **templateList,
			     PluginEntryPoint *pluginEntryPoint,
			     FlowHashBucket *theFlow, 
			     FlowDirection direction,
			     char *line_buffer, 
			     u_int line_buffer_len,
			     u_int8_t json_mode);
extern void sanitizeV4Template(char *str);
extern double toMs(struct timeval *t);
extern u_int32_t msTimeDiff(struct timeval *end, struct timeval *begin);
extern float timevalDiff(struct timeval *end, struct timeval *begin);
extern unsigned int ntop_sleep(unsigned int secs);
extern FlowHashBucket* getListHead(FlowHashBucket **list);
extern void addToList(FlowHashBucket *bkt, FlowHashBucket **list);
extern void parseInterfaceAddressLists(char* _addresses);
extern void parseLocalAddressLists(char* _addresses);
extern unsigned short isLocalAddress(struct in_addr *addr);
extern u_int32_t str2addr(char *address);
extern char* etheraddr_string(const u_char *ep, char *buf);
extern void fixTemplateToIPFIX(void);
extern char* getStandardFieldId(u_int id);
extern u_int16_t ifIdx(FlowHashBucket *theFlow, int computeInputIfIdx);
extern u_int32_t _getAS(IpAddress *addr, HostInfo *bkt);
extern void bitmask_set(u_int32_t n, bitmask_selector* p);
extern void bitmask_clr(u_int32_t n, bitmask_selector* p);
extern u_int8_t bitmask_isset(u_int32_t n, bitmask_selector* p);

extern void loadApplProtocols(void);
extern u_int16_t port2ApplProtocol(u_int8_t proto, u_int16_t port);

extern void copyInt8(u_int8_t t8, char *outBuffer, uint *outBufferBegin, uint *outBufferMax);
extern void copyInt16(u_int16_t _t16, char *outBuffer, uint *outBufferBegin, uint *outBufferMax);
extern void copyInt32(u_int32_t _t32, char *outBuffer, uint *outBufferBegin, uint *outBufferMax);
extern void copyInt64(u_int64_t _t64, char *outBuffer, uint *outBufferBegin, uint *outBufferMax);
extern void copyLen(u_char *str, int strLen, char *outBuffer, uint *outBufferBegin, uint *outBufferMax);


extern u_int64_t _htonll(u_int64_t v);
extern u_int64_t _ntohll(u_int64_t v);

extern int32_t gmt2local(time_t t);
extern void decrementLastPacket(FlowHashBucket *bkt, FlowDirection flow_direction, u_int len);
extern void resetBucketStats(FlowHashBucket* bkt,
			     const struct pcap_pkthdr *h, 
			     u_char *p,
			     u_int len, u_int ip_offset, FlowDirection direction,
			     u_char *payload, int payloadLen);
extern void maximize_socket_buffer(int sock_fd, int buf_type);
extern u_int16_t getFlowApplProtocol(FlowHashBucket *theFlow);

/* bitmask */
extern void reset_bitmask(bitmask_selector *selector);
extern int alloc_bitmask(u_int32_t tot_bits, bitmask_selector *selector);
extern void free_bitmask(bitmask_selector *selector);

/* nprobe.c */
extern void parseBlacklistNetworks(char* _addresses);
extern u_short isBlacklistedAddress(struct in_addr *addr) ;

#ifndef min
#define min(a, b) ((a > b) ? b : a)
#endif

#ifndef max
#define max(a, b) ((a > b) ? a : b)
#endif

#ifdef linux
extern void setCpuAffinity(char *dev_name, char *cpuId);
#endif

extern int mkdir_p(char *path);
extern void dropPrivileges(void);
extern void dumpLogEvent(LogEventType event_type, LogEventSeverity severity, char *message);
extern char* CollectorAddress2Str(CollectorAddress *collector, char *buf, u_int buf_len);
extern u_int64_t to_msec(struct timeval *tv);
extern char *getDummySystemId(void);

extern char* getSystemId(void);
extern struct timeval* min_nonzero_timeval(struct timeval *a, struct timeval *b);
extern struct timeval* max_timeval(struct timeval *a, struct timeval *b);
extern char* format_tv(struct timeval *a, char *buf, u_int buf_len);
extern char* compactEmailList(char *l);
extern char* formatFileTimestamp(time_t epoch, char *buf, u_int buf_len);
extern char* flowDirection2char(FlowDirection direction);
#ifdef HAVE_ZMQ
extern int initZMQ();
extern void sendZMQ(char *str, u_int8_t is_event);
#endif
extern char* detab(char *str);
extern float timeval2ms(struct timeval *tv);

extern u_short getNumCores(void);
extern char *getProtoName(u_short protoId);
#ifdef HAVE_PF_RING
extern int forwardPacket(int rx_device_id, char *p, int p_len);
#endif
extern void freeVarLenStr(varlen_string *str);
extern void appendString(varlen_string *str, u_int32_t seq_id, 
			 char *to_add, u_int to_add_len, u_int8_t zap_chars,
			 u_int8_t zap_trailing_carriage_return);
extern void appendRawString(varlen_string *str, u_int32_t seq_id, char *to_add,
			    u_int to_add_len, u_int8_t zap_chars);
extern int isStringFull(varlen_string *str);
extern int isStringEmpty(varlen_string *str);
extern char* varlen2str(varlen_string *str);
extern void flushVarlenString(varlen_string *str);
extern void removeDoubleSpaces(char *str);

#ifndef HAVE_STRNSTR
extern char* strnstr(const char *s, const char *find, size_t slen);
#endif

extern void initQueue(ItemsQueue *q);
extern void deleteQueue(ItemsQueue *q);

/* ****************************************************** */

#ifdef WIN32
static ticks getticks(void) {
  struct timeval tv;
  gettimeofday (&tv, 0);

  return (((ticks)tv.tv_usec) + (((ticks)tv.tv_sec) * 1000000LL));
}

#else
static __inline__ ticks getticks(void) {
#if defined(__i386__)
  ticks x;

  __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
  return x;
#elif defined(__x86_64__)
  u_int32_t a, d;

  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return (((ticks)a) | (((ticks)d) << 32));

  /*
    __asm __volatile("rdtsc" : "=A" (x));
    return (x);
  */
#else
  struct timeval tv;
  gettimeofday (&tv, 0);

  return (((ticks)tv.tv_usec) + (((ticks)tv.tv_sec) * 1000000LL));
#endif
}
#endif

/* ****************************************************** */

//#define PROFILING

#if defined(PROFILING) && defined(linux)
#define PROFILING_DECLARE(n) ticks __profiling_section_start[n]; char *__profiling_section_label[n]; ticks __profiling_section_tot[n]; u_int64_t __profiling_section_times[n]
#define PROFILING_INIT() memset(__profiling_section_label, 0, sizeof(__profiling_section_label)); memset(__profiling_section_tot, 0, sizeof(__profiling_section_tot)); memset(__profiling_section_times, 0, sizeof(__profiling_section_times))
#define PROFILING_SECTION_ENTER(l, i) __profiling_section_start[i] = getticks(), __profiling_section_label[i] = l
#define PROFILING_SECTION_EXIT(i)  __profiling_section_tot[i] += getticks() - __profiling_section_start[i], __profiling_section_times[i]++
#define PROFILING_SECTION_VAL(i)   __profiling_section_tot[i]
#define PROFILING_SECTION_AVG(i)   (__profiling_section_tot[i] / __profiling_section_times[i])
#define PROFILING_SECTION_CNT(i)   __profiling_section_times[i]
#define PROFILING_SECTION_LABEL(i) __profiling_section_label[i]
#else
#define PROFILING_DECLARE(n)
#define PROFILING_INIT()
#define PROFILING_SECTION_ENTER(l, i)
#define PROFILING_SECTION_EXIT(i)
#define PROFILING_SECTION_VAL(i)
#define PROFILING_SECTION_AVG(i)
#define PROFILING_SECTION_CNT(i)
#define PROFILING_SECTION_LABEL(i)
#endif

/* ****************************************************** */

extern void      initAtomic(atomic_u_int32_t *a);
extern u_int32_t incAtomic(atomic_u_int32_t *a, u_int32_t value);
extern u_int32_t decAtomic(atomic_u_int32_t *a, u_int32_t value);
extern u_int32_t getAtomic(atomic_u_int32_t *a);

/* ****************************************************** */

extern int execute_command(char *command_path, char *path);
extern void dump_bad_packet(const struct pcap_pkthdr *h, const u_char *p);
extern int bindthread2core(pthread_t thread_id, int core_id);
extern int formatTimestamp(struct timeval *tv, char *buf, u_int buf_len);
extern char* escapeQuotes(char *in, char *out, u_int out_len);

/* ****************************************************** */
