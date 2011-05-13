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

#include "nprobe.h"

#ifdef sun
extern char *strtok_r(char *, const char *, char **);
#endif

#ifdef WIN32
#define strtok_r(a, b, c) strtok(a, b)
#endif

#ifdef HAVE_SQLITE
extern void sqlite_exec_sql(char* sql);
#endif

static u_int8_t getIfIdx(struct in_addr *addr, u_int16_t *interface_id);

/* ********************** */

static char *port_mapping[0xFFFF] = { NULL };
static char *proto_mapping[0xFF] = { NULL };

/* ********************** */

#define CUSTOM_FIELD_LEN  16

/* ************************************ */

void traceEvent(const int eventTraceLevel, const char* file,
		const int line, const char * format, ...) {
  va_list va_ap;

  if(eventTraceLevel <= readOnlyGlobals.traceLevel) {
    char buf[2048], out_buf[640];
    char theDate[32], *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    /* We have two paths - one if we're logging, one if we aren't
     *   Note that the no-log case is those systems which don't support it (WIN32),
     *                                those without the headers !defined(USE_SYSLOG)
     *                                those where it's parametrically off...
     */

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime(&theTime));

    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    if(eventTraceLevel == 0 /* TRACE_ERROR */)
      extra_msg = "ERROR: ";
    else if(eventTraceLevel == 1 /* TRACE_WARNING */)
      extra_msg = "WARNING: ";

    while(buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

    snprintf(out_buf, sizeof(out_buf), "%s [%s:%d] %s%s", theDate,
#ifdef WIN32
	     strrchr(file, '\\')+1,
#else
	     file,
#endif
	     line, extra_msg, buf);

#ifndef WIN32
    if(readOnlyGlobals.useSyslog) {
      if(!readWriteGlobals->syslog_opened) {
	openlog(readOnlyGlobals.nprobeId, LOG_PID, LOG_DAEMON);
	readWriteGlobals->syslog_opened = 1;
      }

      syslog(LOG_INFO, "%s", out_buf);
    } else
      printf("%s\n", out_buf);
#else
    printf("%s\n", out_buf);
#endif
  }

  fflush(stdout);
  va_end(va_ap);
}


/* ************************************ */

#ifdef WIN32
unsigned long waitForNextEvent(unsigned long ulDelay /* ms */) {
  unsigned long ulSlice = 1000L; /* 1 Second */

  while(ulDelay > 0L) {
    if(ulDelay < ulSlice)
      ulSlice = ulDelay;
    Sleep(ulSlice);
    ulDelay -= ulSlice;
  }

  return ulDelay;
}

/* ******************************* */

void initWinsock32() {
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

  wVersionRequested = MAKEWORD(2, 0);
  err = WSAStartup( wVersionRequested, &wsaData );
  if( err != 0 ) {
    /* Tell the user that we could not find a usable */
    /* WinSock DLL.                                  */
    traceEvent(TRACE_ERROR, "FATAL ERROR: unable to initialise Winsock 2.x.");
    exit(-1);
  }
}

/* ******************************** */

short isWinNT() {
  DWORD dwVersion;
  DWORD dwWindowsMajorVersion;

  dwVersion=GetVersion();
  dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
  if(!(dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4))
    return 1;
  else
    return 0;
}

/* ****************************************************** */
/*
  int snprintf(char *string, size_t maxlen, const char *format, ...) {
  int ret=0;
  va_list args;

  va_start(args, format);
  vsprintf(string,format,args);
  va_end(args);
  return ret;
  }
*/
#endif /* Win32 */

/* ******************************************************************* */

u_int8_t ip2mask(IpAddress ip) {
  if((readOnlyGlobals.numInterfaceNetworks == 0) || (ip.ipVersion != 4))
    return(0);
  else {
    int i;
    u_int32_t addr = htonl(ip.ipType.ipv4);

    for(i=0; i<readOnlyGlobals.numInterfaceNetworks; i++) {
      if((addr & readOnlyGlobals.interfaceNetworks[i].netmask) == readOnlyGlobals.interfaceNetworks[i].network) {
	// traceEvent(TRACE_INFO, "--> %d", readOnlyGlobals.interfaceNetworks[i].netmask_v6);
	return(readOnlyGlobals.interfaceNetworks[i].netmask_v6);
      }
    }
  }

  return(0); /* Unknown */
}

/* ******************************************************************* */

static ip_to_AS _ip_to_AS;
static fillASinfo _fillASinfo;

void initAS() {
  _ip_to_AS = NULL;
  _fillASinfo = NULL;
}


void setIp2AS(ip_to_AS ptr) {
  _ip_to_AS = ptr;
}

void setFillASInfo(fillASinfo ptr) {
  _fillASinfo = ptr;
}

void fillASInfo(FlowHashBucket *bkt) {
  if(/* (!readWriteGlobals->shutdownInProgress) && */ _fillASinfo)
    _fillASinfo(bkt);
}

/* ******************************************************************* */

static u_int32_t _ip2AS(IpAddress ip) {

  if((!readWriteGlobals->shutdownInProgress) && (_ip_to_AS != NULL)) {
    return(_ip_to_AS(ip));
  }

#ifdef HAVE_GEOIP
  if((readOnlyGlobals.geo_ip_asn_db == NULL)
#ifdef WIN32
     || (ip.ipVersion == 6)
#endif
     )
    return(0);
  else {
    char *rsp = NULL;
    u_int32_t as;

    pthread_rwlock_wrlock(&readWriteGlobals->geoipRwLock);
    if(ip.ipVersion == 4)
      rsp = GeoIP_name_by_ipnum(readOnlyGlobals.geo_ip_asn_db, ip.ipType.ipv4);
    else {
#ifdef INET6
#ifndef WIN32
      rsp = GeoIP_name_by_ipnum_v6(readOnlyGlobals.geo_ip_asn_db, ip.ipType.ipv6);
#endif
#endif
    }
    pthread_rwlock_unlock(&readWriteGlobals->geoipRwLock);

    as = rsp ? atoi(&rsp[2]) : 0;
    free(rsp);
    /* traceEvent(TRACE_WARNING, "--> %s (%d)", rsp, as); */
    return(as);
  }
#else
  return(0);
#endif
}

/* ************************************* */

u_int32_t _getAS(HostHashBucket *bkt) {
  u_int32_t ret;

  if(bkt->aspath && (bkt->aspath_len > 0)) {
    /* The last element is the host AS, the first one is our AS */
    ret = bkt->aspath[bkt->aspath_len-1];
  } else
    ret = _ip2AS(bkt->host);

  /* traceEvent(TRACE_WARNING, "--> %u", ret);  */

  return(ret);
}

/* ************************************ */

u_int32_t getAS(FlowHashBucket *bkt, u_int8_t src_host) {
  if(src_host)
    return((bkt->src_as != 0) ? bkt->src_as : _getAS(bkt->src));
  else
    return((bkt->dst_as != 0) ? bkt->dst_as : _getAS(bkt->dst));
}

/* ************************************ */

void readASs(char *path) {
#ifdef HAVE_GEOIP
  if(path == NULL)
    return;
  else {
    struct stat stats;
    char the_path[256];

    if(stat(path, &stats) == 0)
      snprintf(the_path, sizeof(the_path), "%s", path);
    else
      snprintf(the_path, sizeof(the_path), "/usr/local/nprobe/%s", path);

    if((readOnlyGlobals.geo_ip_asn_db = GeoIP_open(the_path, GEOIP_CHECK_CACHE)) != NULL) {
      traceEvent(TRACE_NORMAL, "GeoIP: loaded AS config file %s", the_path);
    } else
      traceEvent(TRACE_WARNING, "Unable to load AS file %s. AS support disabled", the_path);
  }
#endif
}

/* ************************************ */

void readCities(char *path) {
#ifdef HAVE_GEOIP
  if(path == NULL)
    return;
  else {
    struct stat stats;
    char the_path[256];

    if(stat(path, &stats) == 0)
      snprintf(the_path, sizeof(the_path), "%s", path);
    else
      snprintf(the_path, sizeof(the_path), "/usr/local/nprobe/%s", path);

    if((readOnlyGlobals.geo_ip_city_db = GeoIP_open(the_path, GEOIP_CHECK_CACHE)) != NULL) {
      traceEvent(TRACE_NORMAL, "GeoIP: loaded cities config file %s", the_path);
    } else
      traceEvent(TRACE_WARNING, "Unable to load cities file %s. IP geolocation disabled", the_path);
  }
#endif
}

/* ********* NetFlow v9/IPFIX ***************************** */

/*
  Cisco Systems NetFlow Services Export Version 9

  http://www.faqs.org/rfcs/rfc3954.html

  See http://www.plixer.com/blog/tag/in_bytes/ for IN/OUT directions
*/

V9V10TemplateElementId ver9_templates[] = {
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   1,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "IN_BYTES", "Incoming flow bytes (src->dst)" },
  { OPTION_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID, 1,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SYSTEM_ID", "" }, /* Hack for options template */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   2,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "IN_PKTS", "Incoming flow packets (src->dst)" },
  { OPTION_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID, 2,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "INTERFACE_ID", "" }, /* Hack for options template */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   3,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "FLOWS", "Number of flows" },
  { OPTION_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID, 3,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "LINE_CARD", "" }, /* Hack for options template */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   4,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "PROTOCOL", "IP protocol byte" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   0xA0+4, STATIC_FIELD_LEN, CUSTOM_FIELD_LEN, numeric_format, dump_as_ip_proto,  "PROTOCOL_MAP", "IP protocol name" },
  { OPTION_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID, 4,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "NETFLOW_CACHE", "" }, /* Hack for options template */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   5,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "SRC_TOS", "Type of service byte" },
  { OPTION_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID, 5,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "TEMPLATE_ID", "" }, /* Hack for options template */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   6,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "TCP_FLAGS", "Cumulative of all flow TCP flags" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   7,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "L4_SRC_PORT", "IPv4 source port" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   0xA0+7, STATIC_FIELD_LEN, CUSTOM_FIELD_LEN, numeric_format, dump_as_ip_port,  "L4_SRC_PORT_MAP", "IPv4 source port symbolic name" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   8,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "IPV4_SRC_ADDR", "IPv4 source address" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   9,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_ipv6_address,  "IPV4_SRC_MASK", "IPv4 source subnet mask (/<bits>)" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   10,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "INPUT_SNMP", "Input interface SNMP idx" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   11,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "L4_DST_PORT", "IPv4 destination port" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   0xA0+11, STATIC_FIELD_LEN, CUSTOM_FIELD_LEN, numeric_format, dump_as_ip_port,  "L4_DST_PORT_MAP", "IPv4 destination port symbolic name" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   12,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "IPV4_DST_ADDR", "IPv4 destination address" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   13,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "IPV4_DST_MASK", "IPv4 dest subnet mask (/<bits>)" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   14,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "OUTPUT_SNMP", "Output interface SNMP idx" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   15,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "IPV4_NEXT_HOP", "IPv4 next hop address" },

  /* In earlier versions AS were 16 bit in 'modern' NetFlow v9 and later, they are 32 bit */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   16,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SRC_AS", "Source BGP AS" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   17,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "DST_AS", "Destination BGP AS" },
  /*
    { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   18,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "BGP_IPV4_NEXT_HOP", "" },
    { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   19,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "MUL_DST_PKTS", "" },
    { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   20,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "MUL_DST_BYTES", "" },
  */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   21,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "LAST_SWITCHED", "SysUptime (msec) of the last flow pkt" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   22,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "FIRST_SWITCHED", "SysUptime (msec) of the first flow pkt" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   23,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "OUT_BYTES", "Outgoing flow bytes (dst->src)" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   24,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "OUT_PKTS", "Outgoing flow packets (dst->src)" },
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   25,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   26,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   27,  STATIC_FIELD_LEN, 16, ipv6_address_format, dump_as_ipv6_address,  "IPV6_SRC_ADDR", "IPv6 source address" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   28,  STATIC_FIELD_LEN, 16, ipv6_address_format, dump_as_ipv6_address,  "IPV6_DST_ADDR", "IPv6 destination address" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   29,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "IPV6_SRC_MASK", "IPv6 source mask" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   30,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "IPV6_DST_MASK", "IPv6 destination mask" },
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   31,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "IPV6_FLOW_LABEL", "" }, */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   32,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "ICMP_TYPE", "ICMP Type * 256 + ICMP code" },
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   33,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "MUL_IGMP_TYPE", "" }, */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   34,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SAMPLING_INTERVAL", "Sampling rate" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   35,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "SAMPLING_ALGORITHM", "Sampling type (deterministic/random)" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   36,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "FLOW_ACTIVE_TIMEOUT", "Activity timeout of flow cache entries" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   37,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "FLOW_INACTIVE_TIMEOUT", "Inactivity timeout of flow cache entries" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   38,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "ENGINE_TYPE", "Flow switching engine" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   39,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "ENGINE_ID", "Id of the flow switching engine" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   40,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "TOTAL_BYTES_EXP", "Total bytes exported" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   41,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "TOTAL_PKTS_EXP", "Total flow packets exported" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   42,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "TOTAL_FLOWS_EXP", "Total number of exported flows" },
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   43,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   44,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   45,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   46,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, i*/
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   47,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   48,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   49,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   50,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   51,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   52,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   53,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   54,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   55,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   56,  STATIC_FIELD_LEN, 6, hex_format, dump_as_mac_address,  "IN_SRC_MAC", "Source MAC Address" }, 
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   58,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "SRC_VLAN", "Source VLAN" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   59,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "DST_VLAN", "Destination VLAN" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   60,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "IP_PROTOCOL_VERSION", "[4=IPv4][6=IPv6]" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   61,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "DIRECTION", "It indicates where a sample has been taken (always 0)" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   62,  STATIC_FIELD_LEN, 16, numeric_format, dump_as_uint,  "IPV6_NEXT_HOP", "IPv6 next hop address" },
  /*
    { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   63,  STATIC_FIELD_LEN, 16, ipv6_address_format, dump_as_uint,  "BPG_IPV6_NEXT_HOP", "" },
    { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   64,  STATIC_FIELD_LEN, 16, ipv6_address_format, dump_as_uint,  "IPV6_OPTION_HEADERS", "" },
  */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   65,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   66,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   67,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   68,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   69,  STATIC_FIELD_LEN, 0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   70,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_1",  "MPLS label at position 1" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   71,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_2",  "MPLS label at position 2" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   72,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_3",  "MPLS label at position 3" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   73,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_4",  "MPLS label at position 4" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   74,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_5",  "MPLS label at position 5" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   75,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_6",  "MPLS label at position 6" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   76,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_7",  "MPLS label at position 7" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   77,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_8",  "MPLS label at position 8" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   78,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_9",  "MPLS label at position 9" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   79,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_10", "MPLS label at position 10" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   80,  STATIC_FIELD_LEN, 6, hex_format, dump_as_mac_address,  "OUT_DST_MAC", "Destination MAC Address" }, /* new */

  /* Fields not yet fully supported (collection only) */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  102,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "PACKET_SECTION_OFFSET", "Packet section offset" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  103,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "SAMPLED_PACKET_SIZE", "Sampled packet size" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  104,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "SAMPLED_PACKET_ID",   "Sampled packet id" },

  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  148, STATIC_FIELD_LEN,  8, numeric_format, dump_as_uint, "FLOW_ID", "Serial Flow Identifier" },

  /* Fields not yet fully supported (collection only) */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  277, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "OBSERVATION_POINT_TYPE",  "Observation point type" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  300, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "OBSERVATION_POINT_ID",  "Observation point id" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  302, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SELECTOR_ID",  "Selector id" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  304, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SAMPLING_ALGORITHM",  "Sampling algorithm" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  309, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SAMPLING_SIZE",  "Number of packets to sample" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  310, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SAMPLING_POPULATION", "Sampling population" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  312, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "FRAME_LENGTH", "Original L2 frame length" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  318, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "PACKETS_OBSERVED", "Tot number of packets seen" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  319, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "PACKETS_SELECTED", "Number of pkts selected for sampling" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,  335, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SELECTOR_NAME", "Sampler name" },

  /*
    ntop Extensions

    IMPORTANT
    if you change/add constants here/below make sure
    you change them into ntop too.
  */

  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+80,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "FRAGMENTS", "Number of fragmented flow packets" },
  /* 81 is available */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+82,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "CLIENT_NW_DELAY_SEC",  "Network latency client <-> nprobe (sec)" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+83,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "CLIENT_NW_DELAY_USEC", "Network latency client <-> nprobe (usec)" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+84,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SERVER_NW_DELAY_SEC",  "Network latency nprobe <-> server (sec)" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+85,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SERVER_NW_DELAY_USEC", "Network latency nprobe <-> server (usec)" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+86,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "APPL_LATENCY_SEC", "Application latency (sec)" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+87,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "APPL_LATENCY_USEC", "Application latency (usec)" },

  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+IN_PAYLOAD_ID,  STATIC_FIELD_LEN, 0 /* The length is set at runtime */, ascii_format, dump_as_hex,  "IN_PAYLOAD", "Initial payload bytes" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+OUT_PAYLOAD_ID,  STATIC_FIELD_LEN, 0 /* The length is set at runtime */, ascii_format, dump_as_ascii,  "OUT_PAYLOAD", "Initial payload bytes" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+98,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "ICMP_FLAGS", "Cumulative of all flow ICMP types" },
  /* 99+100 are available */

#ifdef HAVE_GEOIP
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+101, STATIC_FIELD_LEN, 2,  ascii_format, dump_as_ascii, "SRC_IP_COUNTRY", "Country where the src IP is located" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+102, STATIC_FIELD_LEN, 16, ascii_format, dump_as_ascii, "SRC_IP_CITY", "City where the src IP is located" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+103, STATIC_FIELD_LEN, 2,  ascii_format, dump_as_ascii, "DST_IP_COUNTRY", "Country where the dst IP is located" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+104, STATIC_FIELD_LEN, 16, ascii_format, dump_as_ascii, "DST_IP_CITY", "City where the dst IP is located" },
#endif
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+105, STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint, "FLOW_PROTO_PORT", "L7 port that identifies the flow protocol or 0 if unknown" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+106, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "TUNNEL_ID", "Tunnel identifier (e.g. GTP tunnel Id) or 0 if unknown" },

  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+107, STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint, "LONGEST_FLOW_PKT", "Longest packet (bytes) of the flow" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+108, STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint, "SHORTEST_FLOW_PKT", "Shortest packet (bytes) of the flow" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+109, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "RETRANSMITTED_IN_PKTS", "Number of retransmitted TCP flow packets (src->dst)" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+110, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "RETRANSMITTED_OUT_PKTS", "Number of retransmitted TCP flow packets (dst->src)" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+111, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "OOORDER_IN_PKTS", "Number of out of order TCP flow packets (dst->src)" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+112, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "OOORDER_OUT_PKTS", "Number of out of order TCP flow packets (dst->src)" },


  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+113,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "UNTUNNELED_PROTOCOL", "Untunneled IP protocol byte" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+114,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "UNTUNNELED_IPV4_SRC_ADDR", "Untunneled IPv4 source address" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+115,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "UNTUNNELED_L4_SRC_PORT", "Untunneled IPv4 source port" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+116,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "UNTUNNELED_IPV4_DST_ADDR", "Untunneled IPv4 destination address" },
  { FLOW_TEMPLATE, SHORT_SNAPLEN,NTOP_ENTERPRISE_ID,   NTOP_BASE_ID+117,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "UNTUNNELED_L4_DST_PORT", "Untunneled IPv4 destination port" },

  /*
    { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+0,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "PAD1", "" },
    { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+0,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "PAD2", "" },
  */
  { FLOW_TEMPLATE, SHORT_SNAPLEN,STANDARD_ENTERPRISE_ID, 0, STATIC_FIELD_LEN, 0, 0, 0, NULL, NULL }
};


/* ******************************************** */

void printTemplateInfo(V9V10TemplateElementId *templates,
		       u_char show_private_elements) {
  int j = 0;

  while(templates[j].templateElementName != NULL) {
    if(((!show_private_elements)
	&& ((templates[j].templateElementLen > 0)
	    || (templates[j].templateElementId == IN_PAYLOAD_ID)
	    || (templates[j].templateElementId == OUT_PAYLOAD_ID)))
       || (show_private_elements && (templates[j].templateElementId >= 0xFF))) {

      if(templates[j].templateElementEnterpriseId == NTOP_ENTERPRISE_ID) {
	printf("[NFv9 %3d][IPFIX %5d.%d] %%%-22s\t%s\n",
	       templates[j].templateElementId,
	       templates[j].templateElementEnterpriseId, templates[j].templateElementId-NTOP_BASE_ID,
	       templates[j].templateElementName,
	       templates[j].templateElementDescr);
      } else {
	printf("[%3d] %%%-22s\t%s\n",
	       templates[j].templateElementId,
	       templates[j].templateElementName,
	       templates[j].templateElementDescr);
      }
    }

    j++;
  }
}

/* ******************************************** */

char* getStandardFieldId(u_int id) {
  int i = 0;

  while(ver9_templates[i].templateElementName != NULL) {
    if(ver9_templates[i].templateElementId == id)
      return(ver9_templates[i].templateElementName);
    else
      i++;
  }
  
  return("");
}

/* ******************************************** */

void setPayloadLength(int len) {
  int i = 0;

  while(ver9_templates[i].templateElementName != NULL) {
    if((ver9_templates[i].templateElementId == IN_PAYLOAD_ID)
       || (ver9_templates[i].templateElementId == OUT_PAYLOAD_ID)) {
      ver9_templates[i].templateElementLen = len;

      if(0)
	traceEvent(TRACE_ERROR, "--> Setting payload length for element %s",
		   ver9_templates[i].templateElementName);
    }

    i++;
  }
}

/* ******************************************** */

void copyInt8(u_int8_t t8, char *outBuffer,
	      uint *outBufferBegin, uint *outBufferMax) {
  if((*outBufferBegin)+sizeof(t8) < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], &t8, sizeof(t8));
    (*outBufferBegin) += sizeof(t8);
  }
}

/* ******************************************** */

void copyInt16(u_int16_t _t16, char *outBuffer,
	       uint *outBufferBegin, uint *outBufferMax) {
  u_int16_t t16 = htons(_t16);

  if((*outBufferBegin)+sizeof(t16) < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], &t16, sizeof(t16));
    (*outBufferBegin) += sizeof(t16);
  }
}

/* ******************************************** */

void copyInt32(u_int32_t _t32, char *outBuffer,
	       uint *outBufferBegin, uint *outBufferMax) {
  u_int32_t t32 = htonl(_t32);

  if((*outBufferBegin)+sizeof(t32) < (*outBufferMax)) {
#ifdef DEBUG
    char buf1[32];

    printf("(8) %s\n", _intoaV4(_t32, buf1, sizeof(buf1)));
#endif

    memcpy(&outBuffer[(*outBufferBegin)], &t32, sizeof(t32));
    (*outBufferBegin) += sizeof(t32);
  }
}

/* ******************************************** */

/* 64-bit version of ntohl and htonl */
unsigned long long htonll(unsigned long long v) {
  union { unsigned long lv[2]; unsigned long long llv; } u;
  u.lv[0] = htonl(v >> 32);
  u.lv[1] = htonl(v & 0xFFFFFFFFULL);
  return u.llv;
}

unsigned long long ntohll(unsigned long long v) {
  union { unsigned long lv[2]; unsigned long long llv; } u;
  u.llv = v;
  return ((unsigned long long)ntohl(u.lv[0]) << 32) | (unsigned long long)ntohl(u.lv[1]);
}

/* ******************************************** */

void copyInt64(u_int64_t _t64, char *outBuffer,
	       uint *outBufferBegin, uint *outBufferMax) {
  u_int64_t t64 = htonll(_t64);

  if((*outBufferBegin)+sizeof(t64) < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], &t64, sizeof(t64));
    (*outBufferBegin) += sizeof(t64);
  }
}

/* ******************************************** */

void copyLen(u_char *str, int strLen, char *outBuffer,
	     uint *outBufferBegin, uint *outBufferMax) {
  if((*outBufferBegin)+strLen < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], str, strLen);
    (*outBufferBegin) += strLen;
  }
}

/* ******************************************** */

static void copyIpV6(struct in6_addr ipv6, char *outBuffer,
		     uint *outBufferBegin, uint *outBufferMax) {
  copyLen((u_char*)&ipv6, sizeof(ipv6), outBuffer,
	  outBufferBegin, outBufferMax);
}

/* ******************************************** */

static void copyMac(u_char *macAddress, char *outBuffer,
		    uint *outBufferBegin, uint *outBufferMax) {
  copyLen(macAddress, 6 /* lenght of mac address */,
	  outBuffer, outBufferBegin, outBufferMax);
}

/* ******************************************** */

static void copyMplsLabel(struct mpls_labels *mplsInfo, int labelId,
			  char *outBuffer, uint *outBufferBegin,
			  uint *outBufferMax) {
  if(mplsInfo == NULL) {
    int i;

    for(i=0; (i < 3) && (*outBufferBegin < *outBufferMax); i++) {
      outBuffer[*outBufferBegin] = 0;
      (*outBufferBegin)++;
    }
  } else {
    if(((*outBufferBegin)+MPLS_LABEL_LEN) < (*outBufferMax)) {
      memcpy(outBuffer, mplsInfo->mplsLabels[labelId-1], MPLS_LABEL_LEN);
      (*outBufferBegin) += MPLS_LABEL_LEN;
    }
  }
}

/* ****************************************************** */

static void exportPayload(FlowHashBucket *myBucket, FlowDirection direction,
			  V9V10TemplateElementId *theTemplate,
			  char *outBuffer, uint *outBufferBegin,
			  uint *outBufferMax) {
  if(readOnlyGlobals.maxPayloadLen > 0) {
    u_char thePayload[MAX_PAYLOAD_LEN];
    int len;

    if(direction == src2dst_direction)
      len = myBucket->src2dstPayloadLen;
    else
      len = myBucket->dst2srcPayloadLen;

    /*
      u_int16_t t16;

      t16 = theTemplate->templateId;
      copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);
      t16 = maxPayloadLen;
      copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);
    */

    memset(thePayload, 0, readOnlyGlobals.maxPayloadLen);
    if(len > readOnlyGlobals.maxPayloadLen) len = readOnlyGlobals.maxPayloadLen;
    memcpy(thePayload, direction == src2dst_direction ? myBucket->src2dstPayload : myBucket->dst2srcPayload, len);

    copyLen(thePayload, readOnlyGlobals.maxPayloadLen, outBuffer, outBufferBegin, outBufferMax);
  }
}

/* ******************************************** */

u_int16_t ifIdx(FlowHashBucket *myBucket, FlowDirection direction, int inputIf) {
  u_char *mac;
  u_int16_t idx;
  struct in_addr addr;

  if(readOnlyGlobals.use_vlanId_as_ifId) {
    return(myBucket->vlanId);
  }

  addr.s_addr = inputIf ? htonl(myBucket->src->host.ipType.ipv4) : htonl(myBucket->dst->host.ipType.ipv4);

  if(getIfIdx(&addr, &idx))
    return(idx);

  if(readWriteGlobals->num_src_mac_export > 0) {
    int i = 0;

    for(i = 0; i<readWriteGlobals->num_src_mac_export; i++)
      if((((inputIf == 1) && (direction == src2dst_direction))
	  || ((inputIf == 0) && (direction == dst2src_direction)))
	 && (memcmp(myBucket->srcMacAddress,
		    readOnlyGlobals.mac_if_match[i].mac_address, 6) == 0))
        return(readOnlyGlobals.mac_if_match[i].interface_id);
      else if((((inputIf == 0) && (direction == src2dst_direction))
	       || ((inputIf == 1) && (direction == dst2src_direction)))
	      && (memcmp(myBucket->dstMacAddress,
			 readOnlyGlobals.mac_if_match[i].mac_address, 6) == 0))
        return(readOnlyGlobals.mac_if_match[i].interface_id);
  }

  if(inputIf) {
    if(readOnlyGlobals.inputInterfaceIndex != NO_INTERFACE_INDEX)
      return(readOnlyGlobals.inputInterfaceIndex);
  } else {
    if(readOnlyGlobals.outputInterfaceIndex != NO_INTERFACE_INDEX)
      return(readOnlyGlobals.outputInterfaceIndex);
  }

  /* ...else dynamic */

  /* Calculate the input/output interface using
     the last two MAC address bytes */
  if(direction == src2dst_direction /* src -> dst */) {
    if(inputIf)
      mac = &(myBucket->srcMacAddress[4]);
    else
      mac = &(myBucket->dstMacAddress[4]);
  } else {
    if(inputIf)
      mac = &(myBucket->dstMacAddress[4]);
    else
      mac = &(myBucket->srcMacAddress[4]);
  }

  idx = (mac[0] * 256) + mac[1];

  return(idx);
}

/* ******************************************** */

static char* port2name(u_int16_t port, u_int8_t proto) {
#if 0
  struct servent *svt;

  if((svt = getservbyport(htons(port), proto2name(proto))) != NULL)
    return(svt->s_name);
  else {
    static char the_port[8];

    snprintf(the_port, sizeof(the_port), "%d", port);
    return(the_port);
  }
#else
  if(port_mapping[port] != NULL)
    return(port_mapping[port]);
  else if(proto == 6)  return("tcp_other");
  else if(proto == 17) return("udp_other");
  else return("<unknown>"); /* Not reached */
#endif
}

/* **************************************************************** */

void reset_bitmask(bitmask_selector *selector) {
  memset((char*)selector->bits_memory, 0, selector->num_bits/8);
}

/* **************************************************************** */

int alloc_bitmask(u_int32_t tot_bits, bitmask_selector *selector) {
  uint tot_mem = 1 + (tot_bits >> 3); /* /= 8 */

  if((selector->bits_memory = malloc(tot_mem)) != NULL) {
  } else {
    selector->num_bits = 0;
    return(-1);
  }

  selector->num_bits = tot_bits;
  reset_bitmask(selector);
  return(0);
}

/* ********************************** */

void free_bitmask(bitmask_selector *selector) {
  if(selector->bits_memory > 0) {
    free(selector->bits_memory);
    selector->bits_memory = 0;
  }
}

/* ******************************************** */

void bitmask_set(u_int32_t n, bitmask_selector* p)       { (((char*)p->bits_memory)[n >> 3] |=  (1 << (n & 7))); }
void bitmask_clr(u_int32_t n, bitmask_selector* p)       { (((char*)p->bits_memory)[n >> 3] &= ~(1 << (n & 7))); }
u_int8_t bitmask_isset(u_int32_t n, bitmask_selector* p) { return(((char*)p->bits_memory)[n >> 3] &   (1 << (n & 7))); }

/* ******************************************** */

void loadApplProtocols(void) {
  struct servent *s;

  alloc_bitmask(65536, &readOnlyGlobals.udpProto);
  alloc_bitmask(65536, &readOnlyGlobals.tcpProto);

#ifndef WIN32
  setservent(1);
#endif

  while((s = getservent()) != NULL) {
    s->s_port = ntohs(s->s_port);

    if(s->s_proto[0] == 'u')
      bitmask_set(s->s_port, &readOnlyGlobals.udpProto);
    else
      bitmask_set(s->s_port, &readOnlyGlobals.tcpProto);
  }

  endservent();

  /* Add extra protocols (if missing) */
  bitmask_set(4343 /* das   */, &readOnlyGlobals.tcpProto);
  bitmask_set(80   /* http  */, &readOnlyGlobals.tcpProto);
  bitmask_set(43   /* whois */, &readOnlyGlobals.tcpProto);
  bitmask_set(443  /* https */, &readOnlyGlobals.tcpProto);
  bitmask_set(25   /* smtp  */, &readOnlyGlobals.tcpProto);
  bitmask_set(53   /* dns   */, &readOnlyGlobals.udpProto);
}

/* ******************************************** */

u_int16_t port2ApplProtocol(u_int8_t proto, u_int16_t port) {
  u_int16_t value;

  if(proto == IPPROTO_TCP)
    value = bitmask_isset(port, &readOnlyGlobals.tcpProto);
  else if(proto == IPPROTO_UDP)
    value = bitmask_isset(port, &readOnlyGlobals.udpProto);
  else
    value = 0;

  return(value ? port : 0);
}

/* ******************************************** */

u_int16_t getFlowApplProtocol(FlowHashBucket *theFlow) {
  u_int16_t value;
  u_int16_t proto_sport = port2ApplProtocol(theFlow->proto, theFlow->sport);
  u_int16_t proto_dport = port2ApplProtocol(theFlow->proto, theFlow->dport);

  if((theFlow->proto == IPPROTO_TCP) || (theFlow->proto == IPPROTO_UDP)) {
    if(proto_sport == 0) value = proto_dport;
    else if(proto_dport == 0) value = proto_sport;
    else {
      if(theFlow->sport < theFlow->dport) value = proto_sport;
      else value = proto_dport;
    }
  } else
    value = 0;

  // traceEvent(TRACE_ERROR, "[%u/%u] -> %u", theFlow->sport, theFlow->dport, value);

  return(value);
}

/* ******************************************** */

static void handleTemplate(V9V10TemplateElementId *theTemplateElement,
			   u_int8_t ipv4_template,
			   char *outBuffer, uint *outBufferBegin,
			   uint *outBufferMax,
			   char buildTemplate, int *numElements,
			   FlowHashBucket *theFlow, FlowDirection direction,
			   int addTypeLen, int optionTemplate) {
#ifdef HAVE_GEOIP
  GeoIPRecord *geo;
#endif
  u_char null_data[128] = { 0 };
  u_int16_t t16;

  if(buildTemplate || addTypeLen) {
    /* Type */
    t16 = theTemplateElement->templateElementId;

    if((readOnlyGlobals.netFlowVersion == 10)
       && (theTemplateElement->templateElementEnterpriseId != STANDARD_ENTERPRISE_ID)) {
      if(theTemplateElement->templateElementEnterpriseId == NTOP_ENTERPRISE_ID)
	t16 -= NTOP_BASE_ID; /* Just to make sure we don't mess-up the template */

      t16 = t16 | 0x8000; /* Enable the PEN bit */
    }

    copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);

    /* Len */
    if((readOnlyGlobals.netFlowVersion == 10)
       && (theTemplateElement->variableFieldLength == VARIABLE_FIELD_LEN)) {
      t16 = 65535; /* Reserved len as specified in rfc5101 */
    } else
      t16 = theTemplateElement->templateElementLen;

    copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);

    if((readOnlyGlobals.netFlowVersion == 10)
       && (theTemplateElement->templateElementEnterpriseId != STANDARD_ENTERPRISE_ID)) {
      /* PEN */
      copyInt32(theTemplateElement->templateElementEnterpriseId,
		outBuffer, outBufferBegin, outBufferMax);
    }
  }

  if(!buildTemplate) {
    if(theTemplateElement->templateElementLen == 0)
      ; /* Nothing to do: all fields have zero length */
    else {
      u_char custom_field[CUSTOM_FIELD_LEN];

#ifdef DEBUG
	traceEvent(TRACE_INFO, "[%d][%s][%d]",
		   theTemplateElement->templateElementId,
		   theTemplateElement->templateElementName,
		   theTemplateElement->templateElementLen);
#endif

      if(theTemplateElement->isOptionTemplate) {
	copyLen(null_data, theTemplateElement->templateElementLen,
		outBuffer, outBufferBegin, outBufferMax);
      } else {
	/*
	 * IMPORTANT
	 *
	 * Any change below need to be ported also in printRecordWithTemplate()
	 *
	 */
	switch(theTemplateElement->templateElementId) {
	case 1:
	  copyInt32(direction == dst2src_direction ? theFlow->flowCounters.bytesRcvd : theFlow->flowCounters.bytesSent,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 2:
	  copyInt32(direction == dst2src_direction ? theFlow->flowCounters.pktRcvd : theFlow->flowCounters.pktSent,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 4:
	  copyInt8((u_int8_t)theFlow->proto, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 5:
	  copyInt8(direction == src2dst_direction ? theFlow->src2dstTos : theFlow->dst2srcTos,
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 6:
	  copyInt8(direction == src2dst_direction ? theFlow->src2dstTcpFlags : theFlow->dst2srcTcpFlags,
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 7:
	  copyInt16(direction == src2dst_direction ? theFlow->sport : theFlow->dport, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 8:
	  if((theFlow->src->host.ipVersion == 4) && (theFlow->dst->host.ipVersion == 4))
	    copyInt32(direction == src2dst_direction ? theFlow->src->host.ipType.ipv4 : theFlow->dst->host.ipType.ipv4,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 9: /* IPV4_SRC_MASK */
	  copyInt8(ip2mask((direction == src2dst_direction) ? theFlow->src->host: theFlow->dst->host),
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 10: /* INPUT_SNMP */
	  copyInt16((direction == src2dst_direction) ? theFlow->if_input : theFlow->if_output, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 11:
	  copyInt16(direction == src2dst_direction ? theFlow->dport : theFlow->sport, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 12:
	  if((theFlow->src->host.ipVersion == 4) && (theFlow->dst->host.ipVersion == 4))
	    copyInt32(direction == src2dst_direction ? theFlow->dst->host.ipType.ipv4 : theFlow->src->host.ipType.ipv4,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 13: /* IPV4_DST_MASK */
	  copyInt8(ip2mask((direction == dst2src_direction) ? theFlow->src->host: theFlow->dst->host),
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 14: /* OUTPUT_SNMP */
	  copyInt16((direction != src2dst_direction) ? theFlow->if_input : theFlow->if_output, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 15: /* IPV4_NEXT_HOP */
	  copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 16:
	  copyInt32(direction == src2dst_direction ? getAS(theFlow, 1) : getAS(theFlow, 0),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 17:
	  copyInt32(direction == src2dst_direction ? getAS(theFlow, 0) : getAS(theFlow, 1),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 21:
	  if(readOnlyGlobals.collectorInPort > 0)
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(direction == src2dst_direction ? msTimeDiff(&theFlow->flowTimers.lastSeenSent, &readOnlyGlobals.initialSniffTime)
		      : msTimeDiff(&theFlow->flowTimers.lastSeenRcvd, &readOnlyGlobals.initialSniffTime),
		      outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 22:
	  if(readOnlyGlobals.collectorInPort > 0)
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(direction == src2dst_direction ? msTimeDiff(&theFlow->flowTimers.firstSeenSent,
						  &readOnlyGlobals.initialSniffTime)
		      : msTimeDiff(&theFlow->flowTimers.firstSeenRcvd,
				   &readOnlyGlobals.initialSniffTime),
		      outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 23:
	  copyInt32(direction == dst2src_direction ? theFlow->flowCounters.bytesSent : theFlow->flowCounters.bytesRcvd,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 24:
	  copyInt32(direction == dst2src_direction ? theFlow->flowCounters.sentFragPkts : theFlow->flowCounters.rcvdFragPkts,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 27:
	  if((theFlow->src->host.ipVersion == 6) && (theFlow->dst->host.ipVersion == 6))
	    copyIpV6(direction == src2dst_direction ? theFlow->src->host.ipType.ipv6 : theFlow->dst->host.ipType.ipv6,
		     outBuffer, outBufferBegin, outBufferMax);
	  else {
	    struct in6_addr _ipv6;

	    memset(&_ipv6, 0, sizeof(struct in6_addr));
	    copyIpV6(_ipv6, outBuffer, outBufferBegin, outBufferMax);
	  }
	  break;
	case 28:
	  if((theFlow->src->host.ipVersion == 6) && (theFlow->dst->host.ipVersion == 6))
	    copyIpV6(direction == src2dst_direction ? theFlow->dst->host.ipType.ipv6 : theFlow->dst->host.ipType.ipv6,
		     outBuffer, outBufferBegin, outBufferMax);
	  else {
	    struct in6_addr _ipv6;

	    memset(&_ipv6, 0, sizeof(struct in6_addr));
	    copyIpV6(_ipv6, outBuffer, outBufferBegin, outBufferMax);
	  }
	  break;
	case 29:
	case 30:
	  copyInt8(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 32:
	  copyInt16(direction == src2dst_direction ? theFlow->src2dstIcmpType : theFlow->dst2srcIcmpType,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 34: /* SAMPLING INTERVAL */
	  copyInt32(1 /* 1:1 = no sampling */, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 35: /* SAMPLING ALGORITHM */
	  copyInt8(0x01 /* 1=Deterministic Sampling, 0x02=Random Sampling */,
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 36: /* FLOW ACTIVE TIMEOUT */
	  copyInt16(readOnlyGlobals.lifetimeTimeout, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 37: /* FLOW INACTIVE TIMEOUT */
	  copyInt16(readOnlyGlobals.idleTimeout, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 38:
	  copyInt8((u_int8_t)readOnlyGlobals.engineType, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 39:
	  copyInt8((u_int8_t)readOnlyGlobals.engineId, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 40: /* TOTAL_BYTES_EXP */
	  copyInt32(readWriteGlobals->flowExportStats.totExportedBytes, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 41: /* TOTAL_PKTS_EXP */
	  copyInt32(readWriteGlobals->flowExportStats.totExportedPkts, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 42: /* TOTAL_FLOWS_EXP */
	  copyInt32(readWriteGlobals->flowExportStats.totExportedFlows, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 56: /* IN_SRC_MAC */
	  copyMac(direction == src2dst_direction ? theFlow->srcMacAddress : theFlow->dstMacAddress, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 58: /* SRC_VLAN */
	  /* no break */
	case 59: /* DST_VLAN */
	  copyInt16(theFlow->vlanId, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 60: /* IP_PROTOCOL_VERSION */
	  copyInt8((theFlow->src->host.ipVersion == 4) && (theFlow->dst->host.ipVersion == 4) ? 4 : 6, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 61: /* Direction (it indicates where a sample has been taken) */
	  copyInt8(0 /* Always use zero */, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 62: /* IPV6_NEXT_HOP */
	  {
	    IpAddress addr;

	    memset(&addr, 0, sizeof(addr));
	    copyIpV6(addr.ipType.ipv6, outBuffer, outBufferBegin, outBufferMax);
	  }
	  break;
	case 70: /* MPLS: label 1 */
	  copyMplsLabel(theFlow->mplsInfo, 1, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 71: /* MPLS: label 2 */
	  copyMplsLabel(theFlow->mplsInfo, 2, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 72: /* MPLS: label 3 */
	  copyMplsLabel(theFlow->mplsInfo, 3, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 73: /* MPLS: label 4 */
	  copyMplsLabel(theFlow->mplsInfo, 4, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 74: /* MPLS: label 5 */
	  copyMplsLabel(theFlow->mplsInfo, 5, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 75: /* MPLS: label 6 */
	  copyMplsLabel(theFlow->mplsInfo, 6, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 76: /* MPLS: label 7 */
	  copyMplsLabel(theFlow->mplsInfo, 7, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 77: /* MPLS: label 8 */
	  copyMplsLabel(theFlow->mplsInfo, 8, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 78: /* MPLS: label 9 */
	  copyMplsLabel(theFlow->mplsInfo, 9, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 79: /* MPLS: label 10 */
	  copyMplsLabel(theFlow->mplsInfo, 10, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 80: /* OUT_DST_MAC */
	  copyMac(direction == src2dst_direction ? theFlow->dstMacAddress : theFlow->srcMacAddress, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case 148: /* FLOW_ID */
	  copyInt64(theFlow->flow_idx, outBuffer, outBufferBegin, outBufferMax);
	  break;

	  /* ************************************ */

	  /* nProbe Extensions */
	case NTOP_BASE_ID+80:
	  copyInt16(direction == src2dst_direction ? theFlow->flowCounters.sentFragPkts : theFlow->flowCounters.rcvdFragPkts,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
#if 0
	case NTOP_BASE_ID+81:
	  break;
#endif
	case NTOP_BASE_ID+82:
	  copyInt32(nwLatencyComputed(theFlow) ? theFlow->clientNwDelay.tv_sec : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+83:
	  copyInt32(nwLatencyComputed(theFlow) ? theFlow->clientNwDelay.tv_usec : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+84:
	  copyInt32(nwLatencyComputed(theFlow) ? theFlow->serverNwDelay.tv_sec : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+85:
	  copyInt32(nwLatencyComputed(theFlow) ? theFlow->serverNwDelay.tv_usec : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+86:
	  copyInt32(applLatencyComputed(theFlow) ? (direction == src2dst_direction ? theFlow->src2dstApplLatency.tv_sec
						    : theFlow->dst2srcApplLatency.tv_sec) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+87:
	  copyInt32(applLatencyComputed(theFlow) ?
		    (direction == src2dst_direction ? theFlow->src2dstApplLatency.tv_usec :
		     theFlow->dst2srcApplLatency.tv_usec) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+IN_PAYLOAD_ID:
	  exportPayload(theFlow, 0, theTemplateElement, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+OUT_PAYLOAD_ID:
	  exportPayload(theFlow, 1, theTemplateElement, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+98:
	  copyInt32(direction == src2dst_direction ? theFlow->src2dstIcmpFlags : theFlow->dst2srcIcmpFlags,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+101: /* SRC_IP_COUNTRY */
#ifdef HAVE_GEOIP
	  geo = (direction == src2dst_direction) ? theFlow->src->geo : theFlow->dst->geo;
#endif

	  //if(geo) traceEvent(TRACE_ERROR, "SRC_IP_COUNTRY -> %s", (geo && geo->country_code) ? geo->country_code : "???");

	  copyLen((u_char*)(
#ifdef HAVE_GEOIP
			    (geo && geo->country_code) ? geo->country_code :
#endif
			    "  "), 2,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+102: /* SRC_IP_CITY */
#ifdef HAVE_GEOIP
	  geo = (direction == src2dst_direction) ? theFlow->src->geo : theFlow->dst->geo;
#endif

	  // if(geo) traceEvent(TRACE_ERROR, "-> %s [%s]", geo->region, geo->country_code);

	  copyLen((u_char*)(
#ifdef HAVE_GEOIP
			    (geo && geo->city) ? geo->city :
#endif
			    "                "), 16,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+103: /* DST_IP_COUNTRY */
#ifdef HAVE_GEOIP
	  geo = (direction == src2dst_direction) ? theFlow->dst->geo : theFlow->src->geo;
#endif

	  // if(geo) traceEvent(TRACE_ERROR, "DST_IP_COUNTRY -> %s", (geo && geo->country_code) ? geo->country_code : "???");
	  copyLen((u_char*)(
#ifdef HAVE_GEOIP
			    (geo && geo->country_code) ? geo->country_code :
#endif
			    "  "), 2,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+104: /* DST_IP_CITY */
#ifdef HAVE_GEOIP
	  geo = (direction == src2dst_direction) ? theFlow->dst->geo : theFlow->src->geo;
#endif
	  copyLen((u_char*)(
#ifdef HAVE_GEOIP
			    (geo && geo->city) ? geo->city :
#endif
			    "                "), 16,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+105: /* FLOW_PROTO_PORT */
	  t16 = getFlowApplProtocol(theFlow);
	  copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+106: /* TUNNEL_ID */
	  copyInt32(theFlow->tunnel_id, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+107: /* LONGEST_FLOW_PKT */
	  copyInt16(theFlow->flowCounters.pktSize.longest, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+108: /* SHORTEST_FLOW_PKT */
	  copyInt16(theFlow->flowCounters.pktSize.shortest, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+109: /* RETRANSMITTED_IN_PKTS */
	  copyInt32((direction == dst2src_direction) ? theFlow->flowCounters.tcpPkts.rcvdRetransmitted : theFlow->flowCounters.tcpPkts.sentRetransmitted,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+110: /* RETRANSMITTED_OUT_PKTS */
	  copyInt32((direction == src2dst_direction) ? theFlow->flowCounters.tcpPkts.rcvdRetransmitted : theFlow->flowCounters.tcpPkts.sentRetransmitted,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+111: /* OOORDER_IN_PKTS */
	  copyInt32((direction == dst2src_direction) ? theFlow->flowCounters.tcpPkts.rcvdOOOrder : theFlow->flowCounters.tcpPkts.sentOOOrder,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+112: /* OOORDER_OUT_PKTS */
	  copyInt32((direction == src2dst_direction) ? theFlow->flowCounters.tcpPkts.rcvdOOOrder : theFlow->flowCounters.tcpPkts.sentOOOrder,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+113: /* UNTUNNELED_PROTOCOL */
	  copyInt8((u_int8_t)theFlow->untunneled.proto, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+114: /* UNTUNNELED_IPV4_SRC_ADDR */
	  if(readOnlyGlobals.tunnel_mode && (theFlow->untunneled.src->host.ipVersion == 4) && (theFlow->untunneled.dst->host.ipVersion == 4))
	    copyInt32(direction == src2dst_direction ? theFlow->untunneled.src->host.ipType.ipv4 : theFlow->untunneled.dst->host.ipType.ipv4,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+115: /* UNTUNNELED_L4_SRC_PORT */
	  if(readOnlyGlobals.tunnel_mode)
	    copyInt16(direction == src2dst_direction ? theFlow->untunneled.sport : theFlow->untunneled.dport, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt16(0, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+116: /* UNTUNNELED_IPV4_DST_ADDR */
	  if(readOnlyGlobals.tunnel_mode && (theFlow->untunneled.src->host.ipVersion == 4) && (theFlow->untunneled.dst->host.ipVersion == 4))
	    copyInt32(direction == src2dst_direction ? theFlow->untunneled.dst->host.ipType.ipv4 : theFlow->untunneled.src->host.ipType.ipv4,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+117: /* UNTUNNELED_L4_DST_PORT */
	  if(readOnlyGlobals.tunnel_mode)
	    copyInt16(direction == src2dst_direction ? theFlow->untunneled.dport : theFlow->untunneled.sport, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt16(0, outBuffer, outBufferBegin, outBufferMax);
	  break;

	  /* Custom fields */
	case 0xA0+4:
	  snprintf((char*)custom_field, sizeof(custom_field), "%s", proto2name(theFlow->proto));
	  copyLen(custom_field, sizeof(custom_field), outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 0xA0+7:
	  snprintf((char*)custom_field, sizeof(custom_field), "%s", port2name(direction == src2dst_direction ? theFlow->sport : theFlow->dport, theFlow->proto));
	  copyLen(custom_field, sizeof(custom_field), outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 0xA0+11:
	  snprintf((char*)custom_field, sizeof(custom_field), "%s", port2name(direction == src2dst_direction ? theFlow->dport : theFlow->sport, theFlow->proto));
	  copyLen(custom_field, sizeof(custom_field), outBuffer, outBufferBegin, outBufferMax);
	  break;

	default:
	  if(checkPluginExport(theTemplateElement, direction, theFlow,
			       outBuffer, outBufferBegin, outBufferMax) == -1) {
	    /*
	      This flow is the one we like, however we need
	      to store some values anyway, so we put an empty value
	    */
	    
	    if((readOnlyGlobals.netFlowVersion == 10)
	       && (theTemplateElement->variableFieldLength == VARIABLE_FIELD_LEN)) {
	      u_int len = 0;
	      copyInt8(len, outBuffer, outBufferBegin, outBufferMax);
	    } else {
	      copyLen(null_data, theTemplateElement->templateElementLen,
		      outBuffer, outBufferBegin, outBufferMax);
	    }
	  }
	}
      }
    }

#ifdef DEBUG
    traceEvent(TRACE_INFO, "name=%s/Id=%d/len=%d [len=%d][outBufferMax=%d]\n",
	       theTemplateElement->templateElementName,
	       theTemplateElement->templateElementId,
	       theTemplateElement->templateElementLen,
	       *outBufferBegin, *outBufferMax);
#endif
  }

  (*numElements) = (*numElements)+1;

  return;
}

/* ******************************************** */

void load_mappings() {
  struct servent *sv;
#if !defined(WIN32)
  struct protoent *pe;
#endif

  while((sv = getservent()) != NULL) {
    u_short port = ntohs(sv->s_port);
    if(port_mapping[port] == NULL)
      port_mapping[port] = strdup(sv->s_name);
  }

#if !defined(WIN32)
  endservent();
#endif

  /* ******************** */

#if !defined(WIN32)
  while((pe = getprotoent()) != NULL) {
    if(proto_mapping[pe->p_proto] == NULL) {
      proto_mapping[pe->p_proto] = strdup(pe->p_name);
      // traceEvent(TRACE_INFO, "[%d][%s]", pe->p_proto, pe->p_name);
    }
  }

  endprotoent();
#else
  proto_mapping[0] = strdup("ip");
  proto_mapping[1] = strdup("icmp");
  proto_mapping[2] = strdup("igmp");
  proto_mapping[6] = strdup("tcp");
  proto_mapping[17] = strdup("udp");
#endif
}

/* ******************************************** */

void unload_mappings() {
  int i;

  for(i=0; i<0xFFFF; i++) if(port_mapping[i])  free(port_mapping[i]);
  for(i=0; i<0xFF; i++)   if(proto_mapping[i]) free(proto_mapping[i]);
}

/* ******************************************** */

/* FIX: improve performance */
char* proto2name(u_int8_t proto) {
#if 0
  struct protoent *svt;

  if(proto == 6)       return("tcp");
  else if(proto == 17) return("udp");
  else if(proto == 1)  return("icmp");
  else if(proto == 2)  return("igmp");
  else if((svt = getprotobynumber(proto)) != NULL)
    return(svt->p_name);
  else {
    static char the_proto[8];

    snprintf(the_proto, sizeof(the_proto), "%d", proto);
    return(the_proto);
  }
#else
  if(proto_mapping[proto] != NULL) {
    // traceEvent(TRACE_INFO, "[%d][%s]", proto, proto_mapping[proto]);
    return(proto_mapping[proto]);
  } else
    return("unknown");
#endif
}

/* ******************************************** */

static int mplsLabel2int(struct mpls_labels *mplsInfo, int labelId) {
  if(mplsInfo == NULL)
    return(0);
  else
    return((mplsInfo->mplsLabels[labelId][0] << 16)
	   + (mplsInfo->mplsLabels[labelId][1] << 8)
	   + mplsInfo->mplsLabels[labelId][2]);
}

/* ******************************************** */

static void printRecordWithTemplate(V9V10TemplateElementId *theTemplateElement,
				    char *line_buffer, uint line_buffer_len,
				    FlowHashBucket *theFlow, FlowDirection direction) {
  char buf[128], *dst;
#ifdef HAVE_GEOIP
  GeoIPRecord *geo;
#endif
  uint len;

  /* traceEvent(TRACE_INFO, "[%s][%d]",
     theTemplate->templateElementName, theTemplate->templateElementLen);
  */

  len = strlen(line_buffer);
  dst = &line_buffer[len];

  switch(theTemplateElement->templateElementId) {
  case 1:
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == dst2src_direction ? theFlow->flowCounters.bytesRcvd : theFlow->flowCounters.bytesSent);
    break;
  case 2:
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == dst2src_direction ? theFlow->flowCounters.pktRcvd : theFlow->flowCounters.pktSent);
    break;
  case 4:
    snprintf(dst, (line_buffer_len-len), "%d", theFlow->proto);
    break;
  case 0xFF+4:
    snprintf(dst, (line_buffer_len-len), "%s", proto2name(theFlow->proto));
    break;
  case 5:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == src2dst_direction ? theFlow->src2dstTos : theFlow->dst2srcTos);
    break;
  case 6:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == src2dst_direction ? theFlow->src2dstTcpFlags : theFlow->dst2srcTcpFlags);
    break;
  case 7:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == src2dst_direction ? theFlow->sport : theFlow->dport);
    break;
  case 0xFF+7:
    snprintf(dst, (line_buffer_len-len), "%s",
	     port2name(direction == src2dst_direction ? theFlow->sport : theFlow->dport, theFlow->proto));
    break;
  case 8:
  case 27:
    snprintf(dst, (line_buffer_len-len), "%s",
	     _intoa(direction == src2dst_direction ? theFlow->src->host : theFlow->dst->host, buf, sizeof(buf)));
    break;
  case 9: /* IPV4_SRC_MASK */
    snprintf(dst, (line_buffer_len-len), "%d",
	     ip2mask((direction == src2dst_direction) ? theFlow->src->host : theFlow->dst->host));
    break;
  case 10: /* INPUT_SNMP */
    snprintf(dst, (line_buffer_len-len), "%d", (direction == src2dst_direction) ? theFlow->if_input : theFlow->if_output);
    break;
  case 11:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == src2dst_direction ? theFlow->dport : theFlow->sport);
    break;
  case 0xFF+11:
    snprintf(dst, (line_buffer_len-len), "%s",
	     port2name(direction == src2dst_direction ? theFlow->dport : theFlow->sport, theFlow->proto));
    break;
  case 12:
  case 28:
    snprintf(dst, (line_buffer_len-len), "%s",
	     _intoa(direction == src2dst_direction ? theFlow->dst->host : theFlow->src->host, buf, sizeof(buf)));
    break;
  case 13: /* IPV4_DST_MASK */
    snprintf(dst, (line_buffer_len-len), "%d",
	     ip2mask((direction == dst2src_direction) ? theFlow->src->host : theFlow->dst->host));
    break;
  case 14: /* OUTPUT_SNMP */
    snprintf(dst, (line_buffer_len-len), "%d", (direction != src2dst_direction) ? theFlow->if_input : theFlow->if_output);
    break;
  case 15: /* IPV4_NEXT_HOP */
    snprintf(dst, (line_buffer_len-len), "%d", 0);
    break;
  case 16: /* SRC_AS */
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == src2dst_direction ? getAS(theFlow, 1) : getAS(theFlow, 0));
    break;
  case 17: /* DST_AS */
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == src2dst_direction ? getAS(theFlow, 0) : getAS(theFlow, 1));
    break;
    case 21:
      snprintf(dst, (line_buffer_len-len), "%u",
	       (unsigned int)(direction == src2dst_direction ? theFlow->flowTimers.lastSeenSent.tv_sec :
			      theFlow->flowTimers.lastSeenRcvd.tv_sec));
    break;
  case 22:
    snprintf(dst, (line_buffer_len-len), "%u",
	     (unsigned int)(direction == src2dst_direction ? theFlow->flowTimers.firstSeenSent.tv_sec :
			    theFlow->flowTimers.firstSeenRcvd.tv_sec));
    break;
  case 23:
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == dst2src_direction ? theFlow->flowCounters.bytesSent : theFlow->flowCounters.bytesRcvd);
    break;
  case 24:
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == dst2src_direction ? theFlow->flowCounters.sentFragPkts : theFlow->flowCounters.rcvdFragPkts);
    break;
  case 29:
  case 30:
    snprintf(dst, (line_buffer_len-len), "%d", 0);
    break;
  case 32:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == src2dst_direction ? theFlow->src2dstIcmpType : theFlow->dst2srcIcmpType);
    break;
  case 34: /* SAMPLING INTERVAL */
    snprintf(dst, (line_buffer_len-len), "%d", 1 /* 1:1 = no sampling */);
    break;
  case 35: /* SAMPLING ALGORITHM */
    snprintf(dst, (line_buffer_len-len), "%d",
	     0x01 /* 1=Deterministic Sampling, 0x02=Random Sampling */);
    break;
  case 36: /* FLOW ACTIVE TIMEOUT */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readOnlyGlobals.lifetimeTimeout);
    break;
  case 37: /* FLOW INACTIVE TIMEOUT */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readOnlyGlobals.idleTimeout);
    break;
  case 38:
    snprintf(dst, (line_buffer_len-len), "%d",
	     readOnlyGlobals.engineType);
    break;
  case 39:
    snprintf(dst, (line_buffer_len-len), "%d",
	     readOnlyGlobals.engineId);
    break;
  case 40: /* TOTAL_BYTES_EXP */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readWriteGlobals->flowExportStats.totExportedBytes);
    break;
  case 41: /* TOTAL_PKTS_EXP */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readWriteGlobals->flowExportStats.totExportedPkts);
    break;
  case 42: /* TOTAL_FLOWS_EXP */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readWriteGlobals->flowExportStats.totExportedFlows);
    break;
  case 56: /* IN_SRC_MAC */
    snprintf(dst, (line_buffer_len-len), "%s",
	     direction == src2dst_direction ? etheraddr_string(theFlow->srcMacAddress, buf)
	     : etheraddr_string(theFlow->dstMacAddress, buf));
    break;
  case 58: /* SRC_VLAN */
  case 59: /* DST_VLAN */
    snprintf(dst, (line_buffer_len-len), "%d", theFlow->vlanId);
    break;
  case 60: /* IP_PROTOCOL_VERSION */
    snprintf(dst, (line_buffer_len-len), "%d",
	     (theFlow->src->host.ipVersion == 4) && (theFlow->dst->host.ipVersion == 4) ? 4 : 6);
    break;
  case 61: /* Direction */
    snprintf(dst, (line_buffer_len-len), "%d", 0);
    break;
  case 62: /* IPV6_NEXT_HOP */
    snprintf(dst, (line_buffer_len-len), "[::]" /* Same as 0.0.0.0 in IPv4 */);
    break;
  case 70: /* MPLS: label 1 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 0));
    break;
  case 71: /* MPLS: label 2 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 1));
    break;
  case 72: /* MPLS: label 3 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 2));
    break;
  case 73: /* MPLS: label 4 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 3));
    break;
  case 74: /* MPLS: label 5 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 4));
    break;
  case 75: /* MPLS: label 6 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 5));
    break;
  case 76: /* MPLS: label 7 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 6));
    break;
  case 77: /* MPLS: label 8 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 7));
    break;
  case 78: /* MPLS: label 9 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 8));
    break;
  case 79: /* MPLS: label 10 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 9));
    break;
  case 80: /* OUT_DST_MAC */
    snprintf(dst, (line_buffer_len-len), "%s",
	     direction == src2dst_direction ? etheraddr_string(theFlow->dstMacAddress, buf)
	     : etheraddr_string(theFlow->srcMacAddress, buf));
    break;

  case 148: /* FLOW_ID */
    snprintf(dst, (line_buffer_len-len), "%u", theFlow->flow_idx);
    break;

    /* ************************************ */

    /* nProbe Extensions */
  case NTOP_BASE_ID+80:
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == src2dst_direction ? theFlow->flowCounters.sentFragPkts : theFlow->flowCounters.rcvdFragPkts);
    break;
#if 0
  case NTOP_BASE_ID+81:
    break;
#endif
  case NTOP_BASE_ID+82:
    snprintf(dst, (line_buffer_len-len), "%d",
	     (int)(nwLatencyComputed(theFlow) ? theFlow->clientNwDelay.tv_sec : 0));
    break;
  case NTOP_BASE_ID+83:
    snprintf(dst, (line_buffer_len-len), "%u",
	     nwLatencyComputed(theFlow) ? (u_int32_t)theFlow->clientNwDelay.tv_usec : 0);
    break;
  case NTOP_BASE_ID+84:
    snprintf(dst, (line_buffer_len-len), "%u",
	     (int)(nwLatencyComputed(theFlow) ? (u_int32_t)theFlow->serverNwDelay.tv_sec : 0));
    break;
  case NTOP_BASE_ID+85:
    snprintf(dst, (line_buffer_len-len), "%u",
	     nwLatencyComputed(theFlow) ? (u_int32_t)theFlow->serverNwDelay.tv_usec : 0);
    break;

  case NTOP_BASE_ID+86:
    snprintf(dst, (line_buffer_len-len), "%u",
	     (u_int32_t)(applLatencyComputed(theFlow) ?
			 (direction == src2dst_direction ? theFlow->src2dstApplLatency.tv_sec
			  : theFlow->dst2srcApplLatency.tv_sec) : 0));
    break;
  case NTOP_BASE_ID+87:
    snprintf(dst, (line_buffer_len-len), "%d",
	     (u_int32_t)(applLatencyComputed(theFlow) ?
			 (direction == src2dst_direction ? theFlow->src2dstApplLatency.tv_usec
			  : theFlow->dst2srcApplLatency.tv_usec) : 0));
    break;
  case NTOP_BASE_ID+IN_PAYLOAD_ID:
  case NTOP_BASE_ID+OUT_PAYLOAD_ID:
    {
      int idx, len;

      if((theTemplateElement->templateElementId == IN_PAYLOAD_ID)
	 || (theTemplateElement->templateElementId == OUT_PAYLOAD_ID))
	len = theFlow->src2dstPayloadLen;
      else
	len = theFlow->dst2srcPayloadLen;

      for(idx=0; idx<len; idx++)
	snprintf(dst, (line_buffer_len-len), "%c",
		 ((theTemplateElement->templateElementId == IN_PAYLOAD_ID)
		  || (theTemplateElement->templateElementId == OUT_PAYLOAD_ID))
		 ? theFlow->src2dstPayload[idx] : theFlow->dst2srcPayload[idx]);
    }
    break;
  case NTOP_BASE_ID+98:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == src2dst_direction ? theFlow->src2dstIcmpFlags : theFlow->dst2srcIcmpFlags);
    break;

  case NTOP_BASE_ID+101: /* SRC_IP_COUNTRY */
#ifdef HAVE_GEOIP
    geo = (direction == src2dst_direction) ? theFlow->src->geo : theFlow->dst->geo;
#endif
    snprintf(dst, (line_buffer_len-len), "%s",
#ifdef HAVE_GEOIP
	     (geo && geo->country_code) ? geo->country_code :
#endif
	     "");
    break;

  case NTOP_BASE_ID+102: /* SRC_IP_CITY */
#ifdef HAVE_GEOIP
    geo = (direction == src2dst_direction) ? theFlow->src->geo : theFlow->dst->geo;
#endif
    snprintf(dst, (line_buffer_len-len), "%s",
#ifdef HAVE_GEOIP
	     (geo && geo->city) ? geo->city :
#endif
	     "");
    break;

  case NTOP_BASE_ID+103: /* DST_IP_COUNTRY */
#ifdef HAVE_GEOIP
    geo = (direction == src2dst_direction) ? theFlow->dst->geo : theFlow->src->geo;
#endif
    snprintf(dst, (line_buffer_len-len), "%s",
#ifdef HAVE_GEOIP
	     (geo && geo->country_code) ? geo->country_code :
#endif
	     "");
    break;

  case NTOP_BASE_ID+104: /* DST_IP_CITY */
#ifdef HAVE_GEOIP
    geo = (direction == src2dst_direction) ? theFlow->dst->geo : theFlow->src->geo;
#endif
    snprintf(dst, (line_buffer_len-len), "%s",
#ifdef HAVE_GEOIP
	     (geo && geo->city) ? geo->city :
#endif
	     "");
    break;

  case NTOP_BASE_ID+105: /* FLOW_PROTO_PORT */
    snprintf(dst, (line_buffer_len-len), "%u", getFlowApplProtocol(theFlow));
    break;

  case NTOP_BASE_ID+106: /* TUNNEL_ID */
    snprintf(dst, (line_buffer_len-len), "%u", theFlow->tunnel_id);
    break;

  case NTOP_BASE_ID+107: /* LONGEST_FLOW_PKT */
    snprintf(dst, (line_buffer_len-len), "%u",
	     theFlow->flowCounters.pktSize.longest);
    break;

  case NTOP_BASE_ID+108: /* SHORTEST_FLOW_PKT */
    snprintf(dst, (line_buffer_len-len), "%u",
	     theFlow->flowCounters.pktSize.shortest);
    break;

  case NTOP_BASE_ID+109: /* RETRANSMITTED_IN_PKTS */
    snprintf(dst, (line_buffer_len-len), "%u",
	     (direction == dst2src_direction) ? theFlow->flowCounters.tcpPkts.rcvdRetransmitted :
	     theFlow->flowCounters.tcpPkts.sentRetransmitted);
    break;

  case NTOP_BASE_ID+110: /* RETRANSMITTED_OUT_PKTS */
    snprintf(dst, (line_buffer_len-len), "%u",
	     (direction == src2dst_direction) ? theFlow->flowCounters.tcpPkts.rcvdRetransmitted :
	     theFlow->flowCounters.tcpPkts.sentRetransmitted);
    break;

  case NTOP_BASE_ID+111: /* OOORDER_IN_PKTS */
    snprintf(dst, (line_buffer_len-len), "%u",
	     (direction == dst2src_direction) ? theFlow->flowCounters.tcpPkts.rcvdOOOrder :
	     theFlow->flowCounters.tcpPkts.sentOOOrder);
    break;

  case NTOP_BASE_ID+112: /* OOORDER_OUT_PKTS */
    snprintf(dst, (line_buffer_len-len), "%u",
	     (direction == src2dst_direction) ? theFlow->flowCounters.tcpPkts.rcvdOOOrder :
	     theFlow->flowCounters.tcpPkts.sentOOOrder);
    break;

  case NTOP_BASE_ID+113: /* UNTUNNELED_PROTOCOL */
    snprintf(dst, (line_buffer_len-len), "%d",
	     (readOnlyGlobals.tunnel_mode == 0) ? 0 : theFlow->untunneled.proto);
    break;

  case NTOP_BASE_ID+114: /* UNTUNNELED_IPV4_SRC_ADDR */
    snprintf(dst, (line_buffer_len-len), "%s",
	     ((readOnlyGlobals.tunnel_mode == 0) || (theFlow->untunneled.proto == 0)) ? "" :
	     (_intoa(direction == src2dst_direction ? theFlow->untunneled.src->host :
		     theFlow->untunneled.dst->host, buf, sizeof(buf))));
    break;

  case NTOP_BASE_ID+115: /* UNTUNNELED_L4_SRC_PORT */
    snprintf(dst, (line_buffer_len-len), "%d",
	     (readOnlyGlobals.tunnel_mode == 0) ? 0 :
	     (direction == src2dst_direction ? theFlow->untunneled.sport : theFlow->untunneled.dport));
    break;

  case NTOP_BASE_ID+116: /* UNTUNNELED_IPV4_DST_ADDR */
    snprintf(dst, (line_buffer_len-len), "%s",
	     ((readOnlyGlobals.tunnel_mode == 0) || (theFlow->untunneled.proto == 0)) ? "" :
	     (_intoa(direction == src2dst_direction ? theFlow->untunneled.dst->host :
		     theFlow->untunneled.src->host, buf, sizeof(buf))));
    break;

  case NTOP_BASE_ID+117: /* UNTUNNELED_L4_DST_PORT */
    snprintf(dst, (line_buffer_len-len), "%d",
	     (readOnlyGlobals.tunnel_mode == 0) ? 0 :
	     (direction == src2dst_direction ? theFlow->untunneled.dport : theFlow->untunneled.sport));
    break;

  default:
    checkPluginPrint(theTemplateElement, direction, theFlow,
		     line_buffer, line_buffer_len);
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "name=%s/Id=%d\n",
	     theTemplateElement->templateElementName,
	     theTemplateElement->templateElementId);
#endif
}

/* ******************************************** */

void flowPrintf(V9V10TemplateElementId **templateList,
		u_int8_t ipv4_template, char *outBuffer,
		uint *outBufferBegin, uint *outBufferMax,
		int *numElements, char buildTemplate,
		FlowHashBucket *theFlow, FlowDirection direction,
		int addTypeLen, int optionTemplate) {
  int idx = 0;

  (*numElements) = 0;

  while(templateList[idx] != NULL) {
    handleTemplate(templateList[idx], ipv4_template,
		   outBuffer, outBufferBegin, outBufferMax,
		   buildTemplate, numElements,
		   theFlow, direction, addTypeLen,
		   optionTemplate);
    idx++;
  }
}

/* ******************************************** */

void flowFilePrintf(V9V10TemplateElementId **templateList,
		    FILE *stream, FlowHashBucket *theFlow, FlowDirection direction) {
  int idx = 0;
  char line_buffer[2048] = { '\0' };

  readWriteGlobals->sql_row_idx++;
  if(readOnlyGlobals.dumpFormat == sqlite_format)
    snprintf(&line_buffer[strlen(line_buffer)],
	     sizeof(line_buffer), "insert into flows values ('");

  while(templateList[idx] != NULL) {
    if(idx > 0) {
      if(readOnlyGlobals.dumpFormat == sqlite_format)
	snprintf(&line_buffer[strlen(line_buffer)], sizeof(line_buffer), "','");
      else
	snprintf(&line_buffer[strlen(line_buffer)], sizeof(line_buffer), "%s",
		 readOnlyGlobals.csv_separator);
    }

    printRecordWithTemplate(templateList[idx], line_buffer,
			    sizeof(line_buffer), theFlow, direction);
    idx++;
  }

  if(readOnlyGlobals.dumpFormat == sqlite_format) {
    snprintf(&line_buffer[strlen(line_buffer)], sizeof(line_buffer), "');");
#ifdef HAVE_SQLITE
    sqlite_exec_sql(line_buffer);
#endif
  } else
    fprintf(stream, "%s\n", line_buffer);
}

/* ******************************************** */

void compileTemplate(char *_fmt, V9V10TemplateElementId **templateList, int templateElements) {
  int idx=0, endIdx, i, templateIdx, len = strlen(_fmt);
  char fmt[1024], tmpChar, found;
  u_int8_t ignored;

  /* Change \n and \r (if any) to space */
  for(i=0; _fmt[i] != '\0'; i++) {
    switch(_fmt[i]) {
    case '\r':
    case '\n':
      _fmt[i] = ' ';
      break;
    }
  }

  templateIdx = 0;
  snprintf(fmt, sizeof(fmt), "%s", _fmt);

  while((idx < len) && (fmt[idx] != '\0')) {	/* scan format string characters */
    switch(fmt[idx]) {
    case '%':	        /* special format follows */
      endIdx = ++idx;
      while(fmt[endIdx] != '\0') {
	if((fmt[endIdx] == ' ') || (fmt[endIdx] == '%'))
	  break;
	else
	  endIdx++;
      }

      if((endIdx == (idx+1)) && (fmt[endIdx] == '\0')) return;
      tmpChar = fmt[endIdx]; fmt[endIdx] = '\0';

      ignored = 0;

      if(strstr(&fmt[idx], "MYSQL")) readOnlyGlobals.enableMySQLPlugin = 1;

      if(strstr(&fmt[idx], "_COUNTRY") || strstr(&fmt[idx], "_CITY")) {
#ifdef HAVE_GEOIP
	if(readOnlyGlobals.geo_ip_city_db == NULL) {
	  traceEvent(TRACE_WARNING, "Geo-location requires --city-list to be specified: ignored %s", &fmt[idx]);
	  ignored = 1;
	}
#else
	ignored = 1;
#endif
      }

      /* traceEvent(TRACE_WARNING, "Checking '%s' [ignored=%d]", &fmt[idx], ignored); */

      if(!ignored) {
	int duplicate_found = 0;

	i = 0, found = 0;

	while(ver9_templates[i].templateElementName != NULL) {
	  if((strcmp(&fmt[idx], ver9_templates[i].templateElementName) == 0)
	     || ((strncmp(ver9_templates[i].templateElementName, &fmt[idx], 
			  strlen(ver9_templates[i].templateElementName)) == 0) 
		 && (ver9_templates[i].variableFieldLength == VARIABLE_FIELD_LEN))
	     ) {
	    int j;

	    for(j=0; j<templateIdx; j++) {
	      if(templateList[j] == &ver9_templates[i]) {
		traceEvent(TRACE_INFO, "Duplicate template element found %s: skipping", &fmt[idx]);
		duplicate_found = 1;
		break;
	      }
	    }

	    if(!duplicate_found) {
	      templateList[templateIdx++] = &ver9_templates[i];
	      if(ver9_templates[i].useLongSnaplen) readOnlyGlobals.snaplen = PCAP_LONG_SNAPLEN;
	      found = 1;
	    }

	    break;
	  }

	  /* traceEvent(TRACE_WARNING, "Checking [%s][%s][found=%d]", &fmt[idx], ver9_templates[i].templateElementName, found); */

	  i++;
	}

	if(!duplicate_found) {
	  /* traceEvent(TRACE_WARNING, "Checking [%s][found=%d]", &fmt[idx], found); */

	  if(!found) {
	    if((templateList[templateIdx] = getPluginTemplate(&fmt[idx])) != NULL) {
	      if(templateList[templateIdx]->useLongSnaplen) readOnlyGlobals.snaplen = PCAP_LONG_SNAPLEN;
	      templateIdx++;
	    } else {
	      traceEvent(TRACE_WARNING, "Unable to locate template '%s'. Discarded.", &fmt[idx]);
	    }
	  }

	  if(templateIdx >= (templateElements-1)) {
	    traceEvent(TRACE_WARNING, "Unable to add further template elements (%d).", templateIdx);
	    break;
	  }
	}
      }

      fmt[endIdx] = tmpChar;
      if(tmpChar == '%')
	idx = endIdx;
      else
	idx = endIdx+1;
      break;

    default:
      idx++;
      break;
    }
  }

  templateList[templateIdx] = NULL;
}

/* ******************************************** */

double toMs(struct timeval theTime) {
  return((double)theTime.tv_sec+((double)theTime.tv_usec)/1000000);
}

/* ****************************************************** */

u_int32_t msTimeDiff(struct timeval *end, struct timeval *begin) {
  if((end->tv_sec == 0) && (end->tv_usec == 0))
    return(0);
  else
    return((end->tv_sec-begin->tv_sec)*1000+(end->tv_usec-begin->tv_usec)/1000);
}

/* ****************************************************** */

#ifndef WIN32
int createCondvar(ConditionalVariable *condvarId) {
  int rc;

  pthread_mutex_init(&condvarId->mutex, NULL);
  rc = pthread_cond_init(&condvarId->condvar, NULL);
  condvarId->predicate = 0;

  return(rc);
}

/* ************************************ */

void deleteCondvar(ConditionalVariable *condvarId) {
  pthread_mutex_destroy(&condvarId->mutex);
  pthread_cond_destroy(&condvarId->condvar);
}

/* ************************************ */

int waitCondvar(ConditionalVariable *condvarId) {
  int rc;

  if((rc = pthread_mutex_lock(&condvarId->mutex)) != 0)
    return rc;

  while(condvarId->predicate <= 0)
    pthread_cond_wait(&condvarId->condvar, &condvarId->mutex);

  condvarId->predicate--;

  rc = pthread_mutex_unlock(&condvarId->mutex);

  return rc;
}
/* ************************************ */

int signalCondvar(ConditionalVariable *condvarId, int broadcast) {
  int rc;

  pthread_mutex_lock(&condvarId->mutex);
  condvarId->predicate++;
  pthread_mutex_unlock(&condvarId->mutex);

  if(broadcast)
    rc = pthread_cond_broadcast(&condvarId->condvar);
  else
    rc = pthread_cond_signal(&condvarId->condvar);

  return rc;
}

#undef sleep /* Used by ntop_sleep */

#else /* WIN32 */

/* ************************************ */

int createCondvar(ConditionalVariable *condvarId) {
  condvarId->condVar = CreateEvent(NULL,  /* no security */
				   TRUE , /* auto-reset event (FALSE = single event, TRUE = broadcast) */
				   FALSE, /* non-signaled initially */
				   NULL); /* unnamed */
  InitializeCriticalSection(&condvarId->criticalSection);
  return(1);
}

/* ************************************ */

void deleteCondvar(ConditionalVariable *condvarId) {
  CloseHandle(condvarId->condVar);
  DeleteCriticalSection(&condvarId->criticalSection);
}

/* ************************************ */

int waitCondvar(ConditionalVariable *condvarId) {
  int rc;
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Wait (%x)...", condvarId->condVar);
#endif
  EnterCriticalSection(&condvarId->criticalSection);
  rc = WaitForSingleObject(condvarId->condVar, INFINITE);
  LeaveCriticalSection(&condvarId->criticalSection);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Got signal (%d)...", rc);
#endif

  return(rc);
}

/* ************************************ */

/* NOTE: broadcast is currently ignored */
int signalCondvar(ConditionalVariable *condvarId, int broadcast) {
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Signaling (%x)...", condvarId->condVar);
#endif
  return((int)PulseEvent(condvarId->condVar));
}

#define sleep(a /* sec */) waitForNextEvent(1000*a /* ms */)

#endif /* WIN32 */

/* ******************************************* */

unsigned int ntop_sleep(unsigned int secs) {
  unsigned int unsleptTime = secs, rest;

  while((rest = sleep(unsleptTime)) > 0)
    unsleptTime = rest;

  return(secs);
}

/* ******************************************* */

FlowHashBucket* getListHead(FlowHashBucket **list) {
  FlowHashBucket *bkt = *list;

  if(bkt == NULL)
    traceEvent(TRACE_ERROR, "INTERNAL ERROR: getListHead is empty");
  else
    (*list) = bkt->next;

  return(bkt);
}

/* ******************************************* */

void addToList(FlowHashBucket *bkt, FlowHashBucket **list) {
  bkt->next = *list;
  (*list) = bkt;
}

/* **************************************** */

#ifndef WIN32

void detachFromTerminal(int doChdir) {
  if(doChdir) {
    int rc = chdir("/");
    if(rc != 0) traceEvent(TRACE_ERROR, "Error while moving to / directory");
  }

  setsid();  /* detach from the terminal */

  fclose(stdin);
  fclose(stdout);
  /* fclose(stderr); */

  /*
   * clear any inherited file mode creation mask
   */
  umask (0);

  /*
   * Use line buffered stdout
   */
  /* setlinebuf (stdout); */
  setvbuf(stdout, (char *)NULL, _IOLBF, 0);
}

/* **************************************** */

void daemonize(void) {
  int childpid;

  signal(SIGHUP, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);

  if((childpid = fork()) < 0)
    traceEvent(TRACE_ERROR, "INIT: Occurred while daemonizing (errno=%d)", errno);
  else {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "DEBUG: after fork() in %s (%d)",
	       childpid ? "parent" : "child", childpid);
#endif
    if(!childpid) { /* child */
      traceEvent(TRACE_INFO, "INIT: Bye bye: I'm becoming a daemon...");
      detachFromTerminal(1);
    } else { /* father */
      traceEvent(TRACE_INFO, "INIT: Parent process is exiting (this is normal)");
      exit(0);
    }
  }
}

#endif /* WIN32 */

/* ****************************************

   Address management

   **************************************** */

static int int2bits(int number) {
  int bits = 8;
  int test;

  if((number > 255) || (number < 0))
    return(CONST_INVALIDNETMASK);
  else {
    test = ~number & 0xff;
    while (test & 0x1)
      {
	bits --;
	test = test >> 1;
      }
    if(number != ((~(0xff >> bits)) & 0xff))
      return(CONST_INVALIDNETMASK);
    else
      return(bits);
  }
}

/* ********************** */

static int dotted2bits(char *mask) {
  int		fields[4];
  int		fields_num, field_bits;
  int		bits = 0;
  int		i;

  fields_num = sscanf(mask, "%d.%d.%d.%d",
		      &fields[0], &fields[1], &fields[2], &fields[3]);
  if((fields_num == 1) && (fields[0] <= 32) && (fields[0] >= 0))
    {
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: dotted2bits (%s) = %d", mask, fields[0]);
#endif
      return(fields[0]);
    }
  for (i=0; i < fields_num; i++)
    {
      /* We are in a dotted quad notation. */
      field_bits = int2bits (fields[i]);
      switch (field_bits)
	{
	case CONST_INVALIDNETMASK:
	  return(CONST_INVALIDNETMASK);

	case 0:
	  /* whenever a 0 bits field is reached there are no more */
	  /* fields to scan                                       */
	  /* In this case we are in a bits (not dotted quad) notation */
	  return(bits /* fields[0] - L.Deri 08/2001 */);

	default:
	  bits += field_bits;
	}
    }
  return(bits);
}

/* ********************************* */

static char* read_file(char* path, char* buf, uint buf_len) {
  FILE *fd = fopen(&path[1], "r");

  if(fd == NULL) {
    traceEvent(TRACE_WARNING, "Unable to read file %s", path);
    return(NULL);
  } else {
    char line[256];
    int idx = 0;

    while(!feof(fd) && (fgets(line, sizeof(line), fd) != NULL)) {
      if((line[0] == '#') || (line[0] == '\n')) continue;
      while(strlen(line) && (line[strlen(line)-1] == '\n')) {
	line[strlen(line)-1] = '\0';
      }

      snprintf(&buf[idx], buf_len-idx-2, "%s%s", (idx > 0) ? "," : "", line);
      idx = strlen(buf);
    }

    fclose(fd);
    return(buf);
  }
}

/* ********************************* */

static u_int8_t num_network_bits(u_int32_t addr) {
  u_int8_t i, j, bits = 0, fields[4];

  memcpy(fields, &addr, 4);

  for(i = 8; i <= 8; i--)
    for(j=0; j<4; j++)
      if ((fields[j] & (1 << i)) != 0) bits++;

  return(bits);
}

/* ********************** */

typedef struct {
  u_int32_t network;
  u_int32_t networkMask;
  u_int32_t broadcast;
} netAddress_t;

int parseAddress(char * address, netAddress_t * netaddress) {
  u_int32_t network, networkMask, broadcast;
  int bits, a, b, c, d;
  char *mask = strchr(address, '/');

  mask[0] = '\0';
  mask++;
  bits = dotted2bits (mask);

  if(sscanf(address, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
    return -1;

  if(bits == CONST_INVALIDNETMASK) {
    traceEvent(TRACE_WARNING, "netmask '%s' not valid - ignoring entry", mask);
    /* malformed netmask specification */
    return -1;
  }

  network = ((a & 0xff) << 24) + ((b & 0xff) << 16) + ((c & 0xff) << 8) + (d & 0xff);
  /* Special case the /32 mask - yeah, we could probably do it with some fancy
     u long long stuff, but this is simpler...
     Burton Strauss <Burton@ntopsupport.com> Jun2002
  */
  if(bits == 32) {
    networkMask = 0xffffffff;
  } else {
    networkMask = 0xffffffff >> bits;
    networkMask = ~networkMask;
  }

  if((network & networkMask) != network)  {
    /* malformed network specification */

    traceEvent(TRACE_WARNING, "%d.%d.%d.%d/%d is not a valid network - correcting mask",
	       a, b, c, d, bits);
    /* correcting network numbers as specified in the netmask */
    network &= networkMask;

    /*
      a = (int) ((network >> 24) & 0xff);
      b = (int) ((network >> 16) & 0xff);
      c = (int) ((network >>  8) & 0xff);
      d = (int) ((network >>  0) & 0xff);

      traceEvent(CONST_TRACE_NOISY, "Assuming %d.%d.%d.%d/%d [0x%08x/0x%08x]",
      a, b, c, d, bits, network, networkMask);
    */
  }

  broadcast = network | (~networkMask);

  a = (int) ((network >> 24) & 0xff);
  b = (int) ((network >> 16) & 0xff);
  c = (int) ((network >>  8) & 0xff);
  d = (int) ((network >>  0) & 0xff);

  traceEvent(TRACE_INFO, "Adding %d.%d.%d.%d/%d to the local network list",
	     a, b, c, d, bits);

  netaddress->network     = network;
  netaddress->networkMask = networkMask;
  netaddress->broadcast   = broadcast;

  return 0;
}

/* ********************** */

void parseLocalAddressLists(char* _addresses) {
  char *address, *addresses, *strTokState = NULL, buf[2048];

  readOnlyGlobals.numLocalNetworks = 0;

  if((_addresses == NULL) || (_addresses[0] == '\0'))
    return;
  else if(_addresses[0] == '@') {
    addresses = strdup(read_file(_addresses, buf, sizeof(buf)));
  } else
    addresses = strdup(_addresses);

  address = strtok_r(addresses, ",", &strTokState);

  while(address != NULL) {
    char *mask = strchr(address, '/');

    if(mask == NULL) {
      traceEvent(TRACE_WARNING, "Empty mask '%s' - ignoring entry", address);
    } else {
      netAddress_t netaddress;

      if(readOnlyGlobals.numLocalNetworks >= MAX_NUM_NETWORKS) {
	traceEvent(TRACE_WARNING, "Too many networks defined (-L): skipping further networks");
	break;
      }

      if(parseAddress(address, &netaddress)==-1) {
	address = strtok_r(NULL, ",", &strTokState);
	continue;
      }

      /* NOTE: entries are saved in network byte order for performance reasons */
      readOnlyGlobals.localNetworks[readOnlyGlobals.numLocalNetworks].network    = htonl(netaddress.network);
      readOnlyGlobals.localNetworks[readOnlyGlobals.numLocalNetworks].netmask    = htonl(netaddress.networkMask);
      readOnlyGlobals.localNetworks[readOnlyGlobals.numLocalNetworks].broadcast  = htonl(netaddress.broadcast);
      readOnlyGlobals.localNetworks[readOnlyGlobals.numLocalNetworks].netmask_v6 = num_network_bits(netaddress.networkMask); /* Host byte-order */
      readOnlyGlobals.numLocalNetworks++;
    }

    address = strtok_r(NULL, ",", &strTokState);
  }

  free(addresses);
}

/* ********************** */

#define MAX_NUM_ENTRIES 256

struct net_sort {
  u_int mask;
  char *network;
};

int cmpNet(const void *_a, const void *_b) {
  struct net_sort *a = (struct net_sort*)_a;
  struct net_sort *b = (struct net_sort*)_b;

  if(a->mask == b->mask) return(0);
  else if(a->mask > b->mask) return(-1);
  else return(1);
}

/* ********************** */

char *sortNetworks(char *_addresses) {
  int num = 0, i, len = strlen(_addresses)+1;
  char  *strTokState = NULL, *address;
  struct net_sort nwsort[MAX_NUM_ENTRIES];
    
  address = strtok_r(_addresses, ",", &strTokState);

  while(address != NULL) {  
    if(num < MAX_NUM_ENTRIES) {
      char *mask = strchr(address, '/');
      
      if(mask != NULL) {
	nwsort[num].mask = atoi(&mask[1]);
	nwsort[num++].network = address;
      }
    }

    address = strtok_r(NULL, ",", &strTokState);
  }

  qsort(nwsort, num, sizeof(struct net_sort), cmpNet);

  address = (char*)malloc(len);
  if(address == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory");
    return(_addresses);
  } else
    address[0] = '\0';

  for(i=0; i<num; i++) {
    // traceEvent(TRACE_WARNING, "%s => %d", nwsort[i].network, nwsort[i].mask);
    sprintf(&address[strlen(address)], "%s%s", (i == 0) ? "" : ",", nwsort[i].network);
  }

  /* traceEvent(TRACE_WARNING, "<=> '%s'", address); */

  return(address);
}

/* ********************** */

void parseInterfaceAddressLists(char* _addresses) {
  char *address, *addresses, *strTokState = NULL, buf[2048];

  readOnlyGlobals.numInterfaceNetworks = 0;

  if((_addresses == NULL) || (_addresses[0] == '\0'))
    return;
  else if(_addresses[0] == '@') {
    addresses = strdup(read_file(_addresses, buf, sizeof(buf)));
  } else
    addresses = strdup(_addresses);

  addresses = sortNetworks(addresses);

  address = strtok_r(addresses, ",", &strTokState);

  while(address != NULL) {
    char *mask;
    char *at = strchr(address, '@');

    /* traceEvent(TRACE_WARNING, "Parsing %s", address); */

    mask = strchr(address, '/');

    if(mask == NULL) {
      /* Maybe this is a MAC address */
      uint a, b, c, d, e, f, ifIdx;

      if(sscanf(optarg, "%2X:%2X:%2X:%2X:%2X:%2X@%d", &a, &b, &c, &d, &e, &f, &ifIdx) != 7) {
	traceEvent(TRACE_WARNING,
		   "WARNING: Wrong MAC address/Interface specified (format AA:BB:CC:DD:EE:FF@4) "
		   "with '-L': ignored");
      } else {
	if(readWriteGlobals->num_src_mac_export >= NUM_MAC_INTERFACES) {
	  traceEvent(TRACE_ERROR, "Too many '-L' specified. Ignored.");
	  break;
	} else {
	  readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].mac_address[0] = a,
	    readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].mac_address[1] = b,
	    readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].mac_address[2] = c,
	    readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].mac_address[3] = d,
	    readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].mac_address[4] = e,
	    readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].mac_address[5] = f,
	    readOnlyGlobals.mac_if_match[readWriteGlobals->num_src_mac_export].interface_id = ifIdx;
	  readWriteGlobals->num_src_mac_export++;
	}
      }
    } else {
      netAddress_t netaddress;

      if(readOnlyGlobals.numInterfaceNetworks >= MAX_NUM_NETWORKS) {
	traceEvent(TRACE_WARNING, "Too many networks defined (-L): skipping further networks");
	break;
      } 

      if(at == NULL) {
	traceEvent(TRACE_WARNING, "Invalid format for network %s: ignored", address);
      } else {
	at[0] = '\0';
	if(parseAddress(address, &netaddress) == -1) {
	  address = strtok_r(NULL, ",", &strTokState);
	  continue;
	}
	
	/* NOTE: entries are saved in network byte order for performance reasons */
	readOnlyGlobals.interfaceNetworks[readOnlyGlobals.numInterfaceNetworks].network    = htonl(netaddress.network);
	readOnlyGlobals.interfaceNetworks[readOnlyGlobals.numInterfaceNetworks].netmask    = htonl(netaddress.networkMask);
	readOnlyGlobals.interfaceNetworks[readOnlyGlobals.numInterfaceNetworks].broadcast  = htonl(netaddress.broadcast);
	readOnlyGlobals.interfaceNetworks[readOnlyGlobals.numInterfaceNetworks].netmask_v6 = num_network_bits(netaddress.networkMask); /* Host byte-order */
	readOnlyGlobals.interfaceNetworks[readOnlyGlobals.numInterfaceNetworks].interface_id = atoi(&at[1]);
	readOnlyGlobals.numInterfaceNetworks++;
      }
    }

    address = strtok_r(NULL, ",", &strTokState);
  }

  free(addresses);
}

/* ************************************************ */

void parseBlacklistNetworks(char* _addresses) {
  char *address, *addresses, buf[2048], *strTokState = NULL;

  readOnlyGlobals.numBlacklistNetworks = 0;

  if((_addresses == NULL) || (_addresses[0] == '\0'))
    return;
  else if(_addresses[0] == '@') {
    addresses = strdup(read_file(_addresses, buf, sizeof(buf)));
  } else
    addresses = strdup(_addresses);

  address = strtok_r(addresses, ",", &strTokState);

  while(address != NULL) {
    char *mask = strchr(address, '/');

    if(mask == NULL) {
      traceEvent(TRACE_WARNING, "Empty mask '%s' - ignoring entry", address);
    } else {
      netAddress_t netaddress;

      if(readOnlyGlobals.numBlacklistNetworks >= MAX_NUM_NETWORKS) {
	traceEvent(TRACE_WARNING, "Too many networks defined (--black-list): skipping further networks");
	break;
      }

      if (parseAddress(address,&netaddress)==-1) {
	address = strtok_r(NULL, ",", &strTokState);
	continue;
      }

      /* NOTE: entries are saved in network byte order for performance reasons */
      readOnlyGlobals.blacklistNetworks[readOnlyGlobals.numBlacklistNetworks].network    = htonl(netaddress.network);
      readOnlyGlobals.blacklistNetworks[readOnlyGlobals.numBlacklistNetworks].netmask    = htonl(netaddress.networkMask);
      readOnlyGlobals.blacklistNetworks[readOnlyGlobals.numBlacklistNetworks].broadcast  = htonl(netaddress.broadcast);
      readOnlyGlobals.blacklistNetworks[readOnlyGlobals.numBlacklistNetworks].netmask_v6 = num_network_bits(netaddress.networkMask); /* Host byte-order */
      readOnlyGlobals.numBlacklistNetworks++;
    }

    address = strtok_r(NULL, ",", &strTokState);
  }

  free(addresses);
}

/* ************************************************ */

//#define DEBUG
#undef DEBUG

static u_int8_t getIfIdx(struct in_addr *addr, u_int16_t *interface_id) {
  int i;

  if(readOnlyGlobals.numInterfaceNetworks == 0) return(0);

  for(i=0; i<readOnlyGlobals.numInterfaceNetworks; i++)
    if((addr->s_addr & readOnlyGlobals.interfaceNetworks[i].netmask) == readOnlyGlobals.interfaceNetworks[i].network) {
      *interface_id = readOnlyGlobals.interfaceNetworks[i].interface_id;
      return(1);
    }

  return(0);
}

/* ************************************************ */

unsigned short isLocalAddress(struct in_addr *addr) {
  int i;

  /* If unset all the addresses are local */
  if(readOnlyGlobals.numLocalNetworks == 0) return(1);

  for(i=0; i<readOnlyGlobals.numLocalNetworks; i++)
    if((addr->s_addr & readOnlyGlobals.localNetworks[i].netmask) == readOnlyGlobals.localNetworks[i].network) {
      return 1;
    }

  return(0);
}

/* ************************************************ */

u_short isBlacklistedAddress(struct in_addr *addr) {
  int i;
#ifdef DEBUG
  char buf[64];
#endif

  /* If unset is not blacklisted */
  if(readOnlyGlobals.numBlacklistNetworks == 0) return(0);

  for(i=0; i<readOnlyGlobals.numBlacklistNetworks; i++)
    if((addr->s_addr & readOnlyGlobals.blacklistNetworks[i].netmask) == readOnlyGlobals.blacklistNetworks[i].network) {

#ifdef DEBUG
      traceEvent(TRACE_INFO, "%s is blacklisted",
		 _intoaV4(ntohl(addr->s_addr), buf, sizeof(buf)));
#endif
      return 1;
    }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "%s is NOT blacklisted",
	     _intoaV4(ntohl(addr->s_addr), buf, sizeof(buf)));
#endif
  return(0);
}

/* ************************************************ */

/* Utility function */
u_int32_t str2addr(char *address) {
  int a, b, c, d;

  if(sscanf(address, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
    return(0);
  } else
    return(((a & 0xff) << 24) + ((b & 0xff) << 16) + ((c & 0xff) << 8) + (d & 0xff));
}

/* ************************************************ */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
  uint i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

/* ************************************ */

void resetBucketStats(FlowHashBucket* bkt,
		      const struct pcap_pkthdr *h,
		      uint len, FlowDirection direction,
		      u_char *payload, int payloadLen) {
  bkt->bucket_expired = 0; /* Not really necessary */


  memset(&bkt->flowCounters, 0, sizeof(bkt->flowCounters));
  //memset(&bkt->flowTimers, 0, sizeof(bkt->flowTimers));
  //memset(&bkt->clientNwDelay, 0, sizeof(bkt->clientNwDelay));
  //memset(&bkt->serverNwDelay, 0, sizeof(bkt->serverNwDelay));
  memset(&bkt->synTime, 0, sizeof(bkt->synTime));
  memset(&bkt->synAckTime, 0, sizeof(bkt->synAckTime));
  memset(&bkt->src2dstApplLatency, 0, sizeof(bkt->src2dstApplLatency));
  memset(&bkt->dst2srcApplLatency, 0, sizeof(bkt->dst2srcApplLatency));

  if(direction == src2dst_direction /* src -> dst */) {
    bkt->flowCounters.bytesSent = len, bkt->flowCounters.pktSent = 1, bkt->flowCounters.bytesRcvd = bkt->flowCounters.pktRcvd = 0;
    memcpy(&bkt->flowTimers.firstSeenSent, &h->ts, sizeof(struct timeval));
    memcpy(&bkt->flowTimers.lastSeenSent, &h->ts, sizeof(struct timeval));
  } else {
    bkt->flowCounters.bytesSent = bkt->flowCounters.pktSent = 0, bkt->flowCounters.bytesRcvd = len, bkt->flowCounters.pktRcvd = 1;
    memcpy(&bkt->flowTimers.firstSeenRcvd, &h->ts, sizeof(struct timeval));
    memcpy(&bkt->flowTimers.lastSeenRcvd, &h->ts, sizeof(struct timeval));
  }

  /* NOTE: don't reset TOS as this is part of the flow key */
  bkt->flags = 0;
  if(bkt->src2dstPayload) { free(bkt->src2dstPayload);  bkt->src2dstPayload = NULL;  }
  if(bkt->dst2srcPayload) { free(bkt->dst2srcPayload); bkt->dst2srcPayload = NULL; }
  setPayload(bkt, h, payload, payloadLen, direction);
}

/* ****************************************** */

/*
  UNIX was not designed to stop you from doing stupid things, because that
  would also stop you from doing clever things.
  -- Doug Gwyn
*/
void maximize_socket_buffer(int sock_fd, int buf_type) {
  int i, rcv_buffsize_base, rcv_buffsize, max_buf_size = 1024 * 2 * 1024 /* 2 MB */, debug = 0;
  socklen_t len = sizeof(rcv_buffsize_base);

  if(getsockopt(sock_fd, SOL_SOCKET, buf_type, &rcv_buffsize_base, &len) < 0) {
    traceEvent(TRACE_ERROR, "Unable to read socket receiver buffer size [%s]",
	       strerror(errno));
    return;
  } else {
    if(debug) traceEvent(TRACE_INFO, "Default socket %s buffer size is %d",
			 buf_type == SO_RCVBUF ? "receive" : "send",
			 rcv_buffsize_base);
  }

  for(i=2;; i++) {
    rcv_buffsize = i * rcv_buffsize_base;
    if(rcv_buffsize > max_buf_size) break;

    if(setsockopt(sock_fd, SOL_SOCKET, buf_type, &rcv_buffsize, sizeof(rcv_buffsize)) < 0) {
      if(debug) traceEvent(TRACE_ERROR, "Unable to set socket %s buffer size [%s]",
			   buf_type == SO_RCVBUF ? "receive" : "send",
			   strerror(errno));
      break;
    } else
      if(debug) traceEvent(TRACE_INFO, "%s socket buffer size set %d",
			   buf_type == SO_RCVBUF ? "Receive" : "Send",
			   rcv_buffsize);
  }
}

/* ****************************************** */

#ifdef linux

/* /usr/local/bin/setethcore <eth2> <core Id> */
#define SET_NETWORK_CARD_AFFINITY   "/usr/local/bin/setethcore"

void setCpuAffinity(char *dev_name, char *cpuId) {
  pid_t p = 0; /* current process */
  int ret, num = 0;
  cpu_set_t cpu_set;
  int numCpus = sysconf(_SC_NPROCESSORS_CONF);
  char *strtokState, *cpu, _cpuId[256] = { 0 };

  if(cpuId == NULL)
    return; /* No affinity */

  traceEvent(TRACE_INFO, "This computer has %d processor(s)\n", numCpus);

  CPU_ZERO(&cpu_set);

  cpu = strtok_r(cpuId, ",", &strtokState);
  while(cpu != NULL) {
    int id = atoi(cpu);

    if((id >= numCpus) || (id < 0)) {
      traceEvent(TRACE_ERROR, "Skept CPU id %d as you have %d available CPU(s) [0..%d]", id, numCpus, numCpus-1);
    } else {
      CPU_SET(id, &cpu_set), num++;
      traceEvent(TRACE_INFO, "Adding CPU %d to the CPU affinity set", id);
      snprintf(&_cpuId[strlen(_cpuId)], sizeof(_cpuId)-strlen(_cpuId)-1, "%s%d", (_cpuId[0] != '\0') ? "," : "", id);
    }

    cpu = strtok_r(NULL, ",", &strtokState);
  }

  if(num == 0) {
    traceEvent(TRACE_WARNING, "No valid CPU id has been selected: skipping CPU affinity set");
    return;
  }

  ret = sched_setaffinity(p, sizeof(cpu_set_t), &cpu_set);

  if(ret == 0) {
    traceEvent(TRACE_NORMAL, "CPU affinity successfully set to %s", _cpuId);

    if((dev_name != NULL) && strcmp(dev_name, "none")) {
      struct stat stats;

      if(stat(SET_NETWORK_CARD_AFFINITY, &stats) == 0) {
	char affinity_buf[256];
	int ret;

	snprintf(affinity_buf, sizeof(affinity_buf), "%s %s %s",
		 SET_NETWORK_CARD_AFFINITY, dev_name, _cpuId);

	ret = system(affinity_buf);
	traceEvent(TRACE_NORMAL, "Executed '%s' (ret: %d)", affinity_buf, ret);
      } else {
	traceEvent(TRACE_WARNING, "Missing %s: unable to set %s affinity",
		   SET_NETWORK_CARD_AFFINITY, dev_name);
      }
    } else {
      traceEvent(TRACE_NORMAL, "Unspecified card (-i missing): not setting card affinity");
    }
  } else
    traceEvent(TRACE_ERROR, "Unable to set CPU affinity to %08lx [ret: %d]",
	       cpu_set, ret);
}
#endif

/* ******************************************* */

u_int32_t queuedPkts(PacketQueue *queue) {
  u_int32_t ret;

  if(queue->num_queued_pkts >= queue->num_dequeued_pkts)
    ret = (queue->num_queued_pkts-queue->num_dequeued_pkts);
  else
    ret = (((u_int32_t) - 1)-queue->num_dequeued_pkts+queue->num_queued_pkts)+1;

  if(0) traceEvent(TRACE_NORMAL, "queuedPkts=%d", ret);

  return(ret);
}

/* ******************************************* */

u_int32_t numFreeSlots(PacketQueue *queue) {
  u_int32_t ret = queue->queue_capacity - queuedPkts(queue);
  return(ret);
}

/* ******************************************* */

int mkdir_p(char *path) {
  int i, rc = 0;
  int permission = 0777;

  if(path == NULL) return(-1);

#ifdef WIN32
  revertSlash(path, 0);
#endif

  /* Start at 1 to skip the root */
  for(i=1; path[i] != '\0'; i++)
    if(path[i] == CONST_DIR_SEP) {
#ifdef WIN32
      /* Do not create devices directory */
      if((i > 1) && (path[i-1] == ':')) continue;
#endif

      path[i] = '\0';
      rc = mkdir(path, permission);

      if((rc != 0) && (errno != EEXIST) )
	traceEvent(TRACE_WARNING, "mkdir_p(%s): [error=%d/%s]",
		   path, errno, strerror(errno));
      path[i] = CONST_DIR_SEP;
    }

  mkdir(path, permission);

  if((rc != 0) && (errno != EEXIST))
    traceEvent(TRACE_WARNING, "mkdir_p(%s), error %d %s",
	       path, errno, strerror(errno));

  return(rc);
}

/* ******************************************* */

void dropPrivileges(void) {
#ifndef WIN32
  struct passwd *pw = NULL;
  char *username;

  if(readOnlyGlobals.do_not_drop_privileges) return;

  pw = getpwnam(username = "nobody");
  if(pw == NULL) pw = getpwnam(username = "anonymous");

  if(pw != NULL) {
    /* Drop privileges */
    if((setgid(pw->pw_gid) != 0) || (setuid(pw->pw_uid) != 0)) {
      traceEvent(TRACE_WARNING, "Unable to drop privileges [%s]", strerror(errno));
    } else
      traceEvent(TRACE_NORMAL, "nProbe changed user to '%s'", username);
  } else {
    traceEvent(TRACE_WARNING, "Unable to locate user nobody");
  }

  umask(0);
#endif
}

/* ******************************************* */

char* CollectorAddress2Str(CollectorAddress *collector, char *buf, u_int buf_len) {
  char *transport, addr[64];
  u_int port;

  switch(collector->transport) {
  case TRANSPORT_UDP:     transport = "udp";     break;
  case TRANSPORT_TCP:     transport = "tcp";     break;
  case TRANSPORT_SCTP:    transport = "sctp";    break;
  case TRANSPORT_UDP_RAW: transport = "udp-raw"; break;
  default:                transport = "???";
  }

#ifdef IPV4_ONLY
  inet_ntop(AF_INET, &collector->u.v4Address, addr, sizeof(addr)), port = collector->u.v4Address.sin_port;
#else
  if(collector->isIPv6 == 0)
    inet_ntop(AF_INET, &collector->u.v4Address.sin_addr, addr, sizeof(addr)), port = collector->u.v4Address.sin_port;
  else
    inet_ntop(AF_INET6, &collector->u.v6Address.sin6_addr, addr, sizeof(addr)), port = collector->u.v6Address.sin6_port;
#endif

  snprintf(buf, buf_len, "%s://%s:%d", transport, addr, ntohs(port));
  return(buf);
}

/* ******************************************* */

static char* LogEventSeverity2Str(LogEventSeverity event_severity) {
 switch(event_severity) {
 case severity_error:   return("ERROR");
 case severity_warning: return("WARN");
 case severity_info:    return("INFO");
 default:               return("???");
 }
}

/* ******************************************* */

static char* LogEventType2Str(LogEventType event_type) {
  switch(event_type) {
  case probe_started:              return("NPROBE_START");
  case probe_stopped:              return("NPROBE_STOP");
  case packet_drop:                return("CAPTURE_PACKET_DROP");
  case flow_export_error:          return("FLOW_EXPORT_ERROR");
  case collector_connection_error: return("COLLECTOR_CONNECTION_ERROR");
  case collector_connected:        return("CONNECTED_TO_COLLECTOR");
  case collector_disconnected:     return("DISCONNECTED_FROM_COLLECTOR");
  case collector_too_slow:         return("COLLECTOR_TOO_SLOW");
  default:                         return("???");
  }
}

/* ******************************************* */

void dumpLogEvent(LogEventType event_type, LogEventSeverity severity, char *message) {
  FILE *fd;
  time_t theTime;
  char theDate[32];
  static int skipDump = 0;

  if(readOnlyGlobals.eventLogPath == NULL) return;

  fd = fopen(readOnlyGlobals.eventLogPath, "a");
  if(fd == NULL) {
    if(!skipDump) {
      traceEvent(TRACE_WARNING, "Unable to append event on file %s",
		 readOnlyGlobals.eventLogPath);
      skipDump = 1;
    }

    return;
  } else
    skipDump = 0;

  theTime = time(NULL);
  strftime(theDate, sizeof(theDate), "%d/%b/%Y %H:%M:%S", localtime(&theTime));

  fprintf(fd, "%s\t%s\t%s\t%s\n", theDate,
	  LogEventSeverity2Str(severity),
	  LogEventType2Str(event_type), message ? message : "");
  fclose(fd);
}

/* ****************************************************** */

u_int32_t to_msec(struct timeval *tv) {
  return(tv->tv_sec * 1000 + tv->tv_usec/1000);
}

