/*
 *
 *       Copyright (C) 2010 Luca Deri <deri@ntop.org>
 *
 *                     http://www.ntop.org/
 *
 * 
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* ****************************************************************** */

#define REFLECTOR_VERSION        "1.0"
#define DEFAULT_NUM_THREADS         3
#define MAX_NUM_THREADS             8
#define MAX_NUM_COLLECTORS         16
#define MAX_NUM_PROBES             16
#define MAX_FLOW_LEN             1600

#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__

typedef struct collector {
  struct sockaddr_in addr; /* Collector address */
  u_int32_t num_pkts_sent;
} nf_collector;

typedef struct {
  struct in_addr source_addr;
  u_int8_t nf_collector_id;
} nf_probe;

static u_int32_t num_rcvd_flows = 0, unforwarded_as_no_available_collector = 0,num_collectors = 0;
static int in_sock = -1, out_sock, last_target = 0, num_nf_collectors = 0, num_nf_probes = 0;
static nf_collector nf_collectors[MAX_NUM_COLLECTORS];
static nf_probe     nf_probes[MAX_NUM_PROBES];
static u_int8_t shutting_down = 0, traceLevel = 2, dummy_mode = 0;
static char *dump_file = NULL, *preference_file = NULL;

static u_int8_t process_flow(char *msg, int msg_len, struct sockaddr_in *cliAddr);

static void traceEvent(int eventTraceLevel, char* file, int line, char * format, ...);
static char* intoaV4(unsigned int addr, char* buf, u_short bufLen);
static void maximize_socket_buffer(int sock_fd, int buf_type);

/* ******************************** */

/* Print simple copyright message */
void copyright() {
  traceEvent(TRACE_NORMAL, "nf_reflector v.%s - (C) 2010 ntop.org", REFLECTOR_VERSION);
}

/* ******************************** */

/* Print help */
void help() {
  traceEvent(TRACE_NORMAL, "Usage: nf_reflector -c <port> -p <prefs file> [-n <num threads>] [-v] [-d] [-h]\n");

  traceEvent(TRACE_NORMAL, "-c <port>        | UDP port where incoming flows are received");
  traceEvent(TRACE_NORMAL, "-p <pref file>   | Preference file that specifies the reflection policy");
  traceEvent(TRACE_NORMAL, "-v               | Enable verbose logging");
  traceEvent(TRACE_NORMAL, "-d               | Dummy mode (packets are discarded with no processing)\n");
  traceEvent(TRACE_NORMAL, "-h               | Print this help\n");
  traceEvent(TRACE_NORMAL, "Example: nf_reflector -c 2055 -p nf_reflector.conf");

  exit(1);
}

/* ******************************** */

/* Function called when the shutdown_reflector is started */
void shutdown_reflector() {
  u_int32_t tot_sent = 0;
  int i;

  if(!shutting_down) {
    shutting_down = 1;
    traceLevel = 6;
    traceEvent(TRACE_INFO, "Shutting down...");

    shutdown_reflector();
    close(in_sock);

    traceEvent(TRACE_INFO, "Leaving...");
    close(out_sock);
  }

  traceEvent(TRACE_INFO, "Received [%u flow packets]", num_rcvd_flows);

  for(i=0; i<num_nf_collectors; i++) {
    char ebuf[64];

    traceEvent(TRACE_INFO, "Collector %s: forwarded %u flows",
	       intoaV4(ntohl(nf_collectors[i].addr.sin_addr.s_addr), ebuf, sizeof(ebuf)),
	       nf_collectors[i].num_pkts_sent);

    tot_sent += nf_collectors[i].num_pkts_sent;
  }

  traceEvent(TRACE_INFO, "Forwarded [%u flows][%u discarded for missing collector]",
	     tot_sent, unforwarded_as_no_available_collector);
  exit(0);
}

/* ******************************** */

/* signal() handler that causes the application to end */
void sighandler(int sig /* Signal that triggered the call to this function */) {
  shutdown_reflector();
}

/* ******************************** */

int send_packet(int sock, char* msg, u_int msg_len, struct sockaddr_in *dest) {
  int rc;

  rc = sendto(sock, msg, msg_len, 0, (struct sockaddr*)dest, sizeof(struct sockaddr_in));

  if(rc == -1) {
    char ebuf[64];

    /* traceEvent(TRACE_ERROR, "Forwarding error: %s", strerror(errno)); */

    traceEvent(TRACE_ERROR, "Collector %s:%u either down or unreachable",
	       intoaV4(ntohl(nf_collectors[last_target].addr.sin_addr.s_addr), ebuf, sizeof(ebuf)),
	       ntohs(nf_collectors[last_target].addr.sin_port));
  }

  return(rc);
}

/* ******************************** */

/* List known reflectors */
static void list_reflectors(int command_sd, /* Socket where the response will be sent */
			    struct sockaddr_in *cliAddr /* Address of the requestor */) {
  char buf[2500];
  u_int32_t tot_flow_pkts_sent = 0;
  int idx = 0, rc, i;
  time_t now = time(NULL);

  for(i=0; i<num_nf_collectors; i++) {
    char tmpbuf[32];

    idx += snprintf(&buf[idx], sizeof(buf)-idx, "Collector %s:%d : ",
		    intoaV4(ntohl(nf_collectors[i].addr.sin_addr.s_addr), tmpbuf, sizeof(tmpbuf)),
		    ntohs(nf_collectors[i].addr.sin_port));

    idx += snprintf(&buf[idx], sizeof(buf)-idx, "[Sent %u flows pkts]\n",
		    nf_collectors[i].num_pkts_sent);
    tot_flow_pkts_sent += nf_collectors[i].num_pkts_sent;

    idx += snprintf(&buf[idx], sizeof(buf)-idx, "\n");
  }

  if(num_nf_collectors == 0) snprintf(buf, sizeof(buf), "No nf_collectors defined");

  idx += snprintf(&buf[idx], sizeof(buf)-idx, "Total flow packets rcvd / sent / unsent no collector: %u / %u / %u\n",
		  num_rcvd_flows, tot_flow_pkts_sent, unforwarded_as_no_available_collector);
}

/* ******************************** */

/*
  Find collector given its IP address and port

  Return the collector id, or -1 if not found
*/
int do_find_collector(struct in_addr host, int port) {
  int i;

  for(i=0; i<num_nf_collectors; i++) {
    if((nf_collectors[i].addr.sin_addr.s_addr == host.s_addr)
       && (nf_collectors[i].addr.sin_port == htons(port))) {
      return(i);
    }
  }

  return(-1);
}

/* ******************************** */

/*
  Add a new collector

  Return the collector id, or -1 if not found
*/
int do_add_collector(char* host_and_port /* Format host:port */) {
  struct hostent *h;
  char *host = NULL, *port = NULL;
  int idx, rc;
  struct in_addr addr;

  host = strtok(host_and_port, ":");
  if(host) port = strtok(NULL, ":");

  if((!host) || (!port)) {
    traceEvent(TRACE_ERROR, "Invalid host:port format. Skipped.");
    return(-1);
  }

  h = gethostbyname(host);
  if(h == NULL) {
    traceEvent(TRACE_ERROR, "Unknown host '%s'", host);
    return(-1);
  } else
    memcpy((char*)&addr, h->h_addr_list[0], sizeof(addr));

  if(num_nf_collectors >= MAX_NUM_COLLECTORS) {
    traceEvent(TRACE_ERROR, "Too many nf_collectors defined (%d)", num_nf_collectors);
    return(-1);
  }

  if((rc = do_find_collector(addr, atoi(port))) != -1) {
    traceEvent(TRACE_INFO, "Collector %s:%s has been defined multiple times: duplicates are discarded",
	       host, port);
    return(rc);
  }

  idx = num_nf_collectors;
  memset(&nf_collectors[idx], 0, sizeof(nf_collectors[idx]));
  nf_collectors[idx].addr.sin_family = h->h_addrtype;
  memcpy((char *)&nf_collectors[idx].addr.sin_addr.s_addr, &addr, sizeof(addr));
  nf_collectors[idx].addr.sin_port = htons(atoi(port));

#ifndef linux
  nf_collectors[idx].addr.sin_len = sizeof(struct sockaddr_in);
#endif
  num_nf_collectors++;

  traceEvent(TRACE_NORMAL, "Added new collector %s:%d [total: %d]",
	     host, atoi(port), num_nf_collectors);

  return(idx);
}

/* ******************************** */

/* Handler that is used to add a new collector */
static void add_collector(int command_sd, /* Socket description from which the command has been received */
			  struct sockaddr_in *cliAddr, /* Sedevicesr */
			  char *cmd /* Add command */) {
  do_add_collector(cmd);
  list_reflectors(command_sd, cliAddr);
}

/* ******************************** */

/* Parse the preference file */
void parse_preference_file(char *path /* path of the preference file */) {
  FILE *fd = fopen(path, "r");
  char buf[256];
  int line = 1;

  if(!fd) {
    traceEvent(TRACE_WARNING, "Unable to open preference file %s: ignored.", path);
    return;
  }

  /*
    # Source IP	Collector IP:port
    192.168.10.253	192.168.100.200:2055
    192.168.20.253	192.168.100.100:2055
  */
  while(fgets(buf, sizeof(buf), fd)) {
    char *source = NULL, *collector = NULL, *backup = NULL, *tok_state;

    if((buf[0] == '#') || (buf[0] == '\0') || (buf[0] == '\n')  || (buf[0] == '\r'))
      continue;
    else
      buf[strlen(buf)-1] = '\0';

    if((source = strtok_r(buf, "\t ", &tok_state)) != NULL)
      collector = strtok_r(NULL, "\t ", &tok_state);

    if(source && collector) {
      int collector_id = do_add_collector(collector);
      struct in_addr addr;
      int idx = -1, i;

      nf_probes[num_nf_probes].source_addr.s_addr = inet_addr(source);

      for(i=0; i<num_nf_probes; i++)
	if(nf_probes[i].source_addr.s_addr == nf_probes[num_nf_probes].source_addr.s_addr) {
	  idx = i;
	  break;
	}

      if(idx != -1) {
	traceEvent(TRACE_WARNING, "Probe %s defined multiple times: ignored duplicates", source);
      } else {
	nf_probes[num_nf_probes].nf_collector_id = collector_id;
	num_nf_probes++;
	traceEvent(TRACE_NORMAL, "Probe %s defined [total: %d]", source, num_nf_probes);
      }
    } else
      traceEvent(TRACE_WARNING, "Wrong format for line %s:%d", path, line);

    line++;
  }

  fclose(fd);
}

/* ******************************** */

static void* handle_sockets(void* not_used) {
  traceEvent(TRACE_INFO, "Poller thread started [threadId=%u]", pthread_self());

  while(!shutting_down) {
    fd_set readmask;
    int sd = 0, rc, i;

    FD_ZERO(&readmask);
    sd = in_sock;
    FD_SET(in_sock, &readmask);

    FD_SET(out_sock, &readmask);

    rc = select(sd+1, &readmask, NULL, NULL, NULL);

    if(rc > 0) {
      char msg[MAX_FLOW_LEN+1];
      struct sockaddr_in cliAddr;
      socklen_t cliLen = sizeof(cliAddr);
      int len, i;

      if(FD_ISSET(in_sock, &readmask)) {
	len = recvfrom(in_sock, msg, MAX_FLOW_LEN, 0,
		       (struct sockaddr *) &cliAddr, &cliLen);
	if(len <= 0) {
	  if(errno != 0)
	    traceEvent(TRACE_ERROR, "Error while receiving data [%s]", strerror(errno));
	  continue;
	} else {
	  process_flow(msg, len, &cliAddr);
	}
      }
    } else {
      /* traceEvent(TRACE_INFO, "select() failed [%s]", strerror(errno)); */
      break;
    }
  } /* while */

  /*
    traceEvent(TRACE_INFO, "Terminating thread [threadId=%u][shutting_down=%d]",
    pthread_self(), shutting_down);
  */

  return(NULL);
}

/* ******************************** */

int main(int argc, char *argv[]) {
  struct sockaddr_in cliAddr;
  char c;
  u_short num_threads = DEFAULT_NUM_THREADS;
  pthread_t thread_id[MAX_NUM_THREADS];
  int i;

  /* check command line args */
  num_nf_collectors = 0;

  while((c = getopt(argc, argv, "dc:n:p:vh")) != -1) {
    switch(c) {
    case 'd':
      dummy_mode = 1;
      traceEvent(TRACE_NORMAL, "Dummy mode enabled: no flows will be forwarded");
      break;

    case 'c':
      if(in_sock == -1) {
	struct sockaddr_in svrAddr;

	in_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(in_sock < 0) {
	  traceEvent(TRACE_ERROR, "Unable to create socket (are you root?) [%s]",
		     strerror(errno));
	  continue;
	}

	maximize_socket_buffer(in_sock, SO_RCVBUF);

	svrAddr.sin_family = AF_INET;
	svrAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	svrAddr.sin_port = htons(atoi(optarg));

	if(bind(in_sock,
		(struct sockaddr *)&svrAddr, sizeof(svrAddr)) == -1) {
	  traceEvent(TRACE_ERROR, "Cannot bind at port %d [%s]",
		     atoi(optarg), strerror(errno));
	  close(in_sock);
	  continue;
	} else
	  traceEvent(TRACE_NORMAL, "Waiting for flows at port %d", atoi(optarg));
      } else
	traceEvent(TRACE_ERROR, "-c has been already specified: ignored");
      break;

    case 'n':
      num_threads = atoi(optarg);
      if(num_threads > MAX_NUM_THREADS) {
	num_threads = MAX_NUM_THREADS;
	traceEvent(TRACE_INFO, "The number of threads has been set to %d", num_threads);
      }
      break;

    case 'p':
      preference_file = strdup(optarg);
      break;

    case 'v':
      traceLevel = 6;
      break;

    case 'h':
      help();
      return(0);
      break;
    }
  }

  if((in_sock == -1) || (preference_file == NULL))
    help();
  else
    copyright();

  parse_preference_file(preference_file);

  /* ********************* */

  /* Create output socket on which flows will be sent */

  out_sock = socket(AF_INET, SOCK_DGRAM, 0);

  if(out_sock < 0) {
    traceEvent(TRACE_WARNING,
	       "Unable to create socket (are you root?) [%s]",
	       strerror(errno));
    out_sock = socket(AF_INET, SOCK_DGRAM, 0);

    if(out_sock < 0) {
      traceEvent(TRACE_ERROR, "Unable to create socket. Leaving");
      return(-1);
    }
  }

  /* **************************************** */

  /*
    Notifies the socket in case there's a transmission error
    when sendto() is called.
  */
#ifdef IP_RECVERR
  {
    int on = 1;
    
    setsockopt(out_sock, SOL_IP, IP_RECVERR, (const void *)&on, sizeof(on));
  }
#endif

  /* ********************* */

  signal(SIGINT, sighandler);

  traceEvent(TRACE_NORMAL, "Waiting for flows...");

  for(i=0; i<num_threads; i++)
    pthread_create(&thread_id[i], NULL, handle_sockets, (void*)NULL);

  traceEvent(TRACE_NORMAL, "Started %d poller threads", num_threads);

  /* Wait until threads terminate */
  for(i=0; (i<num_threads) && (!shutting_down) ; i++) {
    pthread_join(thread_id[i], NULL);
    traceEvent(TRACE_INFO, "Thread joined");
  }

  /* ********************* */

  shutdown_reflector();
  return(1);
}

/* ******************************************************* */

/* Process the incoming file */
static u_int8_t process_flow(char *msg,    /* Flow */
			     int msg_len,  /* Flow length */
			     struct sockaddr_in *cliAddr /* Flow sedevicesr */) {
  char ebuf[32];
  int rc, targetId = -1, j;

  num_rcvd_flows++;

  if(num_nf_collectors == 0) {
    traceEvent(TRACE_INFO, "Flow dropped: no nf_collectors defined");
    return(1);
  }

  if(traceLevel > 2)
    traceEvent(TRACE_INFO, "Forwarding flow received from %s:%u [len=%d]",
	       intoaV4(ntohl(cliAddr->sin_addr.s_addr), ebuf, sizeof(ebuf)),
	       ntohs(cliAddr->sin_port), msg_len);

  /* Check prefered nf_collectors first */

  for(j=0; j<num_nf_probes; j++)
    if(nf_probes[j].source_addr.s_addr == cliAddr->sin_addr.s_addr) {
      targetId = j;
      break;
    }

  if(targetId != -1) {
    if(!dummy_mode) {
      rc = send_packet(out_sock, msg, msg_len, &nf_collectors[targetId].addr);
      
      if(rc == -1)
	traceEvent(TRACE_ERROR, "Forwarding error: %s", strerror(errno));
    }
    
    nf_collectors[targetId].num_pkts_sent++;
    last_target = targetId;
  } else {
    traceEvent(TRACE_INFO, "No collector available for forwarding");
    unforwarded_as_no_available_collector++;
  }

  return(0);
}

/* ************************************ */

static void traceEvent(int eventTraceLevel, char* file, int line, char * format, ...) {
  va_list va_ap;

  if(eventTraceLevel <= traceLevel) {
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

    snprintf(out_buf, sizeof(out_buf), "%s [%s:%d] %s%s", theDate, file, line, extra_msg, buf);

    printf("%s\n", out_buf);
  }

  fflush(stdout);
  va_end(va_ap);
}

/*
 * A faster replacement for inet_ntoa().
 */
static char* intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  uint byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/*
  UNIX was not designed to stop you from doing stupid things, because that
  would also stop you from doing clever things.
  -- Doug Gwyn
*/
static void maximize_socket_buffer(int sock_fd, int buf_type) {
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

