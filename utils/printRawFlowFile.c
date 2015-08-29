/*
 *  Copyright (C) 2012 Luca Deri <deri@ntop.org>
 *
 *  			http://www.ntop.org/
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

#include "../nprobe.h"


/* ************************************* */

static void help() {
  printf("printRawFlowFile -f <file>.flows\n");
  printf("   -f <file>.flows  | Dump file to print\n");
  printf("Print a file dumped by nProbe with option '-D B'. This is a debug tool!\n");

  exit(0);
}

/* ****************************** */

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

/* ****************************** */

static char* intoa(IpAddress addr, char* buf, u_short bufLen) {
  if(addr.ipVersion == 4)
    return(intoaV4(addr.ipType.ipv4, buf, bufLen));
  else {
    char *ret;
    int len;

    ret = (char*)inet_ntop(AF_INET6, &addr.ipType.ipv6, buf, bufLen);

    if(ret == NULL) {
      printf("WARNING: Internal error (buffer too short)");
      buf[0] = '\0';
    } else {
      len = strlen(ret);
    }

    ret = buf;

    return(ret);
  }
}

/* ************************************* */

int main(int argc, char* argv[]) {
  FILE *fd = NULL;
  char c, buf[512], buf1[64], buf2[64];

  while((c = getopt(argc, argv, "f:")) != -1) {
    switch(c) {
    case 'f':
      fd = fopen(optarg, "rb");
      if(fd == NULL) {
	printf("Unable to open file %s\n", optarg);
	return(-1);
      }
      break;
    }
  }

  if(fd == NULL) {
    help();
    return(-1);
  }

  while(fread(buf, sizeof(FlowHashBucketCoreFields), 1, fd) == 1) {
    FlowHashBucketCoreFields *f = (FlowHashBucketCoreFields*)buf;

    printf("[proto=%d][vlan=%d][%s:%d <-> %s:%d][bytes=%u/%u][pkts=%u/%u]\n", 
	   f->key.k.ipKey.proto, f->key.vlanId, 
	   intoa(f->key.k.ipKey.src, buf1, sizeof(buf1)), f->key.k.ipKey.sport, 
	   intoa(f->key.k.ipKey.dst, buf2, sizeof(buf2)), f->key.k.ipKey.dport,
	   f->flowCounters.bytesSent, f->flowCounters.bytesRcvd,
	   f->flowCounters.pktSent, f->flowCounters.pktRcvd);
  }

  fclose(fd);
  return(0);
}
