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

/*
 *	http://www.winprog.org/tutorial/
 *	http://www.informit.com/articles/printerfriendly.asp?p=342886
 *	ftp://sources.redhat.com/pub/pthreads-win32/
 *
 *  Debugging:
 * http://social.technet.microsoft.com/wiki/contents/articles/8103.application-crash-dump-analysis-windows-7.aspx
 */

#include "nprobe.h"

#include <intrin.h> /* __cpuid */

/* ****************************************************** */

#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

struct timezone {
  int tz_minuteswest; /* minutes W of Greenwich */
  int tz_dsttime;     /* type of dst correction */
};

#if 0
int gettimeofday(struct timeval *tv, void *notUsed) {
  tv->tv_sec = time(NULL);
  tv->tv_usec = 0;
  return(0);
}
#endif

#if 0
int gettimeofday(struct timeval *tv, struct timezone *tz)
{
  FILETIME        ft;
  LARGE_INTEGER   li;
  __int64         t;
  static int      tzflag;

  if (tv)
    {
      GetSystemTimeAsFileTime(&ft);
      li.LowPart  = ft.dwLowDateTime;
      li.HighPart = ft.dwHighDateTime;
      t  = li.QuadPart;       /* In 100-nanosecond intervals */
      t -= EPOCHFILETIME;     /* Offset to the Epoch time */
      t /= 10;                /* In microseconds */
      tv->tv_sec  = (long)(t / 1000000);
      tv->tv_usec = (long)(t % 1000000);
    }

  if (tz)
    {
      if (!tzflag)
        {
	  _tzset();
	  tzflag++;
        }
      tz->tz_minuteswest = _timezone / 60;
      tz->tz_dsttime = _daylight;
    }

  return 0;
}

#endif

/* ****************************************************** */

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

int
inet_aton(const char *cp, struct in_addr *addr)
{
  addr->s_addr = inet_addr(cp);
  return (addr->s_addr == INADDR_NONE) ? 0 : 1;
}

/* ******************************************************* */

#define WIN32_THREADS

#ifdef WIN32_THREADS

/* **************************************

   WIN32 MULTITHREAD STUFF

   ************************************** */

pthread_t pthread_self(void) { return(0); }

int pthread_create(pthread_t *threadId, void* notUsed, void *(*__start_routine) (void *), char* userParm) {
  DWORD dwThreadId, dwThrdParam = 1;

  (*threadId) = CreateThread(NULL, /* no security attributes */
			     0,            /* use default stack size */
			     (LPTHREAD_START_ROUTINE)__start_routine, /* thread function */
			     userParm,     /* argument to thread function */
			     0,            /* use default creation flags */
			     &dwThreadId); /* returns the thread identifier */

  if(*threadId != NULL)
    return(1);
  else
    return(0);
}

/* ************************************ */

void pthread_detach(pthread_t *threadId) {
  CloseHandle((HANDLE)*threadId);
}

/* ************************************ */

int pthread_join (pthread_t threadId, void **_value_ptr) {
  int rc = WaitForSingleObject(threadId, INFINITE);
  CloseHandle(threadId);
  return(rc);
}

/* ************************************ */

int pthread_mutex_init(pthread_mutex_t *mutex, char* notused) {
  (*mutex) = CreateMutex(NULL, FALSE, NULL);
  return(0);
}

/* ************************************ */

void pthread_mutex_destroy(pthread_mutex_t *mutex) {
  ReleaseMutex(*mutex);
  CloseHandle(*mutex);
}

/* ************************************ */

int pthread_mutex_lock(pthread_mutex_t *mutex) {

  if(*mutex == NULL)
    printf("Error\n");
  WaitForSingleObject(*mutex, INFINITE);
  return(0);
}

/* ************************************ */

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
  if(WaitForSingleObject(*mutex, 0) == WAIT_FAILED)
    return(1);
  else
    return(0);
}

/* ************************************ */

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
  if(*mutex == NULL)
    printf("Error\n");
  return(!ReleaseMutex(*mutex));
}

#endif

#if 0

/* https://svn.nmap.org/nmap/libdnet-stripped/src/strsep.c */
/*
 * Get next token from string *stringp, where tokens are possibly-empty
 * strings separated by characters from delim.  
 *
 * Writes NULs into the string at *stringp to end tokens.
 * delim need not remain constant from call to call.
 * On return, *stringp points past the last NUL written (if there might
 * be further tokens), or is NULL (if there are definitely no more tokens).
 *
 * If *stringp is NULL, strsep returns NULL.
 */
char* strsep(char **stringp, const char *delim)
{
	register char *s;
	register const char *spanp;
	register int c, sc;
	char *tok;

	if ((s = *stringp) == NULL)
		return (NULL);
	for (tok = s;;) {
		c = *s++;
		spanp = delim;
		do {
			if ((sc = *spanp++) == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*stringp = s;
				return (tok);
			}
		} while (sc != 0);
	}
	/* NOTREACHED */
}
#endif

/* Reentrant string tokenizer.  Generic version.

   Slightly modified from: glibc 2.1.3

   Copyright (C) 1991, 1996, 1997, 1998, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#ifndef strtok_r
char* strtok_r(char *s, const char *delim, char **save_ptr) {
  char *token;

  if (s == NULL)
    s = *save_ptr;

  /* Scan leading delimiters.  */
  s += strspn (s, delim);
  if (*s == '\0')
    return NULL;

  /* Find the end of the token.  */
  token = s;
  s = strpbrk (token, delim);
  if (s == NULL)
    /* This token finishes the string.  */
    *save_ptr = "";
  else {
    /* Terminate the token and make *SAVE_PTR point past it.  */
    *s = '\0';
    *save_ptr = s + 1;
  }

  return token;
}
#endif

/* ******************************** */

void revertSlash(char *str, int mode) {
  int i;

  for(i=0; str[i] != '\0'; i++)
    switch(mode) {
    case 0:
      if(str[i] == '/') str[i] = '\\';
      //else if(str[i] == ' ') str[i] = '_';
      break;
    case 1:
      if(str[i] == '\\') str[i] = '/';
      break;
    }
}

/* ******************************** */

/*
const char* strcasestr( const char* one, const char* two ) {
  const char* t = two;
  char oneLower = tolower(*one);

  for( ; *t; t++ ) {
    if (tolower(*t) == oneLower) {
      int result = _strnicmp( one, t, strlen(two) );

      if( result == 0 )
        return t;
    }
  }

  return NULL;
}
*/

const char *strcasestr(const char *haystack, const char *needle)
{
        int i=-1;
        while (haystack[++i] != '\0') {
                if (tolower(haystack[i]) == tolower(needle[0])) {
                        int j=i, k=0, match=0;
                        while (tolower(haystack[++j]) == tolower(needle[++k])) {
                                match=1;
                            // Catch case when they match at the end
                                  //printf("j:%d, k:%d\n",j,k);
                                if (haystack[j] == '\0' && needle[k] == '\0') {
                                  //printf("Mj:%d, k:%d\n",j,k);
                                        return &haystack[i];
                                }
                        }
                        // Catch normal case
                        if (match && needle[k] == '\0'){
                                 // printf("Norm j:%d, k:%d\n",j,k);
                                return &haystack[i];
                        }
                }
        }
        return NULL;
}

/* ******************************** */

char* printAvailableInterfaces(char *name_or_index) {
  char ebuf[PCAP_ERRBUF_SIZE];
  char *captureDev, *ifName;
  int ifIdx=0, defaultIdx = -1, numInterfaces = 0;
  uint i, list_devices;
  char intNames[32][256], intDescr[32][256];
  int index;

  captureDev = pcap_lookupdev(ebuf);

  if(captureDev == NULL) {
    traceEvent(TRACE_INFO, "Unable to locate default interface (%s)", ebuf);
    exit(-1);
  }

  /* Check if this is a filename and it exists */
  if(name_or_index != NULL) {
	  if(access(name_or_index, F_OK) == 0)
		return(name_or_index);
  }

  ifName = captureDev;

  if((name_or_index != NULL) && (atoi(name_or_index) == -1))
    list_devices = 1;
  else
    list_devices = 0;

  if(list_devices) printf("\n\nAvailable interfaces:\n");

  if(!isWinNT()) {
    for(i=0;; i++) {
      if(captureDev[i] == 0) {
	if(ifName[0] == '\0')
	  break;
	else {
	  if(list_devices) {
	    numInterfaces++;
	    printf("\t[index=%d] '%s'\n", ifIdx, ifName);
	  }

	  if(ifIdx < 32) {
	    strcpy(intNames[ifIdx], ifName);
	    strcpy(intDescr[ifIdx], ifName);
	    if(list_devices) {
	      if(strncmp(intNames[ifIdx], "PPP", 3) /* Avoid to use the PPP interface */
		 && strncmp(intNames[ifIdx], "ICSHARE", 6)
		 && (!strcasestr(intNames[ifIdx], "dialup"))
		 ) {
		/* Avoid to use the internet sharing interface */
		defaultIdx = ifIdx;
	      }
	    }
	  }
	  ifIdx++;
	  ifName = &captureDev[i+1];
	}
      }
    }

    captureDev = intNames[defaultIdx];
  } else {
    /* WinNT/2K */
    static char tmpString[128];
    int j,ifDescrPos = 0;
    int i;
    unsigned short *ifName; /* UNICODE */
    char *ifDescr;

    ifName = (unsigned short *)captureDev;

    while(*(ifName+ifDescrPos) || *(ifName+ifDescrPos-1))
      ifDescrPos++;
    ifDescrPos++;	/* Step over the extra '\0' */
    ifDescr = (char*)(ifName + ifDescrPos); /* cast *after* addition */

    while(captureDev[0] != '\0') {
      u_char skipInterface;

      for(j=0, i=0; !((captureDev[i] == 0) && (captureDev[i+1] == 0)); i++) {
	if(captureDev[i] != 0)
	  tmpString[j++] = captureDev[i];
      }

      tmpString[j++] = 0;

      if(strstr(ifDescr, "NdisWan") || strstr(ifDescr, "dialup"))
	skipInterface = 1;
      else
	skipInterface = 0;

      if(list_devices) {
	if(!skipInterface) {
	  printf("\t[index=%d] '%s'\n", ifIdx, ifDescr);
	  numInterfaces++;
	}
      }

      captureDev = &captureDev[i+3];
      if(!skipInterface) {
	strcpy(intNames[ifIdx], tmpString);
	strcpy(intDescr[ifIdx], ifDescr);
	if(defaultIdx == -1) defaultIdx = ifIdx;
	ifIdx++;
      }
      ifDescr += strlen(ifDescr)+1;
    }

    if(!list_devices)
      captureDev = intNames[defaultIdx]; /* Default */
  }

  if(list_devices) {
    if(numInterfaces == 0) {
      traceEvent(TRACE_WARNING, "no interfaces available! This application cannot");
      traceEvent(TRACE_WARNING, "work make sure that winpcap is installed properly");
      traceEvent(TRACE_WARNING, "and that you have network interfaces installed.");
    }
    return(NULL);
  }

  /* Return the first available device */
  if(name_or_index == NULL) return(strdup(intNames[defaultIdx]));

  /* Search the interface by name */
  for(i=0; i<ifIdx; i++) {
    if(strcasestr(intDescr[i], name_or_index) != NULL) {
      return(strdup(intNames[i]));
    }
  }

  index = atoi(name_or_index);
  if((index < 0) || (index >= ifIdx)) {
    traceEvent(TRACE_ERROR, "Interface index %d out of range\n", index);
    exit(-1);
  } else
    return(strdup(intNames[index]));
}

/* ****************************** */

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN    16
#endif

#ifndef IN6ADDRSZ
#define IN6ADDRSZ   16   /* IPv6 T_AAAA */
#endif

#ifndef INT16SZ
#define INT16SZ     2    /* word size */
#endif

static const char* inet_ntop_v4 (const void *src, char *dst, size_t size)
{
  const char digits[] = "0123456789";
  int i;
  struct in_addr *addr = (struct in_addr *)src;
  u_long a = ntohl(addr->s_addr);
  const char *orig_dst = dst;

  if (size < INET_ADDRSTRLEN) {
    errno = ENOSPC;
    return NULL;
  }
  for (i = 0; i < 4; ++i) {
    int n = (a >> (24 - i * 8)) & 0xFF;
    int non_zerop = 0;

    if (non_zerop || n / 100 > 0) {
      *dst++ = digits[n / 100];
      n %= 100;
      non_zerop = 1;
    }
    if (non_zerop || n / 10 > 0) {
      *dst++ = digits[n / 10];
      n %= 10;
      non_zerop = 1;
    }
    *dst++ = digits[n];
    if (i != 3)
      *dst++ = '.';
  }
  *dst++ = '\0';
  return orig_dst;
}

/*
 * Convert IPv6 binary address into presentation (printable) format.
 */
static const char* inet_ntop_v6 (const u_char *src, char *dst, size_t size)
{
  /*
   * Note that int32_t and int16_t need only be "at least" large enough
   * to contain a value of the specified size.  On some systems, like
   * Crays, there is no such thing as an integer variable with 16 bits.
   * Keep this in mind if you think this function should have been coded
   * to use pointer overlays.  All the world's not a VAX.
   */
  char  tmp [INET6_ADDRSTRLEN+1];
  char *tp;
  struct {
    long base;
    long len;
  } best, cur;
  u_long words [IN6ADDRSZ / INT16SZ];
  int    i;

  /* Preprocess:
   *  Copy the input (bytewise) array into a wordwise array.
   *  Find the longest run of 0x00's in src[] for :: shorthanding.
   */
  memset (words, 0, sizeof(words));
  for (i = 0; i < IN6ADDRSZ; i++)
    words[i/2] |= (src[i] << ((1 - (i % 2)) << 3));

  best.base = -1;
  cur.base  = -1;
  for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
    {
      if (words[i] == 0)
	{
	  if (cur.base == -1)
	    cur.base = i, cur.len = 1;
	  else cur.len++;
	}
      else if (cur.base != -1)
	{
	  if (best.base == -1 || cur.len > best.len)
	    best = cur;
	  cur.base = -1;
	}
    }
  if ((cur.base != -1) && (best.base == -1 || cur.len > best.len))
    best = cur;
  if (best.base != -1 && best.len < 2)
    best.base = -1;

  /* Format the result.
   */
  tp = tmp;
  for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
    {
      /* Are we inside the best run of 0x00's?
       */
      if (best.base != -1 && i >= best.base && i < (best.base + best.len))
	{
	  if (i == best.base)
	    *tp++ = ':';
	  continue;
	}

      /* Are we following an initial run of 0x00s or any real hex?
       */
      if (i != 0)
	*tp++ = ':';

      /* Is this address an encapsulated IPv4?
       */
      if (i == 6 && best.base == 0 &&
	  (best.len == 6 || (best.len == 5 && words[5] == 0xffff)))
	{
	  if (!inet_ntop_v4(src+12, tp, sizeof(tmp) - (tp - tmp)))
	    {
	      errno = ENOSPC;
	      return (NULL);
	    }
	  tp += strlen(tp);
	  break;
	}
      tp += sprintf (tp, "%lX", words[i]);
    }

  /* Was it a trailing run of 0x00's?
   */
  if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ))
    *tp++ = ':';
  *tp++ = '\0';

  /* Check for overflow, copy, and we're done.
   */
  if ((size_t)(tp - tmp) > size)
    {
      errno = ENOSPC;
      return (NULL);
    }
  return strcpy (dst, tmp);
  return (NULL);
}


PCSTR
WSAAPI
inet_ntop(
	  __in                                INT             af,
	  __in                                PVOID           src,
	  __out_ecount(StringBufSize)         PSTR            dst,
	  __in                                size_t          size
	  ){    switch (af) {
  case AF_INET :
    return inet_ntop_v4 (src, dst, size);
  case AF_INET6:
    return inet_ntop_v6 ((const u_char*)src, dst, size);
  default :
    errno = WSAEAFNOSUPPORT;
    return NULL;
  }
}

/* *********************************************************** */

int nprobe_inet_pton(int af, const char *src, void *dst) {
  if(af != AF_INET) {
    errno = EAFNOSUPPORT;
    return -1;
  } else 
    return inet_aton(src, dst);
}
