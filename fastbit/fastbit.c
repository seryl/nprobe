/*
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6
 *
 *       Copyright (C) 2009-10 Luca Deri <deri@ntop.org>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "nprobe.h"

#ifdef HAVE_FASTBIT

#ifndef WIN32
#include <sys/file.h> /* flock() */
#endif

#include "capi.h"

static int lock_fd;
static u_int32_t num_dumped_flows = 0;

// #define FASTBIT_DEBUG

/* **************************************** */

#ifndef WIN32
int do_lock_unlock_dir(char *dir, int mode) {
  char lock_name[255];
  int ret = 0;
  struct stat stats;

  snprintf(lock_name, sizeof(lock_name), "%s/.lock", dir);

  /* The file does not exit: no need to lock */
  if(stat(lock_name, &stats) != 0) return(0);

  if(mode != LOCK_UN) {
    lock_fd = open(lock_name, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
    if(lock_fd == -1) {
      traceEvent(TRACE_ERROR, "Unable to create lock %s [%d/%s]",
		 lock_name, errno, strerror(errno));
      return(-1);
    }
  }

  if(flock(lock_fd, mode) == -1) {
    traceEvent(TRACE_ERROR, "Unable to acquire the lock %s [%d/%s]",
	       lock_name, errno, strerror(errno));
    ret = -1;
  }

#ifdef FASTBIT_DEBUG
  traceEvent(TRACE_NORMAL, "%s %s",
	     (mode == LOCK_UN) ? "Unlocked" : "Locked",
	     lock_name);
#endif

  if(mode == LOCK_UN) {
    close(lock_fd);
    unlink(lock_name);
  }

  return(ret);
}

/* **************************************** */

int lock_dir(char *dir)   { return(do_lock_unlock_dir(dir, LOCK_EX));  }

/* **************************************** */

int unlock_dir(char *dir) { return(do_lock_unlock_dir(dir, LOCK_UN));  }

#endif

/* **************************************** */

static void index_exec_fastbit_directory(char *dir, char *columns) {
  char exec_cmd[512] = { 0 }, index_cmd[512] = { 0 }, cmd[2048] = { 0 }, cols[2048] = { 0 }, *path;
  struct stat stats;
  int ret;

  if(readOnlyGlobals.fastbit_index_directory) {
    int found = 0;
    path = "./fastbit/fbindex";

    if(stat(path, &stats) != 0) {
      path = "/usr/local/bin/fbindex";
      if(stat(path, &stats) != 0) {
	traceEvent(TRACE_ERROR, "Unable to locate tool %s. Directory indexing aborted", path);
      } else
	found = 1;
    } else
      found = 1;

    if(found) {
      if((columns == NULL) || (columns[0] == '\0'))
	cols[0] = '\0';
      else
	snprintf(cols, sizeof(cols), "-c \"%s\"", columns);

      snprintf(index_cmd, sizeof(index_cmd), "%s -s -d \"%s\" %s ;", path, dir, cols);
    }
  }

  if(readOnlyGlobals.fastbit_exec != NULL) {
    snprintf(exec_cmd, sizeof(exec_cmd), "%s \"%s\"", readOnlyGlobals.fastbit_exec, dir);
  } else
    exec_cmd[0] = '\0';

  snprintf(cmd, sizeof(cmd), "(%s%s) > /dev/null &", index_cmd, exec_cmd);
  ret = system(cmd);

  traceEvent(TRACE_NORMAL, "Indexing/analyzing %u flows on dir '%s' [%s]",
	     num_dumped_flows, dir, cmd);

  num_dumped_flows = 0;
}


/* **************************************** */

static void flush_fastbit2disk(V9V10TemplateElementId **elem, time_t now, u_int8_t final_flush) {
  char next_dump_dir[sizeof(readWriteGlobals->fastbit_actual_dump_dir)] =  { '\0' };

  if(readOnlyGlobals.fastbit_dump_directory == NULL) return;

  if(readWriteGlobals->next_fastbit_rotation < now) {
    char creation_time[256], cmd[256];
    struct tm *tm;
    int ret;

    now -= (now % 60);
    tm = localtime(&now);

    /* Round directory name at the correct time */
    if(readOnlyGlobals.fastbit_mins_rotation > 1) {
      //printf("Before: %u\n", tm->tm_min);
      int diff = (tm->tm_min % readOnlyGlobals.fastbit_mins_rotation);
      tm->tm_min -= diff;
      //printf("After:  %u\n", tm->tm_min);
    }

    strftime(creation_time, sizeof(creation_time), "%Y/%m/%d/%H/%M", tm);

    snprintf(next_dump_dir,
	     sizeof(next_dump_dir), "%s/%s",
	     readOnlyGlobals.fastbit_dump_directory, creation_time);
#ifdef WIN32
    revertSlash(next_dump_dir, 0);
#endif

    snprintf(cmd, sizeof(cmd), "mkdir %s %s",
#ifdef WIN32
	     "",
#else
	     "-p",
#endif
	     next_dump_dir);

    ret = system(cmd);
    readWriteGlobals->next_fastbit_rotation =
      now - (now % (60*readOnlyGlobals.fastbit_mins_rotation))
      + (60 * readOnlyGlobals.fastbit_mins_rotation);
    traceEvent(TRACE_NORMAL, "Fastbit files will be saved in %s",
	       next_dump_dir);
  }

  if(readWriteGlobals->fastbit_actual_dump_dir[0] == '\0') {
    /* Initial dump */
    strcpy(readWriteGlobals->fastbit_actual_dump_dir, next_dump_dir);
    /* Make sure we delete an old .lock file if available */
#ifndef WIN32
    unlock_dir(readWriteGlobals->fastbit_actual_dump_dir);
#endif
    return;
  }

#ifndef WIN32
  if(!final_flush)
    lock_dir(readWriteGlobals->fastbit_actual_dump_dir);
#endif

  if(readWriteGlobals->fastbit.num_entries > 0) {
    struct timeval begin, end, diff;
    char *fb_type = NULL;
    int i, fb_idx;

#ifdef FASTBIT_DEBUG
    traceEvent(TRACE_NORMAL, "Dumping %d fastbit entries",
	       readWriteGlobals->fastbit.num_entries);
#endif

    gettimeofday(&begin, NULL);

    pthread_mutex_lock(&readWriteGlobals->fastbit.fb_mutex);

    for(i=0, fb_idx = 0; i<TEMPLATE_LIST_LEN; i++) {
      if((elem[i] != NULL)
	 && readWriteGlobals->fastbit_dump_switch[i]) {
	int iterations = 1;

	if((elem[i]->templateElementLen <= 6)
	   || (elem[i]->templateElementLen == 16)) {
	  if(elem[i]->templateElementLen <= 1)
	    fb_type = "byte";
	  else if(elem[i]->templateElementLen <= 2)
	    fb_type = "ushort";
	  else if(elem[i]->templateElementLen <= 4)
	    fb_type = "uint";
	  else if(elem[i]->templateElementLen <= 6)
	    fb_type = "ulong";
	  else if(elem[i]->templateElementLen == 16) {
	    fb_type = "uint", iterations = 4;
	  } else
	    fb_type = NULL;

	  if(fb_type != NULL) {
	    if(iterations == 1) {
	      fastbit_add_values(elem[i]->templateElementName,
				 fb_type, readWriteGlobals->fastbit.fb_element[fb_idx++],
				 readWriteGlobals->fastbit.num_entries,
				 0 /* start */);
	    } else {
	      int iter;

	      for(iter=0; iter<iterations; iter++) {
		char buf[128];

		snprintf(buf, sizeof(buf), "%s_%d",
			 elem[i]->templateElementName, iter);

		fastbit_add_values(buf, fb_type,
				   readWriteGlobals->fastbit.fb_element[fb_idx++],
				   readWriteGlobals->fastbit.num_entries,
				   0 /* start */);
	      }
	    }
	  }
	}
      }
    }

    fastbit_flush_buffer(readWriteGlobals->fastbit_actual_dump_dir);
    pthread_mutex_unlock(&readWriteGlobals->fastbit.fb_mutex);

#ifndef WIN32
    unlock_dir(readWriteGlobals->fastbit_actual_dump_dir);
#endif

    gettimeofday(&end, NULL);
    timeval_diff(&begin, &end, &diff, 0);

#ifdef FASTBIT_DEBUG
    traceEvent(TRACE_INFO,
	       "Flushed %d fastbit records on disk in %d.%03d sec",
	       readWriteGlobals->fastbit.num_entries,
	       2*diff.tv_sec, 2*diff.tv_usec/1000);
#endif

    num_dumped_flows += readWriteGlobals->fastbit.num_entries;
    readWriteGlobals->fastbit.num_entries = 0;
  }

  if(next_dump_dir[0] != '\0') {
    if(readWriteGlobals->next_fastbit_rotation
       && (readOnlyGlobals.fastbit_index_directory || readOnlyGlobals.fastbit_exec))
      index_exec_fastbit_directory(readWriteGlobals->fastbit_actual_dump_dir,
				   readOnlyGlobals.fastbit_index_columns);

    strcpy(readWriteGlobals->fastbit_actual_dump_dir, next_dump_dir);
  }
}

/* **************************************** */

int init_fastbit(V9V10TemplateElementId **elems, char *config_file) {
  int i, fb_idx;

  if(readOnlyGlobals.fastbit_dump_directory == NULL) return(0);

  if(readOnlyGlobals.fastbit_dump_template == NULL) {
    traceEvent(TRACE_INFO, "No --fastbit-template option specified. Dumping all fields");
    readOnlyGlobals.fastbit_dump_template = strdup(readOnlyGlobals.stringTemplateV4);
  }

  memset(readWriteGlobals->fastbit_dump_switch, 0,
	 sizeof(readWriteGlobals->fastbit_dump_switch));

  pthread_mutex_init(&readWriteGlobals->fastbit.fb_mutex, NULL);

  fastbit_init(config_file);

#ifdef FASTBIT_DEBUG
  // fastbit_set_verbose_level(99);
#endif

  readWriteGlobals->fastbit.num_entries = 0, readWriteGlobals->fastbit.max_num_entries = 8*4096; // FIX

  for(i=0, fb_idx=0; i<TEMPLATE_LIST_LEN; i++) {
    readWriteGlobals->fastbit.fb_element[fb_idx] = NULL; /* Default */

    if(elems[i] != NULL) {
      if(strstr(readOnlyGlobals.fastbit_dump_template, elems[i]->templateElementName)) {
	/* This field will dump dumped on fastbit */
	readWriteGlobals->fastbit_dump_switch[i] = 1;
      }

      if(readWriteGlobals->fastbit_dump_switch[i]) {
	if((elems[i]->templateElementLen <= 6)
	   || (elems[i]->templateElementLen == 16)) {
	  int iterations = 1, iter, len = 0;

	  if(elems[i]->templateElementLen <= 1)
	    len = 1; /* byte */
	  else if(elems[i]->templateElementLen <= 2)
	    len = 2; /* ushort */
	  else if(elems[i]->templateElementLen <= 4)
	    len = 4; /* uint */
	  else if(elems[i]->templateElementLen <= 6)
	    len = 8; /* ulong */
	  else if(elems[i]->templateElementLen == 16)
	    len = iterations = 4; /* 4 * uint */

	  for(iter=0; iter<iterations; iter++) {
	    int fb_len;

	    // #ifdef FASTBIT_DEBUG
	    traceEvent(TRACE_INFO, "Found [%20s][%d bytes][fb id=%d][fb len=%d]",
		       elems[i]->templateElementName,
		       elems[i]->templateElementLen,
		       fb_idx, len);
	    // #endif

	    fb_len = len * readWriteGlobals->fastbit.max_num_entries;
	    readWriteGlobals->fastbit.fb_element[fb_idx] = (void*)malloc(fb_len);

	    if(readWriteGlobals->fastbit.fb_element[fb_idx] == NULL) {
	      traceEvent(TRACE_ERROR, "Not enough memory");
	      exit(0);
	    } else
	      readWriteGlobals->fastbit.fb_element_len++;

	    fb_idx++;
	  }
	}
      }
    }
  }

  flush_fastbit2disk(elems, time(NULL), 0);
  traceEvent(TRACE_NORMAL, "Successfully initialized FastBit");
  return(0);
}

/* **************************************** */

void term_fastbit(V9V10TemplateElementId **elems) {
  int i;

  if(readOnlyGlobals.fastbit_dump_directory == NULL) return;

  if(readOnlyGlobals.fastbit_dump_template != NULL)
    free(readOnlyGlobals.fastbit_dump_template);

  flush_fastbit2disk(elems, time(NULL), 1); /* Final flush */

  for(i=0; i<TEMPLATE_LIST_LEN; i++) {
    if(elems[i] != NULL) {
      if(readWriteGlobals->fastbit.fb_element[i] != NULL)
	free(readWriteGlobals->fastbit.fb_element[i]);
    }
  }

  traceEvent(TRACE_NORMAL, "FastBit shut down");
}

/* **************************************** */

void dump_flow2fastbit(V9V10TemplateElementId **elems, char *buffer, u_int32_t buffer_len) {
  int i, pos = 0, fb_idx;
  time_t now;

  if(readOnlyGlobals.fastbit_dump_directory == NULL) return;

  for(i=0, fb_idx = 0; i<TEMPLATE_LIST_LEN; i++) {
    if(elems[i] != NULL) {
#ifdef FASTBIT_DEBUG
      traceEvent(TRACE_INFO, "Found [%20s][%d bytes]",
		 template[i]->templateElementName,
		 template[i]->templateElementLen);
#endif

      if(readWriteGlobals->fastbit_dump_switch[i]) {
	if((elems[i]->templateElementLen <= 6)
	   || (elems[i]->templateElementLen == 16)) {
	  u_int8_t a = 0, b = 0, c = 0, d = 0;
	  char *ptr = readWriteGlobals->fastbit.fb_element[fb_idx];

	  if(ptr == NULL) continue;

	  if(elems[i]->templateElementLen == 1) {
	    ptr += (1 /* 8 bit */ * readWriteGlobals->fastbit.num_entries);

	    ptr[0] = buffer[pos], fb_idx++;
#ifdef FASTBIT_DEBUG
	    traceEvent(TRACE_NORMAL, "%s = %u", template[i]->templateElementName, ptr[0]);
#endif
	  } else if(elems[i]->templateElementLen == 2) {
	    u_int16_t val, len = 2 /* 16 bit */;

	    c &= 0xFF, d &= 0xFF;
	    c = buffer[pos], d = buffer[pos+1];
	    val = ((c << 8) + d);

	    ptr += (len * readWriteGlobals->fastbit.num_entries), fb_idx++;
	    memcpy(ptr, &val, len);
#ifdef FASTBIT_DEBUG
	    traceEvent(TRACE_NORMAL, "%s = %u", template[i]->templateElementName, val);
#endif
	  } else if(elems[i]->templateElementLen == 3) {
	    u_int32_t val, len = 4 /* 32 bit */;

	    b = buffer[pos], c = buffer[pos+1], d = buffer[pos+2];
	    b &= 0xFF, c &= 0xFF, d &= 0xFF;
	    val =  ((b << 16) + (c << 8) + d);

#if 0
	    if(elems[i]->templateElementId == 1) {
	      if(val >= 10000000) {
		traceEvent(TRACE_NORMAL, "LEN is broken! Input was: %x %x %x %x!  %u\n",a,b, c,d,val);
	      }
	    }
#endif

	    ptr += (len * readWriteGlobals->fastbit.num_entries), fb_idx++;
	    memcpy(ptr, &val, len);
	  } else if(elems[i]->templateElementLen == 4) {
	    u_int32_t val, len = 4 /* 32 bit */;

	    a = buffer[pos], b = buffer[pos+1], c = buffer[pos+2], d = buffer[pos+3];
	    a &= 0xFF, b &= 0xFF, c &= 0xFF, d &= 0xFF;
	    val =  ((a << 24) + (b << 16) + (c << 8) + d);

	    if((elems[i]->templateElementId == 21 /* LAST_SWITCHED */)
	       || (elems[i]->templateElementId == 22 /* FIRST_SWITCHED */)) {
	      /*
		We need to patch this value as we want to save the epoch on fastbit and not
		the sysuptime expressed in msec
	      */
	      val = (val / 1000) + readOnlyGlobals.initialSniffTime.tv_sec;
	      // traceEvent(TRACE_NORMAL, "%u (%u)", val, readOnlyGlobals.initialSniffTime.tv_sec);
	    }

	    ptr += (len * readWriteGlobals->fastbit.num_entries), fb_idx++;
#ifdef FASTBIT_DEBUG
	    traceEvent(TRACE_NORMAL, "%s = %u", template[i]->templateElementName, val);
#endif
	    memcpy(ptr, &val, len);
	  } else if(elems[i]->templateElementLen <= 6) {
	    /* 8 bytes padding */
	    int len = 8 /* 64 bit */;

	    ptr += (len * readWriteGlobals->fastbit.num_entries);
	    memset(ptr, 0, len-elems[i]->templateElementLen);
	    memcpy(&ptr[len-elems[i]->templateElementLen],
		   &buffer[pos], elems[i]->templateElementLen);
	    fb_idx++;
	  } else if(elems[i]->templateElementLen == 16) {
	    u_int32_t val, len = 4 /* 128 bit = 4 * 32 bit */, iter = 4;
	    int my_pos = pos;

#ifdef FASTBIT_DEBUG
	    {
	      int j=0;

	      for(j=0; j<16; j++) traceEvent(TRACE_NORMAL, "==> [%d][%02X]", j, buffer[my_pos+j] & 0xFF);
	    }
#endif

	    while(iter > 0) {
	      ptr = readWriteGlobals->fastbit.fb_element[fb_idx];
	      ptr += (len * readWriteGlobals->fastbit.num_entries);

	      a = buffer[my_pos], b = buffer[my_pos+1], c = buffer[my_pos+2], d = buffer[my_pos+3];
	      a &= 0xFF, b &= 0xFF, c &= 0xFF, d &= 0xFF;
	      val = ((a << 24) + (b << 16) + (c << 8) + d);
#ifdef FASTBIT_DEBUG
	      traceEvent(TRACE_NORMAL, "==> [fb_idx=%d][val=%08X/%u]", fb_idx, val,val);
#endif
	      memcpy(ptr, &val, len);
	      fb_idx++, my_pos += 4;
	      iter--;
	    }
	  } else {
	    /* Skip values */
	  }
	}
      }

      pos += elems[i]->templateElementLen;

      if(readOnlyGlobals.netFlowVersion == 5) {
	/* We need to skip fields such as pad1 and pad2 */

	if(elems[i]->templateElementId == 11 /* dstport */)
	  pos += 1; /*  skip pad1 */
	else if(elems[i]->templateElementId == 13 /* dst_mask */)
	  pos += 2; /* Skip pad2 */
      }
    }
  }

  readWriteGlobals->fastbit.num_entries++;
  now = time(NULL);

#ifdef FASTBIT_DEBUG
  traceEvent(TRACE_INFO, "Added fastbit record [total=%d][sec2dump=%d]",
	     readWriteGlobals->fastbit.num_entries, readWriteGlobals->next_fastbit_rotation-now);
#endif

  if((readWriteGlobals->fastbit.num_entries == readWriteGlobals->fastbit.max_num_entries)
     || (readWriteGlobals->next_fastbit_rotation == 0)
     || (readWriteGlobals->next_fastbit_rotation < now))
    flush_fastbit2disk(elems, now, 0);
}

/* ************************************************ */

#endif /* HAVE_FASTBIT */
