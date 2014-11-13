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

#include "nprobe.h"

#define FULL_STATS 1
static u_int8_t traceLRU = 1;

/*
   Nutcracker
   https://github.com/twitter/twemproxy
*/
/* ************************************ */

static void incrementSetDeleteQueueStats(u_int16_t id) {
#ifdef HAVE_REDIS
  readWriteGlobals->redis.queuedSetDeleteCommands[id]++, readWriteGlobals->redis.numSetCommands[id]++;

  if(readWriteGlobals->redis.queuedSetDeleteCommands[id] > readWriteGlobals->redis.maxQueuedSetDeleteCommands[id])
    readWriteGlobals->redis.maxQueuedSetDeleteCommands[id] = readWriteGlobals->redis.queuedSetDeleteCommands[id];
#endif
}

/* ************************************ */
 
static void incrementLoggingQueueStats(u_int16_t id) {
#ifdef HAVE_REDIS
  readWriteGlobals->redis.queuedLoggingCommands[id]++, readWriteGlobals->redis.numLoggingCommands[id]++;

  if(readWriteGlobals->redis.queuedLoggingCommands[id] > readWriteGlobals->redis.maxQueuedLoggingCommands[id])
    readWriteGlobals->redis.maxQueuedLoggingCommands[id] = readWriteGlobals->redis.queuedLoggingCommands[id];
#endif
}

/* ************************************ */

#ifdef HAVE_REDIS
static redisContext* connectToRedis(u_int8_t logging_redis) {
  redisContext *rc;
  struct timeval timeout = { 1, 500000 }; // 1.5 seconds
  char *host;
  u_int port;

  if(logging_redis)
    host = readOnlyGlobals.redis.logging_redis_host, port = readOnlyGlobals.redis.logging_redis_port;
  else
    host = readOnlyGlobals.redis.remote_redis_host, port = readOnlyGlobals.redis.remote_redis_port;

  if(host == NULL) return(NULL);

#ifndef WIN32
  if(host[0] == '/')
    rc = redisConnectUnix(host);
  else
#endif
    rc = redisConnectWithTimeout(host, port, timeout);

  if(rc->err) {
    traceEvent(TRACE_ERROR, "Redis Connection error: %s", rc->errstr);
    return(NULL);
  }

  return(rc);
}
#endif

/* ************************************ */

void logCacheKeyValueString(const char *prefix, u_int16_t id, const char *value) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.logging_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_logging[id]);
    if(readOnlyGlobals.redis.logging_context[id] == NULL) readOnlyGlobals.redis.logging_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.logging_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] RPUSH log.%s %s", prefix, value);
      redisAppendCommand(readOnlyGlobals.redis.logging_context[id], "RPUSH log.%s %s", prefix, value);
      incrementLoggingQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_logging[id]);
  }
#endif
}

/* ************************************ */

void queueCacheKeyValueString(const char *prefix, u_int16_t id, const char *queue_name, const char *value) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] RPUSH %s%s %s", prefix, queue_name, value);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "RPUSH %s%s %s", prefix, queue_name, value);
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif
}

/* ************************************ */

void setCacheKeyValueString(const char *prefix, u_int16_t id, const char *key, const char *value) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] SET %s%s %s", prefix, key, value);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "SET %s%s %s", prefix, key, value);
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif
}

/* ************************************************* */

void publishKeyValueString(const char *prefix, u_int16_t id, const char *key, const char *value) {
#ifdef HAVE_REDIS
  if(!readOnlyGlobals.redis.use_nutcracker) {
    if(readOnlyGlobals.redis.write_context[id]) {
      pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
      if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
      if(readOnlyGlobals.redis.write_context[id]) {
	if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] PUBLISH %s%s %s", prefix, key, value);
	redisAppendCommand(readOnlyGlobals.redis.write_context[id], "PUBLISH %s%s %s", prefix, key, value);
	incrementSetDeleteQueueStats(id);
      }
      pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    }
  }
#endif
}

/* ************************************************* */

void setCacheKeyValueNumber(const char *prefix, u_int16_t id, const char *key, u_int64_t value) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {      
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] SET %s%s %llu", prefix, key, value);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "SET %s%s %llu", prefix, key, value);
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif
}

/* ************************************************* */

void setCacheKeyValueNumberNumber(const char *prefix, u_int16_t id, const u_int32_t key, const u_int32_t value) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {      
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] SET %s%u %u", prefix, key, value);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "SET %s%u %u", prefix, key, value);
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif
}

/* ************************************************* */

void setCacheKeyValueNumberString(const char *prefix, u_int16_t id, const u_int32_t key, const char *value) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] SET %s%u %s", prefix, key, value);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "SET %s%u %s", prefix, key, value);
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif
}

/* ************************************************* */

void incrCacheKeyValueNumber(const char *prefix, u_int16_t id, const char *key, u_int64_t value) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] INCRBY %s%s %llu", prefix, key, value);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "INCRBY %s%s %llu", prefix, key, value);
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif
}

/* ************************************************* */

void incrHashCacheKeyValueNumber(const char *element, u_int16_t id, const char *key, u_int64_t value) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] HINCRBY %s %s %llu", element, key, value);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "HINCRBY %s %s %llu", element, key, value);
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif
}

/* ************************************************* */

void expireCacheKey(const char *prefix, u_int16_t id, const char *key, u_int32_t duration_sec) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] EXPIRE %s%s %u", prefix, key, duration_sec);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "EXPIRE %s%s %u", prefix, key, duration_sec);
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif
}

/* ************************************ */

void setCacheHashKeyValueString(const char *element, u_int16_t id, const char *key, const char *value) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] HSET %s %s %s", element, key, value);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "HSET %s %s %s", element, key, value);
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif
}

/* ************************************************* */

void setCacheHashKeyValueNumber(const char *element, u_int16_t id, const char *key, u_int64_t value) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] HSET %s %s %llu", element, key, value);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "HSET %s %s %llu", element, key, value);
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif
}

/* ************************************************* */

void incrCacheHashKeyValueNumber(const char *element,
				 u_int16_t id, const char *key, const u_int64_t value) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id] && (value > 0)) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] HINCRBY %s %s %llu", element, key, value);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "HINCRBY %s %s %llu", element, key, value);
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif
}

/* ************************************************* */

void zIncrCacheHashKeyValueNumber(const char *set_name,
				  u_int16_t id, const char *key, const u_int64_t value) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id] && (value > 0)) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] ZINCRBY %s %llu %s", set_name, value, key);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "ZINCRBY %s %llu %s", set_name, value, key);
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif
}

/* ************************************************* */

void setCacheNumKeyMixedValueDual(const char *prefix,
				  u_int16_t id,
                                  const u_int32_t key0, const char* value0,
                                  const u_int32_t key1, const char* value1) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.use_nutcracker) {
    setCacheKeyValueNumberString(prefix, id, key0, value0);
    setCacheKeyValueNumberString(prefix, id, key1, value1);
  } else {
    if(readOnlyGlobals.redis.write_context[id]) {
      pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
      if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
      if(readOnlyGlobals.redis.write_context[id]) {
	if(unlikely(readOnlyGlobals.enable_debug))
	  traceEvent(TRACE_NORMAL, "[Redis] MSET %s%u %s %s%u %s",
		     prefix, key0, value0, prefix, key1, value1);
	redisAppendCommand(readOnlyGlobals.redis.write_context[id],
			   "MSET %s%u \"%s\" %s%u \"%s\"",
			   prefix, key0, value0, prefix, key1, value1);
	incrementSetDeleteQueueStats(id);
      }
      pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    }
  }
#endif
}

/* ************************************************* */

void setCacheHashNumKeyMixedValueDual(const char *master_key,
				      u_int16_t id,
				      const u_int32_t key0, const char* value0,
				      const u_int32_t key1, const char* value1) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.use_nutcracker) {
    setCacheKeyValueNumberString(master_key, id, key0, value0);
    setCacheKeyValueNumberString(master_key, id, key1, value1);
  } else {
    if(readOnlyGlobals.redis.write_context[id]) {
      pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
      if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
      if(readOnlyGlobals.redis.write_context[id]) {
	if(unlikely(readOnlyGlobals.enable_debug))
	  traceEvent(TRACE_NORMAL, "[Redis] HMSET %s %u %s %u %s",
		     master_key,
		     key0, value0,
		     key1, value1);
	redisAppendCommand(readOnlyGlobals.redis.write_context[id],
			   "HMSET %s %u %s %u %s",
			   master_key,
			   key0, value0,
			   key1, value1);
	
	incrementSetDeleteQueueStats(id);
      }
      pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    }
  }
#endif
}














/* ************************************************* */

void setCacheNumKeyMixedValueQuad(const char *prefix,
				  u_int16_t id,
                                  const u_int32_t key0, const char* value0,
                                  const u_int32_t key1, const char* value1,
                                  const u_int32_t key2, const u_int32_t value2,
                                  const u_int32_t key3, const u_int32_t value3) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.use_nutcracker) {
    setCacheKeyValueNumberString(prefix, id, key0, value0);
    setCacheKeyValueNumberString(prefix, id, key1, value1);
    setCacheKeyValueNumberNumber(prefix, id, key2, value2);
    setCacheKeyValueNumberNumber(prefix, id, key3, value3);
  } else {
    if(readOnlyGlobals.redis.write_context[id]) {
      pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
      if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
      if(readOnlyGlobals.redis.write_context[id]) {
	if(unlikely(readOnlyGlobals.enable_debug))
	  traceEvent(TRACE_NORMAL, "[Redis] MSET %s%u %s %s%u %s %s%u %u %s%u %u",
		     prefix, key0, value0, prefix, key1, value1,
		     prefix, key2, value2, prefix, key3, value3);
	redisAppendCommand(readOnlyGlobals.redis.write_context[id],
			   "MSET %s%u \"%s\" %s%u \"%s\" %s%u %u %s%u %u",
			   prefix, key0, value0, prefix, key1, value1,
			   prefix, key2, value2, prefix, key3, value3);
	incrementSetDeleteQueueStats(id);
      }
      pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    }
  }
#endif
}

/* ************************************************* */

void setCacheHashNumKeyMixedValueQuad(const char *master_key,
				      u_int16_t id,
				      const u_int32_t key0, const char* value0,
				      const u_int32_t key1, const char* value1,
				      const u_int32_t key2, const u_int32_t value2,
				      const u_int32_t key3, const u_int32_t value3) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.use_nutcracker) {
    setCacheKeyValueNumberString(master_key, id, key0, value0);
    setCacheKeyValueNumberString(master_key, id, key1, value1);
    setCacheKeyValueNumberNumber(master_key, id, key2, value2);
    setCacheKeyValueNumberNumber(master_key, id, key3, value3);
  } else {
    if(readOnlyGlobals.redis.write_context[id]) {
      pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
      if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
      if(readOnlyGlobals.redis.write_context[id]) {
	if(unlikely(readOnlyGlobals.enable_debug))
	  traceEvent(TRACE_NORMAL, "[Redis] HMSET %s %u %s %u %s %u %u %u %u",
		     master_key,
		     key0, value0,
		     key1, value1,
		     key2, value2,
		     key3, value3);
	redisAppendCommand(readOnlyGlobals.redis.write_context[id],
			   "HMSET %s %u %s %u %s %u %u %u %u",
			   master_key,
			   key0, value0,
			   key1, value1,
			   key2, value2,
			   key3, value3);
	
	incrementSetDeleteQueueStats(id);
      }
      pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    }
  }
#endif
}

/* ************************************ */

char* getCacheDataNumKey(const char *prefix, u_int16_t id, const u_int32_t key) {
#ifdef HAVE_REDIS
  char *ret = NULL;

  if(readOnlyGlobals.redis.read_context) {
    redisReply *reply = NULL;

    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_get);
    if(readOnlyGlobals.redis.read_context == NULL) readOnlyGlobals.redis.read_context = connectToRedis(0);
    if(readOnlyGlobals.redis.read_context) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] GET %s%u", prefix, key);
      reply = redisCommand(readOnlyGlobals.redis.read_context, "GET %s%u", prefix, key);
      readWriteGlobals->redis.numGetCommands[id]++;
    }

    if(reply && (readOnlyGlobals.redis.read_context->err == REDIS_OK)) {
      if(reply->str) {
	ret = strdup(reply->str);
	if(unlikely(readOnlyGlobals.enable_debug))
	  traceEvent(TRACE_NORMAL, "[Redis] %s(%u)=%s", __FUNCTION__, key, ret);
      }
      freeReplyObject(reply);
    } else {
      /* Redis down ? */
      // redisFree(readOnlyGlobals.redis.read_context);
      readOnlyGlobals.redis.read_context = connectToRedis(0);
    }

    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_get);
  }

  return(ret);
#else
  return(NULL);
#endif
}

/* ************************************ */

char* getCacheDataStrKey(const char *prefix, u_int16_t id, const char *key) {
#ifdef HAVE_REDIS
  char *ret = NULL;

  if(readOnlyGlobals.redis.read_context) {
    redisReply *reply = NULL;

    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_get);
    if(readOnlyGlobals.redis.read_context == NULL) readOnlyGlobals.redis.read_context = connectToRedis(0);
    if(readOnlyGlobals.redis.read_context) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] GET %s%s", prefix, key);
      reply = redisCommand(readOnlyGlobals.redis.read_context, "GET %s%s", prefix, key);
      readWriteGlobals->redis.numGetCommands[id]++;
    }

    if(reply && (readOnlyGlobals.redis.read_context->err == REDIS_OK)) {
      if(reply->str) {
	ret = strdup(reply->str);
	if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_INFO, "[Redis] %s(%u)=%s", __FUNCTION__, key, ret);
      }
      freeReplyObject(reply);
    } else {
      /* Redis down ? */
      // redisFree(readOnlyGlobals.redis.read_context);
      readOnlyGlobals.redis.read_context = connectToRedis(0);
    }

    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_get);
  }

  return(ret);
#else
  return(NULL);
#endif
}

/* ************************************ */

void getCacheDataStrKeyTwin(const char *prefix, u_int16_t id, const char *key1, const char *key2, char **rsp1, char **rsp2) {
#ifdef HAVE_REDIS

  if(readOnlyGlobals.redis.read_context) {
    redisReply *reply = NULL;

    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_get);
    if(readOnlyGlobals.redis.read_context == NULL) readOnlyGlobals.redis.read_context = connectToRedis(0);
    if(readOnlyGlobals.redis.read_context) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] MGET %s%s %s%s", prefix, key1, prefix, key2);
      reply = redisCommand(readOnlyGlobals.redis.read_context, "MGET %s%s %s%s", prefix, key1, prefix, key2);
      readWriteGlobals->redis.numGetCommands[id]++;
    }

    if(reply && (readOnlyGlobals.redis.read_context->err == REDIS_OK)) {
      *rsp1 = reply->element[0]->str ? strdup(reply->element[0]->str) : NULL;
      *rsp2 = reply->element[1]->str ? strdup(reply->element[1]->str) : NULL;

      if(unlikely(readOnlyGlobals.enable_debug))
	traceEvent(TRACE_NORMAL, "[Redis] %s(%s, %s)=(%s, %s)", __FUNCTION__, key1, key2, *rsp1 ? *rsp1 : "", *rsp2 ? *rsp2 : "");
      freeReplyObject(reply);
    } else {
      /* Redis down ? */
      // redisFree(readOnlyGlobals.redis.read_context);
      readOnlyGlobals.redis.read_context = connectToRedis(0);
    }

    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_get);
  }

#endif
}

/* ************************************ */

void getCacheDataNumKeyTwin(const char *prefix, u_int16_t id, const u_int32_t key1, const u_int32_t key2, char **rsp1, char **rsp2) {
#ifdef HAVE_REDIS

  if(readOnlyGlobals.redis.read_context) {
    redisReply *reply = NULL;

    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_get);
    if(readOnlyGlobals.redis.read_context == NULL) readOnlyGlobals.redis.read_context = connectToRedis(0);
    if(readOnlyGlobals.redis.read_context) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] MGET %s%u %s%u", prefix, key1, prefix, key2);
      reply = redisCommand(readOnlyGlobals.redis.read_context, "MGET %s%u %s%u", prefix, key1, prefix, key2);
      readWriteGlobals->redis.numGetCommands[id]++;
    }

    if(reply && (readOnlyGlobals.redis.read_context->err == REDIS_OK)) {
      if(reply->element == NULL)
	*rsp1 = *rsp2 = NULL;
      else {
	*rsp1 = reply->element[0]->str ? strdup(reply->element[0]->str) : NULL;
	*rsp2 = reply->element[1]->str ? strdup(reply->element[1]->str) : NULL;
      }

      if(unlikely(readOnlyGlobals.enable_debug))
	traceEvent(TRACE_NORMAL, "[Redis] %s(%u, %u)=(%s, %s)", __FUNCTION__, key1, key2, *rsp1 ? *rsp1 : "", *rsp2 ? *rsp2 : "");
      freeReplyObject(reply);
    } else {
      /* Redis down ? */
      // redisFree(readOnlyGlobals.redis.read_context);
      readOnlyGlobals.redis.read_context = connectToRedis(0);
    }

    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_get);
  }

#endif
}

/* ************************************ */

int deleteCacheStrKey(const char *prefix, u_int16_t id, const char *key, const u_int32_t delete_delay_sec) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] EXPIRE %s%s %d", prefix, key, delete_delay_sec);
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(delete_delay_sec > 0)
	redisAppendCommand(readOnlyGlobals.redis.write_context[id], "EXPIRE %s%s %d", prefix, key, delete_delay_sec);
      else
	redisAppendCommand(readOnlyGlobals.redis.write_context[id], "DEL %s%s", prefix, key);
      
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif

  return(0);
}

/* ************************************ */

int deleteCacheNumKey(const char *prefix, u_int16_t id, const u_int32_t key, const u_int32_t delete_delay_sec) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);

    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] EXPIRE %s%u %d", prefix, key, delete_delay_sec);
      if(delete_delay_sec > 0)
	redisAppendCommand(readOnlyGlobals.redis.write_context[id], "EXPIRE %s%u %d", prefix, key, delete_delay_sec);
      else
	redisAppendCommand(readOnlyGlobals.redis.write_context[id], "DEL %s%u", prefix, key);
      
      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif

  return(0);
}

/* ************************************ */

/* Redis does not accept expire time */
int deleteCacheNumKeyTwin(const char *prefix, u_int16_t id, const u_int32_t key1, const u_int32_t key2) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);

    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] DEL %s%u %s%u", prefix, key1, prefix, key2);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "DEL %s%u %s%u", prefix, key1, prefix, key2);

      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif

  return(0);
}

/* ************************************ */

/* Redis does not accept expire time */
int deleteCacheStrKeyTwin(const char *prefix, u_int16_t id, const char *key1, const char *key2) {
#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.write_context[id]) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);

    if(readOnlyGlobals.redis.write_context[id] == NULL) readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    if(readOnlyGlobals.redis.write_context[id]) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] DEL %s%s %s%s", prefix, key1, prefix, key2);
      redisAppendCommand(readOnlyGlobals.redis.write_context[id], "DEL %s%s %s%s", prefix, key1, prefix, key2);

      incrementSetDeleteQueueStats(id);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
  }
#endif

  return(0);
}

/* ************************************ */

char* getHashCacheDataStrKey(const char *prefix, u_int16_t id, const char *element, const char *key) {
#ifdef HAVE_REDIS
  char *ret = NULL;

  if(readOnlyGlobals.redis.read_context) {
    redisReply *reply = NULL;

    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_get);
    if(readOnlyGlobals.redis.read_context == NULL) readOnlyGlobals.redis.read_context = connectToRedis(0);
    if(readOnlyGlobals.redis.read_context) {
      if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_NORMAL, "[Redis] HGET %s%s %s", prefix, element, key);
      reply = redisCommand(readOnlyGlobals.redis.read_context, "HGET %s%s %s", prefix, element, key);
      readWriteGlobals->redis.numGetCommands[id]++;
    }

    if(reply && (readOnlyGlobals.redis.read_context->err == REDIS_OK)) {
      if(reply->str) {
	ret = strdup(reply->str);
	// traceEvent(TRACE_NORMAL, "[Redis] %s(%u)=%s", __FUNCTION__, key, ret);
      }
      freeReplyObject(reply);
    } else {
      /* Redis down ? */
      // redisFree(readOnlyGlobals.redis.read_context);
      readOnlyGlobals.redis.read_context = connectToRedis(0);
    }

    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_get);
  }

  return(ret);
#else
  return(NULL);
#endif
}

/* ************************************ */

#ifdef HAVE_REDIS

static void processQueuedRedisCommand(u_int id) {
  redisReply *reply;

  pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);

  if(readOnlyGlobals.redis.write_context[id]) {
    redisGetReply(readOnlyGlobals.redis.write_context[id], (void**)&reply);
    if(reply && (readOnlyGlobals.redis.write_context[id]->err == REDIS_OK))
      freeReplyObject(reply);
    else {
      traceEvent(TRACE_WARNING, "It looks redis has been restarted (id: %u)", id);
      // redisFree(readOnlyGlobals.redis.write_context[id]);
      readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
    }
  } else
    readOnlyGlobals.redis.write_context[id] = connectToRedis(0);

  readWriteGlobals->redis.queuedSetDeleteCommands[id]--;

#if 0
  if(unlikely(readOnlyGlobals.enable_debug))
    traceEvent(TRACE_NORMAL, "[Redis] %s(): got reply [queue=%d]",
	       __FUNCTION__, readWriteGlobals->redis.queuedSetDeleteCommands[id]);
#endif

  pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
}
#endif

/* ************************************ */

#ifdef HAVE_REDIS

static void processQueuedLoggingRedisCommand(u_int id) {
  redisReply *reply;

  
  pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_logging[id]);

  if(readOnlyGlobals.redis.logging_context[id]) {
    redisGetReply(readOnlyGlobals.redis.logging_context[id], (void**)&reply);
    if(reply && (readOnlyGlobals.redis.logging_context[id]->err == REDIS_OK))
      freeReplyObject(reply);
    else {
      traceEvent(TRACE_WARNING, "It looks redis has been restarted (id: %u)", id);
      // redisFree(readOnlyGlobals.redis.logging_context[id]);
      readOnlyGlobals.redis.logging_context[id] = connectToRedis(0);
    }
  } else
    readOnlyGlobals.redis.logging_context[id] = connectToRedis(0);

  readWriteGlobals->redis.queuedLoggingCommands[id]--;

  pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_logging[id]);
}
#endif

/* ************************************ */

#define MAX_NUM_ARGUMENTS   32
#define MAX_ARGUMENT_LEN   256

int readRedisLine(int sock, char *line) {
  int pos = 0;

  while(recv(sock, &line[pos++], 1, 0) > 0) {
    if((pos > 2)
       && (line[pos-2] == '\r')
       && (line[pos-1] == '\n')) {
      line[pos++] = '\0';
      return(pos);
    }
  }

  return(0);
}

int readRedisCommand(int sock, char request[MAX_NUM_ARGUMENTS][MAX_ARGUMENT_LEN]) {
  /*
   *1
   $4
   PING

   *<number of arguments> CR LF
   $<number of bytes of argument 1> CR LF
   <argument data> CR LF
   ...
   $<number of bytes of argument N> CR LF
   <argument data> CR LF
  */


  readRedisLine(sock, request[0]);
  request[1][0] = '\0';

  return(0);
}

/* ************************************ */

void handleClient(int sock) {
  char request[MAX_NUM_ARGUMENTS][MAX_ARGUMENT_LEN];

  while(readRedisCommand(sock, request) >= 0) {
    int i;
    char *rsp;

    for(i=0; request[i][0] != '\0'; i++)
      traceEvent(TRACE_NORMAL, "%s", request[i]);

    rsp = "+OK\r\n";
    send(sock, rsp, strlen(rsp), 0);
  }
}

/* ************************************ */

#ifdef HAVE_REDIS
static void* redisLocalServerLoop(void* notUsed) {
  traceEvent(TRACE_NORMAL, "[Redis Server] %s() started", __FUNCTION__);

  readOnlyGlobals.redis.local_server_running = 0;

  while(!readWriteGlobals->shutdownInProgress) {
    fd_set mask;

    FD_ZERO(&mask);
    FD_SET(readOnlyGlobals.redis.local_server_socket, &mask);

    if(select(readOnlyGlobals.redis.local_server_socket+1, &mask, 0, 0, NULL) > 0) {
      struct sockaddr_in from;
      int rx_sock, from_len;

      rx_sock = accept(readOnlyGlobals.redis.local_server_socket, (struct sockaddr*)&from, (socklen_t*)&from_len);
      if((rx_sock < 0) || (errno != 0)) {
	traceEvent(TRACE_ERROR, "Unable to accept connection [%s/%d]", strerror(errno), errno);
      }

      traceEvent(TRACE_NORMAL, "[Redis Server] New client connected [socket %d]", rx_sock);
      handleClient(rx_sock);
      close(rx_sock);
    }
  }

  readOnlyGlobals.redis.local_server_running = 1;

  return(NULL);
}
#endif

/* ************************************ */

#ifdef HAVE_REDIS
static void* redisAsyncLoop(void* _thid) {
  unsigned long id = (unsigned long)_thid;

  traceEvent(TRACE_INFO, "[Redis] %s(%d) started", __FUNCTION__, id);

  readOnlyGlobals.redis.queue_thread_running[id] = 1;

  while(!readWriteGlobals->shutdownInProgress) {
    if(readWriteGlobals->redis.queuedSetDeleteCommands[id] > 0)
      processQueuedRedisCommand(id);
    else if(readWriteGlobals->redis.queuedLoggingCommands[id] > 0)
      processQueuedLoggingRedisCommand(id);
    else
      usleep(10000); /* 10 ms */
  }

  /* Flush pending commands */
  while(readWriteGlobals->redis.queuedSetDeleteCommands[id] > 0)
    processQueuedRedisCommand(id);

  while(readWriteGlobals->redis.queuedLoggingCommands[id] > 0)
    processQueuedLoggingRedisCommand(id);

  readOnlyGlobals.redis.queue_thread_running[id] = 0;

  traceEvent(TRACE_INFO, "[Redis] %s() completed [queue=%d]", __FUNCTION__, id);
  return(NULL);
}
#endif

/* ************************************ */

int createLocalCacheServer() {
#ifdef HAVE_REDIS
  int sockopt = 1;
  struct sockaddr_in sockIn;

  if(readOnlyGlobals.redis.local_ucloud_port == 0)
    return(0);

  errno = 0;
  readOnlyGlobals.redis.local_server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if((readOnlyGlobals.redis.local_server_socket < 0) || (errno != 0)) {
    traceEvent(TRACE_ERROR, "Unable to create server socket [%s/%d]", strerror(errno), errno);
    exit(-1);
  }

  errno = 0;
  setsockopt(readOnlyGlobals.redis.local_server_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

  memset(&sockIn, 0, sizeof(sockIn));
  sockIn.sin_family = AF_INET, sockIn.sin_port = (int)htons(readOnlyGlobals.redis.local_ucloud_port), errno = 0;
  bind(readOnlyGlobals.redis.local_server_socket, (struct sockaddr *)&sockIn, sizeof(sockIn));
  if((readOnlyGlobals.redis.local_server_socket < 0) || (errno != 0)) {
    traceEvent(TRACE_ERROR, "Unable to bind to the specified port [%s/%d]", strerror(errno), errno);
    exit(-1);
  }

  errno = 0;
  listen(readOnlyGlobals.redis.local_server_socket, 1 /* 1 client max */);

  pthread_create(&readOnlyGlobals.redis.local_server_loop, NULL, redisLocalServerLoop, NULL);
#endif
  return(0);
}

/* ************************************ */

int connectToRemoteCache(void) {
#ifdef HAVE_REDIS
  int i;

  /* Asynchronous */
  if(readOnlyGlobals.redis.remote_redis_host) {
    if(unlikely(readOnlyGlobals.enable_debug))
      traceEvent(TRACE_NORMAL, "[Redis] %s(%s:%u)", __FUNCTION__,
		 readOnlyGlobals.redis.remote_redis_host, readOnlyGlobals.redis.remote_redis_port);
    
    /* Synchronous */
    readOnlyGlobals.redis.read_context = connectToRedis(0);
    
    if(readOnlyGlobals.redis.read_context == NULL)
      exit(-1);
    
    for(i=0; i<MAX_NUM_REDIS_CONNECTIONS; i++) {
      readOnlyGlobals.redis.write_context[i] = connectToRedis(0);
      
      if(readOnlyGlobals.redis.write_context[i] == NULL)
	exit(-1);
    }
  }

  if(readOnlyGlobals.redis.logging_redis_host) {
    for(i=0; i<MAX_NUM_REDIS_CONNECTIONS; i++) {
      readOnlyGlobals.redis.logging_context[i] = connectToRedis(1);
      
      if(readOnlyGlobals.redis.logging_context[i] == NULL)
	exit(-1);
    }
  }

  pthread_rwlock_init(&readOnlyGlobals.redis.lock_get, NULL);

  for(i=0; i<MAX_NUM_REDIS_CONNECTIONS; i++) {
    unsigned long id = i;

    pthread_rwlock_init(&readOnlyGlobals.redis.lock_set_delete[i], NULL);
    pthread_create(&readOnlyGlobals.redis.reply_loop, NULL, redisAsyncLoop, (void*)id);
  }

  createLocalCacheServer();
#endif

  return(0);
}

/* ************************************ */

void disconnectFromRemoteCache(void) {
#ifdef HAVE_REDIS
  int i;

  if(unlikely(readOnlyGlobals.enable_debug))
    traceEvent(TRACE_NORMAL, "[Redis] %s()", __FUNCTION__);

  for(i=0; i<MAX_NUM_REDIS_CONNECTIONS; i++) {
    while(readWriteGlobals->redis.queuedSetDeleteCommands[i] > 0) {
      if(!readOnlyGlobals.redis.queue_thread_running[i])
	processQueuedRedisCommand(i);
      else
	sleep(1);
    }
  }

  if(readOnlyGlobals.redis.read_context)
    redisFree(readOnlyGlobals.redis.read_context);

  for(i=0; i<MAX_NUM_REDIS_CONNECTIONS; i++) {
    if(readOnlyGlobals.redis.write_context[i])
      redisFree(readOnlyGlobals.redis.write_context[i]);

    pthread_rwlock_destroy(&readOnlyGlobals.redis.lock_set_delete[i]);
  }

  for(i=0; i<MAX_NUM_REDIS_CONNECTIONS; i++) {
    if(readOnlyGlobals.redis.logging_context[i])
      redisFree(readOnlyGlobals.redis.logging_context[i]);

    pthread_rwlock_destroy(&readOnlyGlobals.redis.lock_logging[i]);
  }

  pthread_rwlock_destroy(&readOnlyGlobals.redis.lock_get);

  if(readOnlyGlobals.redis.local_server_socket > 0)
    close(readOnlyGlobals.redis.local_server_socket);
#endif
}

/* ************************************ */

#ifdef HAVE_REDIS
static int pingRedisConnection(redisContext *c) {
  if(!readOnlyGlobals.redis.use_nutcracker) {
    if(c != NULL) {
      redisReply *reply = redisCommand(c, "PING");

      if(reply && (c->err == REDIS_OK)) {
	//traceEvent(TRACE_NORMAL, "[Redis] %s (%d)", reply->str ? reply->str : "", id);
	freeReplyObject(reply);
      } else {
	/* Redis down ? */
	return(-1);
      }
    }
  }

  return(0);
}

/* ************************************ */

/* Keep connections alive */
void pingRedisConnections() {
  int id;

  // traceEvent(TRACE_NORMAL, "[Redis] %s", __FUNCTION__);

  if(readOnlyGlobals.redis.read_context) {
    pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_get);
    if(pingRedisConnection(readOnlyGlobals.redis.read_context) == -1) {
      // redisFree(readOnlyGlobals.redis.read_context);
      readOnlyGlobals.redis.read_context = connectToRedis(0);
    }
    pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_get);
  }

  for(id=0; id<MAX_NUM_REDIS_CONNECTIONS; id++) {
    if(readOnlyGlobals.redis.write_context[id]) {
      pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_set_delete[id]);
      if(pingRedisConnection(readOnlyGlobals.redis.write_context[id]) == -1) {
	// redisFree(readOnlyGlobals.redis.read_context);
	readOnlyGlobals.redis.write_context[id] = connectToRedis(0);
      }

      pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_set_delete[id]);
    }
  }

  if(readOnlyGlobals.redis.logging_redis_host) {
    for(id=0; id<MAX_NUM_REDIS_CONNECTIONS; id++) {
      if(readOnlyGlobals.redis.logging_context[id]) {
	pthread_rwlock_wrlock(&readOnlyGlobals.redis.lock_logging[id]);
	if(pingRedisConnection(readOnlyGlobals.redis.logging_context[id]) == -1) {
	  // redisFree(readOnlyGlobals.redis.read_context);
	  readOnlyGlobals.redis.logging_context[id] = connectToRedis(0);
	}
	
	pthread_rwlock_unlock(&readOnlyGlobals.redis.lock_logging[id]);
      }
    }
  }
}
#endif

/* ************************************ */

void dumpCacheStats(u_int timeDifference) {
#ifdef HAVE_REDIS
  int id;
  u_int32_t totNumGets = 0, totNumSets = 0, totNumLogs = 0;
  float s, g, l;

  for(id=0; id<MAX_NUM_REDIS_CONNECTIONS; id++) {
    u_int32_t numGets = readWriteGlobals->redis.numGetCommands[id]-readWriteGlobals->redis.numLastGetCommands[id];
    u_int32_t numSets = readWriteGlobals->redis.numSetCommands[id]-readWriteGlobals->redis.numLastSetCommands[id];
    u_int32_t numLogs = readWriteGlobals->redis.numLoggingCommands[id]-readWriteGlobals->redis.numLastLoggingCommands[id];

#ifdef FULL_STATS
    g = (timeDifference > 0) ? ((float)numGets)/(float)timeDifference : 0;
    s = (timeDifference > 0) ? ((float)numSets)/(float)timeDifference : 0;
    l = (timeDifference > 0) ? ((float)numLogs)/(float)timeDifference : 0;

    if(readWriteGlobals->redis.queuedSetDeleteCommands[id] || numGets || numSets)
      traceEvent(TRACE_NORMAL, "Redis Cache [%d][write queue: actual %u/max %u]"
		 "[%u total/%.1f get/sec]"
		 "[%u total/%.1f set/sec]"
		 "[%u total/%.1f set/sec]",
		 id, readWriteGlobals->redis.queuedSetDeleteCommands[id],
		 readWriteGlobals->redis.maxQueuedSetDeleteCommands[id],
		 numGets, g, numSets, s, numLogs, l);
#endif

    readWriteGlobals->redis.numLastGetCommands[id] = readWriteGlobals->redis.numGetCommands[id];
    readWriteGlobals->redis.numLastSetCommands[id] = readWriteGlobals->redis.numSetCommands[id];
    readWriteGlobals->redis.numLastLoggingCommands[id] = readWriteGlobals->redis.numLoggingCommands[id];
    totNumGets += numGets, totNumSets += numSets, totNumLogs += numLogs;
  }

  g = (timeDifference > 0) ? ((float)totNumGets)/(float)timeDifference : 0;
  s = (timeDifference > 0) ? ((float)totNumSets)/(float)timeDifference : 0;
  l = (timeDifference > 0) ? ((float)totNumLogs)/(float)timeDifference : 0;

  traceEvent(TRACE_NORMAL, "Redis Cache [%u total/%.1f get/sec]"
	     "[%u total/%.1f set/sec]"
	     "[%u total/%.1f set/sec]",
	     (unsigned int)totNumGets, (float)g,
	     (unsigned int)totNumSets, (float)s,
	     (unsigned int)totNumLogs, (float)l);
#endif

  dumpLruCacheStats(timeDifference);
}

/* ************************************ */

int init_lru_cache(struct LruCache *cache, u_int32_t max_size) {
  traceLRU = readOnlyGlobals.enable_debug;

  if(unlikely(traceLRU))
    traceEvent(TRACE_NORMAL, "%s(max_size=%u)", __FUNCTION__, max_size);

  cache->max_cache_node_len = 4;
  cache->hash_size = max_size/cache->max_cache_node_len;

#ifdef FULL_STATS
  cache->mem_size += cache->hash_size*sizeof(struct LruCacheEntry*);
#endif
  if((cache->hash = (struct LruCacheEntry**)calloc(cache->hash_size, sizeof(struct LruCacheEntry*))) == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory?");
    return(-1);
  }

#ifdef FULL_STATS
  cache->mem_size += cache->hash_size*sizeof(u_int32_t);
#endif
  if((cache->current_hash_size = (u_int32_t*)calloc(cache->hash_size, sizeof(u_int32_t))) == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory?");
    return(-1);
  }

  pthread_rwlock_init(&cache->lruLock, NULL);
  return(0);
}

/* ************************************ */

static void free_lru_cache_entry(struct LruCache *cache, struct LruCacheEntry *entry) {
  if(entry->numeric_node) {
    ; /* Nothing to do */
  } else {
#ifdef FULL_STATS
    cache->mem_size -= strlen(entry->u.str.key);
    cache->mem_size -= strlen(entry->u.str.value);
#endif
    free(entry->u.str.key);
    free(entry->u.str.value);
  }
}

/* ************************************ */

void free_lru_cache(struct LruCache *cache) {
  int i;

  if(unlikely(traceLRU)) traceEvent(TRACE_NORMAL, "%s()", __FUNCTION__);

  for(i=0; i<cache->hash_size; i++) {
    struct LruCacheEntry *head = cache->hash[i];

    while(head != NULL) {
      struct LruCacheEntry *next = head->next;

      free_lru_cache_entry(cache, head);
      free(head);
#ifdef FULL_STATS
      cache->mem_size -= sizeof(struct LruCacheEntry);
#endif
      head = next;
    }
  }

  free(cache->hash);
#ifdef FULL_STATS
  cache->mem_size -= cache->hash_size*sizeof(struct LruCacheEntry*);
#endif
  free(cache->current_hash_size);
#ifdef FULL_STATS
  cache->mem_size -= cache->hash_size*sizeof(u_int32_t);
#endif

  pthread_rwlock_destroy(&cache->lruLock);
}

/* ************************************ */

static u_int32_t hash_string(char *a) {
  u_int32_t h = 0, i;

  for(i=0; a[i] != 0; i++) h += ((u_int32_t)a[i])*(i+1);
  return(h);
}

/* ************************************ */

u_int32_t lru_node_key_hash(struct LruCacheEntry *a) {
  if(a->numeric_node)
    return((u_int32_t)a->u.num.key);
  else
    return(hash_string(a->u.str.key));
}

/* ************************************ */
/*
  Return codes
  0  Items are the same
  -1 a < b
  1  a > b
*/
int lru_node_key_entry_compare(struct LruCacheEntry *a, struct LruCacheEntry *b) {
  if(a->numeric_node) {
    if(a->u.num.key == b->u.num.key)
      return(0);
    else if(a->u.num.key < b->u.num.key)
      return(-1);
    else
      return(1);
  } else
    return(strcmp(a->u.str.key, b->u.str.key));
}

/* ********************************************* */

struct LruCacheEntry* allocCacheNumericNode(struct LruCache *cache, u_int64_t key, u_int32_t value) {
  struct LruCacheEntry *node = (struct LruCacheEntry*)calloc(1, sizeof(struct LruCacheEntry));

  if(unlikely(traceLRU))
    traceEvent(TRACE_NORMAL, "%s(key=%lu, value=%u)", __FUNCTION__, key, value);

  if(node == NULL)
    traceEvent(TRACE_ERROR, "Not enough memory?");
  else {
    node->numeric_node = 1;
    node->u.num.key = key, node->u.num.value = value;
  }

#ifdef FULL_STATS
  cache->mem_size += sizeof(struct LruCacheEntry);
  //traceEvent(TRACE_NORMAL, "%s(key=%lu, value=%u) [memory: %u]", __FUNCTION__, key, value, cache->mem_size);
#endif

  return(node);
}

/* ************************************ */

struct LruCacheEntry* allocCacheStringNode(struct LruCache *cache, char *key, char *value, u_int32_t timeout) {
  struct LruCacheEntry *node = (struct LruCacheEntry*)calloc(1, sizeof(struct LruCacheEntry));

  if(unlikely(traceLRU))
    traceEvent(TRACE_NORMAL, "%s(key=%s, value=%s)", __FUNCTION__, key, value);

  if(node == NULL)
    traceEvent(TRACE_ERROR, "Not enough memory?");
  else {
    node->numeric_node = 0;
    node->u.str.key = strdup(key), node->u.str.value = strdup(value);
    node->u.str.expire_time = (timeout == 0) ? 0 : (timeout + readWriteGlobals->now);

#ifdef FULL_STATS
    cache->mem_size += sizeof(struct LruCacheEntry) + strlen(key) + strlen(value);
    //traceEvent(TRACE_NORMAL, "%s(key=%s, value=%s) [memory: %u]", __FUNCTION__, key, value, cache->mem_size);
#endif
  }

  return(node);
}

/* ************************************ */

static void trim_subhash(struct LruCache *cache, u_int32_t hash_id) {
  if(unlikely(traceLRU))
    traceEvent(TRACE_NORMAL, "%s()", __FUNCTION__);

  if(cache->current_hash_size[hash_id] >= cache->max_cache_node_len) {
    struct LruCacheEntry *head = cache->hash[hash_id], *prev = NULL;

    /* Find the last entry and remove it */
    while(head->next != NULL) {
      prev = head;
      head = head->next;
    }

    if(prev) {
      prev->next = head->next;
      free_lru_cache_entry(cache, head);
      free(head);
#ifdef FULL_STATS
      cache->mem_size -= sizeof(struct LruCacheEntry);
#endif
      cache->current_hash_size[hash_id]--;
    } else
      traceEvent(TRACE_ERROR, "Internal error in %s()", __FUNCTION__);
  }
}

/* ************************************ */

static void validate_unit_len(struct LruCache *cache, u_int32_t hash_id) {
  struct LruCacheEntry *head = cache->hash[hash_id];
  u_int num = 0;

  while(head != NULL) {
    head = head->next, num++;
  }

  if(num != cache->current_hash_size[hash_id])
    traceEvent(TRACE_ERROR, "Invalid length [expected: %u][read: %u][hash_id: %u]",
	       cache->current_hash_size[hash_id], num, hash_id);
}

/* ************************************ */

int add_to_lru_cache_num(struct LruCache *cache,
			 u_int64_t key, u_int32_t value) {
  if(cache->hash_size == 0)
    return(0);
  else {
    u_int32_t hash_id = key % cache->hash_size;
    struct LruCacheEntry *node;
    u_int8_t node_already_existing = 0;
    int rc = 0;

    if(unlikely(traceLRU))
      traceEvent(TRACE_NORMAL, "%s(key=%lu, value=%u)", __FUNCTION__, key, value);

    pthread_rwlock_wrlock(&cache->lruLock);
    // validate_unit_len(cache, hash_id);
    cache->num_cache_add++;

    /* [1] Add to hash */
    if(cache->hash[hash_id] == NULL) {
      if((node = allocCacheNumericNode(cache, key, value)) == NULL) {
	rc = -1;
	goto ret_add_to_lru_cache;
      }

      cache->hash[hash_id] = node;
      cache->current_hash_size[hash_id]++;
    } else {
      /* Check if the element exists */
      struct LruCacheEntry *head = cache->hash[hash_id];

      while(head != NULL) {
	if(head->u.num.key == key) {
	  /* Duplicated key found */
	  node = head;
	  node->u.num.value = value; /* Overwrite old value */
	  node_already_existing = 1;
	  break;
	} else
	  head = head->next;
      }

      if(!node_already_existing) {
	if((node = allocCacheNumericNode(cache, key, value)) == NULL) {
	  rc = -2;
	  goto ret_add_to_lru_cache;
	}

	node->next = cache->hash[hash_id];
	cache->hash[hash_id] = node;
	cache->current_hash_size[hash_id]++;
      }
    }

    trim_subhash(cache, hash_id);

    // validate_unit_len(cache, hash_id);

  ret_add_to_lru_cache:
    pthread_rwlock_unlock(&cache->lruLock);
    return(rc);
  }
}

/* ************************************ */

int add_to_lru_cache_str_timeout(struct LruCache *cache,
				 char *key, char *value,
				 u_int32_t timeout) {
  if(cache->hash_size == 0)
    return(0);
  else {
    u_int32_t hash_val =  hash_string(key);
    u_int32_t hash_id = hash_val % cache->hash_size;
    struct LruCacheEntry *node;
    u_int8_t node_already_existing = 0;
    int rc = 0;

    if(unlikely(traceLRU))
      traceEvent(TRACE_NORMAL, "%s(key=%s, value=%s)", __FUNCTION__, key, value);

    pthread_rwlock_wrlock(&cache->lruLock);
    // validate_unit_len(cache, hash_id);
    cache->num_cache_add++;

    /* [1] Add to hash */
    if(cache->hash[hash_id] == NULL) {
      if((node = allocCacheStringNode(cache, key, value, timeout)) == NULL) {
	rc = -1;
	goto ret_add_to_lru_cache;
      }

      cache->hash[hash_id] = node;
      cache->current_hash_size[hash_id]++;
    } else {
      /* Check if the element exists */
      struct LruCacheEntry *head = cache->hash[hash_id];

      while(head != NULL) {
	if(strcmp(head->u.str.key, key) == 0) {
	  /* Duplicated key found */
	  node = head;
	  if(node->u.str.value) {
#ifdef FULL_STATS
	    cache->mem_size -= strlen(node->u.str.value);
#endif
	    free(node->u.str.value);
	  }

	  node->u.str.value = strdup(value); /* Overwrite old value */
#ifdef FULL_STATS
	  cache->mem_size += strlen(value);
#endif

	  node->u.str.expire_time = (timeout == 0) ? 0 : (timeout + readWriteGlobals->now);
	  node_already_existing = 1;
	  break;
	} else
	  head = head->next;
      }

      if(!node_already_existing) {
	if((node = allocCacheStringNode(cache, key, value, timeout)) == NULL) {
	  rc = -2;
	  goto ret_add_to_lru_cache;
	}

	node->next = cache->hash[hash_id];
	cache->hash[hash_id] = node;
	cache->current_hash_size[hash_id]++;
      }
    }

    trim_subhash(cache, hash_id);

    // validate_unit_len(cache, hash_id);

  ret_add_to_lru_cache:
    pthread_rwlock_unlock(&cache->lruLock);
    return(rc);
  }
}

/* ************************************ */

int add_to_lru_cache_str(struct LruCache *cache, char *key, char *value) {
  return(add_to_lru_cache_str_timeout(cache, key, value, 0));
}

/* ************************************ */

u_int32_t find_lru_cache_num(struct LruCache *cache, u_int64_t key) {
  if(cache->hash_size == 0)
    return(0);
  else {
    u_int32_t hash_id = key % cache->hash_size;
    struct LruCacheEntry *head, *prev = NULL;
    u_int32_t ret_val = NDPI_PROTOCOL_UNKNOWN;

    if(unlikely(traceLRU))
      traceEvent(TRACE_NORMAL, "%s(%lu)", __FUNCTION__, key);

    pthread_rwlock_rdlock(&cache->lruLock);
    head = cache->hash[hash_id];
    // validate_unit_len(cache, hash_id);
    cache->num_cache_find++;

    while(head != NULL) {
      if(head->u.num.key == key) {
	ret_val = head->u.num.value;

	/* We now need to move it in front */
	if(prev != NULL) {
	  /* We're not the first element yet */
	  prev->next = head->next;
	  head->next = cache->hash[hash_id];
	  cache->hash[hash_id] = head;
	}
	break;
      } else {
	prev = head;
	head = head->next;
      }
    }

    if(ret_val == NDPI_PROTOCOL_UNKNOWN) cache->num_cache_misses++;
    pthread_rwlock_unlock(&cache->lruLock);

    return(ret_val);
  }
}

/* ************************************ */

char* find_lru_cache_str(struct LruCache *cache, char *key) {
  if(cache->hash_size == 0)
    return(0);
  else {
    u_int32_t hash_val =  hash_string(key);
    u_int32_t hash_id = hash_val % cache->hash_size;
    struct LruCacheEntry *head, *prev = NULL;
    char *ret_val = NULL;

    if(unlikely(traceLRU))
      traceEvent(TRACE_NORMAL, "%s(%s)", __FUNCTION__, key);

    /*
      We need wrlock and not rdlock as if an entry is expired we will
      manipulate the list
    */
    pthread_rwlock_wrlock(&cache->lruLock);
    // validate_unit_len(cache, hash_id);
    cache->num_cache_find++;
    head = cache->hash[hash_id];

    while(head != NULL) {
      if(strcmp(head->u.str.key, key) == 0) {
	if((head->u.str.expire_time > 0) && (head->u.str.expire_time < readWriteGlobals->now)) {
	  /* The node has expired */
	  if(prev == NULL)
	    cache->hash[hash_id] = head->next;
	  else
	    prev->next = head->next;

	  free_lru_cache_entry(cache, head);
	  free(head);
#ifdef FULL_STATS
	  cache->mem_size -= sizeof(struct LruCacheEntry);
#endif
	  ret_val = NULL;
	  cache->current_hash_size[hash_id]--;
	} else
	  ret_val = head->u.str.value;
	break;
      } else {
	prev = head;
	head = head->next;
      }
    }

    if(ret_val == NULL) cache->num_cache_misses++;
    // validate_unit_len(cache, hash_id);
    pthread_rwlock_unlock(&cache->lruLock);

    return(ret_val);
  }
}

/* ************************************ */

static void dumpLruCacheStat(struct LruCache *cache,
			     char* cacheName, u_int timeDifference) {
  u_int32_t tot_cache_add = 0, tot_cache_find = 0;
  u_int32_t tot_mem = 0, grand_total_mem = 0;
  u_int32_t num_cache_add = 0, num_cache_find = 0;
  u_int32_t num_cache_misses = 0, grand_total = 0;
  float a, f, m;
  int j, tot;

  tot_cache_add += cache->num_cache_add;
  num_cache_add += cache->num_cache_add - cache->last_num_cache_add;
  cache->last_num_cache_add = cache->num_cache_add;

  tot_cache_find += cache->num_cache_find;
  num_cache_find += cache->num_cache_find - cache->last_num_cache_find;
  cache->last_num_cache_find = cache->num_cache_find;

  num_cache_misses += cache->num_cache_misses - cache->last_num_cache_misses;
  cache->last_num_cache_misses = cache->num_cache_misses;

  for(tot=0, tot_mem=0, j=0; j<cache->hash_size; j++)
    tot += cache->current_hash_size[j], tot_mem += (cache->mem_size+sizeof(struct LruCache));

  grand_total += tot;
  grand_total_mem += tot_mem;

#ifdef FULL_STATS
  if(tot > 0)
    traceEvent(TRACE_NORMAL, "LRUCacheUnit %s [current_hash_size: %u][max_cache_node_len: %u][mem_size: %.1f MB/%.1f MB]",
	       cacheName, tot, cache->max_cache_node_len, (float)tot_mem/(float)(1024*1024), (float)grand_total_mem/(float)(1024*1024));
#endif

  a = (timeDifference > 0) ? ((float)num_cache_add)/(float)timeDifference : 0;
  f = (timeDifference > 0) ? ((float)num_cache_find)/(float)timeDifference : 0;
  m = (num_cache_add > 0) ? ((float)(num_cache_misses*100))/((float)num_cache_find) : 0;

  if(tot_cache_find || tot_cache_add)
    traceEvent(TRACE_NORMAL, "LRUCache %s [find: %u operations/%.1f find/sec]"
	       "[cache miss %u/%.1f %%][add: %u operations/%.1f add/sec][tot: %u][mem_size: %.1f MB]",
	       cacheName, tot_cache_find, f, num_cache_misses, m, tot_cache_add, a, grand_total,
	       (float)grand_total_mem/(float)(1024*1024));
}

/* ************************************ */

void dumpLruCacheStats(u_int timeDifference) {
  dumpLruCacheStat(&readWriteGlobals->l7Cache, "L7Cache", timeDifference);
  dumpLruCacheStat(&readWriteGlobals->flowUsersCache, "FlowUserCache", timeDifference);
}

/* ************************************ */

void testLRU() {
  while(1) {
    unsigned int i;

    for(i = 0; i<100000; i++) {
      char str[256];

      snprintf(str, sizeof(str), "%u", i);
      add_to_lru_cache_str(&readWriteGlobals->flowUsersCache, str, str);
      find_lru_cache_str(&readWriteGlobals->flowUsersCache, str);
    }

    dumpLruCacheStats(1);
  }
}
