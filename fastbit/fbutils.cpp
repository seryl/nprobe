/*              __ _
 *             / _| |__   __ _ _   _  ___ _ __ _   _
 *            | |_| '_ \ / _` | | | |/ _ \ '__| | | |
 *            |  _| |_) | (_| | |_| |  __/ |  | |_| |
 *            |_| |_.__/ \__, |\__,_|\___|_|   \__, |
 *                          |_|                |___/
 *
 *                     Copyright (C) 2009-2010
 *                    Luca Deri <deri@ntop.org>
 *             Valeria Lorenzetti <lorenzetti@ntop.org>
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
 *
 */


/* Operating System header files */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
using namespace std;

/* Private header files */
#include "fbquery.h"


/* Known flow metadata */
#define TYPE_ASCII     "ascii"
#define TYPE_HEX       "hex"
#define TYPE_UINT      "uint"             /* 1234567890 */
#define TYPE_FUINT     "formatted_uint"   /* 123,456,789 */
#define TYPE_IP_PORT   "ip_port"
#define TYPE_IP_PROTO  "ip_proto"
#define TYPE_IPV4_ADD  "ipv4_address"
#define TYPE_IPV6_ADD  "ipv6_address"
#define TYPE_MAC_ADD   "mac_address"
#define TYPE_EPOCH     "epoch"
#define TYPE_BOOL      "bool"
#define TYPE_TCPFLAGS  "tcp_flags"
#define TYPE_DEFAULT   TYPE_UINT

typedef enum
  {
    DUMP_AS_DEFAULT = 0,
    DUMP_AS_ASCII,
    DUMP_AS_HEX,
    DUMP_AS_UINT,
    DUMP_AS_FUINT,
    DUMP_AS_PORT,
    DUMP_AS_PROTO,
    DUMP_AS_IPV4,
    DUMP_AS_IPV6,
    DUMP_AS_MAC,
    DUMP_AS_EPOCH,
    DUMP_AS_BOOL,
    DUMP_AS_TCPFLAGS,
    DUMP_AS_CHAR_STRING

  } type_number;


/* How to dump a specific column */
int get_type_number (char * type)
{
  if (! strcasecmp (type, TYPE_ASCII))    return DUMP_AS_ASCII;
  if (! strcasecmp (type, TYPE_HEX))      return DUMP_AS_HEX;
  if (! strcasecmp (type, TYPE_UINT))     return DUMP_AS_UINT;
  if (! strcasecmp (type, TYPE_FUINT))    return DUMP_AS_FUINT;
  if (! strcasecmp (type, TYPE_IP_PORT))  return DUMP_AS_PORT;
  if (! strcasecmp (type, TYPE_IP_PROTO)) return DUMP_AS_PROTO;
  if (! strcasecmp (type, TYPE_IPV4_ADD)) return DUMP_AS_IPV4;
  if (! strcasecmp (type, TYPE_IPV6_ADD)) return DUMP_AS_IPV6;
  if (! strcasecmp (type, TYPE_MAC_ADD))  return DUMP_AS_MAC;
  if (! strcasecmp (type, TYPE_EPOCH))    return DUMP_AS_EPOCH;
  if (! strcasecmp (type, TYPE_BOOL))     return DUMP_AS_BOOL;
  if (! strcasecmp (type, TYPE_TCPFLAGS)) return DUMP_AS_TCPFLAGS;

  return DUMP_AS_DEFAULT;
}


/* Parsing the flow metadata file dumped by nProbe */
col_t ** parse_metadata_file (FILE * metafd, char ** cnames)
{
  char line [1024];
  char ** c = cnames;
  col_t ** clist = NULL;

  if (! metafd)
    return clist;

  while (c && * c)
    {
      /* Read a line from the file... */
      while (fgets (line, sizeof (line), metafd) != NULL)
	{
	  char name [1024];
	  char id [1024];
	  char type [1024];
	  char description [1024];

	  /* Skip initial comments */
	  if (* line == '#')
	    continue;

	  /* ...and parse it */
	  sscanf (line, "%s\t%s\t%s\t%s", name, id, type, description);

	  /* Search the column name in the metadata file */
	  if (! strcasecmp (* c, name) || strstr (* c, name))
	    {
	      /* Column name found in the metadata file */
	      col_t * column = mkcol (name, get_type_number (type));

	      /* Add to list */
	      clist = (col_t **) vmore ((void **) clist, (void *) column);

	      break;
	    }
	}

      /* Rewind metadata file */
      rewind (metafd);

      /* Next column name */
      c ++;
    }

  return clist;
}


/* Get value of i-th row and j-th column */
char * get_value_ij (char * value_ij, char * cname, ibis::bundle &bun,
		     u_int64_t row, u_int32_t col, col_t ** clist, u_int8_t native)
{
  u_int32_t val;
  char * s;
  char buf [256];
  time_t t;
  static IpAddress addr;
  struct protoent * p;
  struct servent * port;

  if (native)
    {
      /* Get the value of the named column as an unsigned integer */
      sprintf (value_ij, "%llu", (long long unsigned int)bun.getULong (row, col));

      return (value_ij);
    }

  switch (get_column_type (clist, cname))
    {
      /* Print in ASCII */
    case DUMP_AS_ASCII:
      sprintf (value_ij, "%s", bun.getString (row, col).c_str());
      break;

      /* Print in hexadecimal format */
    case DUMP_AS_HEX:
      sprintf (value_ij, "%llX", (long long unsigned int)bun.getULong (row, col));
      break;

      /* Print as unsigned integer */
    case DUMP_AS_UINT:
      sprintf (value_ij, "%llu", (long long unsigned int)bun.getULong (row, col));
      break;

      /* Print as formatted unsigned integer */
    case DUMP_AS_FUINT:
      s = dump_formatted_uint (bun.getULong (row, col), buf, sizeof (buf));
      sprintf (value_ij, "%s", s);
      break;

      /* Print the official protocol name */
    case DUMP_AS_PROTO:
      val = bun.getUInt (row, col);
      p = getprotobynumber (val);

      if(p != NULL)
	sprintf (value_ij, "%s", p -> p_name);
      else
	sprintf (value_ij, "%u", val);
      break;

      /* Print the symbolic port name */
    case DUMP_AS_PORT:
      val = bun.getUInt (row, col);
      port = getservbyport (htons (val), NULL /* FIX: we should use the real protocol here */);

      if(port)
	sprintf (value_ij, "%s", port -> s_name);
      else
	sprintf (value_ij, "%u", val);
      break;

      /* Print as IPv4 address */
    case DUMP_AS_IPV4:
      addr.ipVersion = 4;
      addr.ipType.ipv4 = bun.getUInt (row, col);
      sprintf (value_ij, "%s", _intoa (addr, buf, sizeof (buf)));
      break;

    case DUMP_AS_CHAR_STRING:
      val = bun.getUInt (row, col);
      s = (char*)&val;
      sprintf (value_ij, "%c%c%c%c", s[1], s[0], s[3], s[2]);
      break;

#if 0 /* TODO !!!!*/

      /* Print as IPv6 address */
    case DUMP_AS_IPV6:
      {
	int a, b, c, d;
	u_int8_t * v = (u_int8_t *) & addr.ipType.ipv6.s6_addr;
	int idx = atoi (& clist [col] -> name [strlen (clist [col] -> name) - 1]);

	val = bun.getUInt (row, col);
	addr.ipVersion = 6;

	a = (val >> 24) & 0xFF, b = (val >> 16) & 0xFF, c = (val >> 8) & 0xFF, d = val & 0xFF;
	v [idx * 4] = a, v [idx * 4 + 1] = b, v [idx * 4 + 2] = c, v [idx * 4 + 3] = d;

	if (idx == 3)
	  sprintf (value_ij, "%s", _intoa (addr, buf, sizeof (buf)));
	else
	  rc = 0;
      }
      break;
#endif

      /* Print as MAC address */
    case DUMP_AS_MAC:
      s = etheraddr_string ((const u_char *) bun.getString (row, col).c_str(), buf);
      sprintf (value_ij, "%s", s);
      break;

      /* Print as date */
    case DUMP_AS_EPOCH:
      t = bun.getUInt (row, col);
      s = ctime (& t);
      sprintf (value_ij, "%*.*s", (int)(strlen (s) - 1), (int)(strlen (s) - 1), s);   /* No trailing "\n" */
      break;

      /* Print as "Y" or "N" */
    case DUMP_AS_BOOL:
      if (bun.getUInt (row, col) == 0)
	sprintf (value_ij, "%s", "N");
      else
	sprintf (value_ij, "%s", "Y");
      break;

      /* Print as TCP flags */
    case DUMP_AS_TCPFLAGS:
      s = dump_tcp_flags (bun.getUInt (row, col), buf, sizeof (buf));
      sprintf (value_ij, "%s", s);
      break;

    default:
      /* Get the value of the named column as an unsigned integer */
      sprintf (value_ij, "%llu", (long long unsigned int)bun.getULong (row, col));
      break;
    }

  return (value_ij);
}


/* Return a string to dump as formatted uint (123,456,789) */
char * dump_formatted_uint (unsigned long input, char * output, int outputLen)
{
  /* Decimal separator */
#define DS ","

  if (input < 1000)
    {
      snprintf (output, outputLen, "%lu", (unsigned long) input);
    }
  else if (input < 1000000)
    {
      snprintf (output, outputLen, "%lu%s%03lu", (unsigned long) (input / 1000), DS, ((unsigned long) input) % 1000);
    }
  else if (input < 1000000000)
    {
      unsigned long a, b, c;

      a = (unsigned long) (input / 1000000);
      b = (unsigned long) ((input - a * 1000000) / 1000);
      c = ((unsigned long) input) % 1000;

      snprintf (output, outputLen, "%lu%s%03lu%s%03lu", a, DS, b, DS, c);
    }
  else
    {
      unsigned long a, b, c, e, f;

      e = input / 1000000000;
      f = input - 1000000000 * e;

      a = (unsigned long) (f / 1000000);
      b = (unsigned long) ((f - a * 1000000) / 1000);
      c = ((unsigned long) f) % 1000;

      snprintf (output, outputLen, "%lu%s%03lu%s%03lu%s%03lu", e, DS, a, DS, b, DS, c);
    }

  return (output);
}


/* Return a string to dump as TCP flags */
char * dump_tcp_flags (u_int8_t flags, char * output, int outputLen)
{
  snprintf (output, outputLen, "%s%s%s%s%s\n",
	    (flags & TH_SYN) ? " SYN" : "", (flags & TH_ACK) ? " ACK" : "",  (flags & TH_FIN) ? " FIN" : "",
	    (flags & TH_RST) ? " RST" : "", (flags & TH_PUSH) ? " PUSH" : "");

  return (output);
}


void get_ipv4 (char * dot1, char * dot2, char * dot3, char * dot4, char * ipv4, size_t size)
{
  /* Lenght of FIRST dot */
  u_int32_t dot1len = strlen (dot1);

  char first_dot [4];
  char last_dot [4];

  /* Separe IPv4 FIRST octet from query string */
  if (isdigit (dot1 [dot1len - 3]))
    {
      /* First octect is formed by 3 digits (192.x.x.x) */
      snprintf (first_dot, 4, "%s", dot1 + (dot1len - 3));
    }
  else if (isdigit (dot1 [dot1len - 2]))
    {
      /* First octect is formed by 2 digits (68.x.x.x) */
      snprintf (first_dot, 3, "%s", dot1 + (dot1len - 2));
    }
  else if (isdigit (dot1 [dot1len - 1]))
    {
      /* First octect is formed by 1 digit (5.x.x.x) */
      snprintf (first_dot, 2, "%s", dot1 + (dot1len - 1));
    }

  /* Separe IPv4 LAST octet from query string */
  if (isdigit (dot4 [2]))
    {
      /* Last octect is formed by 3 digits (x.x.x.102) */
      snprintf (last_dot, 4, "%.3s", dot4);
    }
  else if (isdigit (dot4 [1]))
    {
      /* Last octect is formed by 2 digits (x.x.x.80) */
      snprintf (last_dot, 3, "%.2s", dot4);
    }
  else if (isdigit (dot4 [0]))
    {
      /* Last octect is formed by 1 digit (x.x.x.5) */
      snprintf (last_dot, 2, "%.1s", dot4);
    }

  /* IPv4 in dotted-decimal format */
  snprintf (ipv4, size, "%s.%s.%s.%s", first_dot, dot2, dot3, last_dot);
}


void replace_dotted_decimal (string & query)
{
  const char * q = query.c_str();

  char dot1 [1024] = "";
  char dot2 [1024] = "";
  char dot3 [1024] = "";
  char dot4 [1024] = "";

  /* Search for an IPv4 address in dotted decimal notation */
  while ((sscanf (q, "%[^.].%[^.].%[^.].%s", dot1, dot2, dot3, dot4)) == 4)
    {
      /* IPv4 in dotted decimal notation found! */
      char ipv4 [1024];
      char binary [256];
      u_int32_t address;
      string::size_type i;

      /* IPv4 string with dotted decimal notation */
      get_ipv4 (dot1, dot2, dot3, dot4, ipv4, sizeof (ipv4));

      /* Converts the Internet host address IPv4 from numbers-and-dots notation
       * into binary data in network byte order. */
      address = inet_addr (ipv4);

      /* Converts the address from network byte order to host byte order */
      sprintf (binary, "%u", ntohl (address));

      /* Replace IPv4 dotted decimal notation */
      i = query.find (ipv4, 0);
      if (i != string::npos)
	query.replace (i, strlen (ipv4), binary);

      /* Search for other IPs */
      q = query.c_str();
    }
}


int get_hosts_range (char * netmask, u_int32_t numeric_ipv4, u_int32_t * hostMin, u_int32_t * hostMax)
{
  u_int32_t nm = atoi (netmask);

  if (nm < 0 || nm > 32)
    return 1;

  u_int32_t bitmask = 0xFFFFFFFF;
  u_int32_t subnet = 32 - nm;

  bitmask = bitmask >> subnet;
  bitmask = bitmask << subnet;

  * hostMin = numeric_ipv4 & bitmask;
  * hostMax = numeric_ipv4 | ~bitmask;

  return 0;
}


/* Replace an IPv4 with Subnet Mask notation in
 * a range condition compliant with FastBit.
 *
 * Operator 'equals':
 * Input: "IPV4_SRC_ADDR = 10.0.0.0/24"
 * Output: "( IPV4_SRC_ADDR BETWEEN 167772160 AND 167772415 )"
 *
 * Operator 'not equals'
 * Input: "IPV4_SRC_ADDR != 10.0.0.0/24"
 * Output: "(! (IPV4_SRC_ADDR BETWEEN 167772160 AND 167772415 ))"
 */
void convert_subnet (string & query)
{
  const char * q = query.c_str();

  char dot1 [1024] = "";
  char dot2 [1024] = "";
  char dot3 [1024] = "";
  char dot4 [1024] = "";
  char mask [1024] = "";

  /* Search for an IPv4 address in dotted decimal notation with a subnet mask */
  while ((sscanf (q, "%[^.].%[^.].%[^.].%[^/]/%s", dot1, dot2, dot3, dot4, mask)) == 5)
    {
      char ipv4 [1024];
      string::size_type index_ip, index_op, index_colname = 0;
      u_int32_t address, numeric_ipv4;
      u_int32_t HostMin = 0, HostMax = 0;
      char replace [1024];
      u_int8_t op_equals = 1;
      size_t m;

      /* IPv4 string with dotted decimal notation (without mask) */
      get_ipv4 (dot1, dot2, dot3, dot4, ipv4, sizeof (ipv4));

      /* Converts the Internet host address IPv4 from numbers-and-dots notation
       * into binary data in network byte order. */
      address = inet_addr (ipv4);

      /* Converts the address from network byte order to host byte order */
      numeric_ipv4 = ntohl (address);

      /* Skip not-numeric digits in the mask string */
      m = strlen (mask);
      while (! isdigit (mask[m]))
	mask [m --] = '\0';

      /* Get host range */
      get_hosts_range (mask, numeric_ipv4, &HostMin, &HostMax);
      sprintf (replace, " BETWEEN %u AND %u ))", HostMin, HostMax);

      /* Index position of the IP in the query conditions */
      index_ip = query.find(ipv4, 0);

      if (index_ip == string::npos || index_ip == 0)
	return;

      /* Index position of the operation selected (only '=' or '!=') */
      index_op = query.find_last_of("=", index_ip);

      if (index_op == string::npos || index_op == 0)
	return;

      /* Equals or not equals operator ?  */
      if (query.at(index_op - 1) == '!')
	op_equals = 0;

      /* Scroll the string backward */

      u_int32_t c = op_equals ? (index_op - 1) : (index_op - 2);

      /* Skip all blank spaces between column name and operator */
      while (query.at(c) == ' ' && c > 0)
	c --;

      /* Find the first character of column name */
      while (query.at(c) != ' ' && c > 0)
	c --;

      /* Index position of column name found! */
      index_colname = c;

      /* Delete OLD operator and add the open brackets */
      if (op_equals)
	{
	  query.replace (index_op, strlen ("="), " ");

	  /* Insert the open brackets */
	  query.insert(index_colname, " (( ");
	}
      else
	{
	  query.replace (index_op - 1, strlen ("!="), " ");

	  /* Insert the open brackets and the NEW NOT operator */
	  query.insert(index_colname, " (!( ");
	}

      /* Index position of the IP in the NEW query conditions */
      index_ip = query.find(ipv4, 0);

      /* Replace IPv4 and subnet notation with the "BETWEEN" statement */
      query.replace (index_ip, strlen (ipv4) + strlen (mask) + 1, replace);

      /* Search for other IPs */
      q = query.c_str();
    }
}


/* Convert IPv4 in dotted decimal notation and IPv4 with subnet mask */
void convert_ip (string & query)
{
  /* Search for dots and backslash in query conditions */
  string::size_type dotted_decimal = query.find (".", 0 );
  string::size_type subnet_mask = query.find ("/", 0 );

  while (dotted_decimal != string::npos)
    {
      if (subnet_mask != string::npos)
	{
	  /* This query might contain an IPv4 with a subnet mask specified. Convert it! */
	  convert_subnet(query);
	}
      else
	{
	  /* This query might contain an IPv4 with dotted decimal format. Replace it! */
	  replace_dotted_decimal(query);
	}

      dotted_decimal = query.find (".", 0 );
      subnet_mask = query.find ("/", 0 );
    }
}

/* Convert INT16(XXXX) where XXX is a string */
void convert_int (string & query)
{
  char *s, *q = (char*)query.c_str(), ret[256] = { 0 };
  const char *delimiter16 = "INT16(";

  snprintf(ret, sizeof(ret)-strlen(ret), "%s", q);

  while((s = ::strstr(ret, delimiter16))) {
    int begin = strlen(delimiter16), i = 1, val = 0;
      
    while((s[begin] != 0) && (s[begin] != ')')) {
      val += s[begin] << (i*8);
      s[begin]=' ';
      begin++, i--;
    }
      
    sprintf(s, "%u", val);
    s[begin] = ' ';
  }

  query.assign(ret);
}


/* Return the directory in input with its sub-directories (if any) */
char ** get_subdirs (char * dirname, char ** dirs)
{
  DIR * dir;
  struct dirent * dirent;
  char * file;

  /* Open input directory */
  if ((dir = opendir (dirname)))
    {
      while ((dirent = readdir (dir)))
	{
	  struct stat s;

	  /* Skip "." and ".." */
	  if (! strcmp (dirent -> d_name, ".") || ! strcmp (dirent -> d_name, ".."))
	    continue;

	  file = (char *) calloc (strlen (dirname) + 1 + strlen (dirent -> d_name) + 1, 1);
          sprintf (file, "%s/%s", dirname, dirent -> d_name);

	  stat (file, & s);

 	  if ((stat (file, & s) != -1) && (S_ISDIR (s . st_mode)) && (access (file, X_OK) != -1))
	    {
	      dirs = (char **) argsadd (dirs, file);

	      /* Recursive! */
	      dirs =  get_subdirs (file, dirs);
	    }

	  /* Free Memory */
	  free (file);
	}

      /* Close input directory */
      closedir (dir);
    }

  return dirs;
}


/* Allocate and initialize a new column type */
col_t * mkcol (char * name, int type)
{
  /* Buy memory now */
  col_t * c;

  if (! (c = (col_t*) calloc (sizeof (col_t), 1)))
    return NULL;

  c -> name = name ? strdup (name) : NULL;
  c -> type = type;

  return c;
}


/* Free allocated memory and resources used */
void rmcol (void * col)
{
  col_t * c = (col_t*)col;

    if (! c)
      return;

  if (c -> name)
    free (c -> name);

  free (c);
}


/* How to dump the columns */
int get_column_type (col_t ** clist, char * name)
{
  while (clist && * clist)
    {
      if (! strcasecmp ((* clist) -> name, name))
	return (* clist) -> type;
      clist ++;
    }

  /* Common defaults (formatted output without metadata file) */
  if (! strcasecmp (name, "IPV4_SRC_ADDR")) return DUMP_AS_IPV4;
  if (! strcasecmp (name, "IPV4_DST_ADDR")) return DUMP_AS_IPV4;
  if (! strcasecmp (name, "IPV6_SRC_ADDR")) return DUMP_AS_IPV6;
  if (! strcasecmp (name, "IPV6_DST_ADDR")) return DUMP_AS_IPV6;
  if (strstr(name, "COUNTRY"))              return DUMP_AS_CHAR_STRING;

  return DUMP_AS_DEFAULT;
}


/* Return the # of items in the table */
int vlen (void * argv [])
{
  int argc = 0;
  while (argv && * argv ++)
    argc ++;
  return argc;
}


/* Add an item to the table */
void ** vmore (void * argv [], void * item)
{
  if (item)
    {
      int argc = vlen (argv);
      argv = (void**)realloc (argv, (1 + argc + 1) * sizeof (void **));
      if (! argv)
	return NULL;
      argv [argc ++] = item;
      argv [argc]    = NULL;         /* make the table NULL terminated */
    }
  return argv;
}


/* Cleanup the table */
void ** vcleanup (void * argv [], void (* rmitem) (void *))
{
  void ** r = argv;
  while (r && * r)
    {
      if (rmitem)
	rmitem (* r);
      r ++;
    }
  if (argv)
    free (argv);
  return NULL;
}


/* Add an element to the table of arguments */
char ** argsadd (char * argv [], char * s)
{
  if (s)
    {
      int argc = vlen ((void **) argv);

      /* buy memory for an item */
      if (! (argv = (char**)realloc (argv, (1 + argc + 1) * sizeof (char *))))
        return NULL;
      argv [argc ++] = strdup (s);
      argv [argc]    = NULL;        /* do the table NULL terminated */
    }

  return argv;
}


/* Split a string into pieces */
char ** argspieces (char * list, char * separator)
{
  char ** argv = NULL;
  char * param;
  char * names = list ? strdup (list) : NULL;

  while (names && (param = strtok (! argv ? names : NULL, separator)))
    {
      /* Trim spaces */
      while (* param == ' ') param ++;
      argv = argsadd (argv, param);
    }

  if (names)
    free (names);

  return argv;
}

