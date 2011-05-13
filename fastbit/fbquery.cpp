/*              __ _
 *             / _| |__   __ _ _   _  ___ _ __ _   _
 *            | |_| '_ \ / _` | | | |/ _ \ '__| | | |
 *            |  _| |_) | (_| | |_| |  __/ |  | |_| |
 *            |_| |_.__/ \__, |\__,_|\___|_|   \__, |
 *                          |_|                |___/
 *
 *                     Copyright (C) 2009-10
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
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <getopt.h>
#ifndef WIN32
#include <netdb.h>
#include <arpa/inet.h>
#endif

#ifdef WIN32
extern "C" {
#endif
#include <dirent.h>
#ifdef WIN32
};
#endif

using namespace std;

/* FastBit header file */
#define WITHOUT_FASTBIT_CONFIG_H

extern "C" {
#include "config.h"
};

/* Private header files */
#ifdef WIN32
extern "C" {
#include "nprobe.h"
};
#define strcasecmp _stricmp
#include <dirent.h>
#include <sys/stat.h>
#endif

#include "ibis.h"

#ifdef HAVE_FASTBIT

/* fbquery version info */
#define FBQUERY_VERSION  "1.5.1"
#define FBQUERY_RELEASE  __DATE__


/* What format to use to print columns */
#define UINT_TYPE      "uint"             /* 1234567890 */
#define FUINT_TYPE     "formatted_uint"   /* 123,456,789 */
#define IP_PORT_TYPE   "ip_port"
#define PROTO_TYPE     "ip_proto"
#define IPV4_TYPE      "ipv4_address"
#define IPV6_TYPE      "ipv6_address"
#define MAC_TYPE       "mac_address"
#define EPOCH_TYPE     "epoch"
#define BOOL_TYPE      "bool"
#define TCPFLAGS_TYPE  "tcp_flags"
#define TWO_CHAR_TYPE  "two_char_str"
#define DEFAULT_TYPE   UINT_TYPE


/* Boolean flags to enable/disable verboseness */
static u_int8_t verbose = 0;


/* Display the version number of this program */
static void show_version ()
{
  printf ("\n");
  printf ("Welcome to fbquery v.%s - Built on %s\n", FBQUERY_VERSION, FBQUERY_RELEASE);
  printf ("Copyright (C) 2009-10 Luca Deri <deri@ntop.org>\n");
  printf ("                      Valeria Lorenzetti <lorenzetti@ntop.org>\n");
  printf ("\n");
}


/* Display the syntax for using this program */
static void help ()
{
  show_version ();

  printf ("Usage: fbquery [-c <columns>] -d <directory> [-q <query-conditions>]\n");
  printf ("               [-o <orderby-columns>] [-r] [-g <groupby-columns>] [-m <metadata-file>]\n");
  printf ("               [-D] [-L <i[,j]>] [-S <separator>] [-H] [-N] [-V] [-Q] [-C <ibisrc-file>]\n\n");

  printf ("Info:\n");
  printf (" [--help|-h]                 | Show this help message and exit\n");
  printf (" [--version|-v]              | Show fbquery version number and exit\n\n");

  printf ("Options:\n");
  printf (" [--columns|-c <columns>]    | List of column names to select, separated by comma. Can be specified\n");
  printf ("                             | also the one-argument functions: MIN(), MAX(), SUM() and AVG().\n");
  printf (" [--conf|-C <ibisrcfile>]    | Filename of an ibisrc file.\n");
  printf (" --directory|-d <directory>  | Pathname of directory containing a Fastbit partition on which execute\n");
  printf ("                             | the query. Multiple directories can be defined using multiple -d flags.\n");
  printf (" [--query|-q <conditions>]   | Specifies the conditions of the query with a set of range conditions\n");
  printf ("                             | joined together with logical operators. The supported logical operators\n");
  printf ("                             | are: AND, OR, XOR, NOT. The range condition can be defined with the\n");
  printf ("                             | operators: <, <=, >, and >=, IN and BETWEEN.\n");
  printf (" [--orderby|-o <columns>]    | Sort values in ascending order in according to columns specified\n");
  printf (" [--reverse|-r]              | Sort values in descending order in according to columns specified in the\n");
  printf ("                             | ORDER BY clause (or in the SELECT clause if no ORDER BY clause is  specified)\n");
  printf (" [--groupby|-g <columns>]    | Used along with the aggregate functions like SUM to provide means of\n");
  printf ("                             | grouping the result by certain columns\n");
  printf (" [--metadata-file|-m <file>] | Pathname of the metadata file that has been dumped by nProbe (This file\n");
  printf ("                             | allows to fbquery to print results with a customized format)\n");
  printf (" [--distinct|-D]             | Retrieves only unique rows from the result set\n");
  printf (" [--limit|-L <i[,j]>]        | Limit query results to those that fall within a specified range. Can be\n");
  printf ("                             | used to show the first 'i' number of results, or to show a range using\n");
  printf ("                             | <i,j>, where 'i' is the starting point (the first record is 0) and 'j'\n");
  printf ("                             | is the duration (how many records to display)\n");
  printf (" [--separator|-S <sep>]      | Character to be used as CSV separator between columns of results\n");
  printf (" [--hide-header|-H]          | Hide the header line that contains the column names\n");
  printf (" [--native-format|-N]        | Print each selected column with its native format\n\n");

  printf ("Verboseness:\n");
  printf (" [--verbose|-V]              | Increase the verboseness of fbquery functions\n");
  printf (" [--quiet|-Q]                | Disable the verboseness of FastBit functions\n\n");
}


/* Short command line options */
static const char short_options[] = "hC:vc:d:q:o:g:rm:nDL:S:HNVQ";


/* Long command line options */
static const struct option long_options [] = {

  { "help",           no_argument,        NULL, 'h' },
  { "version",        no_argument,        NULL, 'v' },

  /* Input */
  { "columns",        required_argument,  NULL, 'c' },
  { "conf",           required_argument,  NULL, 'C' },
  { "directory",      required_argument,  NULL, 'd' },
  { "query",          required_argument,  NULL, 'q' },
  { "orderby",        required_argument,  NULL, 'o' },
  { "groupby",        required_argument,  NULL, 'g' },
  { "reverse",        no_argument,        NULL, 'r' },
  { "metadata-file",  required_argument,  NULL, 'm' },

  /* Output */
  { "distinct",       no_argument,        NULL, 'D' },
  { "limit",          required_argument,  NULL, 'L' },
  { "separator",      required_argument,  NULL, 'S' },
  { "hide-header",    no_argument,        NULL, 'H' },
  { "native-format",  no_argument,        NULL, 'N' },

  { "verbose",        no_argument,        NULL, 'V' },
  { "quiet",          no_argument,        NULL, 'Q' },

  /* End of fbquery options */
  { NULL,             0,                  NULL,  0  }
};


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
  /* Search for dots and backslash in the query conditions */
  string::size_type dotted_decimal = query.find (".", 0 );
  string::size_type subnet_mask = query.find ("/", 0 );

  while (dotted_decimal != string::npos)
    {
      if (subnet_mask != string::npos)
	{
	  /* This query might contain an IPv4 with a subnet mask specified */
	  convert_subnet(query);
	}
      else
	{
	  /* This query might contain an IPv4 with dotted decimal format */
	  replace_dotted_decimal(query);
	}

      dotted_decimal = query.find (".", 0 );
      subnet_mask = query.find ("/", 0 );
    }
}


/* Parsing the flow metadata file dumped by nProbe */
void parse_metadata_file (ifstream &mfile, const char * column, char * type)
{
  string line;
  char name [256] = "";

  while (! mfile.eof())
    {
      /* Read a line from the file */
      getline (mfile, line);

      /* Search for the name of the selected column and the format in which print it */
      if (line.size() != 0 && (sscanf (line.c_str(), "%s\t%*s\t%s\t%*s", name, type)) == 2)
	{
	  /* Column name found in the metadata file */
	  if (! strcasecmp (name, column))
	    {
	      /* Return to the beginning of the file */
	      mfile.clear();
	      mfile.seekg(0, ios::beg);

	      return;
	    }
	}
    }

  /* Column name not found. Use the default format to print the unknown column */
  strcpy (type, DEFAULT_TYPE);

  /* Return to the beginning of the file */
  mfile.clear();
  mfile.seekg(0, ios::beg);
  return;
}


/* A faster replacement for inet_ntoa() */
char * fast_intoa (unsigned int addr, char * buf, u_short bufLen)
{
  char * cp, * retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do
    {
      byte = addr & 0xff;
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	{
	  *--cp = byte % 10 + '0';
	  byte /= 10;
	  if (byte > 0)
	    *--cp = byte + '0';
	}
      *--cp = '.';
      addr >>= 8;
    }
  while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}


/* Return a string representing a formatted uint (123,456,789) */
char * formatted_uint (unsigned long input, char * output, int len)
{
  /* Decimal separator */
#define DS ","

  if (input < 1000)
    {
      snprintf (output, len, "%lu", (unsigned long) input);
    }
  else if (input < 1000000)
    {
      snprintf (output, len, "%lu%s%03lu",
		(unsigned long)(input / 1000), DS, ((unsigned long) input) % 1000);
    }
  else if (input < 1000000000)
    {
      unsigned long a, b, c;

      a = (unsigned long) (input / 1000000);
      b = (unsigned long) ((input - a * 1000000) / 1000);
      c = ((unsigned long) input) % 1000;

      snprintf (output, len, "%lu%s%03lu%s%03lu", a, DS, b, DS, c);
    }
  else
    {
      unsigned long a, b, c, e, f;

      e = input / 1000000000;
      f = input - 1000000000 * e;

      a = (unsigned long) (f / 1000000);
      b = (unsigned long) ((f - a * 1000000) / 1000);
      c = ((unsigned long) f) % 1000;

      snprintf (output, len, "%lu%s%03lu%s%03lu%s%03lu", e, DS, a, DS, b, DS, c);
    }
  return (output);
}


void clear_buffers (const ibis::table::typeList& types, std::vector<void*>& buffers)
{
  const size_t n = (types.size() <= buffers.size() ? types.size() : buffers.size());

  for (size_t j = 0; j < n; ++j)
    {
      switch (types[j])
	{
	case ibis::BYTE:
	  {
	    signed char * tmp = static_cast<signed char*>(buffers[j]);
	    delete [] tmp;
	    break;
	  }
	case ibis::USHORT:
	  {
	    uint16_t * tmp = static_cast<uint16_t*>(buffers[j]);
	    delete [] tmp;
	    break;
	  }
	case ibis::UINT:
	  {
	    uint32_t * tmp = static_cast<uint32_t*>(buffers[j]);
	    delete [] tmp;
	    break;
	  }
	case ibis::ULONG:
	  {
	    uint64_t * tmp = static_cast<uint64_t*>(buffers[j]);
	    delete [] tmp;
	    break;
	  }
	case ibis::DOUBLE:
	  {
	    double * tmp = static_cast<double*>(buffers[j]);
	    delete [] tmp;
	    break;
	  }
	default:
	  {
	    uint64_t * tmp = static_cast<uint64_t*>(buffers[j]);
	    delete [] tmp;
	    break;
	  }
	}
    }
}


/* Print each column with the appropriate format */
void dump_ith (size_t i, ibis::TYPE_T type, void * buf, const char * format)
{
  char value [256];
  time_t t;
  char * s;
  struct protoent * p;
  struct servent * port;

  switch (type)
    {
    case ibis::BYTE:
      {
	const signed char * tmp = static_cast<const signed char*>(buf);

	if (! strcasecmp (format, IPV4_TYPE))
	  {
	    /* Print column as IPv4 address */
	    std::cout << fast_intoa ((int)tmp[i], value, sizeof (value));
	  }
	else if (! strcasecmp (format, EPOCH_TYPE))
	  {
	    /* Print column as date */
	    t = (int)tmp[i];
	    s = ctime(&t);
	    sprintf (value, "%*.*s", (int)(strlen(s)-1), (int)(strlen(s)-1), s);   /* No trailing "\n" */
	    std::cout << value;
	  }
	else if (! strcasecmp (format, BOOL_TYPE))
	  {
	    /* Print column as "Y" or "N" */
	    std::cout << ((int)tmp[i] == 0 ? "N" : "Y");
	  }
	else if (! strcasecmp (format, PROTO_TYPE))
	  {
	    /* Print column as the official protocol name */
	    p = getprotobynumber ((int)tmp[i]);
	    if (p != NULL)
	      std::cout << p -> p_name;
	    else
	      std::cout << (int)tmp[i];
	  }
	else if (! strcasecmp (format, IP_PORT_TYPE))
	  {
	    /* Print column as the symbolic port name */
	    port = getservbyport (htons ((int)tmp[i]), NULL /* FIX: we should use the real protocol here */);
	    if (port)
	      std::cout << port -> s_name;
	    else
	      std::cout << (int)tmp[i];
	  }
	else if (! strcasecmp (format, FUINT_TYPE))
	  {
	    /* Print column as formatted unsigned integer */
	    std::cout << formatted_uint ((int)tmp[i], value, sizeof (value));
	  }
	else
	  std::cout << (int)tmp[i];
	break;
      }

    case ibis::USHORT:
      {
	const uint16_t * tmp = static_cast<const uint16_t*>(buf);

	if (! strcasecmp (format, IPV4_TYPE))
	  {
	    /* Print column as IPv4 address */
	    std::cout << fast_intoa (tmp[i], value, sizeof (value));
	  }
	else if (! strcasecmp (format, TWO_CHAR_TYPE))
	  {
	    /* Print column as two char string */
	    uint16_t country = tmp[i];

	    sprintf (value, "%c%c", country >> 8, country & 0xFF);
	    std::cout << value;
	  }
	else if (! strcasecmp (format, EPOCH_TYPE))
	  {
	    /* Print column as date */
	    t = tmp[i];
	    s = ctime(&t);
	    sprintf (value, "%*.*s", (int)(strlen(s)-1), (int)(strlen(s)-1), s);   /* No trailing "\n" */
	    std::cout << value;
	  }
	else if (! strcasecmp (format, BOOL_TYPE))
	  {
	    /* Print column as "Y" or "N" */
	    std::cout << (tmp[i] == 0 ? "N" : "Y");
	  }
	else if (! strcasecmp (format, PROTO_TYPE))
	  {
	    /* Print column as the official protocol name */
	    p = getprotobynumber (tmp[i]);
	    if (p != NULL)
	      std::cout << p -> p_name;
	    else
	      std::cout << tmp[i];
	  }
	else if (! strcasecmp (format, IP_PORT_TYPE))
	  {
	    /* Print column as the symbolic port name */
	    port = getservbyport (htons (tmp[i]), NULL /* FIX: we should use the real protocol here */);
	    if (port)
	      std::cout << port -> s_name;
	    else
	      std::cout << tmp[i];
	  }
	else if (! strcasecmp (format, FUINT_TYPE))
	  {
	    /* Print column as formatted unsigned integer */
	    std::cout << formatted_uint (tmp[i], value, sizeof (value));
	  }
	else
	  std::cout << tmp[i];
	break;
      }

    case ibis::UINT:
      {
	const uint32_t * tmp = static_cast<const uint32_t*>(buf);

	if (! strcasecmp (format, IPV4_TYPE))
	  {
	    /* Print column as IPv4 address */
	    std::cout << fast_intoa (tmp[i], value, sizeof (value));
	  }
	else if (! strcasecmp (format, TWO_CHAR_TYPE))
	  {
	    /* Print column as two char string */
	    uint16_t country = tmp[i];

	    sprintf (value, "%c%c", country >> 8, country & 0xFF);
	    std::cout << value;
	  }
	else if (! strcasecmp (format, EPOCH_TYPE))
	  {
	    /* Print column as date */
	    t = tmp[i];
	    s = ctime(&t);
	    sprintf (value, "%*.*s", (int)(strlen(s)-1), (int)(strlen(s)-1), s);   /* No trailing "\n" */
	    std::cout << value;
	  }
	else if (! strcasecmp (format, BOOL_TYPE))
	  {
	    /* Print column as "Y" or "N" */
	    std::cout << (tmp[i] == 0 ? "N" : "Y");
	  }
	else if (! strcasecmp (format, PROTO_TYPE))
	  {
	    /* Print column as the official protocol name */
	    p = getprotobynumber (tmp[i]);
	    if (p != NULL)
	      std::cout << p -> p_name;
	    else
	      std::cout << tmp[i];
	  }
	else if (! strcasecmp (format, IP_PORT_TYPE))
	  {
	    /* Print column as the symbolic port name */
	    port = getservbyport (htons (tmp[i]), NULL /* FIX: we should use the real protocol here */);
	    if (port)
	      std::cout << port -> s_name;
	    else
	      std::cout << tmp[i];
	  }
	else if (! strcasecmp (format, FUINT_TYPE))
	  {
	    /* Print column as formatted unsigned integer */
	    std::cout << formatted_uint (tmp[i], value, sizeof (value));
	  }
	else
	  std::cout << tmp[i];
	break;
      }

    case ibis::ULONG:
      {
	const uint64_t * tmp = static_cast<const uint64_t*>(buf);

	if (! strcasecmp (format, IPV4_TYPE))
	  {
	    /* Print column as IPv4 address */
	    std::cout << fast_intoa (tmp[i], value, sizeof (value));
	  }
	else if (! strcasecmp (format, EPOCH_TYPE))
	  {
	    /* Print column as date */
	    t = tmp[i];
	    s = ctime(&t);
	    sprintf (value, "%*.*s", (int)(strlen(s)-1), (int)(strlen(s)-1), s);   /* No trailing "\n" */
	    std::cout << value;
	  }
	else if (! strcasecmp (format, BOOL_TYPE))
	  {
	    /* Print column as "Y" or "N" */
	    std::cout << (tmp[i] == 0 ? "N" : "Y");
	  }
	else if (! strcasecmp (format, PROTO_TYPE))
	  {
	    /* Print column as the official protocol name */
	    p = getprotobynumber (tmp[i]);
	    if (p != NULL)
	      std::cout << p -> p_name;
	    else
	      std::cout << tmp[i];
	  }
	else if (! strcasecmp (format, IP_PORT_TYPE))
	  {
	    /* Print column as the symbolic port name */
	    port = getservbyport (htons (tmp[i]), NULL /* FIX: we should use the real protocol here */);
	    if (port)
	      std::cout << port -> s_name;
	    else
	      std::cout << tmp[i];
	  }
	else if (! strcasecmp (format, FUINT_TYPE))
	  {
	    /* Print column as formatted unsigned integer */
	    std::cout << formatted_uint (tmp[i], value, sizeof (value));
	  }
	else
	  std::cout << tmp[i];
	break;
      }

    case ibis::DOUBLE:
      {
	/* Warning:
	 * This format is only used by the library to print the columns corresponding
	 * to the aggregate functions such as SUM, AVG, etc. It is not a column that
	 * can be customized with the metadata file.
	 */
	const double * tmp = static_cast<const double*>(buf);
	std::cout << std::setprecision(15) << tmp[i];
	break;
      }

    default:
      {
	const uint64_t * tmp = static_cast<const uint64_t*>(buf);
	std::cout << tmp[i];
	break;
      }
    }
}


/* Print query results */
int print_results (vector<const char*> names, const ibis::table& results, u_int8_t header,
		   int64_t start, int64_t offset, char * separator, vector<char*> formats)
{
  const size_t nrows = static_cast<size_t>(results.nRows());
  if (nrows != results.nRows())
    {
      cerr << "[fbquery] An error occurred while printing results because the number of rows (" << results.nRows()
	   << ") is too large for it read all records into memory" << endl;
      return -1;
    }

  /* Warning:
   * =======
   * These functions return column names in alphabetical order!
   * They can not be used to print the columns selected by the user.
   */
  ibis::table::stringList alph_names = results.columnNames();
  ibis::table::typeList alph_types = results.columnTypes();

  /* Retrieve types of columns in the same order in which columns are selected.
   * The following code is necessary to read, format and print correctly
   * the selected columns.
   *
   * Please note that "alph_names.size()" can be greater than "names.size()".
   * E.g. with SELECT statment: "SUM(IN_BYTES)
   * alph_names.size() = 2 "SUM(IN_BYTES), COUNT(*)" <-- added transparently
   * names.size()      = 1 "SUM(IN_BYTES)"
   */
  ibis::table::typeList types (alph_names.size());
  for (size_t i = 0; i < names.size(); ++ i)
    {
      int found = 0;
      for (size_t j=0; j < alph_names.size() && found == 0; ++ j)
	{
	  if (names[i] && ! strcasecmp (names[i], alph_names[j]))
	    {
	      types[i] = alph_types[j];
	      found = 1;
	    }
	}
    }

  /* Buffers to read all records into memory */
  std::vector<void*> buffers (names.size(), 0);

  for (size_t i = 0; i < names.size(); ++ i)
    {
      switch (types[i])
	{
	case ibis::BYTE:
	  {
	    char * buf = new char[nrows];
	    if (buf == 0)
	      {
		/* Run out of memory */
		clear_buffers(types, buffers);
		return -1;
	      }
	    int64_t ierr = results.getColumnAsBytes(names[i], buf);
	    if (ierr < 0 || ((size_t) ierr) < nrows)
	      {
		clear_buffers(types, buffers);
		return -2;
	      }
	    buffers[i] = buf;
	    break;
	  }

	case ibis::USHORT:
	  {
	    uint16_t * buf = new uint16_t[nrows];
	    if (buf == 0)
	      {
		/* Run out of memory */
		clear_buffers(types, buffers);
		return -1;
	      }
	    int64_t ierr = results.getColumnAsUShorts(names[i], buf);
	    if (ierr < 0 || ((size_t) ierr) < nrows)
	      {
		clear_buffers(types, buffers);
		return -2;
	      }
	    buffers[i] = buf;
	    break;
	  }

	case ibis::UINT:
	  {
	    uint32_t * buf = new uint32_t[nrows];
	    if (buf == 0)
	      {
		/* Run out of memory */
		clear_buffers(types, buffers);
		return -1;
	      }
	    int64_t ierr = results.getColumnAsUInts(names[i], buf);
	    if (ierr < 0 || ((size_t) ierr) < nrows)
	      {
		clear_buffers(types, buffers);
		return -2;
	      }
	    buffers[i] = buf;
	    break;
	  }

	case ibis::ULONG:
	  {
	    uint64_t * buf = new uint64_t[nrows];
	    if (buf == 0)
	      {
		/* Run out of memory */
		clear_buffers(types, buffers);
		return -1;
	      }
	    int64_t ierr = results.getColumnAsULongs(names[i], buf);
	    if (ierr < 0 || ((size_t) ierr) < nrows)
	      {
		clear_buffers(types, buffers);
		return -2;
	      }
	    buffers[i] = buf;
	    break;
	  }

	case ibis::DOUBLE:
	  {
	    /* Warning:
	     * This format is only used by the library to print the columns corresponding
	     * to the aggregate functions such as SUM, AVG, etc. It is not a column that
	     * can be customized with the metadata file.
	     */

	    double * buf = new double[nrows];
	    if (buf == 0)
	      {
		/* Run out of memory */
		clear_buffers(types, buffers);
		return -1;
	      }
	    int64_t ierr = results.getColumnAsDoubles(names[i], buf);
	    if (ierr < 0 || ((size_t) ierr) < nrows)
	      {
		clear_buffers(types, buffers);
		return -2;
	      }
	    buffers[i] = buf;
	    break;
	  }

	default:
	  {
	    uint64_t * buf = new uint64_t[nrows];
	    if (buf == 0)
	      {
		/* Run out of memory */
		clear_buffers(types, buffers);
		return -1;
	      }

	    int64_t ierr = results.getColumnAsULongs(names[i], buf);
	    if (ierr < 0 || ((size_t) ierr) < nrows)
	      {
		if ((names.size() == 1) && (! strcmp(names[i], "count1"))) /* TO FIX */
		  ierr = results.getColumnAsULongs("COUNT(*)", buf);
	      }

	    if (ierr < 0 || ((size_t) ierr) < nrows)
	      {
		clear_buffers(types, buffers);
		return -2;
	      }
	    buffers[i] = buf;
	    break;
	  }
	}
    }

  if (names.size() == 0) return -3;

  /* No limit specified, all lines are printed */
  if (offset < 0) offset = nrows;

  if (header)
    {
      /* Print the header line that contains the column names */
      cout << names[0];
      for (uint32_t j = 1; j < names.size(); ++ j)
	cout << separator << names[j];
      cout << endl;
    }

  /* Print the records (i=rows, j=columns) */
  for (int64_t i = start; (i < start+offset) && (i < (int64_t)nrows); ++ i)
    {
      dump_ith (i, types[0], buffers[0], formats[0]);
      for (uint32_t j = 1; j < names.size(); ++ j)
	{
	  cout << separator;
	  dump_ith (i, types[j], buffers[j], formats[j]);
	}
      cout << endl;
    }
  clear_buffers(types, buffers);

  return 0;
}


#if defined(WIN32) && !defined(S_ISDIR) 
#define __S_ISTYPE(mode, mask)	(((mode) & S_IFMT) == (mask)) 
#define S_ISDIR(mode)	 __S_ISTYPE((mode), S_IFDIR) 
#endif 

#ifndef X_OK
#define X_OK 0x01
#endif

/* Recursively examine sub-directories */
void walk_dirs (const char * dirname, ibis::table * table)
{
  DIR * dir;
  struct dirent * dirent;
  struct stat stats;

  /* Open input directory */
  if ((dir = opendir (dirname)))
    {
      while ((dirent = readdir (dir)))
	{
	  char subdir [256];
	  char file [256];

	  /* Skip "." and ".." */
	  if (! strcmp (dirent -> d_name, ".") || ! strcmp (dirent -> d_name, ".."))
	    continue;

	  snprintf (subdir, sizeof (subdir), "%s/%s", dirname, dirent -> d_name);
 	  if ((stat (subdir, &stats) != -1) && (S_ISDIR (stats.st_mode)) && (access (subdir, X_OK) != -1))
	    {
	      snprintf (file, sizeof (file), "%s/-part.txt", subdir);
	      if ((stat (file, &stats) == 0) && (access (file, X_OK)))
		{
		  if (verbose) cerr << "[fbquery] Using partition " << subdir << endl;
		  table -> addPartition(subdir);
		}

	      /* Recursive! */
	      walk_dirs (subdir, table);
	    }
	}

      /* Close input directory */
      closedir (dir);
    }
}

#ifdef WIN32
extern "C" { int ptw32_processInitialize(void); };
#endif

int main (int argc, char * argv [])
{
#ifdef WIN32
  ptw32_processInitialize();
#endif

  /* Input options */
  char c;
  const char * columns = 0;
  vector<const char*> dirs;
  string query, qtmp;
  const char * orderkeys = 0;
  const char * groupby = 0;
  u_int8_t reverse = 0;
  char * metadata = NULL;
  ifstream mfile;
  int8_t distinct = 0;
  string limit;
  int64_t start = 0;
  int64_t offset = -1;
  char * separator = (char *) ",";
  u_int8_t header = 1;
  u_int8_t native = 0;
  struct stat stats;
  char path [256];
  const char * ibisrc = 0;

#ifdef WIN32
  ibis::gVerbose = 0;
#endif

  /* Parse the command line options */
  while ((c = getopt_long (argc, argv, short_options, long_options, NULL)) != -1)
    {
      switch (c)
	{
	  /* Info */
	case 'h': help (); return 0;              /* Show this help message and exit */
	case 'v': show_version (); return 0;      /* Show version number and exit */

	  /* Input */
	case 'c': columns = strdup(optarg); break;        /* [SELECT] List of column names to select, separated by comma */
	case 'd':                                 /* [FROM] Pathname of directory containing a Fastbit partition */
	  if ((stat(optarg, &stats) != 0) || (!S_ISDIR(stats.st_mode)))
	    cerr << "[fbquery] Skipping " << optarg << ": unreadable or not a directory " << endl;
	  else
	    dirs.push_back(optarg);
	  break;
	case 'q': query.assign(optarg); break;    /* [WHERE] Query conditions to be satisfied */
	case 'o': orderkeys = optarg; break;      /* [ORDER BY] Sort in ascending order in according to columns specified */
	case 'r': reverse = 1; break;             /* Sort values in descending order */
	case 'g': groupby = optarg; break;        /* [GROUP BY] Perform aggregate functions */
	case 'm': metadata = optarg; break;       /* Metadata file that has been dumped by nProbe */
	case 'C': ibisrc = optarg; break;         /* Configuration settings for ibis */

	  /* Dump format */
	case 'D': distinct = 1; break;            /* [DISTINCT] Retrieves only unique rows from the result set */
	case 'L': limit.assign(optarg); break;    /* [LIMIT] Limit query results */
	case 'S': separator = optarg; break;      /* Character(s) to be used as CSV separator between columns */
	case 'H': header = 0; break;              /* Hide the header line that contains the column names */
	case 'N': native = 1; break;              /* Print each selected column with its native format */

	  /* Output */
	case 'V': verbose = 1; break;             /* Increase the verboseness of fbquery functions */
	case 'Q': ibis::gVerbose = -1; break;     /* Disable the verboseness of FastBit functions */
	}
    }

  /* Initializes internal resources required by FastBit code */
  if (ibisrc && stat(ibisrc, &stats) != 0 ) {
      cerr << "[fbquery] ibisrc " << ibisrc << ": not found " << endl;
  }
  ibis::init(ibisrc);

  /* Table to contain the partitions */
  ibis::table * table = ibis::table::create(0);

  /* Table to contain the results of query */
  ibis::table * results = 0;

  /* Timer */
  ibis::horometer timer;

  /* Check for FastBit directory */
  if (dirs.size() == 0)
    {
      cerr << "[fbquery] Missing mandatory parameter '-d'" << endl;
      cerr << "[fbquery] Leaving ..." << endl;
      help();
      return -1;
    }

  /* Add data partitions from explicitly specified directories */
  for (vector<const char*>::const_iterator it = dirs.begin(); it != dirs.end(); ++it)
    {
      snprintf (path, sizeof (path), "%s/-part.txt", *it);
      if ((stat (path, &stats) == 0) 
#ifndef WIN32
		  && (access (path, X_OK))
#endif
		  )
	{
	  if (verbose) cerr << "[fbquery] Using partition " << *it << endl;
	  table -> addPartition(*it);
	}
      else
	{
	  /* Recursively examine sub-directories */
	  walk_dirs (*it, table);
	}
    }

  /* If no query conditions were specified, select all available rows */
  if (query.size() == 0)
    {
      /* Dummy clause to select all rows */
      query.assign ("1=1");
    }

  /* Check for existence and readability of flow metadata file */
  if (metadata != NULL)
    {
      /* Open the file to parse the output formats */
      mfile.open (metadata);

      if (! mfile.is_open() || ! mfile.good())
	cerr << "[fbquery] Warning: File '" << metadata << "' does not exist or it is not readable ..." << endl;
    }

  /* Parse the LIMIT parameter (if any) */
  if (! limit.empty())
    {
      string::size_type l = limit.find(",");
      if (l != string::npos)
	{
	  /* LIMIT used with two parameters: -L <i,j> */
	  stringstream i(limit.substr(0, l));
	  stringstream j(limit.substr(l+1, limit.size()));
	  i >> start;
	  j >> offset;
	}
      else
	{
	  /* LIMIT used with only one parameter: -L <k> */
	  stringstream k(limit);
	  start = 0;
	  k >> offset;
	}
    }


  /* ===== Evaluate the query ===== */

  /* Store the orginal query string in order to print it in the verbose mode */
  if (verbose) qtmp.assign(query);

  /* Convert IPv4 address in dotted decimal notation or IPv4 with subnet mask specified */
  convert_ip (query);

  timer.start();

  /* Process the query conditions and generate another table to hold the results */
  results = table -> select (columns, query.c_str());
  if (! results) goto fatal;

  /* Perform aggregate functions (if any) */
  if (groupby != 0)
    {
      ibis::table * new_results = results -> groupby (groupby);

      /*
       * In case the group by has not returned rows then
       * we stay with the ungrouped results
       */
      if(new_results)
	results = new_results;
    }
  if (! results) goto fatal;

  /* Warning: This is a dirty workaround!
   * To generate DISTINCT rows is added transparently a GROUP BY clause!
   */
  if (distinct && columns)
    {
      /* Warning:
       * Apply the 'groupby' clause if and only if there are no aggregate functions
       * in the SELECT clause, because these functions use the 'groupby' implicitly.
       * To check if there is an aggregate function (SUM(), AVG(), COUNT(), etc),
       * just look for the occurrence of '(' in the SELECT clause.
       */
      if (! strstr (columns, "("))
	{
	  ibis::table * new_results = results -> groupby (columns);

	  /*
	   * In case the group by has not returned rows then
	   * we stay with the ungrouped results
	   */
	if(new_results)
	  results = new_results;
      }
    }
  if (! results) goto fatal;

  /* Sort the rows of the columns specified with ORDERBY clause (if any) */
  if (orderkeys)
    results -> orderby (orderkeys);
  else
    /* Selected columns in ascending order (default) */
    results -> orderby (columns);

  /* Reverse the order of the rows */
  if (reverse) results -> reverseRows();

  timer.stop();


  /* ===== Print the results ===== */

  if (! results)
    {
    fatal:
      cerr << "[fbquery] An error occurred while executing the query below:" << endl << endl;

      cerr << "  SELECT " << (columns ? columns : "COUNT(*)") << endl;
      cerr << "  WHERE " << query << endl;
      if (orderkeys) cerr << "  ORDER BY " << orderkeys << (reverse ? " DESC " : "") << endl;
      if (! limit.empty()) cerr << "  LIMIT " << limit << endl;
      cerr << endl;

      cerr << "[fbquery] Leaving ..." << endl;
      return -1;
    }

  if (verbose)
    {
      cout << "[fbquery] Running query ..." << endl << endl;

      cout << "  SELECT " << (columns ? columns : "COUNT(*)") << endl;
      cout << "  WHERE " << qtmp << endl;
      if (orderkeys) cout << "  ORDER BY " << orderkeys << (reverse ? " DESC " : "") << endl;
      if (! limit.empty()) cout << "  LIMIT " << limit << endl;
      cout << endl;

      cout << "[fbquery] Query produced " << results->nRows() << " hits, "
	   << "took " << setprecision(3) << timer.CPUTime() << " CPU seconds, "
	   << setprecision(3) << timer.realTime() << " elapsed seconds" << endl;

      qtmp.clear();
    }

  /* Print the rows matching the query conditions */
  if (columns && results->nRows() >= 0)
    {
      /* Returns the column names in the order specified in the query */
      ibis::selectClause sel(columns);

      /* Store names and formats with which to print each column */
      vector<const char*> names (sel.size());
      vector<char*> formats (sel.size());

      for (unsigned j=0; j < sel.size(); ++j)
	{
	  char type [256];

	  /* Store the name of j-th column */
	  names[j] = sel.termName(j);

	  if (metadata)
	    {
	      /* Find the format specified in the file to print the j-th column */
	      parse_metadata_file (mfile, sel.termName(j), type);

	      /* Store the format of j-th column as read from the file */
	      formats[j] = strdup(type);
	    }
	  else
	    {
	      if (native)
		{
		  /* Print each column value with its native format */
		  formats[j] = strdup (DEFAULT_TYPE);
		}
	      else
		{
		  /* Store the default format for the j-th column */
		  if (! strcasecmp (names[j], "IPV4_SRC_ADDR") || ! strcasecmp (names[j], "IPV4_DST_ADDR"))
		    formats[j] = strdup (IPV4_TYPE);
		  else if (strstr (names[j], "COUNTRY"))
		    formats[j] = strdup(TWO_CHAR_TYPE);
		  else
		    formats[j] = strdup (DEFAULT_TYPE);
		}
	    }

	  if (verbose)
	    cout << names[j] << " will be printed as '" << formats[j] << "'" << endl;
	}

      if (results-> nRows() > 0)
	{
	  /* Print the results in a customized format */
	  int error = print_results (names, *results, header, start, offset, separator, formats);

	  if (error != 0)
	    cerr << "[fbquery] An error occurred while printing results (" << error << ")" << " ..." <<  endl;
	}
      else
	{
	  if (header)
	    {
	      /* No results but we still need to print the header */
	      for (size_t i = 0; i < names.size(); ++ i) {
		if(i > 0) cout << separator;
		cout << names[i];
	      }
	      cout << "\n";
	    }
	}

      /* Free memory */
      for (unsigned i=0; i < formats.size(); ++i)
	free (formats[i]);
    }
  else if (results->nRows() == 0 && ! verbose)
    {
      /* To avoid an empty output when there are no results */

      cout << "[fbquery] Query produced " << results->nRows() << " hits, "
	   << "took " << setprecision(3) << timer.CPUTime() << " CPU seconds, "
	   << setprecision(3) << timer.realTime() << " elapsed seconds" << endl;
      cout << "[fbquery] Use flag '-V' to get a more verbose output" << endl;
    }
  else if (! columns && results->nRows() != 0 && ! verbose)
    {
      /* To avoid an empty output when no columns are selected */

      cout << "[fbquery] Query produced " << results->nRows() << " hits, "
	   << "took " << setprecision(3) << timer.CPUTime() << " CPU seconds, "
	   << setprecision(3) << timer.realTime() << " elapsed seconds" << endl;
      cout << "[fbquery] Select at least one column name (using flag '-c') to print rows"
	" that match query conditions" << endl;
    }

  flush (cout);
  flush (cerr);

#ifndef WIN32
  /* Close file */
  if (mfile.is_open()) mfile.close();
#endif

  /* Free Memory */
  delete table;
  delete results;

  return 0;
}


#else /* HAVE_FASTBIT */

int main (int argc, char * argv [])
{
  cerr << "[fbquery] This tool must be configured with FastBit support!" << endl;
  cerr << "[fbquery] Leaving ..." << endl;
  return 0;
}

#endif /* HAVE_FASTBIT */
