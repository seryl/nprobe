/*              __ _     _           _
 *             / _| |__ (_)_ __   __| | _____  __
 *            | |_| '_ \| | '_ \ / _` |/ _ \ \/ /
 *            |  _| |_) | | | | | (_| |  __/>  <
 *            |_| |_.__/|_|_| |_|\__,_|\___/_/\_\
 *
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
#include <dirent.h>


#ifdef HAVE_FASTBIT
#include "ibis.h"
#include "tafel.h"

extern "C" {
#include "nprobe.h"
};

static u_int8_t verbose = 0;
static u_int num_threads = 2;


/* Version info */
#define FBINDEX_VERSION   "1.0"
#define FBINDEX_RELEASE   __DATE__


/* Display the version number of this program */
static void show_version ()
{
  printf ("\n");
  printf ("Welcome to fbindex v.%s - Built on %s\n", FBINDEX_VERSION, FBINDEX_RELEASE);
  printf ("Copyright (C) 2009-2010 Luca Deri <deri@ntop.org>\n");
  printf ("                        Valeria Lorenzetti <lorenzetti@ntop.org>\n");
  printf ("\n");
}


/* Display the syntax for using this program */
static void help ()
{
  show_version ();

  printf ("Index the specified Fastbit partition.\n");
  printf ("Usage: fbindex [-h] [-v] [-s] [-c <column names>] [-t <threads>] -d <directory> \n\n");

  printf (" -h                    | Show this help message and exit\n"
	  " -v                    | Enable verbose mode\n"
	  " -s                    | Reorder data before indexing\n"
	  " -c <column names>     | Indexes only the specified columns\n"
	  " -t <threads>          | Specify the number of threads used during indexing. Default: %d\n"
	  " -d <directory>        | Fastbit partition (directory) to index\n",
	  num_threads);

  exit(0);
}


/* Index Fastbit directory */
void indexDir (char * directory, char * columns, int reorder_data)
{
  struct timeval begin, end, diff;

  /* Construct a data partition from the given data directory */
  ibis::part part (directory, static_cast<const char*>(0));

  if (verbose) printf ("Indexing Fastbit directory. This can take a while, please wait ...\n");

  /* Start timer */
  gettimeofday (& begin, NULL);

  /* Delete old indexes */
  if (verbose) printf ("Purging old indexes ...\n");
  part.purgeIndexFiles();

  if (reorder_data)
    {
      /* Order data (reorder) */
      if (verbose) printf ("Reordering data on directory %s ...\n", directory);
      part.reorder();
    }

  if (columns)
    {
      ibis::partList parts;

      if (verbose) printf ("Indexing columns '%s'\n", columns);

      /* Examining the given directory to look for the metadata files and constructs ibis::part */
      ibis::util::gatherParts (parts, directory);

      for (ibis::partList::const_iterator it = parts.begin(); it != parts.end(); ++ it)
	{
	  ibis::part * mypart = * it;
	  for (uint32_t i = 0; i < mypart -> nColumns(); ++ i)
	    {
	      ibis::column * col = mypart -> getColumn(i);
	      if (strstr (columns, col -> name()))
		{
		  if (verbose) printf ("Indexing column %s ...\n", col -> name());

		  /* Load the index associated with the column */
		  col -> loadIndex();

		  /* Unload the index associated with the column */
		  col -> unloadIndex();
		}
	    }
	}
    }
  else
    {
      if (verbose)
	printf ("Indexing all columns (%d threads may be used) ...\n", num_threads);

      /* Make sure indexes for all columns are available.
       * May use num_threads threads to build indexes
       */
      part.buildIndexes (columns, num_threads);
    }

  /* Stop timer */
  gettimeofday (& end, NULL);
  timeval_diff (& begin, & end, & diff, 0);

  if (verbose)
    printf ("Indexed directory '%s' in %ld.%03d seconds\n",
	    directory, diff.tv_sec, (int)(diff.tv_usec / 1000));
}


int main (int argc, char * argv [])
{
  char c, * dir = NULL, * columns = NULL;
  int reorder_data = 0, i;

  while ((c = getopt (argc, argv, "hvsc:t:d:")) != -1)
    {
      switch (c)
	{
	case 'h': help (); break;                     /* Show help message */
	case 'v': verbose = 1; break;                 /* Enable verbose mode */
	case 's': reorder_data = 1; break;            /* Reorder data before indexing */
	case 'c': 
	  columns = strdup (optarg); 
	  /* Remove % from column names */
	  for(i=strlen(columns)-1; i>=0; i--)
	    if(columns[i] == '%')
	      columns[i] = ' ';
	  break;   /* Indexes only the specified columns */
	case 't': num_threads = atoi (optarg); break; /* Number of threads used during indexing */
	case 'd': dir = strdup(optarg); break;        /* Fastbit partition (directory) to index */
	}
    }

  if (! dir)
    help();
  else
    indexDir (dir, columns, reorder_data);

  /* Free Memory */
  if (columns) free (columns);
  if (dir) free (dir);

  return(0);
}

#else
int main (int argc, char * argv []) {
  printf("This tool was not configured with fastbit support.\nLeaving...\n");
  return(0);
}
#endif
