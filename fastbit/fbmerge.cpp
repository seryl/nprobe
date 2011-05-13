/*              __ _
 *             / _| |__  _ __ ___   ___ _ __ __ _  ___
 *            | |_| '_ \| '_ ` _ \ / _ \ '__/ _` |/ _ \
 *            |  _| |_) | | | | | |  __/ | | (_| |  __/
 *            |_| |_.__/|_| |_| |_|\___|_|  \__, |\___|
 *                                          |___/
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
#include <string.h>
#include <dirent.h>

#include "ibis.h"
#include "tafel.h"

u_int32_t tot_records = 0;
u_int8_t dump_mode = 0;


/* Version info */
#define FBMERGE_VERSION   "1.0"
#define FBMERGE_RELEASE   __DATE__


/* Display the version number of this program */
static void show_version ()
{
  printf ("\n");
  printf ("Welcome to fbmerge v.%s - Built on %s\n", FBMERGE_VERSION, FBMERGE_RELEASE);
  printf ("Copyright (C) 2009-10 Luca Deri <deri@ntop.org>\n");
  printf ("                      Valeria Lorenzetti <lorenzetti@ntop.org>\n");
  printf ("\n");
}


/* Display the syntax for using this program */
static void help ()
{
  show_version ();

  printf ("Merge Fastbit directories enclosed in the root directory specified\n"
	  "with -i flag and saves merged data into the specified output directory\n\n");

  printf ("Usage: fbmerge [-h] [-d] -i <input dir> -o <output dir>\n\n");

  printf (" -h                    | Show this help message and exit\n"
	  " -d                    | Enable dump mode\n"
	  " -i <input_dir>        | Input directory\n"
	  " -o <output_dir>       | Output directory\n");

  exit(0);
}


int mergeDir (char * input_dir, char * output_dir)
{
  u_int i, ret = 0;
  ibis::part part (input_dir, static_cast<const char*>(0));
  ibis::bitvector * bv;
  ibis::tablex * tablex = NULL;

  if (part.nRows() == 0)
    return(0);

  printf ("Found %u records on directory %s\n", part.nRows(), input_dir);

  tot_records += part.nRows();

  bv = new ibis::bitvector();
  bv -> appendFill (1, part.nRows()); /* Set all bitmaps to 1 */

  if (! dump_mode)
    {
      /* tafel stores all its content in memory before the function write is called */
      tablex = new ibis::tafel();
    }

  for (i=0; i < part.nColumns(); i++)
    {
      unsigned char * s8;
      uint16_t * s16;
      uint32_t * s32;
      uint64_t * s64;
      ibis::column * c;
      char path [256];
      FILE * fd;

      c = part.getColumn (i);
      snprintf (path, sizeof (path), "%s/%s", output_dir, c -> name());

      switch (c -> elementSize())
	{
	case 1:
	  s8 = part.selectUBytes (c -> name(), * bv) -> begin();
	  if (dump_mode)
	    {
	      if ((fd = fopen (path, "a")) != NULL)
		{
		  for (u_int j=0; j < part.nRows()-1; j++)
		    fprintf (fd, "%u\n", s8[j]);
		  fclose (fd);
		}
	    }
	  else
	    {
	      /* Add metadata about a new column */
	      tablex -> addColumn (c -> name(), ibis::BYTE);

	      /* Copy the incoming values of column */
	      tablex -> append (c -> name(), 0, part.nRows(), s8);
	    }
	  break;

	case 2:
	  s16 = part.selectUShorts (c -> name(), * bv) -> begin();
	  if (dump_mode)
	    {
	      if((fd = fopen (path, "a")) != NULL)
		{
		  for(u_int j=0; j < part.nRows()-1; j++)
		    fprintf (fd, "%u\n", s16[j]);
		  fclose (fd);
		}
	    }
	  else
	    {
	      /* Add metadata about a new column */
	      tablex -> addColumn (c -> name(), ibis::USHORT);

	      /* Copy the incoming values of column */
	      tablex -> append (c -> name(), 0, part.nRows(), s16);
	    }
	  break;

	case 4:
	  s32 = part.selectUInts (c -> name(), * bv) -> begin();
	  if (dump_mode)
	    {
	      if ((fd = fopen (path, "a")) != NULL)
		{
		  for(u_int j=0; j < part.nRows()-1; j++)
		    fprintf (fd, "%u\n", s32[j]);
		  fclose (fd);
		}
	    }
	  else
	    {
	      /* Add metadata about a new column */
	      tablex -> addColumn (c -> name(), ibis::UINT);

	      /* Copy the incoming values of column */
	      tablex -> append (c -> name(), 0, part.nRows(), s32);
	    }
	  break;

	case 8:
	  s64 = part.selectULongs (c -> name(), * bv) -> begin();
	  if (dump_mode)
	    {
	      if ((fd = fopen(path, "a")) != NULL)
		{
		  for (u_int j=0; j < part.nRows(); j++)
		    fprintf (fd, "%lu\n", (long unsigned int)s64[j]);
		  fclose (fd);
		}
	    }
	  else
	    {
	      /* Add metadata about a new column */
	      tablex -> addColumn (c -> name(), ibis::LONG);

	      /* Copy the incoming values of column */
	      tablex -> append (c -> name(), 0, part.nRows(), s64);
	    }
	  break;
	}
    }

  if (! dump_mode)
    {
      /* Write the data values and update the metadata file */
      tablex -> write (output_dir, 0, 0);
    }

  delete tablex;

  return (ret);
}


int walkDirs (char * input_dir, char * output_dir)
{
  DIR * dir;
  struct dirent * dirent;
  char partname [256];
  struct stat stats;

  printf ("Processing directory %s\n", input_dir);

  if ((dir = opendir (input_dir)) != NULL)
    {
      while ((dirent = readdir (dir)))
	{
	  char dirname [256];

	  if (dirent -> d_name [0] == '.') continue;

	  snprintf (dirname, sizeof (dirname), "%s/%s", input_dir, dirent -> d_name);
	  if(stat (dirname, &stats) == 0)
	    {
	      if (S_ISDIR (stats.st_mode))
		walkDirs (dirname, output_dir);
	    }
	}

      closedir (dir);
    }

  snprintf (partname, sizeof (partname), "%s/-part.txt", input_dir);
  if (stat (partname, &stats) == 0)
    {
      if (access (partname, X_OK))
	mergeDir (input_dir, output_dir);
      else
	printf ("WARNING: skipping unreadable directory %s\n", partname);
    }

  return(0);
}


int main (int argc, char * argv [])
{
  char c, * input_dir = NULL, * output_dir = NULL;

  while ((c = getopt (argc, argv, "hdi:o:")) != -1)
    {
      switch (c)
	{
	case 'h': help(); break;                        /* Show help message */

	case 'd': dump_mode = 1; break;                 /* Enable dump mode */
	case 'i': input_dir = strdup (optarg); break;   /* Input directory */
	case 'o': output_dir = strdup (optarg); break;  /* Output directory */
	}
    }

  if ((! input_dir) || (! output_dir))
    help ();

  printf ("Searching Fastbit directories on %s ...\n", input_dir);

  walkDirs (input_dir, output_dir);

  printf ("Merged %u records into directory %s ...\n", tot_records, output_dir);
  printf ("Leaving ...\n");

  /* Free Memory */
  if (input_dir) free (input_dir);
  if (output_dir) free (output_dir);

  exit(0);
}
