#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#else
typedef enum { FALSE = 0, TRUE = 1 } bool;
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
#include "getopt.h"
#endif

#include <string.h>
#include <errno.h>

static u32 fgetu32 (FILE *f)
{
  register u32 r;

  r  = fgetc(f) <<  0;
  r |= fgetc(f) <<  8;
  r |= fgetc(f) << 16;
  r |= fgetc(f) << 24;

  return r;
}

static u32 fgetu16 (FILE *f)
{
  register u32 r;

  r  = fgetc(f) <<  0;
  r |= fgetc(f) <<  8;

  return r;
}

static void parse_zip (char *path)
{
  FILE *f = fopen (path, "rb");
  
  if (!f)
    {
      fprintf (stderr, "skipping '%s': %s\n", path, strerror (errno));
      goto out;
    }
  
  while (!feof (f))
    {
    u32 id = fgetu32 (f);
    
    if (id == 0x04034b50UL)
      {
        u16 version		= fgetu16 (f);
        u16 flags		= fgetu16 (f);
        u16 compression_method 	= fgetu16 (f);
        u16 lastmodtime		= fgetu16 (f);
        u16 lastmoddate		= fgetu16 (f);
        u32 crc32		= fgetu32 (f);
        u32 compr_size		= fgetu32 (f);
        u32 uncompr_size	= fgetu32 (f);
        u16 name_len		= fgetu16 (f);
        u16 extra_field_len	= fgetu16 (f);
        
        char zip_path [1024];

        (void)crc32; /* suppress warning */
        
        /* these are unused.  */
        (void) lastmoddate;
        (void) lastmodtime;
        (void) compression_method;
        (void) version;
        
        if (name_len < 1024)
          {
            fread (zip_path, name_len, 1, f);
            zip_path [name_len] = 0;
          }
        else
          {
            fprintf (stderr, "filename too long (>1023 bytes), skipping zipfile\n");
            goto out;
          }
        
        fseek (f, extra_field_len, SEEK_CUR);
        
        printf ("found file '%s', size %ld (%ld)", zip_path, (long)uncompr_size, (long)compr_size);
        
        if (flags & 1)
          printf (", encrypted");
        
        if (compr_size >= 23)
          {
            u8 file[24];
            fread (file, 24, 1, f);
            
            printf ("\n%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                    file[0], file[1], file[ 2], file[ 3], 
                    file[4], file[5], file[ 6], file[ 7], 
                    file[8], file[9], file[10], file[11]);
                    
            printf (" : %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                    file[12], file[13], file[14], file[15], 
                    file[16], file[17], file[18], file[19], 
                    file[20], file[21], file[22], file[23]);
                    
            compr_size -= 24;
          }
        
        printf ("\n");
        
        fseek (f, compr_size, SEEK_CUR);
      }
    else if (id == 0x08074b50UL) /* extended local sig (?)  */
      {
        fseek (f, 12, SEEK_CUR);
      }
    else if (id == 0x30304b50UL)
      {
        /* ignore */
      }
    else if (id == 0x02014b50UL || id == 0x06054b50UL)
      {
        goto out;
      }
    else
      {
        fprintf (stderr, "found id %08lx, '%s' is not a zipfile ver 2.xx, skipping\n",
                 (unsigned long)id, path);
        goto out;
      }
    }
  
  out:
  fclose (f);
}

static void usage (int ec)
{
  printf ("\n"
                 PACKAGE " version " VERSION ", zipinfo - tell me about a zip file\n"
                 "written by Marc Lehmann <pcg@goof.com> You can find more info on\n"
                 "http://www.goof.com/pcg/marc/\n"
                 "\n"
                 "USAGE: zipinfo file...                the zipfiles to parse\n"
                 "\n"
          );
  
  exit (ec);
}

static struct option options[] = {
  { "help"		, no_argument		, 0, 'h' },
  { "version"		, no_argument		, 0, 'R' },
  { 0			, 0			, 0,  0  },
};

int main (int argc, char *argv[])
{
  int option_index = 0;
  int c;
  
  while ((c = getopt_long (argc, argv, "", options, &option_index)) != -1)
    switch (c)
      {
      case 'h':
        usage (0);
        break;
      case 'R':
        printf ("zipinfo version " VERSION "\n");
        exit (0);
      }
  
  if (optind >= argc)
    {
      fprintf (stderr, "you have to specify one or more zip files (try --help)\n");
      exit (1);
    }
  
  for (; optind < argc; optind++)
    parse_zip (argv[optind]);
  
  return 0;
}
