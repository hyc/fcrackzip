#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "crack.h"

u8 pw[MAX_PW + 1] = "aaaaaa";
u8 *pw_end;			/* must point to the trailing zero byte.  */

u8 files[MAX_FILES * HEADER_SIZE];
const char *file_path[MAX_FILES];
int file_count;

u8 bf_next[256];
u8 bf_last;

int verbosity;

static u8 mult_tab[16384];

static u32
fgetu32 (FILE * f)
{
  return (fgetc (f) << 0) |
    (fgetc (f) << 8) |
    (fgetc (f) << 16) |
    (fgetc (f) << 24);
}

static u32
fgetu16 (FILE * f)
{
  return (fgetc (f) << 0) |
    (fgetc (f) << 8);
}

static void
load_zip (const char *path)
{
  FILE *f = fopen (path, "rb");

  if (!f)
    {
      fprintf (stderr, "skipping '%s': %s\n", path, strerror (errno));
      return;
    }

  while (!feof (f))
    {
      u32 id = fgetu32 (f);

      if (id == 0x04034b50UL)
	{
	  u16 version = fgetu16 (f);
	  u16 flags = fgetu16 (f);
	  u16 compression_method = fgetu16 (f);
	  u16 lastmodtime = fgetu16 (f);
	  u16 lastmoddate = fgetu16 (f);
	  u32 crc32 = fgetu32 (f);
	  u32 compr_size = fgetu32 (f);
	  u32 uncompr_size = fgetu32 (f);
	  u16 name_len = fgetu16 (f);
	  u16 extra_field_len = fgetu16 (f);

	  char zip_path[1024];

	  /* these are unused.  */
	  (void) lastmoddate;
	  (void) lastmodtime;
	  (void) compression_method;
	  (void) version;

	  if (name_len < 1024)
	    {
	      fread (zip_path, name_len, 1, f);
	      zip_path[name_len] = 0;
	    }
	  else
	    {
	      fprintf (stderr, "filename too long (>1023 bytes), skipping zipfile\n");
	      goto out;
	    }

	  fseek (f, extra_field_len, SEEK_CUR);

	  if (flags & 1)
	    {
	      if (compr_size >= 12)
		{
		  u8 *file = files + HEADER_SIZE * file_count;
		  fread (file, FILE_SIZE, 1, f);

                  if (flags & 8)
                    {
                      /* extended header format? */
                      file[FILE_SIZE] = lastmodtime >> 8;
                      file[FILE_SIZE + 1] = lastmodtime;
                    }
                  else
                    {
                      file[FILE_SIZE] = crc32 >> 24;
                      file[FILE_SIZE + 1] = crc32 >> 16;
                    }

		  file_path[file_count] = strdup (path);

		  if (verbosity)
		    printf ("found file '%s', (size cp/uc %6lu/%6lu, flags %lx, chk %02x%02x)\n",
                            zip_path, (unsigned long) compr_size, (unsigned long) uncompr_size, (unsigned long) flags,
                            file[FILE_SIZE], file[FILE_SIZE+1]);

		  if (++file_count >= MAX_FILES)
		    {
		      if (verbosity)
			printf ("%d file maximum reached, skipping further files\n", MAX_FILES);

		      goto out;
		    }

		  compr_size -= 12;
		}
	      else
		{
		  fprintf (stderr, "'%s' is corrupted, skipping zipfile\n", zip_path);
		  goto out;
		}
	    }
	  else if (verbosity)
	    printf ("'%s' is not encrypted, skipping\n", zip_path);

	  fseek (f, compr_size, SEEK_CUR);
	}
      else if (id == 0x08074b50UL)	/* extended local sig (?)  */
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
		   (unsigned long) id, path);
	  goto out;
	}
    }

out:
  fclose (f);
}

#include "cpmask.c"
#include "crackdef.c"
