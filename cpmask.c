#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* CP mask code */

/* The original CP code was written by Hirotsuna Mizuno and is
 * Copyright (c) 1998 Hirotsuna Mizuno <s1041150@u-aizu.ac.jp>
 *
 * I heavily modified his code.
 * as for speed, this algorithm could be improved without end,
 * and alternative algorithms might exist that might be several orders
 * of magnitude faster.
 */

/* this is faster */
typedef unsigned int UI;

static UI image_width;
static UI image_height;
static u8 *image_data;
static UI transform_width;
static UI transform_height;
static u8 *transform_data;

typedef struct
  {
    UI dst_x, dst_y;
    int mirror;
  }
cp_cell;

static UI cp_cells;
static cp_cell *cp_trans;
static int *cp_table;
static UI cp_width;
static UI cp_height;


#define CP_CODE_MAX_LENGTH	16
#define CP_CELL_SIZE		8
#define CP_BPP			3
#define OFFSET_X		0
#define OFFSET_Y		0

/* the maximum size of the transformed image in cells */
#define MAX_SIZE		4

#define MAX_CP_WIDTH		2048

#define src_pixel(x,y,c) image_data     [((y)*image_width    +(x)) * CP_BPP + (c)]
#define dst_pixel(x,y,c) transform_data [((y)*transform_width+(x)) * CP_BPP + (c)]

static void
load_img (const char *name)
{
  FILE *img;
  UI image_depth;

  if (image_data)
    fprintf (stderr, "cannot load more than one image\n");
  else
    {
      img = fopen (name, "rb");
      if (img)
	{
	  if (fscanf (img, "P6 ") == EOF)
	    perror ("no BINARY PPM header detected");
	  else
	    {
	      fscanf (img, "#%*[^\012\015] ");	/* comment */
	      if (fscanf (img, "%u ", &image_width) != 1)
		fprintf (stderr, "unable to read image width\n");
	      else
		{
		  fscanf (img, "#%*[^\012\015] ");	/* comment */
		  if (fscanf (img, "%u ", &image_height) != 1)
		    fprintf (stderr, "unable to read image height\n");
		  else
		    {
		      fscanf (img, "#%*[^\012\015] ");	/* comment */
		      if (fscanf (img, "%u%*[ \012\015] ", &image_depth) != 1)
			fprintf (stderr, "unable to read image depth\n");
		      else
			{
			  if (image_depth != 255)
			    fprintf (stderr, "pixel maxval %d (!= 255) is not supported\n", image_depth);
			  else
			    {
			      image_data = (u8 *) malloc (image_width * image_height * CP_BPP);
			      if (!image_data)
				fprintf (stderr, "unable to allocate memory for image\n");
			      else
				{
				  if (fread (image_data, image_width * image_height * CP_BPP, 1, img) != 1)
				    fprintf (stderr, "unable to read image data\n");
				  else
				    {
				      /*fprintf (stderr, "read image %dx%d, %d\n", image_width, image_height, image_depth); */
				      file_path[file_count++] = name;
				    }
				}
			    }
			}
		    }
		}
	      fclose (img);
	    }
	}
    }
}

/* if you are interested, the following code can detect hidden passwords
 * stored in CP-masked-JPEG files.
 */

/*
 * sorry, the detect code was removed ;)
 */

/*----------------------------------------------------------------------------*/

static u8 cp_key[] =
{
0x10, 0x17, 0x13, 0x15, 0x09, 0x08, 0x0a, 0x14, 0x06, 0x05, 0x16, 0x02, 0x0d,
0x03, 0x01, 0x04, 0x19, 0x0c, 0x0f, 0x0e, 0x12, 0x07, 0x0b, 0x18, 0x11, 0x1a
};

static cp_table_lu1[MAX_CP_WIDTH];
static cp_table_lu2[MAX_CP_WIDTH];

/* this is a bottleneck */
static void
cp_set_pw (u8 * pw, u8 * pw_end)
{
  u8 *cursor;
  int i, j, x, y, len;
  int *table;
  cp_cell *trans;

  len = pw_end - pw;

  for (i = x = y = 0, table = cp_table, trans = cp_trans;
       i < cp_cells;
       i++)
    {
      *table++ = -1;
      trans->dst_x = x;
      trans->dst_y = y;
      trans->mirror = 0;
      trans++;

      if (++x == cp_width)
	{
	  x = 0;
	  y++;
	}
    }

  x = cp_cells - 1;
  y = len + cp_cells % len;

  for (i = 0, cursor = pw; i < cp_cells; i++)
    {
      x = cp_key[*cursor - 'A'] + x + y;

      if (++cursor == pw_end)
	cursor = pw;

      if (x >= cp_cells)
	x -= cp_cells;

      if (x >= cp_cells)
	x -= cp_cells;

      while (cp_table[x] != -1)
	{
	  ++x;
	  if (x >= cp_cells)
	    x = 0;
	}

      cp_table[x] = i;
      y++;

      if (++i >= cp_cells)
	break;

      x = cp_key[*cursor - 'A'] + x + y;

      if (++cursor == pw_end)
	cursor = pw;

      if (x >= cp_cells)
	x -= cp_cells;

      if (x >= cp_cells)
	x -= cp_cells;

      while (cp_table[x] != -1)
	{
	  if (x == 0)
	    x = cp_cells;

	  x--;
	}

      cp_table[x] = i;
      y++;
    }

  for (i = 0, j = cp_cells - 1; i < j; i++, j--)
    {
      cp_trans[cp_table[i]].dst_x = cp_table_lu1[j];
      cp_trans[cp_table[i]].dst_y = cp_table_lu2[j];
      cp_trans[cp_table[j]].dst_x = cp_table_lu1[i];
      cp_trans[cp_table[j]].dst_y = cp_table_lu2[i];

      if ((cp_table[i] ^ cp_table[j]) & 1)
	{
	  cp_trans[cp_table[i]].mirror = 1;
	  cp_trans[cp_table[j]].mirror = 1;
	}
    }
}

/*----------------------------------------------------------------------------*/

static void
cp_do_mask (void)
{
  UI x, y, src_x, src_y;
  UI u, v, dst_x, dst_y;
  UI xx;
  int rot;
  cp_cell *cell = cp_trans;

  for (y = 0; y < cp_height; ++y)
    {
      for (x = 0; x < cp_width; ++x)
	{
	  {
	    u = cell->dst_x;
	    v = cell->dst_y;
	    rot = cell->mirror;
	    cell++;
	    dst_x = x * CP_CELL_SIZE + OFFSET_X;
	    dst_y = y * CP_CELL_SIZE + OFFSET_Y;
	    src_x = u * CP_CELL_SIZE + OFFSET_X;
	    src_y = v * CP_CELL_SIZE + OFFSET_Y;
	  }

#define   COPY(sx,sy,dx,dy) do { \
            u8 *s = &src_pixel (src_x + (sx), src_y + (sy), 0);	\
            u8 *d = &dst_pixel (dst_x + (dx), dst_y + (dy), 0);	\
            *d++ = *s++;	\
            *d++ = *s++;	\
            *d++ = *s++;	\
	  } while(0)

	  if (dst_x + CP_CELL_SIZE <= transform_width &&
	      dst_y + CP_CELL_SIZE <= transform_height)
	    {
	      if (rot)
		{
		  /* this is shit */
		  for (xx = CP_CELL_SIZE - 1; xx--;)
		    {
		      COPY (xx + 1, 0, 0, xx + 1);
		      COPY (0, xx, xx, 0);
		      COPY (xx, CP_CELL_SIZE - 1, CP_CELL_SIZE - 1, xx);
		      COPY (CP_CELL_SIZE - 1, xx + 1, xx + 1, CP_CELL_SIZE - 1);
		    }
		}
	      else
		{
		  for (xx = CP_CELL_SIZE; xx--;)
		    {
		      COPY (xx + 1, 0, xx + 1, 0);
		      COPY (0, xx, 0, xx);
		      COPY (xx, CP_CELL_SIZE - 1, xx, CP_CELL_SIZE - 1);
		      COPY (CP_CELL_SIZE - 1, xx + 1, CP_CELL_SIZE - 1, xx + 1);
		    }
		}
	    }

#undef COPY
	}
    }
//  {FILE *f=fopen("x.ppm","wb"); fprintf (f,"P6 %d %d %d ",transform_width,transform_height,255); fwrite(transform_data,transform_width*transform_height*CP_BPP,1,f); fclose(f); }
}

static void
cp_cleanup (void)
{
  if (cp_table)
    free (cp_table);

  if (cp_trans)
    free (cp_trans);
}

static void
init_cpmask (void)
{
  UI i;

  assert (image_data);
  cp_width = image_width / CP_CELL_SIZE;
  cp_height = image_height / CP_CELL_SIZE;
  cp_cells = cp_width * cp_height;
  cp_table = (int *) malloc (sizeof (int) * cp_cells);
  cp_trans = (cp_cell *) malloc (sizeof (cp_cell) * cp_cells);

  if (cp_width > MAX_CP_WIDTH)
    {
      printf ("maximum image width in this version is %d\n", MAX_CP_WIDTH * CP_CELL_SIZE);
      exit (1);
    }

  for (i = 0; i < MAX_CP_WIDTH; i++)
    {
      cp_table_lu1[i] = i % cp_width;
      cp_table_lu2[i] = i / cp_width;
    }

  transform_width = image_width < CP_CELL_SIZE * MAX_SIZE ? image_width : CP_CELL_SIZE * MAX_SIZE;
  transform_height = image_height < CP_CELL_SIZE * MAX_SIZE ? image_height : CP_CELL_SIZE * MAX_SIZE;

  transform_data = (u8 *) malloc (transform_width * transform_height * CP_BPP);
}

static int
crack_cpmask (gen_func genfunc, callback_func cbfunc)
{
  unsigned long minimum = 1 << 31;
  unsigned long current;
  int changed = -1;
  int x, y;

  do
    {
      if (changed >= 4 && verbosity)
	printf ("checking pw %s\r", pw), fflush (stdout);

      if (changed < 0)
	pw_end = pw + strlen (pw);

      cp_set_pw (pw, pw_end);
      cp_do_mask ();

#define P(x,y,c) (UI)dst_pixel((x),(y),(c))
      current = 0;

      for (x = CP_CELL_SIZE; x < transform_width; x += CP_CELL_SIZE)
	for (y = transform_height; y--;)
	  {
	    current += abs (P (x - 1, y, 0) - P (x, y, 0));
	    current += abs (P (x - 1, y, 1) - P (x, y, 1));
	    current += abs (P (x - 1, y, 2) - P (x, y, 2));

            if (current > minimum)
              goto overflow;
	  }

      for (y = CP_CELL_SIZE; y < transform_height && current < minimum; y += CP_CELL_SIZE)
	for (x = transform_width; x-- && current < minimum;)
	  {
	    current += abs (P (x, y - 1, 0) - P (x, y, 0));
	    current += abs (P (x, y - 1, 1) - P (x, y, 1));
	    current += abs (P (x, y - 1, 2) - P (x, y, 2));

            if (current > minimum)
              goto overflow;
	  }
#undef P

overflow:
      if (current < minimum)
	{
	  char info[80];

	  minimum = current + 99;

	  sprintf (info, "badness %ld", current);

	  if ((changed = cbfunc (pw, info)))
	    return changed;
	}

    }
  while ((changed = genfunc ()));

  return 0;
}
