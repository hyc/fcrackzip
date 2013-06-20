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
#ifdef HAVE_GETTIMEOFDAY
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#endif

#include <string.h>

#ifdef USE_UNIX_REDIRECTION
#define DEVNULL ">/dev/null 2>&1"
#else
#define DEVNULL ">NUL 2>&1"
#endif

#include "crack.h"

int use_unzip;

static method *crack_method = methods;
static int method_number = -1;
static int min_length = -1;
static int max_length = -1;
static int residuent = 0;
static int modul = 1;

static FILE *dict_file;

int REGPARAM
check_unzip (const char *pw)
{
  char buff[1024];
  int status;

  sprintf (buff, "unzip -qqtP \"%s\" %s " DEVNULL, pw, file_path[0]);
  status = system (buff);

#undef REDIR

  if (status == EXIT_SUCCESS)
    {
      printf("\n\nPASSWORD FOUND!!!!: pw == %s\n", pw);
      exit (EXIT_SUCCESS);
    }

  return !status;
}

/* misc. callbacks.  */

static int
false_callback (const char *pw, const char *info)
{
  (void) pw;
  (void) info;                        /* suppress warning */
  return 0;
}

static int
true_callback (const char *pw, const char *info)
{
  (void) pw;
  (void) info;                        /* suppress warning */
  return 1;
}

static int
print_callback (const char *pw, const char *info)
{
  if (!use_unzip || check_unzip (pw))
    {
      printf ("possible pw found: %s (%s)\n", pw, info ? info : "");
      /*exit(0); */
    }

  return 0;
}

static int
brute_force_gen (void)
{
  u8 *p = pw_end;

  do
    {
      u8 o = *--p;
      *p = bf_next[o];
      if (o != bf_last)
        return pw_end - p;
    }
  while (p > pw);

  if (pw_end - pw < max_length)
    {
      p = ++pw_end;
      *p = 0;

      while (p > pw)
        *--p = bf_next[255];

      return -1;
    }
  else
    return 0;
}

static int
dictionary_gen (void)
{
  /* should optimize this, comparing prefixes would be a net win.
   * however, not using fgets but something better might be an
   * even higher win :(
   */
  if (fgets (pw, MAX_PW+1, dict_file))
    {
      pw[strlen (pw) - 1] = 0;
      return -1;
    }
  else
    {
      if (!feof (dict_file))
        perror ("dictionary_read_next_password");

      return 0;
    }
}

static int
validate_gen (void)
{
  return 0;
}

static void
validate (void)
{
  u8 header[HEADER_SIZE + 1] =
  {0xf4, 0x28, 0xd6, 0xee, 0xd7, 0xd2,
   0x3c, 0x1a, 0x20, 0xab, 0xdf, 0x73,
   0xd6, 0xba, 0};                /* PW: "Martha" */
  strcpy ((char *) files, (char *) header);        /* yeah, dirty... */
  file_count = 1;

  if (crack_method->desc[0] == 'z')
    {
      crack_method->init_crack_pw ();

      strcpy (pw, "Martha");
      if (crack_method->crack_pw (validate_gen, true_callback))
        printf ("validate ok (%s == Martha)\n", pw);
      else
        printf ("validation error (%s != Martha)\n", pw);
    }
  else
    printf ("validate only works for zip methods, use --method to select one.\n");
}

static void
parse_charset (char *cs)
{
  u8 chars[800];
  u8 map[256];
  u8 *p = chars;

  while (*cs)
    switch (*cs++)
      {
      case 'a':
        strcpy ((char *) p, "abcdefghijklmnopqrstuvwxyz");
        p += 26;
        break;

      case 'A':
        strcpy ((char *) p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        p += 26;
        break;

      case '1':
        strcpy ((char *) p, "0123456789");
        p += 10;
        break;

      case '!':
        strcpy ((char *) p, "!:$%&/()=?{[]}+-*~#");
        p += 18;
        break;

      case ':':
        while (*cs)
          *p++ = *cs++;
        break;

      default:
        fprintf (stderr, "unknown charset specifier, only 'aA1!:' recognized\n");
        exit (1);
      }

  *p = 0;

  p = chars;
  bf_last = *p++;
  memset (bf_next, bf_last, sizeof bf_next);
  memset (map, 0, 256);

  for (; *p; p++)
    if (!map[*p])
      {
        map[*p] = 1;
        bf_next[bf_last] = *p;
        bf_last = *p;
      }

  bf_next[bf_last] = chars[0];

/*  { int i; for (i = 0; i < 255; i++) printf ("bf_next [%3d] = %3d\n", i, bf_next[i]);}; */
}

static int benchmark_count;

static int
benchmark_gen (void)
{
  if (!--benchmark_count)
    return 0;

  return brute_force_gen ();
}

static void
benchmark (void)
{
#ifdef HAVE_GETTIMEOFDAY
  int i;
  long j, k;
  struct timeval tv1, tv2;

  do
    {
      for (i = 0; i < HEADER_SIZE * 3; i++)
        files[i] = i ^ (i * 3);

      file_count = 3;
      strcpy (pw, "abcdefghij");
      parse_charset ("a");
      benchmark_count = BENCHMARK_LOOPS;

      verbosity = 0;

      printf ("%c%s: ",
              (crack_method - methods == default_method) ? '*' : ' ',
              crack_method->desc);

      if (strncmp ("zip", crack_method->desc, 3))
        printf ("(skipped)");
      else
        {
          fflush (stdout);

          crack_method->init_crack_pw ();
          gettimeofday (&tv1, 0);
          crack_method->crack_pw (benchmark_gen, false_callback);
          gettimeofday (&tv2, 0);
          tv2.tv_sec -= tv1.tv_sec;
          tv2.tv_usec -= tv1.tv_usec;

          j = tv2.tv_sec * 1000000 + tv2.tv_usec;
          k = BENCHMARK_LOOPS;

          printf ("cracks/s = ");

          for (i = 7; i--;)
            printf ("%ld", k / j), k = (k - k / j * j) * 10;
        }

      printf ("\n");
      crack_method++;
    }
  while (method_number < 0 && crack_method->desc);
#else
  fprintf (stderr, "This executable was compiled without support for benchmarking\n");
  exit (1);
#endif
}

static void
usage (int ec)
{
  printf ("\n"
          PACKAGE " version " VERSION ", a fast/free zip password cracker\n"
          "written by Marc Lehmann <pcg@goof.com> You can find more info on\n"
          "http://www.goof.com/pcg/marc/\n"
          "\n"
          "USAGE: fcrackzip\n"
          "          [-b|--brute-force]            use brute force algorithm\n"
          "          [-D|--dictionary]             use a dictionary\n"
          "          [-B|--benchmark]              execute a small benchmark\n"
          "          [-c|--charset characterset]   use characters from charset\n"
          "          [-h|--help]                   show this message\n"
          "          [--version]                   show the version of this program\n"
          "          [-V|--validate]               sanity-check the algortihm\n"
          "          [-v|--verbose]                be more verbose\n"
          "          [-p|--init-password string]   use string as initial password/file\n"
          "          [-l|--length min-max]         check password with length min to max\n"
          "          [-u|--use-unzip]              use unzip to weed out wrong passwords\n"
          "          [-m|--method num]             use method number \"num\" (see below)\n"
          "          [-2|--modulo r/m]             only calculcate 1/m of the password\n"
          "          file...                    the zipfiles to crack\n"
          "\n"
    );

  printf ("methods compiled in (* = default):\n\n");
  for (crack_method = methods; crack_method->desc; crack_method++)
    printf ("%c%d: %s\n",
            (crack_method - methods == default_method) ? '*' : ' ',
            crack_method - methods,
            crack_method->desc);

  printf ("\n");
  exit (ec);
}

static struct option options[] =
{
  {"version", no_argument, 0, 'R'},
  {"brute-force", no_argument, 0, 'b'},
  {"dictionary", no_argument, 0, 'D'},
  {"benchmark", no_argument, 0, 'B'},
  {"charset", required_argument, 0, 'c'},
  {"help", no_argument, 0, 'h'},
  {"validate", no_argument, 0, 'V'},
  {"verbose", no_argument, 0, 'v'},
  {"init-password", required_argument, 0, 'p'},
  {"length", required_argument, 0, 'l'},
  {"use-unzip", no_argument, 0, 'u'},
  {"method", required_argument, 0, 'm'},
  {"modulo", required_argument, 0, 2},
  {0, 0, 0, 0},
};

int
main (int argc, char *argv[])
{
  int c;
  int option_index = 0;
  char *charset = "aA1!";
  enum { m_benchmark, m_brute_force, m_dictionary } mode = m_brute_force;

  while ((c = getopt_long (argc, argv, "DbBc:hVvp:l:um:2:", options, &option_index)) != -1)
    switch (c)
      {
      case 'b':
        mode = m_brute_force;
        break;

      case 'D':
        mode = m_dictionary;
        break;

      case 'p':
        strcpy (pw, optarg);
        break;

      case 'l':
        pw[0] = 0;
        switch (sscanf (optarg, "%d-%d", &min_length, &max_length))
          {
          default:
            fprintf (stderr, "'%s' is an incorrect length specification\n", optarg);
            exit (1);
          case 1:
            max_length = min_length;
          case 2:
            ;
          }
        break;

      case 2:
        if (sscanf (optarg, "%d/%d", &residuent, &modul) != 2)
          fprintf (stderr, "malformed --modulo option, expected 'residuent/modul'\n"), exit (1);

        if (residuent < 0 || modul <= 0)
          fprintf (stderr, "residuent and modul must be positive\n"), exit (1);

        if (residuent >= modul)
          fprintf (stderr, "residuent must be less than modul\n"), exit (1);

        break;

      case 'B':
        mode = m_benchmark;
        benchmark ();
        exit (0);

      case 'v':
        verbosity++;
        break;

      case 'm':
        {
          for (method_number = 0; methods[method_number].desc; method_number++)
            if (!strncmp (methods[method_number].desc, optarg, strlen (optarg)))
              break;

          if (!methods[method_number].desc)
            method_number = atoi (optarg);

          crack_method = methods + method_number;
        }
        break;

      case 'V':
        validate ();
        exit (0);

      case 'c':
        charset = optarg;
        break;

      case 'u':
        use_unzip = 1;
        break;

      case 'h':
        usage (0);
      case 'R':
        printf (PACKAGE " version " VERSION "\n");
        exit (0);

      case ':':
        fprintf (stderr, "required argument missing\n");
        exit (1);

      case '?':
        fprintf (stderr, "unknown option\n");
        exit (1);

      default:
        usage (1);
      }

  if (method_number < 0)
    {
      method_number = default_method;
      crack_method = methods + default_method;
    }

  if (optind >= argc)
    {
      fprintf (stderr, "you have to specify one or more zip files (try --help)\n");
      exit (1);
    }

  for (; optind < argc; optind++)
    if (file_count < MAX_FILES)
      crack_method->load_file (argv[optind]);
    else if (verbosity)
      printf ("%d file maximum reached, ignoring '%s'\n", MAX_FILES, argv[optind]);

  if (file_count == 0)
    {
      fprintf (stderr, "no usable files found\n");
      exit (1);
    }

  crack_method->init_crack_pw ();

  switch (mode)
    {
    case m_brute_force:
      parse_charset (charset);

      if (!pw[0])
        {
          if (min_length < 0)
            {
              fprintf (stderr, "you have to specify either --init-password or --length with --brute-force\n");
              exit (1);
            }
          else
            {
              u8 *p = pw;
              while (p < pw + min_length)
                *p++ = bf_next[255];

              *p++ = 0;
            }
        }

      if (residuent)
        {
          int xmodul = modul;
          modul = residuent;
          pw_end = pw + strlen (pw);
          brute_force_gen ();
          printf ("%s\n", pw);
          modul = xmodul;
          printf ("WARNING: residuent mode NOT supported YET!\n");
        }

      crack_method->crack_pw (brute_force_gen, print_callback);
      break;

    case m_dictionary:
      if (!pw[0])
        {
          fprintf (stderr, "you have to specify a file to read passwords from using the -p switch\n");
          exit (1);
        }

      if (!(dict_file = fopen (pw, "r")))
        {
          perror (pw);
          exit (1);
        }
      else
        {
          *(pw_end = pw) = 0;
          dictionary_gen (); /* fetch first password */
          crack_method->crack_pw (dictionary_gen, print_callback);

          fclose (dict_file);
        }

      break;

    default:
      fprintf (stderr, "specified mode not supported in this version\n");
      exit (1);
    }

  return 0;
}
