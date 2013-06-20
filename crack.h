#ifndef CRACK_H
#define CRACK_H

#define MAX_PW		40	/* should be low, but conservative.  */
#define BENCHMARK_LOOPS 5000000

extern u8 pw[MAX_PW+1];
extern u8 *pw_end;

/* a gen_func must modify the global variables "pw" and "pw_end" to the next
 * password to be checked and return the number of characters that have
 * changed, counting from the end, or zero, to indicate end of cracking.
 */
typedef int (*gen_func)(void);

/* a callback_func can investigate the passed password. nonzero
 * return values stop cracking (and the return value will be handed
 * out to the caller.
 */
typedef int (*callback_func)(const char *, const char *);

/* brute force.  */
extern u8 bf_next[256];
extern u8 bf_last;

extern int verbosity;
extern int use_unzip;

#define FILE_SIZE	12
#define CRC_SIZE	2
#define HEADER_SIZE	(FILE_SIZE+CRC_SIZE)

#define MAX_FILES	8

extern u8 files[MAX_FILES*HEADER_SIZE];
extern const char *file_path[MAX_FILES];
extern int file_count;

typedef struct {
  char *desc;
  void (*init_crack_pw)(void);
  int (*crack_pw)(gen_func, callback_func);
  void (*load_file)(const char *);
} method;

extern method methods[];
extern int default_method;

#endif
