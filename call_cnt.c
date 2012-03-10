#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <link.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "call_cnt.h"

#ifdef DEBUG
#define DLOG(fmt, args...) fprintf(stderr, "%s:%d "fmt,		\
				   __func__,__LINE__,args)	
#else
#define DLOG(fmt, args...)
#endif

struct walk_callback_data {
  char const *to_intercept;
  char *path;
};


int
walk_libraries_callback(struct dl_phdr_info *info,
                        size_t size, void *data) {

  DLOG("0x%lx: %s\n", info->dlpi_addr, info->dlpi_name);

  struct walk_callback_data *d = data;
  if(d->path != NULL) {
    return 0;
  } else {
    char *path = strdup(info->dlpi_name);
    char *bname = basename(path);
    if(0 == strcmp(bname, d->to_intercept)) {
      DLOG("Found intercept path: %s\n", info->dlpi_name);
      d->path = strdup(info->dlpi_name);
    }
    free(path);
  }
}

int
intercept(struct call_cnt ** desc, char const * lib_name) {
  struct walk_callback_data d;
  d.to_intercept = lib_name;
  d.path = NULL;
  
  dl_iterate_phdr(walk_libraries_callback, &d);
  
  if(d.path == NULL) {
    return -1;
  }

  int fd = open(d.path, O_RDONLY);
  if(-1 == fd) {
    return -1;
  }

  struct stat buf;
  if(-1 == fstat(fd, &buf)) {
    return -1;
  }
  unsigned char *mem = mmap(0, buf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) mem;
  ElfW(Phdr) *phdr = (ElfW(Phdr) *)(mem + ehdr->e_phoff);
  ElfW(Shdr) *shdr = (ElfW(Shdr) *)(mem + ehdr->e_shoff);
}


