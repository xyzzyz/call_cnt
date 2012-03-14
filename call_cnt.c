#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include <unistd.h>
#include <elf.h>
#include <link.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdbool.h>

#include "call_cnt.h"

#ifdef DEBUG
#define DLOG(fmt, args...) fprintf(stderr, "%s:%d "fmt,		\
				   __func__,__LINE__,args)	
#else
#define DLOG(fmt, args...)
#endif

struct walk_callback_data {
  char const *to_intercept;
  ElfW(Addr) **plt_entries;
  int plt_count;
};

#ifdef __x86_64__

static const unsigned char header[] = {
  '\x50',         // push %rax
  '\x48', '\xb8', // movabs, ..., %rax
};

static const unsigned char inc[] = {
  '\xf0', '\xff', '\x00', // lock incl (%rax)
  '\x48', '\xb8',         // movabs ..., %rax
};

static const unsigned char jump[] = {
  '\x48', '\x87', '\x04', '\x24', // xchg %rax, (%rsp)
  '\xc3',                         // retq
};

typedef unsigned char counter_code_t[sizeof(header) +
                                     sizeof(int*) +
                                     sizeof(inc) +
                                     sizeof(ElfW(Addr))+
                                     sizeof(jump)];
#endif

struct call_cnt {
  int plt_count;

  ElfW(Addr) **plt_entries;
  ElfW(Addr) *saved_entries;

  int *call_count;

  counter_code_t *code;
};



void
make_inc_counter_code(counter_code_t *code,
                      int* counter_addr,
                      ElfW(Addr) fun_addr) {
  unsigned char *pos = (unsigned char*) code;
  
  memcpy(pos, header, sizeof(header));
  pos += sizeof(header);

  memcpy(pos, &counter_addr, sizeof(counter_addr));
  pos += sizeof(counter_addr);

  memcpy(pos, inc, sizeof(inc));
  pos += sizeof(inc);

  memcpy(pos, &fun_addr, sizeof(fun_addr));
  pos += sizeof(fun_addr);

  memcpy(pos, jump, sizeof(jump));
}


                    
int
walk_libraries_callback(struct dl_phdr_info *info,
                        size_t __attribute__((unused)) size,
                        void *data) {

  DLOG("0x%lx: %s\n", info->dlpi_addr, info->dlpi_name);

  struct walk_callback_data *d = data;
  char *path = strdup(info->dlpi_name);
  char *bname = basename(path);
  if(0 == strcmp(bname, d->to_intercept)) {
    DLOG("Found intercept path: %s\n", info->dlpi_name);
    for(int i = 0; i < info->dlpi_phnum; i++) {
      if(info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
        ElfW(Dyn) *dyn = (void*) info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;

        int pltrel_count = 0;
        ElfW(Rela) *jmprel;

        while(dyn->d_tag != DT_NULL) {
          switch(dyn->d_tag) {

          case DT_PLTRELSZ:
            pltrel_count = dyn->d_un.d_val / sizeof(ElfW(Rela)); 
            DLOG("pltrel_count: %d\n", pltrel_count);
            break;

          case DT_JMPREL:
            DLOG("mamy DT_JMPREL, ptr: 0x%lx\n", dyn->d_un.d_ptr);
            jmprel = (void*) dyn->d_un.d_ptr;
            break;
          }

          dyn++;
        }

        if(pltrel_count <= 0) {
          return -1;
        }
        d->plt_count = pltrel_count;
        d->plt_entries = malloc(pltrel_count * sizeof(ElfW(Addr)*));
                  
        for(int j = 0; j < pltrel_count; j++) {
          ElfW(Addr) *addr = (ElfW(Addr)*) (info->dlpi_addr + jmprel[j].r_offset);
          DLOG("pltentry: 0x%lx\n", *((ElfW(Addr)*) addr));
          d->plt_entries[j] = addr;
        }
        
      }
    }
  }
  free(path);
  return 0;
}

int
intercept(struct call_cnt **desc, char const *lib_name) {
  struct walk_callback_data d;
  d.to_intercept = lib_name;
  d.plt_entries = NULL;
  dl_iterate_phdr(walk_libraries_callback, &d);
  
  if(d.plt_entries == NULL) {
    return -1;
  }
  int n = d.plt_count;
  struct call_cnt *cnt = *desc;
  
  cnt = malloc(sizeof(struct call_cnt));
  cnt->saved_entries = malloc(n*sizeof(ElfW(Addr)));
  cnt->plt_count = n;
  cnt->plt_entries = d.plt_entries;
  cnt->call_count = calloc(n, sizeof(int));
  cnt->code = memalign(sysconf(_SC_PAGE_SIZE),  n*sizeof(counter_code_t));
  mprotect(cnt->code, n*sizeof(counter_code_t), PROT_READ | PROT_WRITE | PROT_EXEC);
  for(int i = 0; i < n; i++) {
    cnt->saved_entries[i] = *(cnt->plt_entries[i]);
    make_inc_counter_code(&(cnt->code[i]),
                          &(cnt->call_count[i]),
                          cnt->saved_entries[i]);
    *(cnt->plt_entries[i]) = (ElfW(Addr)) &(cnt->code[i]);

  }
  return 0;
}

int
stop_intercepting(struct call_cnt __attribute__((unused)) *desc) {
  return 0;
}

int
release_stats(struct call_cnt *desc) {
  free(desc->plt_entries);
  free(desc->call_count);
  return 0;
}
