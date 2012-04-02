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

  bool *is_internal;
  
  int plt_count;
};

#ifdef __x86_64__

#define FMT "%lx"

// XXX HACK
#define REL_TYPE ElfW(Rela) 

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

#else

#define FMT "%x"


// XXX HACK
#define REL_TYPE ElfW(Rel) 


/* 0:   50                      push   %eax */
/* 1:   b8 78 56 34 12          mov    $0x12345678,%eax */
/* 6:   f0 ff 00                lock incl (%eax) */
/* 9:   b8 44 33 22 11          mov    $0x11223344,%eax */
/* e:   87 04 24                xchg   %eax,(%esp) */
/* 11:  c3                      ret     */

static const unsigned char header[] = {
  '\x50', // push %eax
  '\xb8', // mov ..., %eax
};

static const unsigned char inc[] = {
  '\xf0', '\xff', '\x00', // lock incl (%eax)
  '\xb8', // mov ..., %eax,
};

static const unsigned char jump[] = {
  '\x87', '\x04', '\x24', // xchg %eax, (%esp)
  '\xc3' // ret
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

  bool *is_internal;
  
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

  DLOG("0x"FMT": %s\n", info->dlpi_addr, info->dlpi_name);

  struct walk_callback_data *d = data;
  char *path = strdup(info->dlpi_name);
  if(path == NULL) {
    return -1;
  }
  char *bname = basename(path);
  if(0 == strcmp(bname, d->to_intercept)) {
    DLOG("Found intercept path: %s\n", info->dlpi_name);
    free(path);
    int *pt_loads = malloc(info->dlpi_phnum * sizeof(int));
    if(pt_loads == NULL) {
      return -1;
    }
    int pt_loads_count = 0;
    for(int i = 0; i < info->dlpi_phnum; i++) {
      if(info->dlpi_phdr[i].p_type == PT_LOAD) {
        DLOG("found PT_LOAD: %d\n", i);
        pt_loads[pt_loads_count] = i;
        pt_loads_count++;
      } else if(info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
        ElfW(Dyn) *dyn = (void*) info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;

        int pltrel_count = -1;
        REL_TYPE *jmprel;

        while(dyn->d_tag != DT_NULL) {
          switch(dyn->d_tag) {

          case DT_PLTRELSZ:
            pltrel_count = dyn->d_un.d_val / sizeof(REL_TYPE); 
            DLOG("pltrel_count: %d\n", pltrel_count);
            break;

          case DT_JMPREL:
            DLOG("mamy DT_JMPREL, ptr: 0x"FMT"\n", dyn->d_un.d_ptr);
            jmprel = (void*) dyn->d_un.d_ptr;
            break;
          }

          dyn++;
        }

        if(pltrel_count < 0) {
          free(pt_loads);
          return -1;
        }
        d->plt_count = pltrel_count;
        d->plt_entries = malloc(pltrel_count * sizeof(ElfW(Addr)*));
        if(d->plt_entries == NULL) {
          free(pt_loads);
          return -1;
        }
        d->is_internal = calloc(pltrel_count, sizeof(bool));
        if(d->is_internal == NULL) {
          free(d->plt_entries);
          free(pt_loads);
          return -1;
        }
        
        for(int j = 0; j < pltrel_count; j++) {
          ElfW(Addr) *addr = (ElfW(Addr)*) (info->dlpi_addr + jmprel[j].r_offset);
          ElfW(Addr) fun_addr = *((ElfW(Addr)*) addr);
          DLOG("pltentry: 0x"FMT"\n", fun_addr);
          d->plt_entries[j] = addr;
          for(int k = 0; k < pt_loads_count; k++) {
            ElfW(Phdr) phdr = info->dlpi_phdr[k];
            ElfW(Addr) load_addr = info->dlpi_addr + info->dlpi_phdr[k].p_vaddr;
            if(load_addr <= fun_addr && fun_addr <= load_addr + phdr.p_memsz) {
              d->is_internal[j] = true;
            }
          }
        }
      }
    }
    free(pt_loads);
  } else {
    free(path);
  }
  return 0;
}

int
intercept(struct call_cnt **desc, char const *lib_name) {
  struct walk_callback_data d;
  d.to_intercept = lib_name;
  d.plt_entries = NULL;
  d.is_internal = NULL;
  dl_iterate_phdr(walk_libraries_callback, &d);
  
  if(d.plt_entries == NULL) {
    return -1;
  }
  int n = d.plt_count;
  struct call_cnt *cnt;
  
  cnt = malloc(sizeof(struct call_cnt));
  if(cnt == NULL) goto cnt_fail;
  cnt->saved_entries = malloc(n*sizeof(ElfW(Addr)));
  if(cnt->saved_entries == NULL) goto saved_entries_fail;
  cnt->plt_count = n;
  cnt->plt_entries = d.plt_entries;
  cnt->is_internal = d.is_internal;
  cnt->call_count = calloc(n, sizeof(int));
  if(cnt->call_count == NULL) goto call_count_fail;

  cnt->code = memalign(sysconf(_SC_PAGE_SIZE),  n*sizeof(counter_code_t));
  if(cnt->code == NULL) goto code_fail;

  if(-1 == mprotect(cnt->code,
                    n*sizeof(counter_code_t),
                    PROT_READ | PROT_WRITE | PROT_EXEC))
    goto mprotect_fail;
  
  for(int i = 0; i < n; i++) {
    cnt->saved_entries[i] = *(cnt->plt_entries[i]);
    make_inc_counter_code(&(cnt->code[i]),
                          &(cnt->call_count[i]),
                          cnt->saved_entries[i]);
    *(cnt->plt_entries[i]) = (ElfW(Addr)) &(cnt->code[i]);

  }
  *desc = cnt;
  return 0;
  
 mprotect_fail:
  free(cnt->code);
 code_fail:
  free(cnt->call_count);
 call_count_fail:
  free(cnt->saved_entries);
 saved_entries_fail:
  free(cnt);
 cnt_fail:
  free(d.plt_entries);
  free(d.is_internal);
  return -1;
}

int
stop_intercepting(struct call_cnt *desc) {
  int n = desc->plt_count;
  for(int i = 0; i < n; i++) {
    *(desc->plt_entries[i]) = desc->saved_entries[i];
  }
  return 0;
}

int
print_stats_to_stream(FILE *stream, struct call_cnt *desc) {
  int n = desc->plt_count;
  Dl_info info;
  for(int i = 0; i < n; i++) {
    if(0 != dladdr((void*) desc->saved_entries[i], &info)) {
      if(info.dli_sname != NULL) {
        fprintf(stream, "%s: %d\n", info.dli_sname, desc->call_count[i]);
      } else {
        fprintf(stream, "0x"FMT": %d\n", desc->saved_entries[i], desc->call_count[i]);
      }
    } else {
        fprintf(stream, "0x"FMT": %d\n", desc->saved_entries[i], desc->call_count[i]);
    }
    
  }
  return 0;
  
}

ssize_t
get_num_intern_calls(struct call_cnt * desc) {
  ssize_t count = 0;
  int n = desc->plt_count;
  for(int i = 0; i < n; i++) {
    if(desc->is_internal[i]) {
      count += desc->call_count[i];
    }
  }
  return count;
}

ssize_t get_num_extern_calls(struct call_cnt * desc) {
  ssize_t count = 0;
  int n = desc->plt_count;
  for(int i = 0; i < n; i++) {
    if(!desc->is_internal[i]) {
      count += desc->call_count[i];
    }
  }
  return count;
}



int
release_stats(struct call_cnt *desc) {
  free(desc->plt_entries);
  free(desc->is_internal);
  free(desc->call_count);
  free(desc->saved_entries);
  free(desc->code);
  free(desc);
  return 0;
}
