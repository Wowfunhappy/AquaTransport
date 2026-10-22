// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name Facebook nor the names of its contributors may be used to
//     endorse or promote products derived from this software without specific
//     prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "fishhook.h"

#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif

struct rebindings_entry {
  struct rebinding *rebindings;
  size_t rebindings_nel;
  struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

static int prepend_rebindings(struct rebindings_entry **rebindings_head,
                              struct rebinding rebindings[],
                              size_t nel) {
  if (!rebindings || !nel) return -1;
  for (size_t i = 0; i < nel; i++) {
    if (!rebindings[i].name || !rebindings[i].name[0] || !rebindings[i].replacement ||
        !rebindings[i].providers || !rebindings[i].providers[0]) return -1;
    for (const char *const *p = rebindings[i].providers; *p; p++)
      if (!**p) return -1;
  }
  struct rebindings_entry *new_entry = (struct rebindings_entry *) malloc(sizeof(struct rebindings_entry));
  if (!new_entry) {
    return -1;
  }
  new_entry->rebindings = (struct rebinding *) malloc(sizeof(struct rebinding) * nel);
  if (!new_entry->rebindings) {
    free(new_entry);
    return -1;
  }
  memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
  new_entry->rebindings_nel = nel;
  new_entry->next = *rebindings_head;
  *rebindings_head = new_entry;
  return 0;
}

#if 0
static int get_protection(void *addr, vm_prot_t *prot, vm_prot_t *max_prot) {
  mach_port_t task = mach_task_self();
  vm_size_t size = 0;
  vm_address_t address = (vm_address_t)addr;
  memory_object_name_t object;
#ifdef __LP64__
  mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
  vm_region_basic_info_data_64_t info;
  kern_return_t info_ret = vm_region_64(
      task, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_64_t)&info, &count, &object);
#else
  mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT;
  vm_region_basic_info_data_t info;
  kern_return_t info_ret = vm_region(task, &address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &count, &object);
#endif
  if (info_ret == KERN_SUCCESS) {
    if (prot != NULL)
      *prot = info.protection;

    if (max_prot != NULL)
      *max_prot = info.max_protection;

    return 0;
  }

  return -1;
}
#endif

static bool provider_matches(const char *provider, const char *const expected[]) {
  if (!provider) return false;
  for (size_t i = 0; expected[i]; i++)
    if (strcmp(provider, expected[i]) == 0) return true;
  return false;
}

static void perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                           section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab,
                                           const char *const providers[],
                                           uint32_t nsyms, uint32_t strsize,
                                           uint32_t nindirectsyms) {
  size_t count = section->size / sizeof(void *);
  if (section->reserved1 > nindirectsyms ||
      count > nindirectsyms - section->reserved1) return;
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);

  for (size_t i = 0; i < count; i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS)) {
      continue;
    }
    if (symtab_index >= nsyms) continue;
    nlist_t *symbol = &symtab[symtab_index];
    unsigned type = symbol->n_type & N_TYPE;
    if ((symbol->n_type & N_STAB) || (type != N_UNDF && type != N_PBUD) ||
        (symbol->n_desc & N_REF_TO_WEAK)) continue;
    unsigned ordinal = GET_LIBRARY_ORDINAL(symbol->n_desc);
    if (ordinal == SELF_LIBRARY_ORDINAL || ordinal > MAX_LIBRARY_ORDINAL ||
        !providers[ordinal]) continue;
    // A missing weak import must remain missing.
    if ((symbol->n_desc & N_WEAK_REF) && !indirect_symbol_bindings[i]) continue;
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    if (strtab_offset >= strsize ||
        !memchr(strtab + strtab_offset, '\0', strsize - strtab_offset)) continue;
    char *symbol_name = strtab + strtab_offset;
    bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
    struct rebindings_entry *cur = rebindings;
    while (cur) {
      for (uint j = 0; j < cur->rebindings_nel; j++) {
        if (symbol_name_longer_than_1 && strcmp(&symbol_name[1], cur->rebindings[j].name) == 0 &&
            provider_matches(providers[ordinal], cur->rebindings[j].providers)) {
          kern_return_t err;

          if (cur->rebindings[j].replaced != NULL && indirect_symbol_bindings[i] != cur->rebindings[j].replacement)
            *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];

          /**
           * 1. Moved the vm protection modifying codes to here to reduce the
           *    changing scope.
           * 2. Adding VM_PROT_WRITE mode unconditionally because vm_region
           *    API on some iOS/Mac reports mismatch vm protection attributes.
           * -- Lianfu Hao Jun 16th, 2021
           **/
          err = vm_protect (mach_task_self (), (uintptr_t)indirect_symbol_bindings, section->size, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
          if (err == KERN_SUCCESS) {
            /**
             * Once we failed to change the vm protection, we
             * MUST NOT continue the following write actions!
             * iOS 15 has corrected the const segments prot.
             * -- Lionfore Hao Jun 11th, 2021
             **/
            indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
          }
          goto symbol_loop;
        }
      }
      cur = cur->next;
    }
  symbol_loop:;
  }
}

static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
  // The ordinal is authoritative only under two-level lookup. Forced-flat
  // processes and coalesced/lookup-special symbols cannot establish a provider.
  const struct mach_header *main_header = _dyld_get_image_header(0);
  if (!header || !(header->flags & MH_TWOLEVEL) ||
      (header->flags & MH_FORCE_FLAT) ||
      (main_header && (main_header->flags & MH_FORCE_FLAT)) ||
      getenv("DYLD_FORCE_FLAT_NAMESPACE")) return;
  Dl_info info;
  if (dladdr(header, &info) == 0) {
    return;
  }

  segment_command_t *cur_seg_cmd;
  segment_command_t *linkedit_segment = NULL;
  struct symtab_command* symtab_cmd = NULL;
  struct dysymtab_command* dysymtab_cmd = NULL;
  const char *providers[MAX_LIBRARY_ORDINAL + 1] = {0};
  unsigned ordinal = 0;

  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  uintptr_t end = cur + header->sizeofcmds;
  if (end < cur) return;
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    if (cur > end || end - cur < sizeof(struct load_command)) return;
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmdsize < sizeof(struct load_command) ||
        cur_seg_cmd->cmdsize > end - cur) return;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (cur_seg_cmd->cmdsize < sizeof(segment_command_t) ||
          cur_seg_cmd->nsects > (cur_seg_cmd->cmdsize - sizeof(segment_command_t)) / sizeof(section_t)) return;
      if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
        linkedit_segment = cur_seg_cmd;
      }
    } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
      if (cur_seg_cmd->cmdsize < sizeof(struct symtab_command)) return;
      symtab_cmd = (struct symtab_command*)cur_seg_cmd;
    } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
      if (cur_seg_cmd->cmdsize < sizeof(struct dysymtab_command)) return;
      dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
    } else if (cur_seg_cmd->cmd == LC_LOAD_DYLIB ||
               cur_seg_cmd->cmd == LC_LOAD_WEAK_DYLIB ||
               cur_seg_cmd->cmd == LC_REEXPORT_DYLIB ||
               cur_seg_cmd->cmd == LC_LOAD_UPWARD_DYLIB ||
               cur_seg_cmd->cmd == LC_LAZY_LOAD_DYLIB) {
      // LC_ID_DYLIB is deliberately excluded: dependency ordinals start at 1.
      const struct dylib_command *dylib = (const struct dylib_command *)cur;
      if (dylib->cmdsize < sizeof(*dylib) || dylib->dylib.name.offset < sizeof(*dylib) ||
          dylib->dylib.name.offset >= dylib->cmdsize) return;
      const char *name = (const char *)cur + dylib->dylib.name.offset;
      if (!memchr(name, '\0', dylib->cmdsize - dylib->dylib.name.offset)) return;
      if (++ordinal <= MAX_LIBRARY_ORDINAL) providers[ordinal] = name;
    }
  }

  if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment ||
      !dysymtab_cmd->nindirectsyms) {
    return;
  }

  // Find base symbol/string table addresses
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);

  // Get indirect symbol table (array of uint32_t indices into symbol table)
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

  cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
          strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) {
        continue;
      }
      for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
        section_t *sect =
          (section_t *)(cur + sizeof(segment_command_t)) + j;
        if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab,
                                         providers, symtab_cmd->nsyms, symtab_cmd->strsize, dysymtab_cmd->nindirectsyms);
        }
        if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab,
                                         providers, symtab_cmd->nsyms, symtab_cmd->strsize, dysymtab_cmd->nindirectsyms);
        }
      }
    }
  }
}

static void _rebind_symbols_for_image(const struct mach_header *header,
                                      intptr_t slide) {
    rebind_symbols_for_image(_rebindings_head, header, slide);
}

int rebind_symbols_image(void *header,
                         intptr_t slide,
                         struct rebinding rebindings[],
                         size_t rebindings_nel) {
    struct rebindings_entry *rebindings_head = NULL;
    int retval = prepend_rebindings(&rebindings_head, rebindings, rebindings_nel);
    if (retval < 0) return retval;
    rebind_symbols_for_image(rebindings_head, (const struct mach_header *) header, slide);
    if (rebindings_head) {
      free(rebindings_head->rebindings);
    }
    free(rebindings_head);
    return retval;
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
  int retval = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
  if (retval < 0) {
    return retval;
  }
  // If this was the first call, register callback for image additions (which is also invoked for
  // existing images, otherwise, just run on existing images
  if (!_rebindings_head->next) {
    _dyld_register_func_for_add_image(_rebind_symbols_for_image);
  } else {
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
      _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
  }
  return retval;
}

void *fishhook_resolve(const char *const providers[], const char *name) {
  if (!providers || !name) return NULL;
  for (size_t i = 0; providers[i]; i++) {
    void *handle = dlopen(providers[i], RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD | RTLD_FIRST);
    if (!handle) continue;
    void *symbol = dlsym(handle, name);
    dlclose(handle);
    if (symbol) return symbol;
  }
  return NULL;
}
