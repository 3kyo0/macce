#include "memreader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <mach/vm_map.h>
#include <mach/mach_error.h>

#include <libproc.h>

struct mr_process {
    pid_t        pid;
    mach_port_t  task;
};

int mr_open(pid_t pid, mr_process_t **out) {
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr,
                "task_for_pid(%d) failed: %s (kr=%d)\n"
                "  -> 需要 sudo 运行，且二进制经过 ad-hoc 签名 + debugger entitlement。\n"
                "  -> 若仍失败，可能目标进程是 hardened-runtime 签名，需关闭 SIP。\n",
                pid, mach_error_string(kr), kr);
        return -1;
    }
    mr_process_t *p = (mr_process_t *)calloc(1, sizeof(*p));
    if (!p) {
        mach_port_deallocate(mach_task_self(), task);
        return -1;
    }
    p->pid  = pid;
    p->task = task;
    *out = p;
    return 0;
}

void mr_close(mr_process_t *p) {
    if (!p) return;
    if (p->task != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), p->task);
    free(p);
}

ssize_t mr_write(mr_process_t *p, uint64_t addr, const void *buf, size_t n) {
    if (!p || !buf || n == 0) { errno = EINVAL; return -1; }

    mach_vm_address_t qa = (mach_vm_address_t)addr;
    mach_vm_size_t    qs = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t info_cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr = mach_vm_region_recurse(
        p->task, &qa, &qs, &depth,
        (vm_region_recurse_info_t)&info, &info_cnt);
    if (kr != KERN_SUCCESS) { errno = EFAULT; return -1; }

    int orig_prot = info.protection;
    bool changed = false;
    if (!(orig_prot & VM_PROT_WRITE)) {
        kr = mach_vm_protect(p->task, (mach_vm_address_t)addr, (mach_vm_size_t)n,
                             FALSE, orig_prot | VM_PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS) { errno = EACCES; return -1; }
        changed = true;
    }

    kr = mach_vm_write(p->task, (mach_vm_address_t)addr,
                       (vm_offset_t)buf, (mach_msg_type_number_t)n);

    if (changed) {
        mach_vm_protect(p->task, (mach_vm_address_t)addr, (mach_vm_size_t)n,
                        FALSE, orig_prot);
    }

    if (kr != KERN_SUCCESS) { errno = EFAULT; return -1; }
    return (ssize_t)n;
}

int mr_view_open(mr_process_t *p, uint64_t base, size_t size, mr_view_t *out) {
    if (!p || !out || size == 0) return -1;
    mach_vm_address_t target = 0;
    vm_prot_t cur = VM_PROT_NONE, max = VM_PROT_NONE;
    kern_return_t kr = mach_vm_remap(
        mach_task_self(),
        &target,
        (mach_vm_size_t)size,
        0,
        VM_FLAGS_ANYWHERE,
        p->task,
        (mach_vm_address_t)base,
        TRUE,                 /* copy=TRUE => lazy COW snapshot of target's
                                 current view. With copy=FALSE we'd share the
                                 underlying VM object and miss any rw-private
                                 page the target has COW-modified, which is
                                 exactly where game state lives. */
        &cur, &max,
        VM_INHERIT_NONE);
    if (kr == KERN_SUCCESS) {
        out->data = (void *)(uintptr_t)target;
        out->size = size;
        out->is_mapped = true;
        return 0;
    }
    /* Fallback: allocate and read. */
    void *buf = malloc(size);
    if (!buf) return -1;
    mach_vm_size_t got = 0;
    kr = mach_vm_read_overwrite(p->task,
                                (mach_vm_address_t)base,
                                (mach_vm_size_t)size,
                                (mach_vm_address_t)buf,
                                &got);
    if (kr != KERN_SUCCESS || got == 0) { free(buf); return -1; }
    out->data = buf;
    out->size = (size_t)got;
    out->is_mapped = false;
    return 0;
}

void mr_view_close(mr_view_t *v) {
    if (!v || !v->data) return;
    if (v->is_mapped) {
        mach_vm_deallocate(mach_task_self(),
                           (mach_vm_address_t)(uintptr_t)v->data,
                           (mach_vm_size_t)v->size);
    } else {
        free(v->data);
    }
    v->data = NULL;
    v->size = 0;
}

ssize_t mr_read(mr_process_t *p, uint64_t addr, void *buf, size_t n) {
    if (!p || !buf || n == 0) { errno = EINVAL; return -1; }
    mach_vm_size_t out_size = 0;
    kern_return_t kr = mach_vm_read_overwrite(
        p->task,
        (mach_vm_address_t)addr,
        (mach_vm_size_t)n,
        (mach_vm_address_t)buf,
        &out_size);
    if (kr != KERN_SUCCESS) {
        errno = EFAULT;
        return -1;
    }
    return (ssize_t)out_size;
}

int mr_regions(mr_process_t *p, mr_region_cb cb, void *ud) {
    if (!p || !cb) return -1;

    mach_vm_address_t addr = 0;
    mach_vm_size_t    size = 0;
    /* Userspace cap on x86_64 macOS — avoid wandering into kernel-mapped
       regions where recurse can stall. */
    const mach_vm_address_t USER_END = 0x00007fffffffffffULL;

    for (;;) {
        natural_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

        if (addr > USER_END) break;

        kern_return_t kr = mach_vm_region_recurse(
            p->task, &addr, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;

        if (info.is_submap) {
            /* Skip past the submap — we don't descend. Memory scanning
               targets leaf rw- private mappings; submaps (dyld_shared_cache
               etc.) are read-only and noisy. */
            if (size == 0) break;
            addr += size;
            continue;
        }

        mr_region_t r;
        memset(&r, 0, sizeof(r));
        r.base     = (uint64_t)addr;
        r.size     = (uint64_t)size;
        r.prot     = info.protection;
        r.max_prot = info.max_protection;
        r.shared   = (info.share_mode != SM_PRIVATE) ? 1 : 0;

        char path[PROC_PIDPATHINFO_MAXSIZE];
        path[0] = 0;
        if (proc_regionfilename(p->pid, addr, path, sizeof(path)) > 0) {
            strncpy(r.path, path, sizeof(r.path) - 1);
        }

        if (cb(&r, ud) != 0) return 0;

        /* Guard against pathological 0-size returns. */
        if (size == 0) break;
        addr += size;
    }
    return 0;
}

int mr_find_pid(const char *substr, pid_t *out_pid) {
    if (!substr || !out_pid) return -1;

    /* Query required buffer size in bytes. */
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (bytes <= 0) return -1;
    /* Pad in case of races with new processes appearing. */
    bytes *= 2;

    pid_t *pids = (pid_t *)calloc(1, (size_t)bytes);
    if (!pids) return -1;

    int got = proc_listpids(PROC_ALL_PIDS, 0, pids, bytes);
    if (got <= 0) { free(pids); return -1; }
    int n = got / (int)sizeof(pid_t);

    int rc = -1;
    for (int i = 0; i < n; i++) {
        if (pids[i] <= 0) continue;
        char name[2 * MAXCOMLEN + 1];
        name[0] = 0;
        if (proc_name(pids[i], name, sizeof(name)) <= 0) continue;
        if (strstr(name, substr)) {
            *out_pid = pids[i];
            rc = 0;
            break;
        }
    }
    free(pids);
    return rc;
}

/* ---------- module map ---------- */

typedef struct {
    uint64_t base;
    uint64_t size;
    const char *name;   /* points into mm->name_pool */
    uint64_t module_base;
} mod_ent_t;

struct mr_module_map {
    mod_ent_t *ents;
    size_t     count;
    /* Pool of unique basenames so name pointers stay stable. */
    char     **name_pool;
    size_t     names;
    size_t     names_cap;
};

static const char* mm_intern(mr_module_map_t *mm, const char *s) {
    for (size_t i = 0; i < mm->names; i++)
        if (strcmp(mm->name_pool[i], s) == 0) return mm->name_pool[i];
    if (mm->names == mm->names_cap) {
        mm->names_cap = mm->names_cap ? mm->names_cap * 2 : 32;
        mm->name_pool = (char **)realloc(mm->name_pool, mm->names_cap * sizeof(char*));
    }
    mm->name_pool[mm->names++] = strdup(s);
    return mm->name_pool[mm->names - 1];
}

typedef struct {
    mr_module_map_t *mm;
    size_t cap;
} mm_build_ctx;

static int mm_collect_cb(const mr_region_t *r, void *ud) {
    mm_build_ctx *ctx = (mm_build_ctx *)ud;
    mr_module_map_t *mm = ctx->mm;
    if (r->path[0] == 0) return 0;

    /* derive basename */
    const char *base = r->path;
    const char *slash = strrchr(r->path, '/');
    if (slash) base = slash + 1;
    const char *name = mm_intern(mm, base);

    if (mm->count == ctx->cap) {
        ctx->cap = ctx->cap ? ctx->cap * 2 : 64;
        mm->ents = (mod_ent_t *)realloc(mm->ents, ctx->cap * sizeof(mod_ent_t));
    }
    mod_ent_t *e = &mm->ents[mm->count++];
    e->base = r->base;
    e->size = r->size;
    e->name = name;
    e->module_base = r->base; /* fixed up below */
    return 0;
}

mr_module_map_t* mr_module_map_build(mr_process_t *p) {
    if (!p) return NULL;
    mr_module_map_t *mm = (mr_module_map_t *)calloc(1, sizeof(*mm));
    mm_build_ctx ctx = { .mm = mm, .cap = 0 };
    mr_regions(p, mm_collect_cb, &ctx);

    /* Compute module_base = min over entries with same name pointer. */
    for (size_t i = 0; i < mm->count; i++) {
        uint64_t min_b = mm->ents[i].base;
        for (size_t j = 0; j < mm->count; j++) {
            if (mm->ents[j].name == mm->ents[i].name
                && mm->ents[j].base < min_b)
                min_b = mm->ents[j].base;
        }
        mm->ents[i].module_base = min_b;
    }
    return mm;
}

void mr_module_map_free(mr_module_map_t *mm) {
    if (!mm) return;
    for (size_t i = 0; i < mm->names; i++) free(mm->name_pool[i]);
    free(mm->name_pool);
    free(mm->ents);
    free(mm);
}

const char* mr_module_map_resolve(const mr_module_map_t *mm,
                                   uint64_t addr, uint64_t *out_offset) {
    if (!mm) return NULL;
    for (size_t i = 0; i < mm->count; i++) {
        const mod_ent_t *e = &mm->ents[i];
        if (addr >= e->base && addr < e->base + e->size) {
            if (out_offset) *out_offset = addr - e->module_base;
            return e->name;
        }
    }
    return NULL;
}

size_t mr_module_map_count(const mr_module_map_t *mm) {
    return mm ? mm->names : 0;
}

const char* mr_module_map_name(const mr_module_map_t *mm, size_t idx) {
    if (!mm || idx >= mm->names) return NULL;
    return mm->name_pool[idx];
}

int mr_module_map_range(const mr_module_map_t *mm, const char *name,
                        uint64_t *lo, uint64_t *hi) {
    if (!mm || !name) return -1;
    uint64_t a = UINT64_MAX, b = 0;
    bool found = false;
    for (size_t i = 0; i < mm->count; i++) {
        const mod_ent_t *e = &mm->ents[i];
        if (strcmp(e->name, name) != 0) continue;
        found = true;
        if (e->base < a) a = e->base;
        if (e->base + e->size > b) b = e->base + e->size;
    }
    if (!found) return -1;
    if (lo) *lo = a;
    if (hi) *hi = b;
    return 0;
}

int mr_list_processes(mr_proc_cb cb, void *ud) {
    if (!cb) return -1;
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (bytes <= 0) return -1;
    bytes *= 2;

    pid_t *pids = (pid_t *)calloc(1, (size_t)bytes);
    if (!pids) return -1;

    int got = proc_listpids(PROC_ALL_PIDS, 0, pids, bytes);
    if (got <= 0) { free(pids); return -1; }
    int n = got / (int)sizeof(pid_t);

    for (int i = 0; i < n; i++) {
        if (pids[i] <= 0) continue;
        char name[2 * MAXCOMLEN + 1];
        char path[PROC_PIDPATHINFO_MAXSIZE];
        name[0] = 0; path[0] = 0;
        if (proc_name(pids[i], name, sizeof(name)) <= 0) continue;
        proc_pidpath(pids[i], path, sizeof(path));
        if (cb(pids[i], name, path, ud) != 0) break;
    }
    free(pids);
    return 0;
}
