#ifndef MEMREADER_H
#define MEMREADER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mr_process mr_process_t;

typedef struct {
    uint64_t base;
    uint64_t size;
    int      prot;       /* VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE */
    int      max_prot;
    int      shared;     /* 1 if shared, 0 if private */
    char     path[1024]; /* backing file, "" if anonymous */
} mr_region_t;

/* Attach to pid. Caller must hold task_for_pid privilege (sudo + signed). */
int  mr_open(pid_t pid, mr_process_t **out);
void mr_close(mr_process_t *p);

/* Read up to n bytes from addr into buf. Returns bytes read, -1 on error. */
ssize_t mr_read(mr_process_t *p, uint64_t addr, void *buf, size_t n);

/* Zero-copy view of a remote region. On success, .data points to a mapping
   of the target's pages in our address space (shared, read-only), .size is
   the number of valid bytes. Must be released with mr_view_close.

   If shared remap fails (some submaps reject it), falls back to malloc +
   mr_read; the data is still usable, just not zero-copy. is_mapped tells
   you which path was used (mostly for debug). */
typedef struct {
    void  *data;
    size_t size;
    bool   is_mapped;
} mr_view_t;

int  mr_view_open(mr_process_t *p, uint64_t base, size_t size, mr_view_t *out);
void mr_view_close(mr_view_t *v);

/* Write n bytes from buf to addr. Temporarily upgrades page protection if
   needed. Returns bytes written, -1 on error. */
ssize_t mr_write(mr_process_t *p, uint64_t addr, const void *buf, size_t n);

/* Enumerate regions. cb returns 0 to continue, nonzero to stop. */
typedef int (*mr_region_cb)(const mr_region_t *r, void *ud);
int mr_regions(mr_process_t *p, mr_region_cb cb, void *ud);

/* Find first pid whose proc name contains substr. 0 on success, -1 otherwise. */
int mr_find_pid(const char *substr, pid_t *out_pid);

/* Enumerate all processes on the system. cb gets (pid, executable name,
   executable path). Returns 0 to continue, nonzero to stop. */
typedef int (*mr_proc_cb)(pid_t pid, const char *name, const char *path, void *ud);
int mr_list_processes(mr_proc_cb cb, void *ud);

/* ----- Module map: resolve addr -> "<module name> + <offset>" ----- */
/* A "module" is a contiguous-or-fragmented set of regions sharing a backing
   file path. The module base is the lowest base across those regions.
   Useful for CE-style "static" address coloring. */
typedef struct mr_module_map mr_module_map_t;

mr_module_map_t* mr_module_map_build(mr_process_t *p);
void             mr_module_map_free(mr_module_map_t *m);

/* If addr is within a file-backed region, returns pointer to the module
   basename (owned by mm, lives until mr_module_map_free) and writes the
   offset from module base into *out_offset. Returns NULL otherwise. */
const char* mr_module_map_resolve(const mr_module_map_t *mm,
                                   uint64_t addr, uint64_t *out_offset);

/* Enumerate unique modules. Names are interned in mm and stable until
   mr_module_map_free. */
size_t      mr_module_map_count(const mr_module_map_t *mm);
const char* mr_module_map_name (const mr_module_map_t *mm, size_t idx);

/* Compute the [lo, hi) address span covered by a module across all of its
   file-backed regions. Returns 0 if found, -1 otherwise. */
int mr_module_map_range(const mr_module_map_t *mm, const char *name,
                        uint64_t *lo, uint64_t *hi);

#ifdef __cplusplus
}
#endif

#endif /* MEMREADER_H */
