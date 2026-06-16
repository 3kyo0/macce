#ifndef SCANNER_H
#define SCANNER_H

#include "memreader.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ST_I8 = 0, ST_I16, ST_I32, ST_I64,
    ST_U8, ST_U16, ST_U32, ST_U64,
    ST_F32, ST_F64,
    ST_BYTES,        /* variable-length byte pattern, with optional wildcard mask */
    ST__COUNT
} scan_type_t;

typedef enum {
    /* Available on first scan & rescan */
    SP_EQ = 0, SP_NE, SP_LT, SP_LE, SP_GT, SP_GE,
    SP_RANGE,             /* op1 <= v <= op2 */
    SP_UNKNOWN,           /* any value (first scan only) */
    /* Rescan-only (compare to previously stored value) */
    SP_CHANGED, SP_UNCHANGED, SP_INCREASED, SP_DECREASED,
    SP__COUNT
} scan_predicate_t;

typedef struct {
    union { int64_t i; uint64_t u; double f; } v1, v2;
    /* For ST_BYTES: pattern and optional wildcard mask. mask[i]=0xFF -> match,
       mask[i]=0x00 -> wildcard. mask==NULL means no mask (all bytes literal). */
    const uint8_t *bytes;
    const uint8_t *mask;
    size_t         bytes_len;
} scan_operand_t;

typedef struct {
    bool     include_rw_private; /* default ON  — heap, stack */
    bool     include_rw_shared;  /* default OFF — wineserver shared rings */
    bool     include_ro;         /* default OFF — read-only data */
    bool     include_rx;         /* default OFF — code segments */
    uint64_t addr_min;           /* 0 means no lower bound */
    uint64_t addr_max;           /* 0 means no upper bound */
    size_t   max_region_bytes;   /* 0 means unlimited */
    bool     aligned;            /* default ON: only check addresses where
                                    (addr % typesize) == 0. CE default. Set
                                    false for "unaligned" (1-byte stride). */
} scan_filter_t;

/* progress_cb: done_bytes/total_bytes. Return nonzero to cancel. */
typedef int (*scan_progress_cb)(uint64_t done, uint64_t total, void *ud);

typedef struct scan_session scan_session_t;

scan_session_t* scanner_new(mr_process_t *p);
void            scanner_free(scan_session_t *s);

void scanner_default_filter(scan_filter_t *out);

/* First scan: clears any previous matches, scans memory regions. */
int scanner_first_scan(scan_session_t *s,
                       scan_type_t type,
                       scan_predicate_t op,
                       const scan_operand_t *operand,
                       const scan_filter_t *filter,
                       scan_progress_cb cb, void *ud);

/* Rescan: walks existing match set, drops those that don't satisfy predicate. */
int scanner_next_scan(scan_session_t *s,
                      scan_predicate_t op,
                      const scan_operand_t *operand,
                      scan_progress_cb cb, void *ud);

void        scanner_clear(scan_session_t *s);
size_t      scanner_match_count(scan_session_t *s);
scan_type_t scanner_current_type(scan_session_t *s);
/* True when last first-scan was SP_UNKNOWN — match-set is unmaterialized,
   only the underlying byte snapshot is held. Doing any rescan transitions
   to normal match-set mode. */
bool        scanner_in_snapshot(scan_session_t *s);
uint64_t    scanner_snapshot_bytes(scan_session_t *s);  /* 0 if not in snap */

typedef struct {
    uint64_t addr;
    uint64_t old_value;     /* value at last scan, packed little-endian */
    uint64_t current_value; /* freshly read if refresh=true */
    bool     current_valid;
} scan_match_view_t;

size_t scanner_get_matches(scan_session_t *s, size_t offset, size_t cap,
                           scan_match_view_t *out, bool refresh_current);

/* Persist / restore match set + type + pid. Used by stateless CLI. */
int scanner_save(scan_session_t *s, const char *path, pid_t pid);
int scanner_load(scan_session_t *s, const char *path, pid_t *out_pid);

/* Helpers */
size_t      scanner_type_size(scan_type_t t);
const char* scanner_type_name(scan_type_t t);
const char* scanner_op_name(scan_predicate_t op);
int         scanner_parse_type(const char *s, scan_type_t *out);
int         scanner_parse_op(const char *s, scan_predicate_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SCANNER_H */
