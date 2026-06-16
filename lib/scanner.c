#include "scanner.h"
#include "memreader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <mach/vm_prot.h>

/* ---------- type / op tables ---------- */

size_t scanner_type_size(scan_type_t t) {
    switch (t) {
        case ST_I8:  case ST_U8:  return 1;
        case ST_I16: case ST_U16: return 2;
        case ST_I32: case ST_U32: case ST_F32: return 4;
        case ST_I64: case ST_U64: case ST_F64: return 8;
        case ST_BYTES: return 0; /* variable */
        default: return 0;
    }
}

static const char *const TYPE_NAMES[ST__COUNT] = {
    "i8","i16","i32","i64","u8","u16","u32","u64","f32","f64","bytes"
};

const char* scanner_type_name(scan_type_t t) {
    return (t >= 0 && t < ST__COUNT) ? TYPE_NAMES[t] : "?";
}

int scanner_parse_type(const char *s, scan_type_t *out) {
    for (int i = 0; i < ST__COUNT; i++)
        if (!strcmp(s, TYPE_NAMES[i])) { *out = (scan_type_t)i; return 0; }
    return -1;
}

static const char *const OP_NAMES[SP__COUNT] = {
    "eq","ne","lt","le","gt","ge","range","unknown",
    "changed","unchanged","inc","dec"
};

const char* scanner_op_name(scan_predicate_t op) {
    return (op >= 0 && op < SP__COUNT) ? OP_NAMES[op] : "?";
}

int scanner_parse_op(const char *s, scan_predicate_t *out) {
    for (int i = 0; i < SP__COUNT; i++)
        if (!strcmp(s, OP_NAMES[i])) { *out = (scan_predicate_t)i; return 0; }
    return -1;
}

/* ---------- value union + packing ---------- */

typedef union {
    int8_t  i8;  uint8_t u8;
    int16_t i16; uint16_t u16;
    int32_t i32; uint32_t u32;
    int64_t i64; uint64_t u64;
    float   f32; double f64;
    uint8_t bytes[8];
} val_t;

/* Pack `size` bytes from p into a uint64_t (little-endian, host order). */
static inline uint64_t pack_le(const void *p, size_t size) {
    uint64_t r = 0;
    memcpy(&r, p, size);
    return r;
}

/* Build val_t from typed bytes (memory snapshot). */
static inline val_t val_from_bytes(scan_type_t t, const void *p) {
    val_t r; r.u64 = 0;
    memcpy(&r, p, scanner_type_size(t));
    return r;
}

/* Build val_t from packed uint64 (stored old_value). */
static inline val_t val_from_packed(scan_type_t t, uint64_t u) {
    (void)t;
    val_t r; r.u64 = u;
    return r;
}

/* Build val_t from the operand for the given type. */
static inline val_t val_from_operand_v1(scan_type_t t, const scan_operand_t *o) {
    val_t r; r.u64 = 0;
    if (!o) return r;
    switch (t) {
        case ST_I8:  r.i8  = (int8_t)o->v1.i;  break;
        case ST_I16: r.i16 = (int16_t)o->v1.i; break;
        case ST_I32: r.i32 = (int32_t)o->v1.i; break;
        case ST_I64: r.i64 = (int64_t)o->v1.i; break;
        case ST_U8:  r.u8  = (uint8_t)o->v1.u;  break;
        case ST_U16: r.u16 = (uint16_t)o->v1.u; break;
        case ST_U32: r.u32 = (uint32_t)o->v1.u; break;
        case ST_U64: r.u64 = (uint64_t)o->v1.u; break;
        case ST_F32: r.f32 = (float)o->v1.f;    break;
        case ST_F64: r.f64 = o->v1.f;           break;
        default: break;
    }
    return r;
}

static inline val_t val_from_operand_v2(scan_type_t t, const scan_operand_t *o) {
    val_t r; r.u64 = 0;
    if (!o) return r;
    switch (t) {
        case ST_I8:  r.i8  = (int8_t)o->v2.i;  break;
        case ST_I16: r.i16 = (int16_t)o->v2.i; break;
        case ST_I32: r.i32 = (int32_t)o->v2.i; break;
        case ST_I64: r.i64 = (int64_t)o->v2.i; break;
        case ST_U8:  r.u8  = (uint8_t)o->v2.u;  break;
        case ST_U16: r.u16 = (uint16_t)o->v2.u; break;
        case ST_U32: r.u32 = (uint32_t)o->v2.u; break;
        case ST_U64: r.u64 = (uint64_t)o->v2.u; break;
        case ST_F32: r.f32 = (float)o->v2.f;    break;
        case ST_F64: r.f64 = o->v2.f;           break;
        default: break;
    }
    return r;
}

/* ---------- predicate evaluation ---------- */

#define ARM(FIELD)                                                         \
    switch (op) {                                                          \
        case SP_EQ:        return v.FIELD == o1.FIELD;                     \
        case SP_NE:        return v.FIELD != o1.FIELD;                     \
        case SP_LT:        return v.FIELD <  o1.FIELD;                     \
        case SP_LE:        return v.FIELD <= o1.FIELD;                     \
        case SP_GT:        return v.FIELD >  o1.FIELD;                     \
        case SP_GE:        return v.FIELD >= o1.FIELD;                     \
        case SP_RANGE:     return v.FIELD >= o1.FIELD && v.FIELD <= o2.FIELD; \
        case SP_UNKNOWN:   return true;                                    \
        case SP_CHANGED:   return v.FIELD != ov.FIELD;                     \
        case SP_UNCHANGED: return v.FIELD == ov.FIELD;                     \
        case SP_INCREASED: return v.FIELD >  ov.FIELD;                     \
        case SP_DECREASED: return v.FIELD <  ov.FIELD;                     \
        default:           return false;                                   \
    }

static inline bool eval_predicate(scan_type_t t, scan_predicate_t op,
                           val_t v, val_t o1, val_t o2, val_t ov)
{
    switch (t) {
        case ST_I8:  ARM(i8);
        case ST_I16: ARM(i16);
        case ST_I32: ARM(i32);
        case ST_I64: ARM(i64);
        case ST_U8:  ARM(u8);
        case ST_U16: ARM(u16);
        case ST_U32: ARM(u32);
        case ST_U64: ARM(u64);
        case ST_F32: ARM(f32);
        case ST_F64: ARM(f64);
        default: return false;
    }
}

/* ---------- match storage ---------- */

typedef struct {
    uint64_t addr;
    uint64_t value;  /* packed little-endian, only low type-size bytes meaningful */
} match_t;

typedef struct {
    match_t *data;
    size_t   count;
    size_t   cap;
} match_vec_t;

static int match_addr_cmp(const void *a, const void *b) {
    uint64_t aa = ((const match_t *)a)->addr;
    uint64_t bb = ((const match_t *)b)->addr;
    return (aa < bb) ? -1 : (aa > bb) ? 1 : 0;
}

static int vec_reserve(match_vec_t *v, size_t need) {
    if (need <= v->cap) return 0;
    size_t nc = v->cap ? v->cap : 4096;
    while (nc < need) nc *= 2;
    void *p = realloc(v->data, nc * sizeof(match_t));
    if (!p) return -1;
    v->data = p;
    v->cap  = nc;
    return 0;
}

static inline int vec_push(match_vec_t *v, uint64_t addr, uint64_t value) {
    if (v->count == v->cap) {
        if (vec_reserve(v, v->count + 1) != 0) return -1;
    }
    v->data[v->count].addr  = addr;
    v->data[v->count].value = value;
    v->count++;
    return 0;
}

/* ---------- snapshot (for SP_UNKNOWN first scan) ---------- */

typedef struct {
    uint64_t base;
    uint64_t size;
    uint8_t *data;
} snap_region_t;

typedef struct {
    snap_region_t *regions;
    size_t         count;
    size_t         cap;
    uint64_t       total_bytes;
} snapshot_t;

static void snapshot_free(snapshot_t *snap) {
    if (!snap) return;
    for (size_t i = 0; i < snap->count; i++) free(snap->regions[i].data);
    free(snap->regions);
    free(snap);
}

/* ---------- session ---------- */

struct scan_session {
    mr_process_t *proc;
    match_vec_t   matches;
    snapshot_t   *snap;       /* non-NULL if last first-scan was SP_UNKNOWN */
    scan_type_t   type;
    bool          has_type;
};

scan_session_t* scanner_new(mr_process_t *p) {
    scan_session_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->proc = p;
    return s;
}

void scanner_free(scan_session_t *s) {
    if (!s) return;
    free(s->matches.data);
    snapshot_free(s->snap);
    free(s);
}

void scanner_clear(scan_session_t *s) {
    if (!s) return;
    s->matches.count = 0;
    snapshot_free(s->snap);
    s->snap = NULL;
    s->has_type = false;
}

size_t scanner_match_count(scan_session_t *s) {
    if (!s) return 0;
    if (s->snap) {
        /* Report covered slot count as the "match" count. The user sees this
           as "all of memory currently tracked" until they do the first rescan. */
        size_t tsize = scanner_type_size(s->type);
        if (tsize == 0) tsize = 1;
        return (size_t)(s->snap->total_bytes / tsize);
    }
    return s->matches.count;
}
scan_type_t scanner_current_type(scan_session_t *s) { return s ? s->type : ST_I32; }

bool scanner_in_snapshot(scan_session_t *s) { return s && s->snap != NULL; }
uint64_t scanner_snapshot_bytes(scan_session_t *s) {
    return (s && s->snap) ? s->snap->total_bytes : 0;
}

void scanner_default_filter(scan_filter_t *o) {
    if (!o) return;
    memset(o, 0, sizeof(*o));
    o->include_rw_private = true;
    o->max_region_bytes   = (size_t)1 << 30; /* 1 GiB cap per region */
    o->aligned            = true;            /* CE default */
}

static bool region_accepted(const scan_filter_t *f, const mr_region_t *r) {
    int prot_r = (r->prot & VM_PROT_READ)    != 0;
    int prot_w = (r->prot & VM_PROT_WRITE)   != 0;
    int prot_x = (r->prot & VM_PROT_EXECUTE) != 0;
    if (!prot_r) return false;

    if (prot_w && !prot_x && !r->shared && !f->include_rw_private) return false;
    if (prot_w && !prot_x &&  r->shared && !f->include_rw_shared)  return false;
    if (!prot_w && !prot_x && !f->include_ro) return false;
    if (prot_x && !f->include_rx) return false;

    /* fast-path for the common defaults: only rw-private */
    if (f->include_rw_private && !f->include_rw_shared
        && !f->include_ro && !f->include_rx)
    {
        if (!(prot_w && !prot_x && !r->shared)) return false;
    }

    if (f->addr_min && (r->base + r->size) <= f->addr_min) return false;
    if (f->addr_max && r->base >= f->addr_max) return false;
    if (f->max_region_bytes && r->size > f->max_region_bytes) return false;
    return true;
}

/* ---------- bytes pattern matcher ---------- */

static inline bool bytes_match(const uint8_t *hay, const uint8_t *pat,
                               const uint8_t *mask, size_t plen) {
    if (mask) {
        for (size_t i = 0; i < plen; i++)
            if ((hay[i] & mask[i]) != (pat[i] & mask[i])) return false;
        return true;
    }
    return memcmp(hay, pat, plen) == 0;
}

/* ---------- Boyer-Moore-Horspool skip table for AOB ----------
   Anchored at the rightmost fully-literal byte (R). At each position we
   read hay[i+R] and shift by skip[hay[i+R]]. Wildcard positions in [0..R)
   contribute the conservative shift = R - j (any byte fits), so coarse
   masks degrade gracefully. Falls back to naive scan if there is no fully
   literal byte (pattern is all wildcards / too short). */

typedef struct {
    int  skip[256];
    int  R;              /* index of rightmost literal byte */
    bool use_bmh;
} aob_skip_t;

static void aob_build_skip(const uint8_t *pat, const uint8_t *mask,
                           size_t plen, aob_skip_t *out) {
    out->use_bmh = false;
    if (plen < 4) return;

    int R = -1;
    for (int i = (int)plen - 1; i >= 0; i--) {
        if (!mask || mask[i] == 0xFF) { R = i; break; }
    }
    if (R <= 0) return;  /* no literal byte we can anchor on (R==0 == naive) */

    out->R = R;
    out->use_bmh = true;
    int default_shift = R + 1;
    for (int i = 0; i < 256; i++) out->skip[i] = default_shift;

    for (int j = 0; j < R; j++) {
        int shift = R - j;
        if (!mask || mask[j] == 0xFF) {
            uint8_t b = pat[j];
            if (out->skip[b] > shift) out->skip[b] = shift;
        } else {
            /* Wildcard / partial mask at j: every byte could match here,
               so every shift candidate is bounded by this distance. */
            for (int b = 0; b < 256; b++)
                if (out->skip[b] > shift) out->skip[b] = shift;
        }
    }
}

/* ---------- first scan ---------- */

typedef struct {
    scan_session_t  *s;
    scan_type_t      type;
    scan_predicate_t op;
    val_t            o1, o2;
    const scan_operand_t *raw_operand;   /* for ST_BYTES: bytes/mask/len */
    const scan_filter_t *f;
    /* BMH skip table, pre-built for ST_BYTES first scan. */
    aob_skip_t       bmh;
    /* progress */
    uint64_t total_bytes;
    uint64_t done_bytes;
    scan_progress_cb cb;
    void *ud;
    bool cancel;
} fs_ctx_t;

static int fs_count_region(const mr_region_t *r, void *ud) {
    fs_ctx_t *ctx = ud;
    if (region_accepted(ctx->f, r)) ctx->total_bytes += r->size;
    return 0;
}

/* Process a single region into a (thread-local) match vector. Returns 0 on
   success or short read, -1 on push failure. */
static int process_region_local(const fs_ctx_t *ctx, const mr_region_t *r,
                                match_vec_t *out) {
    mr_view_t view = {0};
    if (mr_view_open(ctx->s->proc, r->base, (size_t)r->size, &view) != 0)
        return 0;
    const uint8_t *buf = (const uint8_t *)view.data;
    ssize_t got = (ssize_t)view.size;

    /* ---- ST_BYTES path: literal byte pattern with optional mask ---- */
    if (ctx->type == ST_BYTES) {
        const uint8_t *pat  = ctx->raw_operand->bytes;
        const uint8_t *mask = ctx->raw_operand->mask;
        size_t plen         = ctx->raw_operand->bytes_len;
        if (plen == 0 || !pat) { mr_view_close(&view); return 0; }
        size_t end_b = (size_t)got >= plen ? (size_t)got - plen + 1 : 0;
        size_t prev_len = plen < 8 ? plen : 8;

        if (ctx->bmh.use_bmh && end_b > 0) {
            /* Boyer-Moore-Horspool: anchor at rightmost literal byte. */
            int R = ctx->bmh.R;
            uint8_t anchor = pat[R];
            size_t i = 0;
            while (i < end_b) {
                uint8_t b = buf[i + R];
                if (b == anchor && bytes_match(buf + i, pat, mask, plen)) {
                    uint64_t packed = pack_le(buf + i, prev_len);
                    if (vec_push(out, r->base + i, packed) != 0) {
                        mr_view_close(&view); return -1;
                    }
                    i += 1;  /* allow overlapping matches */
                } else {
                    int s = ctx->bmh.skip[b];
                    i += s > 0 ? (size_t)s : 1;
                }
            }
        } else {
            /* Naive 1-byte stride (short pattern or all-wildcard). */
            for (size_t i = 0; i < end_b; i++) {
                if (bytes_match(buf + i, pat, mask, plen)) {
                    uint64_t packed = pack_le(buf + i, prev_len);
                    if (vec_push(out, r->base + i, packed) != 0) {
                        mr_view_close(&view); return -1;
                    }
                }
            }
        }
        mr_view_close(&view);
        return 0;
    }

    size_t tsize = scanner_type_size(ctx->type);

    if (ctx->f->aligned) {
        /* Aligned-stride, type+op specialized kernel. Op is unswitched
           OUTSIDE the inner loop so clang can auto-vectorize each branch
           (SSE2 / AVX2). ~3-8x faster than a per-iter switch. */
#define LOOP_BODY(CT, COND)                                                \
        for (size_t i = 0; i < n; i++) {                                   \
            CT v = p[i];                                                   \
            if (COND) {                                                    \
                uint64_t packed = 0;                                       \
                memcpy(&packed, &v, sizeof(CT));                           \
                if (vec_push(out,                                          \
                             r->base + i * sizeof(CT), packed) != 0) {     \
                    mr_view_close(&view); return -1;                       \
                }                                                          \
            }                                                              \
        }
#define KERNEL(CT, FIELD)                                                  \
    do {                                                                   \
        const CT *p = (const CT *)buf;                                     \
        size_t n = (size_t)got / sizeof(CT);                               \
        CT v1 = ctx->o1.FIELD, v2 = ctx->o2.FIELD;                         \
        switch (ctx->op) {                                                 \
            case SP_EQ:    { LOOP_BODY(CT, v == v1)              } break;  \
            case SP_NE:    { LOOP_BODY(CT, v != v1)              } break;  \
            case SP_LT:    { LOOP_BODY(CT, v <  v1)              } break;  \
            case SP_LE:    { LOOP_BODY(CT, v <= v1)              } break;  \
            case SP_GT:    { LOOP_BODY(CT, v >  v1)              } break;  \
            case SP_GE:    { LOOP_BODY(CT, v >= v1)              } break;  \
            case SP_RANGE: { LOOP_BODY(CT, v >= v1 && v <= v2)   } break;  \
            default: break;                                                \
        }                                                                  \
        (void)v2;                                                          \
    } while (0)

        switch (ctx->type) {
            case ST_I8:  KERNEL(int8_t,   i8);  break;
            case ST_U8:  KERNEL(uint8_t,  u8);  break;
            case ST_I16: KERNEL(int16_t,  i16); break;
            case ST_U16: KERNEL(uint16_t, u16); break;
            case ST_I32: KERNEL(int32_t,  i32); break;
            case ST_U32: KERNEL(uint32_t, u32); break;
            case ST_I64: KERNEL(int64_t,  i64); break;
            case ST_U64: KERNEL(uint64_t, u64); break;
            case ST_F32: KERNEL(float,    f32); break;
            case ST_F64: KERNEL(double,   f64); break;
            default: break;
        }
#undef KERNEL
#undef LOOP_BODY
    } else {
        /* Unaligned 1-byte stride fallback (rare in CE workflows). */
        val_t  ov = {0};
        size_t end = (size_t)got >= tsize ? (size_t)got - tsize + 1 : 0;
        for (size_t i = 0; i < end; i++) {
            val_t v = val_from_bytes(ctx->type, buf + i);
            if (eval_predicate(ctx->type, ctx->op, v, ctx->o1, ctx->o2, ov)) {
                uint64_t packed = pack_le(buf + i, tsize);
                if (vec_push(out, r->base + i, packed) != 0) {
                    mr_view_close(&view);
                    return -1;
                }
            }
        }
    }
    mr_view_close(&view);
    return 0;
}

/* ---- Parallel driver ---- */

typedef struct {
    mr_region_t *items;
    size_t count, cap;
} region_vec_t;

static int region_collect_cb(const mr_region_t *r, void *ud) {
    region_vec_t *v = ud;
    if (v->count == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 64;
        v->items = realloc(v->items, v->cap * sizeof(mr_region_t));
    }
    v->items[v->count++] = *r;
    return 0;
}

typedef struct {
    const fs_ctx_t       *ctx;
    const region_vec_t   *regs;
    _Atomic size_t       *next_idx;
    _Atomic uint64_t     *done_bytes;
    _Atomic int          *cancel_flag;
    match_vec_t           local;
} worker_arg_t;

static void* fs_worker(void *arg) {
    worker_arg_t *w = arg;
    const fs_ctx_t *ctx = w->ctx;
    size_t n = w->regs->count;
    for (;;) {
        if (atomic_load_explicit(w->cancel_flag, memory_order_relaxed)) break;
        size_t i = atomic_fetch_add_explicit(w->next_idx, 1, memory_order_relaxed);
        if (i >= n) break;
        const mr_region_t *r = &w->regs->items[i];
        if (!region_accepted(ctx->f, r)) continue;

        int rc = process_region_local(ctx, r, &w->local);
        uint64_t new_done = atomic_fetch_add_explicit(
            w->done_bytes, r->size, memory_order_relaxed) + r->size;

        if (rc < 0) {
            atomic_store_explicit(w->cancel_flag, 1, memory_order_relaxed);
            break;
        }
        if (ctx->cb) {
            /* cb may be called concurrently; for GUI it stores atomics,
               for CLI it just prints a percent line. Acceptable. */
            if (ctx->cb(new_done, ctx->total_bytes, ctx->ud) != 0) {
                atomic_store_explicit(w->cancel_flag, 1, memory_order_relaxed);
                break;
            }
        }
    }
    return NULL;
}

/* Returns 0 on success, 1 on cancel. */
static int run_parallel_first_scan(fs_ctx_t *ctx) {
    region_vec_t regs = {0};
    mr_regions(ctx->s->proc, region_collect_cb, &regs);

    int nthreads = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (nthreads < 1) nthreads = 1;
    if (nthreads > 8) nthreads = 8;
    if ((size_t)nthreads > regs.count) nthreads = (int)regs.count;
    if (nthreads < 1) nthreads = 1;

    _Atomic size_t   next_idx = 0;
    _Atomic uint64_t done_b   = 0;
    _Atomic int      cancel   = 0;

    worker_arg_t *args = calloc(nthreads, sizeof(*args));
    pthread_t   *tids  = calloc(nthreads, sizeof(*tids));
    for (int t = 0; t < nthreads; t++) {
        args[t].ctx         = ctx;
        args[t].regs        = &regs;
        args[t].next_idx    = &next_idx;
        args[t].done_bytes  = &done_b;
        args[t].cancel_flag = &cancel;
        pthread_create(&tids[t], NULL, fs_worker, &args[t]);
    }
    for (int t = 0; t < nthreads; t++) pthread_join(tids[t], NULL);

    /* Compute total result count and merge thread-local vecs into s->matches. */
    size_t total = 0;
    for (int t = 0; t < nthreads; t++) total += args[t].local.count;
    if (total > 0) {
        if (vec_reserve(&ctx->s->matches, total) == 0) {
            for (int t = 0; t < nthreads; t++) {
                match_vec_t *lv = &args[t].local;
                if (lv->count) {
                    memcpy(ctx->s->matches.data + ctx->s->matches.count,
                           lv->data, lv->count * sizeof(match_t));
                    ctx->s->matches.count += lv->count;
                }
            }
        }
    }
    /* Sort the merged set by address (deterministic, matches CE display). */
    if (ctx->s->matches.count > 1) {
        qsort(ctx->s->matches.data, ctx->s->matches.count,
              sizeof(match_t), match_addr_cmp);
    }

    for (int t = 0; t < nthreads; t++) free(args[t].local.data);
    free(args);
    free(tids);
    free(regs.items);

    int cancelled = atomic_load(&cancel) ? 1 : 0;
    ctx->s = ctx->s;  /* silence */
    return cancelled;
}

/* ---------- snapshot path (SP_UNKNOWN first scan) ---------- */

typedef struct {
    scan_session_t *s;
    snapshot_t     *snap;
    const scan_filter_t *f;
    uint64_t total_bytes;
    uint64_t done_bytes;
    scan_progress_cb cb;
    void *ud;
    bool cancel;
} snap_ctx_t;

static int snap_count_cb(const mr_region_t *r, void *ud) {
    snap_ctx_t *ctx = ud;
    if (region_accepted(ctx->f, r)) ctx->total_bytes += r->size;
    return 0;
}

static int snap_collect_cb(const mr_region_t *r, void *ud) {
    snap_ctx_t *ctx = ud;
    if (!region_accepted(ctx->f, r)) return 0;
    if (ctx->cancel) return 1;

    size_t sz = (size_t)r->size;
    uint8_t *data = malloc(sz);
    if (!data) { ctx->done_bytes += r->size; return 0; }

    ssize_t got = mr_read(ctx->s->proc, r->base, data, sz);
    if (got <= 0) { free(data); ctx->done_bytes += r->size; return 0; }

    /* If short read, only store what we got. */
    if ((size_t)got < sz) {
        uint8_t *shrunk = realloc(data, (size_t)got);
        if (shrunk) data = shrunk;
        sz = (size_t)got;
    }

    /* Grow snap regions vector */
    snapshot_t *snap = ctx->snap;
    if (snap->count == snap->cap) {
        size_t nc = snap->cap ? snap->cap * 2 : 64;
        snap->regions = realloc(snap->regions, nc * sizeof(snap_region_t));
        snap->cap = nc;
    }
    snap->regions[snap->count].base = r->base;
    snap->regions[snap->count].size = sz;
    snap->regions[snap->count].data = data;
    snap->count++;
    snap->total_bytes += sz;

    ctx->done_bytes += r->size;
    if (ctx->cb && ctx->cb(ctx->done_bytes, ctx->total_bytes, ctx->ud) != 0) {
        ctx->cancel = true;
        return 1;
    }
    return 0;
}

int scanner_first_scan(scan_session_t *s,
                       scan_type_t type,
                       scan_predicate_t op,
                       const scan_operand_t *operand,
                       const scan_filter_t *filter,
                       scan_progress_cb cb, void *ud)
{
    if (!s || !s->proc) return -1;
    if (op >= SP_CHANGED) return -1; /* rescan-only ops not allowed here */

    /* Type-specific validation */
    if (type == ST_BYTES) {
        if (op != SP_EQ) return -1; /* bytes only support EQ on first scan */
        if (!operand || !operand->bytes || operand->bytes_len == 0) return -1;
    } else {
        if (scanner_type_size(type) == 0) return -1;
    }

    scanner_clear(s);
    s->type     = type;
    s->has_type = true;

    scan_filter_t deflt;
    if (!filter) { scanner_default_filter(&deflt); filter = &deflt; }

    /* ---- SP_UNKNOWN: snapshot mode ---- */
    if (op == SP_UNKNOWN) {
        if (type == ST_BYTES) return -1; /* unknown not meaningful for bytes */
        snapshot_t *snap = calloc(1, sizeof(*snap));
        if (!snap) return -1;
        s->snap = snap;

        snap_ctx_t ctx = {0};
        ctx.s = s; ctx.snap = snap; ctx.f = filter;
        ctx.cb = cb; ctx.ud = ud;
        mr_regions(s->proc, snap_count_cb,   &ctx);
        mr_regions(s->proc, snap_collect_cb, &ctx);
        return ctx.cancel ? 1 : 0;
    }

    fs_ctx_t ctx = {0};
    ctx.s    = s;
    ctx.type = type;
    ctx.op   = op;
    ctx.o1   = val_from_operand_v1(type, operand);
    ctx.o2   = val_from_operand_v2(type, operand);
    ctx.raw_operand = operand;
    ctx.f    = filter;
    ctx.cb   = cb;
    ctx.ud   = ud;
    if (type == ST_BYTES && operand) {
        aob_build_skip(operand->bytes, operand->mask,
                       operand->bytes_len, &ctx.bmh);
    }

    /* Two-pass for accurate progress: count bytes first. */
    mr_regions(s->proc, fs_count_region, &ctx);
    int rc = run_parallel_first_scan(&ctx);
    return rc;
}

/* ---------- rescan ---------- */

typedef struct {
    scan_session_t *s;
    scan_type_t     type;
    scan_predicate_t op;
    val_t            o1, o2;
    size_t           tsize;
    match_t         *in;
    size_t           start, end;
    match_vec_t      local;
    _Atomic uint64_t *done_atomic;
    uint64_t         total;
    scan_progress_cb cb;
    void            *ud;
    _Atomic int     *cancel;
} rs_arg_t;

static void* rs_worker(void *vp) {
    rs_arg_t *a = vp;
    const size_t BATCH_MAX = 64 * 1024;
    uint8_t *batch = malloc(BATCH_MAX + 16);
    if (!batch) return NULL;
    size_t i = a->start;
    while (i < a->end) {
        if (atomic_load_explicit(a->cancel, memory_order_relaxed)) break;
        size_t j = i + 1;
        uint64_t base = a->in[i].addr;
        while (j < a->end
               && a->in[j].addr + a->tsize - base <= BATCH_MAX) j++;
        size_t span = (size_t)(a->in[j - 1].addr - base) + a->tsize;

        ssize_t got = mr_read(a->s->proc, base, batch, span);
        size_t valid = got > 0 ? (size_t)got : 0;

        for (size_t k = i; k < j; k++) {
            uint64_t off = a->in[k].addr - base;
            if (off + a->tsize > valid) continue;
            val_t v  = val_from_bytes(a->type, batch + off);
            val_t ov = val_from_packed(a->type, a->in[k].value);
            if (eval_predicate(a->type, a->op, v, a->o1, a->o2, ov)) {
                uint64_t packed = pack_le(batch + off, a->tsize);
                if (vec_push(&a->local, a->in[k].addr, packed) != 0) {
                    atomic_store_explicit(a->cancel, 1, memory_order_relaxed);
                    free(batch);
                    return NULL;
                }
            }
        }
        uint64_t done = atomic_fetch_add_explicit(
            a->done_atomic, j - i, memory_order_relaxed) + (j - i);
        if (a->cb && a->cb(done, a->total, a->ud) != 0) {
            atomic_store_explicit(a->cancel, 1, memory_order_relaxed);
            break;
        }
        i = j;
    }
    free(batch);
    return NULL;
}

int scanner_next_scan(scan_session_t *s,
                      scan_predicate_t op,
                      const scan_operand_t *operand,
                      scan_progress_cb cb, void *ud)
{
    if (!s || !s->proc || !s->has_type) return -1;
    if (op == SP_UNKNOWN) return -1; /* unknown only valid on first scan */

    scan_type_t type = s->type;

    /* ---- snapshot mode: first rescan after SP_UNKNOWN. Walk snapshot
            regions, compare each typed position against current memory,
            emit matches that satisfy predicate. Then free snapshot. ---- */
    if (s->snap) {
        size_t tsize = scanner_type_size(type);
        if (tsize == 0) return -1; /* bytes can't be in snap mode anyway */

        val_t o1 = val_from_operand_v1(type, operand);
        val_t o2 = val_from_operand_v2(type, operand);

        uint64_t total_b = s->snap->total_bytes ? s->snap->total_bytes : 1;
        uint64_t done_b  = 0;

        for (size_t ri = 0; ri < s->snap->count; ri++) {
            snap_region_t *sr = &s->snap->regions[ri];
            uint8_t *cur = malloc(sr->size);
            if (!cur) { done_b += sr->size; continue; }
            ssize_t got = mr_read(s->proc, sr->base, cur, sr->size);
            size_t valid = got > 0 ? (size_t)got : 0;
            size_t cmp_len = valid < sr->size ? valid : sr->size;
            size_t end = cmp_len >= tsize ? cmp_len - tsize + 1 : 0;

            for (size_t i = 0; i < end; i++) {
                val_t nv = val_from_bytes(type, cur + i);
                val_t ov = val_from_bytes(type, sr->data + i);
                if (eval_predicate(type, op, nv, o1, o2, ov)) {
                    uint64_t packed = pack_le(cur + i, tsize);
                    if (vec_push(&s->matches, sr->base + i, packed) != 0) {
                        free(cur);
                        snapshot_free(s->snap); s->snap = NULL;
                        return -1;
                    }
                }
            }
            free(cur);
            done_b += sr->size;
            if (cb && cb(done_b, total_b, ud) != 0) {
                snapshot_free(s->snap); s->snap = NULL;
                return 1;
            }
        }

        /* Transition to match-set mode: snapshot can be freed. */
        snapshot_free(s->snap);
        s->snap = NULL;
        if (cb) cb(total_b, total_b, ud);
        return 0;
    }

    /* ---- ST_BYTES rescan ---- */
    if (type == ST_BYTES) {
        if (op != SP_EQ && op != SP_NE) return -1;
        if (!operand || !operand->bytes || operand->bytes_len == 0) return -1;

        const uint8_t *pat  = operand->bytes;
        const uint8_t *mask = operand->mask;
        size_t plen         = operand->bytes_len;

        match_t *in   = s->matches.data;
        size_t   n_in = s->matches.count;
        size_t   keep = 0;
        uint64_t total = n_in ? n_in : 1;

        uint8_t *tmp = malloc(plen);
        if (!tmp) return -1;
        for (size_t i = 0; i < n_in; i++) {
            ssize_t got = mr_read(s->proc, in[i].addr, tmp, plen);
            bool matches = (got == (ssize_t)plen) && bytes_match(tmp, pat, mask, plen);
            bool keep_it = (op == SP_EQ) ? matches : !matches;
            if (keep_it) {
                in[keep].addr  = in[i].addr;
                size_t prev_len = plen < 8 ? plen : 8;
                in[keep].value = pack_le(tmp, prev_len);
                keep++;
            }
            if (cb && (i & 0xFFFF) == 0xFFFF) {
                if (cb((uint64_t)i, total, ud) != 0) {
                    free(tmp); s->matches.count = keep; return 1;
                }
            }
        }
        free(tmp);
        s->matches.count = keep;
        if (cb) cb(total, total, ud);
        return 0;
    }

    size_t tsize     = scanner_type_size(type);
    val_t o1 = val_from_operand_v1(type, operand);
    val_t o2 = val_from_operand_v2(type, operand);

    match_t *in   = s->matches.data;
    size_t   n_in = s->matches.count;

    /* Sort by addr so adjacent matches share a page and we can batch reads. */
    qsort(in, n_in, sizeof(match_t), match_addr_cmp);
    uint64_t total = n_in ? n_in : 1;
    if (n_in == 0) {
        if (cb) cb(total, total, ud);
        return 0;
    }

    int nthreads = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (nthreads < 1) nthreads = 1;
    if (nthreads > 8) nthreads = 8;
    if ((size_t)nthreads > n_in) nthreads = (int)n_in;
    if (nthreads < 1) nthreads = 1;

    _Atomic uint64_t done_atomic = 0;
    _Atomic int      cancel_flag = 0;

    rs_arg_t *args = calloc(nthreads, sizeof(*args));
    pthread_t *tids = calloc(nthreads, sizeof(*tids));
    size_t per = n_in / nthreads;
    size_t rem = n_in % nthreads;
    size_t cursor = 0;
    for (int t = 0; t < nthreads; t++) {
        size_t take = per + (t < (int)rem ? 1 : 0);
        args[t].s = s; args[t].type = type; args[t].op = op;
        args[t].o1 = o1; args[t].o2 = o2;
        args[t].tsize = tsize;
        args[t].in = in;
        args[t].start = cursor;
        args[t].end   = cursor + take;
        args[t].done_atomic = &done_atomic;
        args[t].total = total;
        args[t].cb = cb; args[t].ud = ud;
        args[t].cancel = &cancel_flag;
        cursor += take;
        pthread_create(&tids[t], NULL, rs_worker, &args[t]);
    }
    for (int t = 0; t < nthreads; t++) pthread_join(tids[t], NULL);

    /* Merge in thread order — since partitions are address-sorted contiguous,
       concatenation preserves global sorted order. */
    size_t merged = 0;
    for (int t = 0; t < nthreads; t++) merged += args[t].local.count;
    /* Compact in place: in[] is the source and destination buffer. */
    size_t w = 0;
    for (int t = 0; t < nthreads; t++) {
        match_vec_t *lv = &args[t].local;
        if (lv->count) {
            memmove(in + w, lv->data, lv->count * sizeof(match_t));
            w += lv->count;
        }
        free(lv->data);
    }
    s->matches.count = merged;
    free(args);
    free(tids);

    if (atomic_load(&cancel_flag)) return 1;
    if (cb) cb(total, total, ud);
    return 0;
}

/* ---------- enumeration ---------- */

size_t scanner_get_matches(scan_session_t *s, size_t offset, size_t cap,
                           scan_match_view_t *out, bool refresh_current)
{
    if (!s || !out) return 0;
    /* In snapshot mode, individual matches haven't been materialized.
       Caller should see "rescan with changed/unchanged/etc to narrow down". */
    if (s->snap) return 0;
    if (offset >= s->matches.count) return 0;

    size_t n = s->matches.count - offset;
    if (n > cap) n = cap;

    size_t tsize = scanner_type_size(s->type);
    /* For variable-length types we sample the first 8 bytes as preview. */
    if (tsize == 0) tsize = 8;

    for (size_t i = 0; i < n; i++) {
        match_t *m = &s->matches.data[offset + i];
        out[i].addr      = m->addr;
        out[i].old_value = m->value;
        out[i].current_value = 0;
        out[i].current_valid = false;
        if (refresh_current) {
            uint8_t bytes[8] = {0};
            ssize_t got = mr_read(s->proc, m->addr, bytes, tsize);
            if (got == (ssize_t)tsize) {
                out[i].current_value = pack_le(bytes, tsize);
                out[i].current_valid = true;
            }
        }
    }
    return n;
}

/* ---------- persistence (for stateless CLI between invocations) ---------- */

#define SAVE_MAGIC "MRMATCH2"  /* v2 adds optional snapshot blob */

int scanner_save(scan_session_t *s, const char *path, pid_t pid) {
    if (!s) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(SAVE_MAGIC, 1, 8, f);
    int32_t type_i = (int32_t)s->type;
    int32_t pid_i  = (int32_t)pid;
    fwrite(&pid_i,  sizeof(pid_i),  1, f);
    fwrite(&type_i, sizeof(type_i), 1, f);
    uint64_t cnt = s->matches.count;
    fwrite(&cnt, sizeof(cnt), 1, f);
    if (s->matches.count > 0)
        fwrite(s->matches.data, sizeof(match_t), s->matches.count, f);

    /* Snapshot blob (optional, present when last first-scan was SP_UNKNOWN). */
    uint8_t has_snap = s->snap ? 1 : 0;
    fwrite(&has_snap, 1, 1, f);
    if (has_snap) {
        uint64_t rc = s->snap->count;
        fwrite(&rc, sizeof(rc), 1, f);
        for (size_t i = 0; i < s->snap->count; i++) {
            uint64_t base = s->snap->regions[i].base;
            uint64_t size = s->snap->regions[i].size;
            fwrite(&base, sizeof(base), 1, f);
            fwrite(&size, sizeof(size), 1, f);
            fwrite(s->snap->regions[i].data, 1, size, f);
        }
    }
    fclose(f);
    return 0;
}

int scanner_load(scan_session_t *s, const char *path, pid_t *out_pid) {
    if (!s) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    char magic[8];
    if (fread(magic, 1, 8, f) != 8 || memcmp(magic, SAVE_MAGIC, 8) != 0) {
        fclose(f); return -1;
    }
    int32_t pid_i, type_i;
    uint64_t cnt;
    if (fread(&pid_i, sizeof(pid_i), 1, f) != 1) { fclose(f); return -1; }
    if (fread(&type_i, sizeof(type_i), 1, f) != 1) { fclose(f); return -1; }
    if (fread(&cnt,    sizeof(cnt),    1, f) != 1) { fclose(f); return -1; }
    if (out_pid) *out_pid = (pid_t)pid_i;
    scanner_clear(s);
    s->type     = (scan_type_t)type_i;
    s->has_type = true;
    if (cnt > 0) {
        if (vec_reserve(&s->matches, cnt) != 0) { fclose(f); return -1; }
        if (fread(s->matches.data, sizeof(match_t), cnt, f) != cnt) {
            fclose(f); return -1;
        }
        s->matches.count = cnt;
    }
    /* Optional snapshot blob */
    uint8_t has_snap = 0;
    if (fread(&has_snap, 1, 1, f) == 1 && has_snap) {
        uint64_t rc = 0;
        if (fread(&rc, sizeof(rc), 1, f) != 1) { fclose(f); return -1; }
        snapshot_t *snap = calloc(1, sizeof(*snap));
        snap->cap = rc;
        snap->regions = calloc(rc, sizeof(snap_region_t));
        for (uint64_t i = 0; i < rc; i++) {
            uint64_t base = 0, size = 0;
            if (fread(&base, sizeof(base), 1, f) != 1) { fclose(f); snapshot_free(snap); return -1; }
            if (fread(&size, sizeof(size), 1, f) != 1) { fclose(f); snapshot_free(snap); return -1; }
            uint8_t *data = malloc(size);
            if (fread(data, 1, size, f) != size) { free(data); fclose(f); snapshot_free(snap); return -1; }
            snap->regions[i].base = base;
            snap->regions[i].size = size;
            snap->regions[i].data = data;
            snap->total_bytes += size;
        }
        snap->count = rc;
        s->snap = snap;
    }
    fclose(f);
    return 0;
}
