#include "memreader.h"
#include "scanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>

#include <mach/vm_prot.h>

static volatile sig_atomic_t g_cancel = 0;
static void sigint_handler(int sig) { (void)sig; g_cancel = 1; }

#define STATE_PATH "/tmp/macce.session"
#define AOB_PATH   "/tmp/macce.session.aob"

/* CE-style address formatting: green "<mod>+0xOFF" if file-backed, plain
   hex otherwise. Writes into out buffer. */
static void format_addr(const mr_module_map_t *mm, uint64_t addr,
                        char *out, size_t cap) {
    uint64_t off = 0;
    const char *mod = mm ? mr_module_map_resolve(mm, addr, &off) : NULL;
    bool color = isatty(fileno(stdout));
    if (mod) {
        if (color)
            snprintf(out, cap, "\x1b[32m%s+0x%llx\x1b[0m",
                     mod, (unsigned long long)off);
        else
            snprintf(out, cap, "%s+0x%llx",
                     mod, (unsigned long long)off);
    } else {
        snprintf(out, cap, "%016llx", (unsigned long long)addr);
    }
}

static int save_aob(const uint8_t *bytes, const uint8_t *mask, size_t len) {
    FILE *f = fopen(AOB_PATH, "wb");
    if (!f) return -1;
    uint32_t L = (uint32_t)len;
    uint8_t  has_mask = mask ? 1 : 0;
    fwrite(&L, sizeof(L), 1, f);
    fwrite(&has_mask, 1, 1, f);
    fwrite(bytes, 1, len, f);
    if (mask) fwrite(mask, 1, len, f);
    fclose(f);
    return 0;
}

static int load_aob(uint8_t **bytes_out, uint8_t **mask_out, size_t *len_out) {
    FILE *f = fopen(AOB_PATH, "rb");
    if (!f) return -1;
    uint32_t L; uint8_t has_mask = 0;
    if (fread(&L, sizeof(L), 1, f) != 1) { fclose(f); return -1; }
    if (fread(&has_mask, 1, 1, f) != 1) { fclose(f); return -1; }
    uint8_t *b = (uint8_t *)malloc(L);
    if (fread(b, 1, L, f) != L) { free(b); fclose(f); return -1; }
    uint8_t *m = NULL;
    if (has_mask) {
        m = (uint8_t *)malloc(L);
        if (fread(m, 1, L, f) != L) { free(b); free(m); fclose(f); return -1; }
    }
    fclose(f);
    *bytes_out = b; *mask_out = m; *len_out = L;
    return 0;
}

static const char* prot_str(int p) {
    static char buf[4];
    buf[0] = (p & VM_PROT_READ)    ? 'r' : '-';
    buf[1] = (p & VM_PROT_WRITE)   ? 'w' : '-';
    buf[2] = (p & VM_PROT_EXECUTE) ? 'x' : '-';
    buf[3] = 0;
    return buf;
}

static int print_region(const mr_region_t *r, void *ud) {
    (void)ud;
    printf("%016" PRIx64 "-%016" PRIx64 " %6" PRIu64 "K %s %s %s\n",
           r->base, r->base + r->size,
           r->size / 1024,
           prot_str(r->prot),
           r->shared ? "shr" : "prv",
           r->path[0] ? r->path : "");
    return 0;
}

static void hexdump(uint64_t base, const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i += 16) {
        printf("%016" PRIx64 "  ", base + i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < n) printf("%02x ", buf[i + j]);
            else           printf("   ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < n; j++) {
            uint8_t c = buf[i + j];
            putchar((c >= 32 && c < 127) ? c : '.');
        }
        printf("|\n");
    }
}

/* Naive byte-pattern scan across all readable, non-shared regions. */
typedef struct {
    mr_process_t *p;
    const uint8_t *pat;
    size_t patlen;
    int limit;
    int hits;
} scan_ctx_t;

static int scan_cb(const mr_region_t *r, void *ud) {
    scan_ctx_t *ctx = (scan_ctx_t *)ud;
    if (!(r->prot & VM_PROT_READ)) return 0;
    if (r->size == 0 || r->size > (1ULL << 32)) return 0; /* skip huge regions */

    uint8_t *buf = (uint8_t *)malloc((size_t)r->size);
    if (!buf) return 0;

    ssize_t got = mr_read(ctx->p, r->base, buf, (size_t)r->size);
    if (got > 0 && (size_t)got >= ctx->patlen) {
        for (size_t i = 0; i + ctx->patlen <= (size_t)got; i++) {
            if (memcmp(buf + i, ctx->pat, ctx->patlen) == 0) {
                printf("%016" PRIx64 "\n", r->base + i);
                if (++ctx->hits >= ctx->limit) { free(buf); return 1; }
            }
        }
    }
    free(buf);
    return 0;
}

/* Parse AOB pattern: "DE AD ?? BE EF" -> bytes=[DE,AD,00,BE,EF], mask=[FF,FF,00,FF,FF].
   If pattern has no wildcards, *mask_out is freed and set to NULL. */
static int parse_aob(const char *s, uint8_t **bytes_out, uint8_t **mask_out, size_t *len_out) {
    size_t cap = strlen(s) / 2 + 1;
    uint8_t *b = (uint8_t *)malloc(cap);
    uint8_t *m = (uint8_t *)malloc(cap);
    size_t n = 0;
    int hi = -1, hi_mask = 0;  /* bit 0: hi nibble is wildcard */
    bool has_wild = false;
    for (; *s; s++) {
        if (isspace((unsigned char)*s)) continue;
        int v; bool wild = false;
        if      (*s == '?')              { v = 0; wild = true; has_wild = true; }
        else if (*s >= '0' && *s <= '9')  v = *s - '0';
        else if (*s >= 'a' && *s <= 'f')  v = 10 + *s - 'a';
        else if (*s >= 'A' && *s <= 'F')  v = 10 + *s - 'A';
        else { free(b); free(m); return -1; }
        if (hi < 0) { hi = v; hi_mask = wild ? 0 : 1; }
        else {
            b[n] = (uint8_t)((hi << 4) | v);
            uint8_t mb = 0;
            if (hi_mask) mb |= 0xF0;
            if (!wild)   mb |= 0x0F;
            m[n] = mb;
            n++;
            hi = -1;
        }
    }
    if (hi >= 0) { free(b); free(m); return -1; }
    *bytes_out = b;
    *len_out   = n;
    if (has_wild) {
        *mask_out = m;
    } else {
        free(m);
        *mask_out = NULL;
    }
    return 0;
}

static int parse_hex_bytes(const char *s, uint8_t **out, size_t *outlen) {
    /* Accept "DE AD BE EF" or "deadbeef" */
    size_t cap = strlen(s) / 2 + 1;
    uint8_t *b = (uint8_t *)malloc(cap);
    size_t n = 0;
    int hi = -1;
    for (; *s; s++) {
        if (isspace((unsigned char)*s)) continue;
        int v;
        if      (*s >= '0' && *s <= '9') v = *s - '0';
        else if (*s >= 'a' && *s <= 'f') v = 10 + *s - 'a';
        else if (*s >= 'A' && *s <= 'F') v = 10 + *s - 'A';
        else { free(b); return -1; }
        if (hi < 0) hi = v;
        else { b[n++] = (uint8_t)((hi << 4) | v); hi = -1; }
    }
    if (hi >= 0) { free(b); return -1; }
    *out = b; *outlen = n;
    return 0;
}

static int parse_operand_for_type(scan_type_t t, const char *s,
                                   scan_operand_t *op, int slot)
{
    /* slot 0 -> v1, slot 1 -> v2 */
    char *end = NULL;
    union { int64_t i; uint64_t u; double f; } *target =
        (slot == 0) ? (void *)&op->v1 : (void *)&op->v2;

    switch (t) {
        case ST_I8: case ST_I16: case ST_I32: case ST_I64:
            target->i = strtoll(s, &end, 0);
            return (end && *end == 0) ? 0 : -1;
        case ST_U8: case ST_U16: case ST_U32: case ST_U64:
            target->u = strtoull(s, &end, 0);
            return (end && *end == 0) ? 0 : -1;
        case ST_F32: case ST_F64:
            target->f = strtod(s, &end);
            return (end && *end == 0) ? 0 : -1;
        default:
            return -1;
    }
}

static void fmt_value(scan_type_t t, uint64_t packed, char *out, size_t cap) {
    switch (t) {
        case ST_I8:  snprintf(out, cap, "%" PRId8,  (int8_t)packed);  return;
        case ST_I16: snprintf(out, cap, "%" PRId16, (int16_t)packed); return;
        case ST_I32: snprintf(out, cap, "%" PRId32, (int32_t)packed); return;
        case ST_I64: snprintf(out, cap, "%" PRId64 " (0x%" PRIx64 ")", (int64_t)packed, packed); return;
        case ST_U8:  snprintf(out, cap, "%" PRIu8,  (uint8_t)packed);  return;
        case ST_U16: snprintf(out, cap, "%" PRIu16, (uint16_t)packed); return;
        case ST_U32: snprintf(out, cap, "%" PRIu32, (uint32_t)packed); return;
        case ST_U64: snprintf(out, cap, "%" PRIu64 " (0x%" PRIx64 ")", packed, packed); return;
        case ST_F32: { uint32_t b = (uint32_t)packed; float f; memcpy(&f, &b, 4);
                       snprintf(out, cap, "%g", (double)f); return; }
        case ST_F64: { double d; memcpy(&d, &packed, 8);
                       snprintf(out, cap, "%g", d); return; }
        case ST_BYTES: {
            uint8_t b[8]; memcpy(b, &packed, 8);
            char ascii[9]; for (int i = 0; i < 8; i++)
                ascii[i] = (b[i] >= 32 && b[i] < 127) ? (char)b[i] : '.';
            ascii[8] = 0;
            snprintf(out, cap,
                     "%02x %02x %02x %02x %02x %02x %02x %02x  |%s|",
                     b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], ascii);
            return;
        }
        default: snprintf(out, cap, "?"); return;
    }
}

static int progress_print(uint64_t done, uint64_t total, void *ud) {
    (void)ud;
    if (g_cancel) return 1;
    static uint64_t last_pct = 999;
    if (total == 0) return 0;
    uint64_t pct = done * 100 / total;
    if (pct != last_pct && (pct % 5) == 0) {
        fprintf(stderr, "\r  scan progress %3llu%%  (%.1f MB / %.1f MB)",
                (unsigned long long)pct,
                (double)done / (1024.0 * 1024.0),
                (double)total / (1024.0 * 1024.0));
        fflush(stderr);
        last_pct = pct;
    }
    if (done == total) fprintf(stderr, "\n");
    return 0;
}

static int cmd_write(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: write <pid> <hex-addr> <hex-bytes>\n");
        return 1;
    }
    pid_t pid    = (pid_t)atoi(argv[2]);
    uint64_t addr = strtoull(argv[3], NULL, 16);
    uint8_t *bytes = NULL; size_t blen = 0;
    if (parse_hex_bytes(argv[4], &bytes, &blen) != 0 || blen == 0) {
        fprintf(stderr, "bad hex bytes\n"); return 1;
    }

    mr_process_t *p = NULL;
    if (mr_open(pid, &p) != 0) { free(bytes); return 1; }

    ssize_t w = mr_write(p, addr, bytes, blen);
    if (w < 0) {
        fprintf(stderr, "write failed at %016" PRIx64 "\n", addr);
        free(bytes); mr_close(p); return 1;
    }
    fprintf(stderr, "wrote %zd bytes at %016" PRIx64 "\n", w, addr);

    /* read back to verify */
    uint8_t *vb = malloc(blen);
    ssize_t r = mr_read(p, addr, vb, blen);
    fprintf(stderr, "verify: ");
    for (size_t i = 0; i < (size_t)(r > 0 ? r : 0); i++) fprintf(stderr, "%02x ", vb[i]);
    fprintf(stderr, "\n");
    free(vb);

    free(bytes);
    mr_close(p);
    return 0;
}

/* Decode one UTF-8 codepoint from s. Returns codepoint and writes byte
   advance count into *adv. Returns -1 on invalid sequence. */
static int32_t utf8_decode(const char *s, int *adv) {
    unsigned char c = (unsigned char)s[0];
    if (c == 0) { *adv = 0; return -1; }
    if (c < 0x80) { *adv = 1; return c; }
    if ((c & 0xE0) == 0xC0) {
        unsigned char c1 = (unsigned char)s[1];
        if ((c1 & 0xC0) != 0x80) return -1;
        *adv = 2;
        int32_t cp = ((c & 0x1F) << 6) | (c1 & 0x3F);
        return cp < 0x80 ? -1 : cp;
    }
    if ((c & 0xF0) == 0xE0) {
        unsigned char c1 = (unsigned char)s[1], c2 = (unsigned char)s[2];
        if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80) return -1;
        *adv = 3;
        int32_t cp = ((c & 0x0F) << 12) | ((c1 & 0x3F) << 6) | (c2 & 0x3F);
        return cp < 0x800 ? -1 : cp;
    }
    if ((c & 0xF8) == 0xF0) {
        unsigned char c1 = (unsigned char)s[1], c2 = (unsigned char)s[2], c3 = (unsigned char)s[3];
        if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80) return -1;
        *adv = 4;
        int32_t cp = ((c & 0x07) << 18) | ((c1 & 0x3F) << 12)
                   | ((c2 & 0x3F) << 6) | (c3 & 0x3F);
        return (cp < 0x10000 || cp > 0x10FFFF) ? -1 : cp;
    }
    return -1;
}

/* Encode a UTF-8 string literal to bytes.
   wide=false: pass-through UTF-8 bytes (works for ASCII and CJK alike if
               target memory uses UTF-8 too).
   wide=true:  decode UTF-8 codepoints, re-encode as UTF-16LE (Windows native).
   Caller frees *out. */
static int encode_string(const char *s, bool wide, uint8_t **out, size_t *out_len) {
    size_t n = strlen(s);
    if (n == 0) return -1;
    if (!wide) {
        uint8_t *b = (uint8_t *)malloc(n);
        memcpy(b, s, n);
        *out = b; *out_len = n;
        return 0;
    }

    /* Worst case: 4 bytes per ASCII char (surrogate pair). */
    uint8_t *b = (uint8_t *)malloc(n * 4 + 4);
    size_t out_i = 0;
    const char *p = s;
    while (*p) {
        int adv = 0;
        int32_t cp = utf8_decode(p, &adv);
        if (cp < 0 || adv == 0) { free(b); return -1; }
        if (cp <= 0xFFFF) {
            if (cp >= 0xD800 && cp <= 0xDFFF) { free(b); return -1; }
            b[out_i++] = (uint8_t)(cp & 0xFF);
            b[out_i++] = (uint8_t)((cp >> 8) & 0xFF);
        } else {
            uint32_t v = cp - 0x10000;
            uint16_t hi = 0xD800 | (v >> 10);
            uint16_t lo = 0xDC00 | (v & 0x3FF);
            b[out_i++] = (uint8_t)(hi & 0xFF);
            b[out_i++] = (uint8_t)((hi >> 8) & 0xFF);
            b[out_i++] = (uint8_t)(lo & 0xFF);
            b[out_i++] = (uint8_t)((lo >> 8) & 0xFF);
        }
        p += adv;
    }
    *out = b; *out_len = out_i;
    return 0;
}

static int cmd_scan(int argc, char **argv) {
    if (argc < 5) return -1;
    pid_t pid = (pid_t)atoi(argv[2]);
    scan_type_t type;
    bool string_mode = false; bool string_wide = false;
    if (!strcmp(argv[3], "str"))  { type = ST_BYTES; string_mode = true; string_wide = false; }
    else if (!strcmp(argv[3], "wstr")) { type = ST_BYTES; string_mode = true; string_wide = true; }
    else if (scanner_parse_type(argv[3], &type) != 0) {
        fprintf(stderr, "bad type '%s' (expected i8/i16/i32/i64/u*/f32/f64/bytes/str/wstr)\n", argv[3]);
        return 1;
    }
    scan_predicate_t op;
    if (scanner_parse_op(argv[4], &op) != 0) {
        fprintf(stderr, "bad op '%s' (eq/ne/lt/le/gt/ge/range/unknown)\n", argv[4]);
        return 1;
    }
    scan_operand_t operand = {0};
    uint8_t *aob_bytes = NULL, *aob_mask = NULL;
    size_t   aob_len = 0;

    if (string_mode) {
        if (op != SP_EQ) {
            fprintf(stderr, "string scan only supports 'eq' on first scan\n");
            return 1;
        }
        if (argc < 6) {
            fprintf(stderr, "string scan needs a literal value, e.g. scan PID str eq \"hello\"\n");
            return 1;
        }
        if (encode_string(argv[5], string_wide, &aob_bytes, &aob_len) != 0) {
            fprintf(stderr, "empty string\n"); return 1;
        }
        aob_mask = NULL;
        operand.bytes     = aob_bytes;
        operand.mask      = NULL;
        operand.bytes_len = aob_len;
        fprintf(stderr, "  encoded %s string (%zu bytes): ", string_wide ? "UTF-16LE" : "UTF-8", aob_len);
        for (size_t i = 0; i < aob_len && i < 24; i++) fprintf(stderr, "%02x ", aob_bytes[i]);
        if (aob_len > 24) fprintf(stderr, "...");
        fprintf(stderr, "\n");
    } else if (type == ST_BYTES) {
        if (op != SP_EQ) {
            fprintf(stderr, "bytes type only supports 'eq' on first scan\n");
            return 1;
        }
        if (argc < 6) {
            fprintf(stderr, "bytes scan needs a hex pattern (e.g. \"DE AD ?? BE EF\")\n");
            return 1;
        }
        if (parse_aob(argv[5], &aob_bytes, &aob_mask, &aob_len) != 0 || aob_len == 0) {
            fprintf(stderr, "bad hex/AOB pattern\n");
            return 1;
        }
        operand.bytes     = aob_bytes;
        operand.mask      = aob_mask;
        operand.bytes_len = aob_len;
    } else if (op != SP_UNKNOWN) {
        if (argc < 6) {
            fprintf(stderr, "op '%s' needs a value argument\n", argv[4]);
            return 1;
        }
        if (parse_operand_for_type(type, argv[5], &operand, 0) != 0) {
            fprintf(stderr, "bad value '%s' for type %s\n", argv[5], argv[3]);
            return 1;
        }
        if (op == SP_RANGE) {
            if (argc < 7) { fprintf(stderr, "range needs two values\n"); return 1; }
            if (parse_operand_for_type(type, argv[6], &operand, 1) != 0) {
                fprintf(stderr, "bad upper value '%s'\n", argv[6]);
                return 1;
            }
        }
    }

    mr_process_t *p = NULL;
    if (mr_open(pid, &p) != 0) { free(aob_bytes); free(aob_mask); return 1; }
    scan_session_t *s = scanner_new(p);

    fprintf(stderr, "first-scan: type=%s op=%s pid=%d%s\n",
            scanner_type_name(type), scanner_op_name(op), pid,
            type == ST_BYTES ? " (bytes)" : "");

    int rc = scanner_first_scan(s, type, op, &operand, NULL, progress_print, NULL);
    if (rc < 0) {
        fprintf(stderr, "scan failed\n");
        scanner_free(s); mr_close(p);
        return 1;
    }
    if (rc == 1) fprintf(stderr, "scan cancelled\n");

    size_t cnt = scanner_match_count(s);
    if (scanner_in_snapshot(s)) {
        fprintf(stderr,
                "snapshot taken: %.1f MB covering %zu candidate slots\n"
                "  → run `rescan changed/unchanged/inc/dec/eq/...` to narrow down\n",
                scanner_snapshot_bytes(s) / 1048576.0, cnt);
    } else {
        fprintf(stderr, "matches: %zu\n", cnt);
    }

    if (scanner_save(s, STATE_PATH, pid) != 0) {
        fprintf(stderr, "warning: failed to save session to %s\n", STATE_PATH);
    } else {
        fprintf(stderr, "session saved to %s\n", STATE_PATH);
    }
    /* For bytes type, save the pattern alongside so rescan can use it. */
    if (type == ST_BYTES) save_aob(aob_bytes, aob_mask, aob_len);
    else                  unlink(AOB_PATH);

    /* Print up to 20 matches as a preview. */
    size_t preview = cnt < 20 ? cnt : 20;
    if (preview > 0) {
        scan_match_view_t view[20];
        size_t got = scanner_get_matches(s, 0, preview, view, false);
        mr_module_map_t *mm = mr_module_map_build(p);
        char buf[64], addr_s[300];
        for (size_t i = 0; i < got; i++) {
            fmt_value(type, view[i].old_value, buf, sizeof(buf));
            format_addr(mm, view[i].addr, addr_s, sizeof(addr_s));
            printf("  %-50s  = %s\n", addr_s, buf);
        }
        mr_module_map_free(mm);
        if (cnt > preview) printf("  ... %zu more (run `list` to see range)\n", cnt - preview);
    }

    free(aob_bytes); free(aob_mask);
    scanner_free(s);
    mr_close(p);
    return 0;
}

static int cmd_rescan(int argc, char **argv) {
    if (argc < 3) return -1;
    scan_predicate_t op;
    if (scanner_parse_op(argv[2], &op) != 0) {
        fprintf(stderr, "bad op\n"); return 1;
    }
    if (op == SP_UNKNOWN) {
        fprintf(stderr, "rescan does not support 'unknown'\n"); return 1;
    }

    pid_t pid = 0;
    /* We need a session to know the type before parsing the operand. */
    scan_session_t *tmp = scanner_new(NULL);
    if (scanner_load(tmp, STATE_PATH, &pid) != 0) {
        fprintf(stderr, "no saved session at %s — run `scan` first\n", STATE_PATH);
        scanner_free(tmp);
        return 1;
    }
    scan_type_t type = scanner_current_type(tmp);

    scan_operand_t operand = {0};
    uint8_t *aob_bytes = NULL, *aob_mask = NULL;
    size_t   aob_len = 0;

    if (type == ST_BYTES) {
        if (op != SP_EQ && op != SP_NE) {
            fprintf(stderr, "bytes rescan supports only 'eq' or 'ne'\n");
            scanner_free(tmp); return 1;
        }
        if (load_aob(&aob_bytes, &aob_mask, &aob_len) != 0) {
            fprintf(stderr, "no AOB pattern saved (run `scan` with bytes type first)\n");
            scanner_free(tmp); return 1;
        }
        operand.bytes     = aob_bytes;
        operand.mask      = aob_mask;
        operand.bytes_len = aob_len;
    } else {
        bool needs_value = !(op == SP_CHANGED || op == SP_UNCHANGED
                             || op == SP_INCREASED || op == SP_DECREASED);
        if (needs_value) {
            if (argc < 4) {
                fprintf(stderr, "op '%s' needs a value\n", argv[2]);
                scanner_free(tmp); return 1;
            }
            if (parse_operand_for_type(type, argv[3], &operand, 0) != 0) {
                fprintf(stderr, "bad value\n"); scanner_free(tmp); return 1;
            }
            if (op == SP_RANGE) {
                if (argc < 5) { fprintf(stderr, "range needs two values\n");
                    scanner_free(tmp); return 1; }
                if (parse_operand_for_type(type, argv[4], &operand, 1) != 0) {
                    fprintf(stderr, "bad upper value\n"); scanner_free(tmp); return 1;
                }
            }
        }
    }

    mr_process_t *p = NULL;
    if (mr_open(pid, &p) != 0) { scanner_free(tmp); return 1; }
    /* Re-bind process. */
    scanner_free(tmp);
    scan_session_t *s = scanner_new(p);
    scanner_load(s, STATE_PATH, &pid);

    if (scanner_in_snapshot(s)) {
        fprintf(stderr, "rescan from snapshot: pid=%d type=%s op=%s (%.1f MB)\n",
                pid, scanner_type_name(type), scanner_op_name(op),
                scanner_snapshot_bytes(s) / 1048576.0);
    } else {
        fprintf(stderr, "rescan: pid=%d type=%s op=%s prev_matches=%zu\n",
                pid, scanner_type_name(type), scanner_op_name(op),
                scanner_match_count(s));
    }

    int rc = scanner_next_scan(s, op, &operand, progress_print, NULL);
    size_t cnt = scanner_match_count(s);
    fprintf(stderr, "matches: %zu\n", cnt);
    if (rc == 1) fprintf(stderr, "rescan cancelled\n");

    scanner_save(s, STATE_PATH, pid);

    size_t preview = cnt < 20 ? cnt : 20;
    if (preview > 0) {
        scan_match_view_t view[20];
        size_t got = scanner_get_matches(s, 0, preview, view, true);
        mr_module_map_t *mm = mr_module_map_build(p);
        char cb[64], pb[64], addr_s[300];
        for (size_t i = 0; i < got; i++) {
            fmt_value(type, view[i].current_value, cb, sizeof(cb));
            fmt_value(type, view[i].old_value,     pb, sizeof(pb));
            format_addr(mm, view[i].addr, addr_s, sizeof(addr_s));
            printf("  %-50s  cur=%s  prev=%s\n", addr_s, cb, pb);
        }
        mr_module_map_free(mm);
        if (cnt > preview) printf("  ... %zu more\n", cnt - preview);
    }

    free(aob_bytes); free(aob_mask);
    scanner_free(s);
    mr_close(p);
    return 0;
}

static int cmd_list(int argc, char **argv) {
    size_t offset = 0, count = 50;
    if (argc >= 3) offset = (size_t)strtoull(argv[2], NULL, 0);
    if (argc >= 4) count  = (size_t)strtoull(argv[3], NULL, 0);

    pid_t pid = 0;
    scan_session_t *tmp = scanner_new(NULL);
    if (scanner_load(tmp, STATE_PATH, &pid) != 0) {
        fprintf(stderr, "no session at %s\n", STATE_PATH);
        scanner_free(tmp); return 1;
    }
    scan_type_t type = scanner_current_type(tmp);

    mr_process_t *p = NULL;
    if (mr_open(pid, &p) != 0) { scanner_free(tmp); return 1; }
    scanner_free(tmp);
    scan_session_t *s = scanner_new(p);
    scanner_load(s, STATE_PATH, &pid);

    size_t total = scanner_match_count(s);
    fprintf(stderr, "session pid=%d type=%s matches=%zu (showing %zu+%zu)\n",
            pid, scanner_type_name(type), total, offset, count);

    if (offset >= total) { scanner_free(s); mr_close(p); return 0; }
    if (offset + count > total) count = total - offset;

    scan_match_view_t *view = calloc(count, sizeof(*view));
    size_t got = scanner_get_matches(s, offset, count, view, true);
    mr_module_map_t *mm = mr_module_map_build(p);
    char cb[64], pb[64], addr_s[300];
    for (size_t i = 0; i < got; i++) {
        fmt_value(type, view[i].current_value, cb, sizeof(cb));
        fmt_value(type, view[i].old_value,     pb, sizeof(pb));
        format_addr(mm, view[i].addr, addr_s, sizeof(addr_s));
        printf("  [%zu] %-50s  cur=%s  saved=%s\n",
               offset + i, addr_s, cb, pb);
    }
    mr_module_map_free(mm);
    free(view);
    scanner_free(s);
    mr_close(p);
    return 0;
}

/* ---------- pointer scan ---------- */

typedef struct { mr_region_t *regions; size_t count, cap; } region_list_t;

static int rl_collect(const mr_region_t *r, void *ud) {
    region_list_t *L = (region_list_t *)ud;
    if (L->count == L->cap) {
        L->cap = L->cap ? L->cap * 2 : 64;
        L->regions = (mr_region_t *)realloc(L->regions, L->cap * sizeof(*L->regions));
    }
    L->regions[L->count++] = *r;
    return 0;
}

static const mr_region_t* rl_find(const region_list_t *L, uint64_t addr) {
    for (size_t i = 0; i < L->count; i++) {
        const mr_region_t *r = &L->regions[i];
        if (addr >= r->base && addr < r->base + r->size) return r;
    }
    return NULL;
}

static int cmd_pscan(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
"usage: macce pscan <pid> <target-hex-addr> [max-offset=0x1000] [depth=1]\n"
"\n"
"Finds candidate one- or multi-level pointer chains terminating at <target>.\n"
"Chain: anchor + off0  ->  ptr1, ptr1 + off1 -> ptr2, ..., ptrN + offN-1 == target.\n"
"Anchors with a backing file path are static (good chains for stable cheats).\n");
        return 1;
    }
    pid_t pid       = (pid_t)atoi(argv[2]);
    uint64_t target = strtoull(argv[3], NULL, 16);
    uint64_t max_off = (argc >= 5) ? strtoull(argv[4], NULL, 0) : 0x1000;
    int depth        = (argc >= 6) ? atoi(argv[5]) : 1;
    if (depth < 1) depth = 1;
    if (depth > 4) depth = 4;

    mr_process_t *p = NULL;
    if (mr_open(pid, &p) != 0) return 1;

    region_list_t regs = {0};
    mr_regions(p, rl_collect, &regs);

    /* BFS over depth levels. Frontier holds (current_target, chain_so_far). */
    typedef struct {
        uint64_t cur_target;
        int n;                  /* number of offsets accumulated */
        uint64_t anchors[8];    /* addresses at each level, deepest=last  */
        int32_t  offsets[8];    /* offsets at each level                  */
    } frontier_t;

    frontier_t *frontier = (frontier_t *)calloc(1, sizeof(frontier_t));
    size_t f_cnt = 1;
    frontier[0].cur_target = target;
    frontier[0].n = 0;

    typedef struct {
        int      n;
        uint64_t anchors[8];
        int32_t  offsets[8];
    } chain_t;
    chain_t *chains = NULL;
    size_t c_cnt = 0, c_cap = 0;
    const size_t MAX_CHAINS = 5000;
    const size_t MAX_PER_LEVEL = 2000;

    fprintf(stderr, "pscan: target=%016llx max_off=0x%llx depth=%d\n",
            (unsigned long long)target, (unsigned long long)max_off, depth);

    scan_session_t *sess = scanner_new(p);

    for (int level = 0; level < depth && c_cnt < MAX_CHAINS; level++) {
        frontier_t *next = NULL;
        size_t n_cnt = 0, n_cap = 0;

        fprintf(stderr, "  level %d: frontier=%zu nodes\n", level + 1, f_cnt);

        for (size_t fi = 0; fi < f_cnt && c_cnt < MAX_CHAINS; fi++) {
            frontier_t *fr = &frontier[fi];
            scan_operand_t op = {0};
            op.v1.u = fr->cur_target > max_off ? fr->cur_target - max_off : 0;
            op.v2.u = fr->cur_target;

            scanner_clear(sess);
            scanner_first_scan(sess, ST_U64, SP_RANGE, &op, NULL, NULL, NULL);
            size_t cnt = scanner_match_count(sess);
            if (cnt > MAX_PER_LEVEL) cnt = MAX_PER_LEVEL;

            scan_match_view_t *view = (scan_match_view_t *)calloc(cnt, sizeof(*view));
            scanner_get_matches(sess, 0, cnt, view, false);

            for (size_t i = 0; i < cnt && c_cnt < MAX_CHAINS; i++) {
                uint64_t a = view[i].addr;
                int32_t  o = (int32_t)(fr->cur_target - view[i].old_value);

                /* extend chain */
                int n_new = fr->n + 1;
                if (n_new > 8) continue;

                const mr_region_t *r = rl_find(&regs, a);
                /* file-backed = "static" anchor: relative offset to module base
                   is stable across runs even if Wine mapped it rw-COW. */
                bool is_static = (r && r->path[0]);

                if (is_static || level == depth - 1) {
                    /* emit chain */
                    if (c_cnt == c_cap) {
                        c_cap = c_cap ? c_cap * 2 : 64;
                        chains = (chain_t *)realloc(chains, c_cap * sizeof(chain_t));
                    }
                    chain_t *c = &chains[c_cnt++];
                    c->n = n_new;
                    for (int k = 0; k < fr->n; k++) {
                        c->anchors[k] = fr->anchors[k];
                        c->offsets[k] = fr->offsets[k];
                    }
                    c->anchors[fr->n] = a;
                    c->offsets[fr->n] = o;
                }
                if (!is_static && level < depth - 1) {
                    /* keep extending */
                    if (n_cnt == n_cap) {
                        n_cap = n_cap ? n_cap * 2 : 64;
                        next = (frontier_t *)realloc(next, n_cap * sizeof(frontier_t));
                    }
                    frontier_t *nf = &next[n_cnt++];
                    nf->cur_target = a;
                    nf->n = n_new;
                    for (int k = 0; k < fr->n; k++) {
                        nf->anchors[k] = fr->anchors[k];
                        nf->offsets[k] = fr->offsets[k];
                    }
                    nf->anchors[fr->n] = a;
                    nf->offsets[fr->n] = o;
                }
            }
            free(view);
        }
        free(frontier);
        frontier = next;
        f_cnt = n_cnt;
        if (f_cnt == 0) break;
    }
    free(frontier);
    scanner_free(sess);

    fprintf(stderr, "found %zu chains%s\n", c_cnt,
            c_cnt >= MAX_CHAINS ? " (capped, increase target specificity)" : "");

    /* Sort: static (file-backed) anchors first. */
    mr_module_map_t *mm = mr_module_map_build(p);
    char addr_s[300];
    for (size_t i = 0; i < c_cnt; i++) {
        chain_t *c = &chains[i];
        uint64_t root = c->anchors[c->n - 1];
        const mr_region_t *r = rl_find(&regs, root);
        bool stat = (r && r->path[0]);
        format_addr(mm, root, addr_s, sizeof(addr_s));
        printf("  %s [%s]", stat ? "STATIC" : "      ", addr_s);
        for (int k = c->n - 1; k >= 0; k--) {
            printf(" + 0x%-4x", c->offsets[k]);
            if (k > 0) printf(" ->");
        }
        printf("\n");
    }
    mr_module_map_free(mm);

    free(chains);
    free(regs.regions);
    mr_close(p);
    return 0;
}

static int cmd_clear(void) {
    int n = 0;
    if (unlink(STATE_PATH) == 0) n++;
    if (unlink(AOB_PATH)   == 0) n++;
    if (n > 0) fprintf(stderr, "session cleared\n");
    else       fprintf(stderr, "no session to clear\n");
    return 0;
}

static void usage(void) {
    fprintf(stderr,
"macce — macOS native Wine memory reader + scanner\n"
"\n"
"low-level:\n"
"  macce find    <name-substr>\n"
"  macce regions <pid>\n"
"  macce read    <pid> <hex-addr> <length>\n"
"  macce write   <pid> <hex-addr> <hex-bytes>\n"
"  macce bscan   <pid> <hex-bytes> [limit]   (raw byte-pattern scan)\n"
"\n"
"value scanner (saves session to /tmp/macce.session):\n"
"  macce scan    <pid> <type> <op> [value] [value2]\n"
"      type: i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 bytes str wstr\n"
"      op:   eq ne lt le gt ge range unknown\n"
"      e.g. macce scan 1234 i32 eq 100\n"
"           macce scan 1234 f32 range 99.5 100.5\n"
"           macce scan 1234 i32 unknown\n"
"           macce scan 1234 bytes eq \"DE AD ?? BE EF\"\n"
"           macce scan 1234 str   eq \"hello world\"      (UTF-8 bytes)\n"
"           macce scan 1234 wstr  eq \"Notepad\"          (UTF-16LE, Windows native)\n"
"  macce rescan  <op> [value] [value2]\n"
"      op:   eq ne lt le gt ge range changed unchanged inc dec\n"
"      e.g. macce rescan eq 95\n"
"           macce rescan dec\n"
"           macce rescan eq          (bytes: re-check saved pattern)\n"
"           macce rescan ne          (bytes: pattern no longer there)\n"
"  macce list    [offset] [count]\n"
"  macce clear\n"
"\n"
"pointer scan:\n"
"  macce pscan   <pid> <target-hex> [max-offset=0x1000] [depth=1]\n"
"      Find pointer chains terminating at <target>. STATIC anchors are\n"
"      file-backed (typically stable across runs).\n"
"\n"
"ad-hoc signed with debugger entitlement (make handles signing).\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }
    signal(SIGINT, sigint_handler);

    if (!strcmp(argv[1], "find") && argc == 3) {
        pid_t pid;
        if (mr_find_pid(argv[2], &pid) == 0) {
            printf("%d\n", pid);
            return 0;
        }
        fprintf(stderr, "not found\n");
        return 1;
    }

    if (!strcmp(argv[1], "regions") && argc == 3) {
        pid_t pid = (pid_t)atoi(argv[2]);
        mr_process_t *p = NULL;
        if (mr_open(pid, &p) != 0) return 1;
        mr_regions(p, print_region, NULL);
        mr_close(p);
        return 0;
    }

    if (!strcmp(argv[1], "read") && argc == 5) {
        pid_t pid = (pid_t)atoi(argv[2]);
        uint64_t addr = (uint64_t)strtoull(argv[3], NULL, 16);
        size_t n = (size_t)strtoull(argv[4], NULL, 0);
        if (n == 0) { fprintf(stderr, "length must be > 0\n"); return 1; }

        mr_process_t *p = NULL;
        if (mr_open(pid, &p) != 0) return 1;

        uint8_t *buf = (uint8_t *)malloc(n);
        ssize_t got = mr_read(p, addr, buf, n);
        if (got < 0) {
            fprintf(stderr, "read failed at %016" PRIx64 "\n", addr);
            free(buf); mr_close(p);
            return 1;
        }
        hexdump(addr, buf, (size_t)got);
        free(buf);
        mr_close(p);
        return 0;
    }

    if (!strcmp(argv[1], "scan"))   return cmd_scan(argc, argv);
    if (!strcmp(argv[1], "rescan")) return cmd_rescan(argc, argv);
    if (!strcmp(argv[1], "list"))   return cmd_list(argc, argv);
    if (!strcmp(argv[1], "clear"))  return cmd_clear();
    if (!strcmp(argv[1], "pscan"))  return cmd_pscan(argc, argv);
    if (!strcmp(argv[1], "write"))  return cmd_write(argc, argv);

    if (!strcmp(argv[1], "bscan") && (argc == 4 || argc == 5)) {
        pid_t pid = (pid_t)atoi(argv[2]);
        uint8_t *pat = NULL; size_t plen = 0;
        if (parse_hex_bytes(argv[3], &pat, &plen) != 0 || plen == 0) {
            fprintf(stderr, "bad hex pattern\n");
            return 1;
        }
        int limit = (argc == 5) ? atoi(argv[4]) : 32;

        mr_process_t *p = NULL;
        if (mr_open(pid, &p) != 0) { free(pat); return 1; }

        scan_ctx_t ctx = { .p = p, .pat = pat, .patlen = plen,
                           .limit = limit, .hits = 0 };
        mr_regions(p, scan_cb, &ctx);
        fprintf(stderr, "%d hit(s)\n", ctx.hits);

        free(pat);
        mr_close(p);
        return 0;
    }

    usage();
    return 1;
}
