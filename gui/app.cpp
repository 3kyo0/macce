#include "app.h"
#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>

/* ---------- helpers ---------- */

/* TYPE_LABELS[0..ST__COUNT-1] mirror scan_type_t. Indices ST__COUNT and
   ST__COUNT+1 are UI-only string aliases that scan as ST_BYTES. */
static const int UI_STR_IDX  = (int)ST__COUNT;       /* "str"  (UTF-8) */
static const int UI_WSTR_IDX = (int)ST__COUNT + 1;   /* "wstr" (UTF-16LE) */

static const char *TYPE_LABELS[] = {
    "i8","i16","i32","i64","u8","u16","u32","u64","f32","f64","bytes",
    "str","wstr"
};
static const char *OP_FIRST_LABELS[] = {
    "eq","ne","lt","le","gt","ge","range","unknown"
};
/* indices 0..7 are first-scan ops, 8..11 are rescan-only ops */
static const char *OP_RESCAN_LABELS[] = {
    "eq","ne","lt","le","gt","ge","range",
    "changed","unchanged","inc","dec"
};

static double now_seconds() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

/* Parse "DE AD ?? BE EF" into bytes + optional mask. */
static bool parse_aob(const char *s,
                      std::vector<uint8_t> &bytes,
                      std::vector<uint8_t> &mask,
                      bool &has_mask)
{
    bytes.clear(); mask.clear(); has_mask = false;
    int hi = -1; bool hi_w = false;
    for (; *s; s++) {
        if (std::isspace((unsigned char)*s)) continue;
        int v; bool wild = false;
        if      (*s == '?')              { v = 0; wild = true; has_mask = true; }
        else if (*s >= '0' && *s <= '9')  v = *s - '0';
        else if (*s >= 'a' && *s <= 'f')  v = 10 + *s - 'a';
        else if (*s >= 'A' && *s <= 'F')  v = 10 + *s - 'A';
        else return false;
        if (hi < 0) { hi = v; hi_w = wild; }
        else {
            bytes.push_back((uint8_t)((hi << 4) | v));
            uint8_t mb = 0;
            if (!hi_w)  mb |= 0xF0;
            if (!wild)  mb |= 0x0F;
            mask.push_back(mb);
            hi = -1;
        }
    }
    if (hi >= 0) return false;
    if (!has_mask) mask.clear();
    return !bytes.empty();
}

static bool parse_value(scan_type_t t, const char *s, scan_operand_t &op, int slot) {
    char *end = nullptr;
    auto *target = (slot == 0) ? &op.v1 : &op.v2;
    switch (t) {
        case ST_I8: case ST_I16: case ST_I32: case ST_I64: {
            int64_t v = strtoll(s, &end, 0);
            if (!end || *end) return false;
            target->i = v; return true;
        }
        case ST_U8: case ST_U16: case ST_U32: case ST_U64: {
            uint64_t v = strtoull(s, &end, 0);
            if (!end || *end) return false;
            target->u = v; return true;
        }
        case ST_F32: case ST_F64: {
            double v = strtod(s, &end);
            if (!end || *end) return false;
            target->f = v; return true;
        }
        default: return false;
    }
}

static void format_value(scan_type_t t, uint64_t packed, char *out, size_t cap) {
    switch (t) {
        case ST_I8:  snprintf(out, cap, "%d",   (int)(int8_t)packed); break;
        case ST_I16: snprintf(out, cap, "%d",   (int)(int16_t)packed); break;
        case ST_I32: snprintf(out, cap, "%d",   (int)(int32_t)packed); break;
        case ST_I64: snprintf(out, cap, "%lld", (long long)(int64_t)packed); break;
        case ST_U8:  snprintf(out, cap, "%u",   (unsigned)(uint8_t)packed); break;
        case ST_U16: snprintf(out, cap, "%u",   (unsigned)(uint16_t)packed); break;
        case ST_U32: snprintf(out, cap, "%u",   (unsigned)(uint32_t)packed); break;
        case ST_U64: snprintf(out, cap, "%llu", (unsigned long long)packed); break;
        case ST_F32: { uint32_t b=(uint32_t)packed; float f; std::memcpy(&f,&b,4);
                       snprintf(out, cap, "%g", (double)f); break; }
        case ST_F64: { double d; std::memcpy(&d, &packed, 8);
                       snprintf(out, cap, "%g", d); break; }
        case ST_BYTES: {
            uint8_t b[8]; std::memcpy(b, &packed, 8);
            char ascii[9]; for (int i = 0; i < 8; i++)
                ascii[i] = (b[i] >= 32 && b[i] < 127) ? (char)b[i] : '.';
            ascii[8] = 0;
            snprintf(out, cap,
                     "%02x %02x %02x %02x %02x %02x %02x %02x |%s|",
                     b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], ascii);
            break;
        }
        default: snprintf(out, cap, "?"); break;
    }
}

/* Heuristic for "this is a Windows program running under a translation
   layer". Covers any Wine fork / wrapper, not just CrossOver-based:
     - Plain Homebrew Wine, MacPorts Wine
     - CrossOver (Codeweavers)
     - Whisky, Kegworks, PlayOnMac
     - Apple Game Porting Toolkit (GPTK)  — does NOT contain "wine" in path
     - NetEase / Tencent / etc. game-bundled wine wrappers
     - Any process whose executable basename ends with .exe (strong signal)
   Use case-insensitive substring match. User can extend via the
   MACCE_WINE_PATTERNS env var (colon-separated). */
static bool is_wine_process(const char *name, const char *path) {
    if (!name) name = "";
    if (!path) path = "";

    /* .exe binary running natively on macOS is almost certainly under a
       translation layer. */
    size_t nlen = std::strlen(name);
    if (nlen >= 4 && strcasecmp(name + nlen - 4, ".exe") == 0) return true;

    static const char *patterns[] = {
        "wine",                /* catches /wine/, wine64, wineloader,
                                  wineserver, wine-preloader, etc. */
        "crossover",
        "gameportingtoolkit",  /* Apple GPTK */
        "whisky",
        "kegworks",
        "playonmac",
        "winebridge",
        "wineskin",
        "wpreloader",
        NULL,
    };
    for (int i = 0; patterns[i]; i++)
        if (strcasestr(path, patterns[i])) return true;

    /* User-extensible: e.g. MACCE_WINE_PATTERNS="mygame:custom_wrapper" */
    const char *extra = std::getenv("MACCE_WINE_PATTERNS");
    if (extra && *extra) {
        char buf[1024];
        std::strncpy(buf, extra, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = 0;
        for (char *tok = std::strtok(buf, ":"); tok; tok = std::strtok(NULL, ":"))
            if (*tok && strcasestr(path, tok)) return true;
    }
    return false;
}

/* ---------- ctor / dtor ---------- */

App::App() {
    refresh_process_list();
}

App::~App() {
    if (worker.joinable()) {
        scan_cancel = true;
        worker.join();
    }
    detach();
}

/* ---------- process list ---------- */

static int proc_collect_cb(pid_t pid, const char *name, const char *path, void *ud) {
    auto *v = reinterpret_cast<std::vector<ProcEntry>*>(ud);
    ProcEntry e;
    e.pid     = pid;
    e.name    = name;
    e.path    = path;
    e.is_wine = is_wine_process(name, path);
    v->push_back(std::move(e));
    return 0;
}

void App::refresh_process_list() {
    procs.clear();
    mr_list_processes(proc_collect_cb, &procs);
    std::sort(procs.begin(), procs.end(),
              [](const ProcEntry &a, const ProcEntry &b) {
                  if (a.is_wine != b.is_wine) return a.is_wine; /* wine first */
                  return a.name < b.name;
              });
}

/* ---------- attach / detach ---------- */

void App::attach(pid_t pid, const std::string &name) {
    detach();
    mr_process_t *p = nullptr;
    if (mr_open(pid, &p) != 0) {
        last_error = "task_for_pid failed (need entitlement / SIP)";
        return;
    }
    proc      = p;
    cur_pid   = pid;
    cur_name  = name;
    session   = scanner_new(proc);
    mods      = mr_module_map_build(proc);
    results_dirty = true;
    last_error.clear();
}

void App::detach() {
    if (worker.joinable()) { scan_cancel = true; worker.join(); }
    if (session) { scanner_free(session); session = nullptr; }
    if (mods)    { mr_module_map_free(mods); mods = nullptr; }
    if (proc)    { mr_close(proc); proc = nullptr; }
    cur_pid = 0;
    cur_name.clear();
    results_cache.clear();
    watches.clear();
}

/* ---------- scan threading ---------- */

int App::scan_session_progress(uint64_t done, uint64_t total, void *ud) {
    auto *a = reinterpret_cast<App*>(ud);
    a->scan_done.store(done);
    a->scan_total.store(total);
    return a->scan_cancel.load() ? 1 : 0;
}

static int32_t utf8_decode_one(const char *s, int *adv) {
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

static void encode_str_utf8(const char *s, std::vector<uint8_t> &out) {
    size_t n = std::strlen(s);
    out.assign((const uint8_t *)s, (const uint8_t *)s + n);
}

/* UTF-8 input -> UTF-16LE bytes. Drops on invalid sequence (leaves partial). */
static bool encode_str_utf16le(const char *s, std::vector<uint8_t> &out) {
    out.clear();
    const char *p = s;
    while (*p) {
        int adv = 0;
        int32_t cp = utf8_decode_one(p, &adv);
        if (cp < 0 || adv == 0) return false;
        if (cp <= 0xFFFF) {
            if (cp >= 0xD800 && cp <= 0xDFFF) return false;
            out.push_back((uint8_t)(cp & 0xFF));
            out.push_back((uint8_t)((cp >> 8) & 0xFF));
        } else {
            uint32_t v = cp - 0x10000;
            uint16_t hi = 0xD800 | (v >> 10);
            uint16_t lo = 0xDC00 | (v & 0x3FF);
            out.push_back((uint8_t)(hi & 0xFF));
            out.push_back((uint8_t)((hi >> 8) & 0xFF));
            out.push_back((uint8_t)(lo & 0xFF));
            out.push_back((uint8_t)((lo >> 8) & 0xFF));
        }
        p += adv;
    }
    return true;
}

void App::start_scan(bool rescan) {
    if (!session || scan_running.load()) return;

    /* Translate UI-only string types to bytes + remember pattern. */
    bool string_mode = false;
    bool string_wide = false;
    scan_type_t t;
    if (ui_type == UI_STR_IDX)       { t = ST_BYTES; string_mode = true; string_wide = false; }
    else if (ui_type == UI_WSTR_IDX) { t = ST_BYTES; string_mode = true; string_wide = true;  }
    else if (ui_type >= 0 && ui_type < (int)ST__COUNT) { t = (scan_type_t)ui_type; }
    else                              { last_error = "bad type"; return; }
    scan_predicate_t op;
    if (rescan) {
        static const scan_predicate_t MAP[] = {
            SP_EQ, SP_NE, SP_LT, SP_LE, SP_GT, SP_GE, SP_RANGE,
            SP_CHANGED, SP_UNCHANGED, SP_INCREASED, SP_DECREASED
        };
        if (ui_op < 0 || ui_op >= (int)(sizeof(MAP)/sizeof(MAP[0]))) return;
        op = MAP[ui_op];
    } else {
        static const scan_predicate_t MAP[] = {
            SP_EQ, SP_NE, SP_LT, SP_LE, SP_GT, SP_GE, SP_RANGE, SP_UNKNOWN
        };
        if (ui_op < 0 || ui_op >= (int)(sizeof(MAP)/sizeof(MAP[0]))) return;
        op = MAP[ui_op];
    }

    scan_operand_t operand{};

    if (t == ST_BYTES) {
        if (!rescan) {
            if (string_mode) {
                if (string_wide) {
                    if (!encode_str_utf16le(val1_buf, aob_bytes)) {
                        last_error = "invalid UTF-8 input";
                        return;
                    }
                } else {
                    encode_str_utf8(val1_buf, aob_bytes);
                }
                aob_mask.clear();
                aob_has_mask = false;
                if (aob_bytes.empty()) { last_error = "empty string"; return; }
            } else if (!parse_aob(val1_buf, aob_bytes, aob_mask, aob_has_mask)) {
                last_error = "bad AOB pattern";
                return;
            }
            if (op != SP_EQ) { last_error = "bytes/string first scan: only eq"; return; }
        } else {
            if (aob_bytes.empty()) { last_error = "no pattern; do first scan first"; return; }
            if (op != SP_EQ && op != SP_NE) { last_error = "bytes/string rescan: eq or ne"; return; }
        }
        operand.bytes     = aob_bytes.data();
        operand.mask      = aob_has_mask ? aob_mask.data() : nullptr;
        operand.bytes_len = aob_bytes.size();
    } else {
        bool needs_v1 = !(op == SP_UNKNOWN
                          || op == SP_CHANGED || op == SP_UNCHANGED
                          || op == SP_INCREASED || op == SP_DECREASED);
        if (needs_v1 && !parse_value(t, val1_buf, operand, 0)) {
            last_error = "bad value";
            return;
        }
        if (op == SP_RANGE && !parse_value(t, val2_buf, operand, 1)) {
            last_error = "bad upper value";
            return;
        }
    }

    scan_filter_t filter{};
    filter.include_rw_private = flt_rw_private;
    filter.include_rw_shared  = flt_rw_shared;
    filter.include_ro         = flt_ro;
    filter.include_rx         = flt_rx;
    filter.max_region_bytes   = (size_t)1 << 30;
    filter.aligned            = flt_aligned;

    /* Module scope: when a specific module is selected, restrict the scan
       to that module's [lo, hi) address range. Also implicitly include the
       module's read-only / executable regions since modules typically span
       multiple protection classes (Wine COW-maps .data as rw-prv but .text
       is r-x, .rodata is r--). */
    size_t nmods = mr_module_map_count(mods);
    if (flt_module_idx > 0 && (size_t)flt_module_idx <= nmods) {
        uint64_t lo = 0, hi = 0;
        const char *n = mr_module_map_name(mods, flt_module_idx - 1);
        if (mr_module_map_range(mods, n, &lo, &hi) == 0) {
            filter.addr_min = lo;
            filter.addr_max = hi;
            filter.include_ro = true;
            filter.include_rx = true;
        }
    }

    if (worker.joinable()) worker.join();

    scan_running = true;
    scan_cancel  = false;
    is_rescan    = rescan;
    scan_done    = 0;
    scan_total   = 0;
    last_error.clear();

    /* copy by value so the thread is self-contained */
    worker = std::thread([this, t, op, operand, filter, rescan]() {
        if (rescan) {
            scanner_next_scan(session, op, &operand, &App::scan_session_progress, this);
        } else {
            scanner_first_scan(session, t, op, &operand, &filter,
                               &App::scan_session_progress, this);
        }
        scan_running = false;
    });
}

void App::cancel_scan() { scan_cancel = true; }

void App::clear_scan() {
    if (worker.joinable()) { scan_cancel = true; worker.join(); }
    if (session) scanner_clear(session);
    results_cache.clear();
    results_dirty = true;
}

/* ---------- watches ---------- */

void App::add_watch(uint64_t addr) {
    WatchEntry w{};
    w.addr  = addr;
    w.type  = (scan_type_t)ui_type;
    w.note  = watch_note_buf;
    watches.push_back(std::move(w));
}

void App::refresh_watches() {
    if (!proc) return;
    double now = now_seconds();
    if (now - last_watch_refresh < (1.0 / watch_refresh_hz)) return;
    last_watch_refresh = now;

    for (auto &w : watches) {
        size_t tsize = scanner_type_size(w.type);
        uint8_t buf[8] = {0};
        ssize_t got = mr_read(proc, w.addr, buf, tsize);
        if (got == (ssize_t)tsize) {
            w.current_value = 0;
            std::memcpy(&w.current_value, buf, tsize);
            w.current_valid = true;
            if (w.locked && w.current_value != w.locked_value) {
                /* re-write the locked value */
                uint8_t out[8] = {0};
                std::memcpy(out, &w.locked_value, tsize);
                mr_write(proc, w.addr, out, tsize);
            }
        } else {
            w.current_valid = false;
        }
    }
}

void App::draw_address_cell(uint64_t addr) {
    uint64_t off = 0;
    const char *mod = mods ? mr_module_map_resolve(mods, addr, &off) : nullptr;
    char text[256];
    if (mod) {
        snprintf(text, sizeof(text), "%s+0x%llx", mod, (unsigned long long)off);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.40f, 1.0f, 0.40f, 1.0f));
        ImGui::TextUnformatted(text);
        ImGui::PopStyleColor();
    } else {
        snprintf(text, sizeof(text), "%016llx", (unsigned long long)addr);
        ImGui::TextUnformatted(text);
    }
    if (ImGui::IsItemHovered()) {
        if (mod) ImGui::SetTooltip("static: %s + 0x%llx\nabsolute: %016llx",
                                    mod, (unsigned long long)off, (unsigned long long)addr);
        else     ImGui::SetTooltip("dynamic (heap/stack)\n%016llx", (unsigned long long)addr);
    }
}

/* ---------- draw ---------- */

void App::draw() {
    /* refresh watches each frame (throttled internally) */
    refresh_watches();

    /* invalidate results cache if scan just finished */
    static bool prev_running = false;
    bool now_running = scan_running.load();
    if (prev_running && !now_running) {
        results_dirty = true;
    }
    prev_running = now_running;

    draw_menu();

    /* Full-window layout: process picker left, main area right, watch bottom. */
    ImGuiViewport *vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##root", nullptr,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize
                 | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse
                 | ImGuiWindowFlags_NoBringToFrontOnFocus);

    float total_w = ImGui::GetContentRegionAvail().x;
    float total_h = ImGui::GetContentRegionAvail().y;
    float left_w  = 280.0f;
    float bottom_h = 200.0f;

    ImGui::BeginChild("##left", ImVec2(left_w, total_h - bottom_h), true);
    draw_process_picker();
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##right", ImVec2(total_w - left_w - 8, total_h - bottom_h), false);
    draw_scan_panel();
    ImGui::Separator();
    draw_filter_panel();
    ImGui::Separator();
    draw_results_panel();
    ImGui::EndChild();

    ImGui::BeginChild("##bottom", ImVec2(0, 0), true);
    draw_watch_panel();
    ImGui::EndChild();

    ImGui::End();
}

void App::draw_menu() {
    if (!last_error.empty()) {
        ImGui::GetForegroundDrawList()->AddText(
            ImVec2(10, 10), IM_COL32(255, 80, 80, 255), last_error.c_str());
    }
}

void App::draw_process_picker() {
    ImGui::Text("Processes");
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh")) refresh_process_list();
    ImGui::SameLine();
    ImGui::Checkbox("wine only", &show_wine_only);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip(
            "Filter to Wine / CrossOver / GPTK / Whisky / Kegworks /\n"
            "PlayOnMac / Wineskin / GameBundled-Wine processes, or any\n"
            "binary whose name ends with .exe.\n\n"
            "Extend with env var, e.g.:\n"
            "  MACCE_WINE_PATTERNS=\"mygame:custom_wrapper\" ./macce-gui");
    ImGui::InputText("##search", proc_search, sizeof(proc_search));
    ImGui::Separator();

    if (cur_pid) {
        ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.5f, 1.0f),
                           "attached: %s (%d)", cur_name.c_str(), cur_pid);
        if (ImGui::SmallButton("Detach")) detach();
        ImGui::Separator();
    }

    ImGui::BeginChild("##proclist");
    for (const auto &e : procs) {
        if (show_wine_only && !e.is_wine) continue;
        if (proc_search[0]) {
            if (e.name.find(proc_search) == std::string::npos) continue;
        }
        char label[256];
        snprintf(label, sizeof(label), "%-30s  %d", e.name.c_str(), e.pid);
        bool sel = (e.pid == cur_pid);
        if (ImGui::Selectable(label, sel)) {
            attach(e.pid, e.name);
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("%s", e.path.c_str());
        }
    }
    ImGui::EndChild();
}

void App::draw_scan_panel() {
    ImGui::Text("Scan");

    ImGui::SetNextItemWidth(80);
    ImGui::Combo("type", &ui_type, TYPE_LABELS, IM_ARRAYSIZE(TYPE_LABELS));
    ImGui::SameLine();

    bool has_results = session && scanner_match_count(session) > 0;
    const char *const *ops = has_results ? OP_RESCAN_LABELS : OP_FIRST_LABELS;
    int op_count = has_results ? (int)(sizeof(OP_RESCAN_LABELS)/sizeof(OP_RESCAN_LABELS[0]))
                                : (int)(sizeof(OP_FIRST_LABELS)/sizeof(OP_FIRST_LABELS[0]));
    if (ui_op >= op_count) ui_op = 0;

    ImGui::SetNextItemWidth(110);
    ImGui::Combo("op", &ui_op, ops, op_count);

    /* Value inputs. */
    const char *op_name = ops[ui_op];
    bool needs_v1 = !(std::strcmp(op_name, "unknown") == 0
                      || std::strcmp(op_name, "changed") == 0
                      || std::strcmp(op_name, "unchanged") == 0
                      || std::strcmp(op_name, "inc") == 0
                      || std::strcmp(op_name, "dec") == 0);
    bool is_range = (std::strcmp(op_name, "range") == 0);

    ImGui::SameLine();
    ImGui::SetNextItemWidth(140);
    ImGui::BeginDisabled(!needs_v1);
    ImGui::InputText("value", val1_buf, sizeof(val1_buf));
    ImGui::EndDisabled();

    if (is_range) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(140);
        ImGui::InputText("..to", val2_buf, sizeof(val2_buf));
    }

    /* Buttons. */
    ImGui::BeginDisabled(!session || scan_running.load());
    if (ImGui::Button(has_results ? "Rescan" : "First scan",
                      ImVec2(120, 0))) {
        start_scan(has_results);
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!has_results || scan_running.load());
    if (ImGui::Button("New scan")) clear_scan();
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!scan_running.load());
    if (ImGui::Button("Cancel")) cancel_scan();
    ImGui::EndDisabled();

    /* Progress + status. */
    if (scan_running.load()) {
        uint64_t d = scan_done.load(), t = scan_total.load();
        float frac = t ? (float)((double)d / (double)t) : 0.0f;
        char buf[128];
        snprintf(buf, sizeof(buf), "%.1f / %.1f MB",
                 d / 1048576.0, t / 1048576.0);
        ImGui::SameLine();
        ImGui::ProgressBar(frac, ImVec2(200, 0), buf);
    } else if (session) {
        ImGui::SameLine();
        if (scanner_in_snapshot(session)) {
            ImGui::TextColored(ImVec4(1.0f, 0.9f, 0.4f, 1.0f),
                "snapshot %.1f MB — rescan to materialize",
                scanner_snapshot_bytes(session) / 1048576.0);
        } else {
            ImGui::Text("matches: %zu", scanner_match_count(session));
        }
    }
}

void App::draw_filter_panel() {
    ImGui::Text("Filter:");
    ImGui::SameLine();
    ImGui::Checkbox("rw-prv (heap/stack)", &flt_rw_private);
    ImGui::SameLine();
    ImGui::Checkbox("rw-shr", &flt_rw_shared);
    ImGui::SameLine();
    ImGui::Checkbox("r--", &flt_ro);
    ImGui::SameLine();
    ImGui::Checkbox("r-x (code)", &flt_rx);
    ImGui::SameLine();
    ImGui::Checkbox("aligned", &flt_aligned);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Only check addresses where (addr %% typesize) == 0.\n"
                          "4-8x faster. CE default. Uncheck for unaligned scan.");

    /* Module scope dropdown. Lets the user restrict scanning to a single
       loaded module's address range — useful for narrowing down e.g. the
       Wine notepad.exe image. */
    ImGui::Text("Module:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(260.0f);
    size_t nmods = mr_module_map_count(mods);
    const char *cur_label = (flt_module_idx == 0 || (size_t)flt_module_idx > nmods)
                                ? "(all)"
                                : mr_module_map_name(mods, flt_module_idx - 1);
    if (ImGui::BeginCombo("##modscope", cur_label)) {
        if (ImGui::Selectable("(all)", flt_module_idx == 0))
            flt_module_idx = 0;
        for (size_t i = 0; i < nmods; i++) {
            const char *n = mr_module_map_name(mods, i);
            bool selected = (flt_module_idx == (int)(i + 1));
            if (ImGui::Selectable(n, selected))
                flt_module_idx = (int)(i + 1);
            if (selected) ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
    if (flt_module_idx > 0 && (size_t)flt_module_idx <= nmods) {
        uint64_t lo = 0, hi = 0;
        const char *n = mr_module_map_name(mods, flt_module_idx - 1);
        if (mr_module_map_range(mods, n, &lo, &hi) == 0) {
            ImGui::SameLine();
            ImGui::TextDisabled("[%016llx, %016llx)  %.1f MB",
                                (unsigned long long)lo,
                                (unsigned long long)hi,
                                (hi - lo) / 1048576.0);
        }
    }
}

void App::draw_results_panel() {
    ImGui::Text("Results");
    if (!session) { ImGui::TextDisabled("(attach to a process first)"); return; }

    if (scanner_in_snapshot(session)) {
        ImGui::TextDisabled("(snapshot mode — no individual matches yet; "
                            "run rescan with changed/unchanged/inc/dec/eq/range)");
        return;
    }

    size_t total = scanner_match_count(session);
    if (total == 0) {
        ImGui::TextDisabled("(no matches yet)");
        return;
    }

    /* Refresh cache periodically (every 200ms) or when dirty. */
    double now = now_seconds();
    if (results_dirty || (now - last_results_refresh > 0.2)) {
        last_results_refresh = now;
        results_dirty = false;
        size_t max_show = total < 5000 ? total : 5000;
        results_cache.resize(max_show);
        scanner_get_matches(session, 0, max_show, results_cache.data(), true);
    }

    if (ImGui::BeginTable("results", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg
            | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Current");
        ImGui::TableSetupColumn("Previous");
        ImGui::TableSetupColumn("");
        ImGui::TableHeadersRow();

        scan_type_t t = scanner_current_type(session);

        ImGuiListClipper clip;
        clip.Begin((int)results_cache.size());
        while (clip.Step()) {
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
                const auto &v = results_cache[i];
                char cur_s[64], prev_s[64];
                if (v.current_valid)
                    format_value(t, v.current_value, cur_s, sizeof(cur_s));
                else
                    snprintf(cur_s, sizeof(cur_s), "??");
                format_value(t, v.old_value, prev_s, sizeof(prev_s));

                ImGui::TableNextRow();
                ImGui::PushID(i);
                ImGui::TableSetColumnIndex(0);
                draw_address_cell(v.addr);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(cur_s);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(prev_s);
                ImGui::TableSetColumnIndex(3);
                if (ImGui::SmallButton("→watch")) {
                    add_watch(v.addr);
                }
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }

    if (total > results_cache.size()) {
        ImGui::TextDisabled("(showing first %zu of %zu)",
                            results_cache.size(), total);
    }
}

void App::draw_watch_panel() {
    ImGui::Text("Watches  (%zu)", watches.size());
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##goto", "0x... addr to add", goto_addr_buf, sizeof(goto_addr_buf));
    ImGui::SameLine();
    if (ImGui::Button("Add")) {
        uint64_t a = strtoull(goto_addr_buf, nullptr, 16);
        if (a) add_watch(a);
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##note", "note (optional)", watch_note_buf, sizeof(watch_note_buf));

    if (ImGui::BeginTable("watches", 6,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg
                          | ImGuiTableFlags_ScrollY))
    {
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupColumn("Value");
        ImGui::TableSetupColumn("Locked", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("Note");
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < watches.size(); ) {
            auto &w = watches[i];
            ImGui::TableNextRow();
            ImGui::PushID((int)i);

            ImGui::TableSetColumnIndex(0);
            draw_address_cell(w.addr);
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%s", TYPE_LABELS[(int)w.type]);

            ImGui::TableSetColumnIndex(2);
            char buf[64];
            if (w.current_valid) {
                if (w.locked) {
                    format_value(w.type, w.locked_value, buf, sizeof(buf));
                    ImGui::SetNextItemWidth(120);
                    if (ImGui::InputText("##val", buf, sizeof(buf),
                                         ImGuiInputTextFlags_EnterReturnsTrue)) {
                        scan_operand_t op{};
                        if (parse_value(w.type, buf, op, 0)) {
                            uint64_t pv = 0;
                            std::memcpy(&pv, &op.v1, scanner_type_size(w.type));
                            w.locked_value = pv;
                        }
                    }
                } else {
                    format_value(w.type, w.current_value, buf, sizeof(buf));
                    ImGui::Text("%s", buf);
                }
            } else {
                ImGui::TextDisabled("??");
            }

            ImGui::TableSetColumnIndex(3);
            bool locked = w.locked;
            if (ImGui::Checkbox("##lock", &locked)) {
                w.locked = locked;
                if (locked) w.locked_value = w.current_value;
            }

            ImGui::TableSetColumnIndex(4);
            ImGui::Text("%s", w.note.c_str());

            ImGui::TableSetColumnIndex(5);
            bool removed = false;
            if (ImGui::SmallButton("Del")) {
                watches.erase(watches.begin() + (long)i);
                removed = true;
            }
            ImGui::PopID();
            if (!removed) ++i;
        }
        ImGui::EndTable();
    }
}
