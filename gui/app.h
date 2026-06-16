#pragma once

#include <atomic>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>

extern "C" {
#include "memreader.h"
#include "scanner.h"
}

struct ProcEntry {
    pid_t       pid;
    std::string name;
    std::string path;
    bool        is_wine;
};

struct WatchEntry {
    uint64_t    addr;
    scan_type_t type;
    uint64_t    locked_value;   /* packed LE */
    bool        locked;
    /* freshly read value, updated by refresh */
    uint64_t    current_value;
    bool        current_valid;
    std::string note;
};

class App {
public:
    App();
    ~App();
    void draw();                /* called once per frame */

private:
    /* layout panels */
    void draw_menu();
    void draw_process_picker();
    void draw_scan_panel();
    void draw_filter_panel();
    void draw_results_panel();
    void draw_watch_panel();

    /* actions */
    void refresh_process_list();
    void attach(pid_t pid, const std::string &name);
    void detach();
    void start_scan(bool rescan);
    void cancel_scan();
    void clear_scan();
    void add_watch(uint64_t addr);
    void refresh_watches();
    static int  scan_session_progress(uint64_t done, uint64_t total, void *ud);

    /* Render an address cell with CE-style coloring: green "<mod>+0xOFF"
       for static (file-backed) addresses, default for dynamic. */
    void draw_address_cell(uint64_t addr);

    /* process / session */
    pid_t              cur_pid = 0;
    std::string        cur_name;
    mr_process_t      *proc = nullptr;
    scan_session_t    *session = nullptr;
    mr_module_map_t   *mods = nullptr;   /* for static address coloring */

    /* process list */
    std::vector<ProcEntry> procs;
    char                   proc_search[128] = "";
    bool                   show_wine_only = true;

    /* scan inputs */
    int  ui_type = (int)ST_I32;
    int  ui_op   = (int)SP_EQ;
    char val1_buf[256] = "0";
    char val2_buf[64]  = "0";
    /* AOB operand storage (owned by App so background scan thread can use it). */
    std::vector<uint8_t> aob_bytes;
    std::vector<uint8_t> aob_mask;
    bool                 aob_has_mask = false;

    /* filter */
    bool flt_rw_private = true;
    bool flt_rw_shared  = false;
    bool flt_ro         = false;
    bool flt_rx         = false;
    bool flt_aligned    = true;   /* CE default: 4-8x faster first scan */
    int  flt_module_idx = 0;      /* 0 = all modules; otherwise (idx-1) into mods */

    /* worker thread state */
    std::thread          worker;
    std::atomic<bool>    scan_running {false};
    std::atomic<bool>    scan_cancel  {false};
    std::atomic<bool>    is_rescan    {false};
    std::atomic<uint64_t> scan_done   {0};
    std::atomic<uint64_t> scan_total  {0};
    std::string          last_error;

    /* results virtualization */
    bool   results_dirty = true;
    std::vector<scan_match_view_t> results_cache;
    double last_results_refresh = 0.0;

    /* watch list */
    std::vector<WatchEntry> watches;
    double last_watch_refresh = 0.0;
    double watch_refresh_hz = 10.0;

    /* misc */
    char  goto_addr_buf[32] = "";
    char  watch_note_buf[128] = "";
};
