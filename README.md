# MacCE

[![CI](https://github.com/3kyo0/macce/actions/workflows/ci.yml/badge.svg)](https://github.com/3kyo0/macce/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[简体中文 »](README_zh.md)

A native, Cheat-Engine–style memory scanner for **macOS targets running under
any Windows translation layer** — Wine, CrossOver, Whisky, Kegworks,
PlayOnMac, Apple's Game Porting Toolkit, or Game-bundled custom Wine builds.

No SIP disabling. No sudo. No kext. Just an ad-hoc-signed binary with the
`com.apple.security.cs.debugger` entitlement, talking to the kernel via
`task_for_pid` / `mach_vm_*`.

## Why this exists

CheatEngine itself doesn't run natively on macOS; existing scanners
(`scanmem`, `gameconqueror`) are Linux-only. On macOS, anyone who wants
to inspect / scan a Windows program under Wine has historically had to do
it through GDB or write Mach VM glue from scratch. MacCE wraps that into a
GUI that looks and behaves like CE: type/op/value/range scans with rescan
chaining, AOB with wildcards, snapshot-based unknown initial scan, module
map (`notepad.exe+0x4150` rendered in CE-style green for static
addresses), multi-level pointer scan, lock/watch list, and so on.

## Features

| Category | What works |
|---|---|
| Numeric types | i8/i16/i32/i64, u8/u16/u32/u64, f32, f64 |
| Predicates | eq, ne, lt, le, gt, ge, range, unknown (first scan) |
| Rescan predicates | + changed, unchanged, increased, decreased |
| AOB / bytes | hex pattern with `??` wildcards (e.g. `DE AD ?? BE EF`) |
| Strings | UTF-8 (`str`) and UTF-16LE (`wstr` — Windows native, **CJK works**) |
| Region filter | rw-prv / rw-shr / r-- / r-x, aligned/unaligned, module-scoped |
| Snapshot mode | `op=unknown` first scan keeps raw bytes; first rescan diffs |
| Pointer scan | 1–4 level BFS chain finder, static-anchor prioritised |
| Module map | basename + offset display; green for file-backed (static) addrs |
| Lock / Watch | freeze values, periodic refresh |
| Process picker | filters Wine / CrossOver / GPTK / Whisky / Kegworks / Wineskin / .exe |

## Performance

Major optimisations layered on top of the naïve scan:

- **`mach_vm_remap(copy=TRUE)`** — first-scan reads are zero-copy: target
  pages are lazily COW-mapped into our address space; no `mach_vm_read`
  buffer.
- **Aligned stride + per-(type, op) specialised kernels** — `clang -O2`
  auto-vectorises each branch to SSE2/AVX2.
- **Parallel first scan** — region work queue across N=min(ncpu, 8) pthreads,
  thread-local match vectors, one merge + qsort at the end.
- **Parallel rescan** — sorted match array partitioned by index; each thread
  batch-reads up to 64 KiB per `mach_vm_read_overwrite` call.
- **Boyer-Moore-Horspool** skip table for AOB — anchored at the rightmost
  literal byte so wildcard-tail patterns still benefit. Auto-falls back to
  naïve for short or all-wildcard patterns.

On an 8-core Intel Mac, a typical first-scan against a few-GB Wine target
finishes in well under a second; subsequent rescans are near-instant until
the match set is paged out.

## Build

Requirements:
- macOS (Intel; ARM64 should work with minor Mach changes).
- Xcode command-line tools.
- `glfw` from Homebrew: `brew install glfw`.

```sh
make imgui      # one-time: clones ImGui v1.91.5 into gui/third_party/
make            # CLI:  ./macce
make gui        # GUI:  ./macce-gui
```

Both binaries are ad-hoc-signed with the entitlement in `entitlements.plist`.
No `sudo` is needed to attach to your own processes; SIP can stay enabled.

## CLI quick start

```sh
# Find a process by name substring
./macce find notepad

# Dump region map (filter via -- in your shell as needed)
./macce regions <pid>

# First scan: 32-bit int equal to 100
./macce scan <pid> i32 eq 100

# Rescan: value decreased
./macce rescan dec

# String scan (UTF-16LE — Windows native)
./macce scan <pid> wstr eq "Notepad"

# AOB with wildcards
./macce scan <pid> bytes eq "DE AD ?? BE EF"

# Pointer chain finder (target -> static anchor)
./macce pscan <pid> 7ff0deadbeef 0x1000 3

# Read / write
./macce read  <pid> 7ff0deadbeef 64
./macce write <pid> 7ff0deadbeef "01 02 03 04"

./macce list                 # show match preview
./macce clear                # clear saved session at /tmp/macce.session
```

## GUI quick start

1. `./macce-gui`
2. In the process picker, leave **wine only** checked (or untick to see all
   processes). Pick the Wine-hosted `.exe` you want to attach to.
3. Type/op/value → **First scan**.
4. Change the value in the target program → **Rescan** with the relevant
   predicate (`changed`, `decreased`, `eq <new value>`, …).
5. Right-click a result to **lock** or add to **watch**.
6. Static (module-backed) addresses are rendered in green as
   `notepad.exe+0x4150`; dynamic heap/stack addresses stay in normal hex.

### Extending Wine-process detection

If your runtime isn't matched by the built-in patterns
(`wine`, `crossover`, `gameportingtoolkit`, `whisky`, `kegworks`,
`playonmac`, `winebridge`, `wineskin`, `wpreloader`) or a binary that
ends in `.exe`, extend at runtime:

```sh
MACCE_WINE_PATTERNS="mygame:custom_wrapper" ./macce-gui
```

(Colon-separated, case-insensitive substring match against the executable
path.)

## ⚠️ Authorised use only

This tool reads and writes another process's memory. **Only use it against
software you own, software you are authorised to test, or in CTF /
research / educational contexts.**

- Do **not** use it against online games or services with anti-cheat /
  ToS restrictions.
- Targeting commercial multiplayer games with anti-cheat technology
  (Easy Anti-Cheat, BattlEye, NetEase ProtectShield/NP, Vanguard, etc.)
  is very likely to violate the software's Terms of Service. Depending on
  your jurisdiction, it may also violate computer-misuse laws — including
  but not limited to PRC Criminal Law Art. 285/286, US CFAA, UK CMA, and
  equivalent legislation in other jurisdictions.
- The authors and contributors accept no responsibility for misuse.

The intended use cases are: reversing software you own, single-player
offline games, CTF practice, exam targets, debugging your own Wine app,
and similar.

## License

MIT — see [`LICENSE`](LICENSE).

## Third-party

- [Dear ImGui](https://github.com/ocornut/imgui) (MIT), pinned to v1.91.5.
- [GLFW](https://www.glfw.org/) (zlib/libpng), via Homebrew.
