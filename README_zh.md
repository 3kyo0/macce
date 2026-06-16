# MacCE

[![CI](https://github.com/3kyo0/macce/actions/workflows/ci.yml/badge.svg)](https://github.com/3kyo0/macce/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

macOS 原生的 Cheat Engine 风格内存扫描器，专门面向**在任意 Windows 翻译层下运行的目标进程**——Wine、CrossOver、Whisky、Kegworks、PlayOnMac、Apple 的 Game Porting Toolkit (GPTK)，以及游戏自带的私有 Wine。

无需关闭 SIP、无需 sudo、无需 kext。仅靠一个 ad-hoc 签名 + `com.apple.security.cs.debugger` entitlement 的二进制，通过 `task_for_pid` / `mach_vm_*` 与内核打交道。

[English README »](README.md)

## 为什么会有这个项目

CheatEngine 本身没有 macOS 原生版本；现存的 `scanmem` / `gameconqueror` 只跑在 Linux 上。在 macOS 上想检查、扫描一个 Wine 下的 Windows 程序，过去要么 GDB 手撕、要么从零写 Mach VM 胶水。MacCE 把这套封成一个 CE 风格的 GUI：类型/谓词/值/区间扫描 + rescan 链式过滤，AOB 含通配符，snapshot 模式应对"未知初值"，模块地址映射（`notepad.exe+0x4150` 这种静态地址用 CE 同款绿色显示），多级指针扫描，锁定/监视列表，等等。

## 功能特性

| 类别 | 支持内容 |
|---|---|
| 数值类型 | i8/i16/i32/i64、u8/u16/u32/u64、f32、f64 |
| 谓词（首次扫描） | eq、ne、lt、le、gt、ge、range、unknown |
| 谓词（rescan） | 上述 + changed、unchanged、increased、decreased |
| AOB / 字节模式 | 含 `??` 通配符的十六进制模式，如 `DE AD ?? BE EF` |
| 字符串扫描 | UTF-8 (`str`) 与 UTF-16LE (`wstr`，Windows 原生，**中文/CJK 正常**) |
| 区域过滤 | rw-prv / rw-shr / r-- / r-x，对齐/非对齐，按模块限定范围 |
| Snapshot 模式 | `op=unknown` 首次扫描保留原始字节，首次 rescan 时做差分 |
| 指针扫描 | 1–4 级 BFS 链路搜索，优先返回带静态锚点的链 |
| 模块映射 | 显示 `<模块名>+0x偏移`；file-backed 静态地址绿色高亮 |
| 锁定 / 监视 | 数值冻结、周期刷新 |
| 进程选择器 | 自动识别 Wine / CrossOver / GPTK / Whisky / Kegworks / Wineskin / `.exe` |

## 性能优化（相对朴素扫描的累计提升）

- **`mach_vm_remap(copy=TRUE)`** —— 首次扫描零拷贝：目标页用 lazy COW 映射进我们的地址空间，没有 `mach_vm_read` 缓冲。
- **对齐步进 + 按 (类型, op) 特化的内核** —— `clang -O2` 把每个分支自动向量化到 SSE2 / AVX2。
- **首次扫描并行化** —— region 工作队列被 `min(cpu核数, 8)` 个 pthread 抢占式消费，每线程独立 match 容器，最后合并 + qsort 一次。
- **rescan 并行化** —— 已排序的 match 数组按区间等分给多线程，每线程一次 `mach_vm_read_overwrite` 批量读最多 64 KiB 跨度。
- **Boyer-Moore-Horspool** AOB 跳表 —— 锚定在模式最右侧的字面值字节，所以即使尾部带通配符也能享受跳表加速。短模式/纯通配符自动回落到朴素扫描，无回归。

在 8 核 Intel Mac 上，针对几 GB 的 Wine 目标，首次扫描通常一秒以内就能完成；后续 rescan 几乎瞬时。

## 编译

依赖：
- macOS（Intel；ARM64 需小幅 Mach 适配）。
- Xcode 命令行工具。
- Homebrew 装 `glfw`：`brew install glfw`。

```sh
make imgui      # 一次性：克隆 ImGui v1.91.5 到 gui/third_party/
make            # CLI:  ./macce
make gui        # GUI:  ./macce-gui
```

两个二进制都会用 `entitlements.plist` 做 ad-hoc 签名。**附加到你自己的进程不需要 sudo，SIP 也可以保持开启。**

## CLI 速查

```sh
# 按名字子串找 pid
./macce find notepad

# region 表
./macce regions <pid>

# 首次扫描：32 位整数等于 100
./macce scan <pid> i32 eq 100

# Rescan：数值变小了
./macce rescan dec

# 字符串扫描（UTF-16LE，Windows 原生编码）
./macce scan <pid> wstr eq "记事本"

# 含通配符的 AOB
./macce scan <pid> bytes eq "DE AD ?? BE EF"

# 指针链回溯：从动态地址找到静态锚点
./macce pscan <pid> 7ff0deadbeef 0x1000 3

# 读 / 写
./macce read  <pid> 7ff0deadbeef 64
./macce write <pid> 7ff0deadbeef "01 02 03 04"

./macce list                 # 当前匹配预览
./macce clear                # 清掉 /tmp/macce.session
```

## GUI 速查

1. `./macce-gui`
2. 进程选择器里默认勾上 **wine only**（不勾就会列出全部进程）。选你要附加的 `.exe`。
3. 选类型/谓词/值 → 点 **First scan**。
4. 让目标程序内部数值变一下 → 点 **Rescan**，配合 `changed` / `decreased` / `eq <新值>` 等谓词不断收敛。
5. 在某条结果上右键可以 **lock**（冻结）或加入 **watch** 监视。
6. 静态（模块支持的）地址显示为绿色的 `notepad.exe+0x4150`；堆/栈等动态地址保持普通 16 进制。

### 扩展 Wine 进程识别

内置规则匹配 `wine` / `crossover` / `gameportingtoolkit` / `whisky` / `kegworks` / `playonmac` / `winebridge` / `wineskin` / `wpreloader`，或可执行文件名以 `.exe` 结尾。规则之外的运行环境可以用环境变量临时加：

```sh
MACCE_WINE_PATTERNS="我的游戏:custom_wrapper" ./macce-gui
```

冒号分隔，大小写不敏感，对可执行文件**路径**做子串匹配。

## ⚠️ 仅供合法授权场景使用

本工具会读写另一个进程的内存。**只能用于：你拥有的软件、获得授权可以测试的软件、CTF / 安全研究 / 教学场景。**

- **请勿**用于含有反作弊或 ToS 限制的网游与在线服务。
- 攻击带反作弊的商业多人游戏（如 EAC、BattlEye、NetEase ProtectShield/NP、Vanguard 等）几乎一定违反对方 ToS；视你所在司法管辖区还可能违反相关计算机犯罪法 —— 包括但不限于：
  - 中国《刑法》第 285 条（非法侵入计算机信息系统罪 / 非法获取计算机信息系统数据罪）、第 286 条（破坏计算机信息系统罪）；
  - 美国 CFAA（18 U.S.C. § 1030）；
  - 英国 Computer Misuse Act；
  - 其他司法管辖区的对应立法。
- 项目作者与贡献者对任何滥用行为概不负责。

合理使用场景示例：逆向你自己的软件、单机离线游戏、CTF 练习、考试逆向题目、调试自己开发的 Wine 应用，等等。

## 开源许可

MIT —— 详见 [`LICENSE`](LICENSE)。

## 第三方组件

- [Dear ImGui](https://github.com/ocornut/imgui)（MIT），锁定 v1.91.5。
- [GLFW](https://www.glfw.org/)（zlib/libpng），通过 Homebrew 引入。
