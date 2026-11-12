# unitlint

**按 systemd 装载单元的方式来审计单元**：搜索路径优先级、drop-in 覆盖、以及某个指令最后一次是谁设的。

[![CI](https://github.com/xuange-hu/unitlint/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/unitlint/actions/workflows/ci.yml)
![tests-235%20passing](https://img.shields.io/badge/tests-235%20passing-brightgreen)
![rules-44](https://img.shields.io/badge/rules-44-blue)
![dependencies-0](https://img.shields.io/badge/dependencies-0-brightgreen)
![python-3.10%2B](https://img.shields.io/badge/python-3.10%2B-blue)
![license-MIT](https://img.shields.io/badge/license-MIT-blue)

零依赖。44 条确定性规则。每条结论带文件、行号、字节偏移和原始字节。SARIF 直接接 CI。能读一个 rootfs、一层容器镜像，或者单个文件。

English: [README.md](README.md)

---

## 你读到的单元，不是真正跑起来的那个

`systemctl cat web-api.service` 会把基础文件和 drop-in 依次打印出来，但**没有一条命令打印合并结果**。真正生效的是三条规则的结果，而这三条规则没有任何单文件扫描器实现：

```
/etc/systemd/system/web-api.service      覆盖厂商单元，不是与之合并
/usr/lib/systemd/system/web-api.service  上面那个文件一存在，这个就是死代码
/etc/systemd/system/web-api.service.d/   按文件名排序，在基础单元之后应用
   10-limits.conf
   99-debug.conf                        三个月后有人写进去 NoNewPrivileges=no，没人再回头看
/usr/lib/systemd/system/web-api.service.d/
   10-limits.conf                       永远不会被读取：同名文件，目录优先级更低
```

`systemd-analyze security` 评的是**正在运行**的单元——那时值已经生效，而它不会告诉你是哪个文件造成的。对 `*.service` 做 grep 的扫描器会看到加固行，然后报告"已加固"。两者都漏掉生产环境真正发生的情况：一个 drop-in 悄悄撤销了基础文件里的加固。

unitlint 先把合并做出来，再审计结果，并且永远能回答**哪个文件的哪一行赢了**：

```console
$ unitlint why examples/rootfs web-api.service NoNewPrivileges
web-api.service  NoNewPrivileges  ->  no
  section [Service]
    /usr/lib/systemd/system/web-api.service:13             yes   vendor priority 3
    /etc/systemd/system/web-api.service.d/99-debug.conf:3   no    dropin priority 0  <= effective
```

这段输出就是这个工具存在的全部理由。

---

## 三步跑通

```bash
# 1. 安装（也可以 uvx --from unitlint unitlint ...）
pip install unitlint

# 2. 审计一棵树：挂载的 rootfs、容器层、或者单个文件
unitlint scan /path/to/rootfs

# 3. 接进 CI
unitlint scan ./image-rootfs --fail-on high --sarif > unitlint.sarif
```

手边没有 rootfs？内置语料会把 44 条规则全部打一遍：

```console
$ unitlint demo
units: 16, findings: 55, risk: 100/100
rules fired: 44/44
every rule in the table has a sample that triggers it
```

光看一条结论长什么样：

```console
$ unitlint scan examples/rootfs --unit web-api.service
web-api.service (/usr/lib/systemd/system/web-api.service)
  kind=service  base=/usr/lib/systemd/system/web-api.service (vendor)  drop-ins=10-limits.conf, 99-debug.conf
  19 finding(s)  critical=0  high=8  medium=8  low=2  note=1  risk=100/100

[high    ] UNT101  A drop-in weakens a hardening directive
           NoNewPrivileges=yes at /usr/lib/systemd/system/web-api.service:13 is undone by NoNewPrivileges=no at /etc/systemd/system/web-api.service.d/99-debug.conf:3
           /etc/systemd/system/web-api.service.d/99-debug.conf:3, offset 0x2a+22
           saw:  NoNewPrivileges=no
           fix:  make both files agree, or gate the override behind ConditionPathExists=
```

每条结论都带文件、行号、字节偏移和原始字节。核对不了的结论只是意见。

---

## 44 条规则

第一遍看单个单元，第二遍看 systemd 组装完成之后的单元，以及同目录树里的其它单元。

| 分类 | 规则 | 例子 |
| --- | --- | --- |
| 权限 | UNT002 / 008 / 010 / 011 / 012 / 013 | `AmbientCapabilities=CAP_SETUID`；`User=app` 配 `Group=root`；root 服务没开 `NoNewPrivileges=` |
| 文件系统暴露 | UNT003 / 006 / 009 / 017 / 018 | 二进制在 `/tmp`；`EnvironmentFile` 在 `/home`；`ProtectSystem=strict` 却 `ReadWritePaths=/etc` |
| 密钥 | UNT007 | `Environment=` 里写字面量 `PASSWORD=` |
| 生命周期 | UNT001 / 014 / 015 / 019 / 020 / 033 | `Restart=always` 配 `StartLimitIntervalSec=0`；`Type=forking` 没有 `PIDFile=` |
| 定时器 | UNT021 / 022 / 023 / 105 | 每分钟 `OnCalendar=`；没有 `RandomizedDelaySec=`；timer 指向不存在的 service |
| 套接字 | UNT024 / 025 / 026 / 106 | `SocketMode=0666`；`ListenStream=0.0.0.0:9090`；两个 socket 抢同一个地址 |
| 配置陷阱 | UNT027 / 028 / 029 / 030 / 031 / 034 / 035 | `[Services]` 拼错；指令写在不认它的段里；废弃的 `PermissionsStartOnly=` |
| 合并本身 | UNT101 / 102 / 103 / 104 / 107 / 108 | drop-in 削弱加固；`/etc` 单元整体替换厂商单元；同名 drop-in 被更高优先级遮蔽 |
| 开机启用 | UNT109 | `WantedBy=` 一个没有任何单元定义的 target |

每条规则的完整理由和修法：`unitlint explain UNT101`，或 [docs/rules.md](docs/rules.md)。
每条结论对攻击者意味着什么、哪些是"服务被拿下"和"整机被拿下"的分界线：[docs/attack-guide.md](docs/attack-guide.md)。

---

## 接进 CI

```yaml
- name: Audit the image's units
  run: |
    pip install unitlint
    unitlint scan ./rootfs --fail-on high --sarif > unitlint.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: unitlint.sarif
```

退出码：`0` 没有达到 `--fail-on` 的结论，`1` 有，`2` 输入读不了。`--fail-on none` 只出报告、不让 job 红。

不手工解包镜像也能扫：

```bash
docker create --name u img:tag && docker export u | tar -x -C ./rootfs && docker rm u
unitlint scan ./rootfs --fail-on high
```

## 从 agent 调用（MCP）

```bash
pip install "unitlint[mcp]"
uvx --from "unitlint[mcp]" unitlint-mcp      # stdio 服务，7 个工具
```

| 工具 | 回答什么 |
| --- | --- |
| `unitlint_scan` | 审文件 / 目录 / rootfs，返回判定与证据 |
| `unitlint_text` | 审一段单元文本，不落盘，适合 PR 或对话里的片段 |
| `unitlint_why` | 某指令最后是谁设的、覆盖了谁 |
| `unitlint_rules` | 规则表，可按 stage 或严重级过滤 |
| `unitlint_explain` | 单条规则：查什么、为什么、怎么修 |
| `unitlint_sarif` | SARIF 2.1.0，供 code scanning 上传 |
| `unitlint_demo` | 一次调用验证整条链路 |

## 它不做什么

- **不启停、不查询 systemd**。它是静态读取器：回答"systemd 会加载什么"，不是"现在加载了什么"。
- **不跟随符号链接出你指定的那棵树**，也不读 `/proc`。
- **不认 generator 产物**（`/run/systemd/generator`）。启动时由 generator 生成的单元不在范围内；建模的搜索路径优先级只覆盖手写单元。
- **不猜意图**。一个确实需要 root 的单元写了 `User=root`，照样在 `medium` 报出来——要么调 `--fail-on`，要么在你的流水线里忽略该规则。

## 开发

```bash
git clone https://github.com/xuange-hu/unitlint && cd unitlint
python -m pytest -q                 # 235 个测试，不需要先安装
python -m ruff check .
python -m unitlint demo             # 44/44 必须全中
```

模块划分：`parser.py`（一个文件 → 带偏移的指令）、`merge.py`（搜索路径 + drop-in → 一个单元）、`rules.py`（44 个检查）、`rulebook.py`（严重级与文案）、`engine.py`（表 → 报告）、`render.py`（text / JSON / SARIF）、`cli.py`、`mcp_server.py`。

规则表是数据，检查是代码，并有测试断言"表里每个 id 都有一个真会跑的检查"。加一条规则要同时加检查、加元数据、加一个能触发它的样例——否则 demo 覆盖率测试会红。

MIT。
