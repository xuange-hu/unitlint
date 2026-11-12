# 攻击手册：systemd 单元的利用链与审计顺序

这份文档说明每条规则在攻击链上的位置。目的不是给利用脚本，而是回答一个问题：**一条 `medium` 和一条 `high` 之间差的是什么**。

## 0. 前提：合并后的单元才是攻击面

攻击者读的不是 `/usr/lib/systemd/system/web-api.service`，而是 `systemd-analyze cat-config` 展开后的结果。所以审计也必须从合并结果出发，否则会出现两种错判：

- **假阴性**：基础文件写了 `ProtectSystem=strict`，drop-in 写了 `ProtectSystem=no`，单文件扫描报告"已加固"。
- **假阳性**：`/etc` 下的单元整体替换了厂商单元，厂商文件里的 `User=app` 早已不生效，扫描器却按它判断"非 root 运行"。

三条语义决定合并结果：

| 语义 | 后果 |
| --- | --- |
| 搜索路径优先级 `/etc` > `/run` > `/usr/local/lib` > `/usr/lib` > `/lib` | 同名单元只有优先级最高的那份生效，其余是死代码 |
| drop-in 在各目录中按**文件名**排序、在基础单元之后应用 | `99-*` 永远在 `10-*` 之后；写 `99` 的人改变了最终值 |
| 同名 drop-in 只取优先级最高的目录 | 另一个文件永远不生效，两个管理员都以为自己改了 |

## 1. 从"能写"到"能执行"

服务以 root 运行时，任何**它执行的东西**都必须只有 root 能写。三个常见破口：

### 1.1 二进制在可写目录（UNT003）

```ini
ExecStart=/tmp/web-api --port 8080
```

`/tmp` 是 1777。任何本地账户可以 `rm` 后重建同名文件，等服务重启（或 `Restart=always` 触发）就以 root 执行攻击者的代码。

变体：`/home/deploy/app`、`/opt` 被 `chown -R` 给了部署用户、`/var/www` 可写、容器里 `/app` 属于 uid 1000。

### 1.2 环境文件可写（UNT006）

```ini
EnvironmentFile=/tmp/web-api.env
```

环境文件由服务进程以**服务身份**打开。攻击者在里面写：

```
LD_PRELOAD=/tmp/evil.so
```

glibc 在 `execve` 后加载它，构造函数以 root 运行。比替换二进制更隐蔽：文件权限、哈希、包校验全都没变。

`EnvironmentFile=-/path` 的 `-` 只是"读不到就算了"，不影响这条链。

### 1.3 工作目录可写 + 相对路径（UNT018 / UNT005）

`WorkingDirectory=/home/app` 且程序按相对路径打开配置、插件、缓存，等于允许在服务启动前投毒。`ExecStart=bin/app` 这种相对路径把"执行哪个文件"交给启动时的工作目录。

## 2. 加固指令与实际效果之间的缝

### 2.1 `ReadWritePaths` 把 `ProtectSystem` 打穿（UNT009）

```ini
ProtectSystem=strict
ReadWritePaths=/etc
```

`ProtectSystem=strict` 把 `/usr`、`/boot`、`/etc` 挂成只读，然后 `ReadWritePaths=/etc` 又把它挂回可写。此时被拿下的服务可以：

1. 改写自己的 unit 文件（`/etc/systemd/system/web-api.service.d/`）；
2. 改写 `/etc/ld.so.preload`；
3. 改写 `/etc/passwd` 加一个 uid 0 账户。

加固还在，只是没有覆盖它本来要保护的东西。审计口径：`ReadWritePaths` 里出现 `/`、`/etc`、`/usr`、`/boot`、`/var` 一律 `high`。

### 2.2 能力集（UNT010 / UNT011）

`CapabilityBoundingSet` 是**上界**，`AmbientCapabilities` 是**实际授予**且跨 `exec` 保留。

- `CAP_SYS_ADMIN`：挂载、`ptrace` 大部分场景、改内核参数——在多数内核上等价 root。
- `CAP_SYS_PTRACE`：读任意进程内存，包括 `systemd` 自己。
- `CAP_DAC_OVERRIDE`：绕过所有文件权限检查。
- `CAP_SETUID` / `CAP_SETGID`：直接 `setuid(0)`。

`AmbientCapabilities=CAP_SETUID` 给一个非 root 服务，等价于给它 root。

### 2.3 组权限（UNT012 / UNT013）

`User=app` + `Group=root`，或者 `SupplementaryGroups=root`。`/etc` 下大量文件是 `root:root 0640`，root 组可读；`/var/log` 常见 `root:adm`，但不少自建服务把日志目录设成 root 组可写。组权限是最容易被 review 漏掉的一侧，因为 `User=` 那行看起来是对的。

## 3. 日志与套接字：两条被低估的链

### 3.1 `StandardOutput=append:/tmp/x.log`（UNT017）

systemd 以 root 打开该路径，**跟随符号链接**。攻击者先 `ln -s /etc/shadow /tmp/x.log`，服务下次写日志就以 root 覆写目标文件。这是经典的 symlink-follow 写入，`append:` 与 `file:` 都一样。

### 3.2 `SocketMode=0666`（UNT024）

socket 激活的服务，认证方式往往就是"能不能连上这个 socket"。`0666` 等于把认证交给"本机任意用户"。配合 `Accept=yes` 无 `MaxConnections=`，还多一个 fork 放大面。

## 4. 定时器：延迟执行与横向

- `OnCalendar=*:*:00`（UNT021）：每分钟一次。若它执行的脚本在可写路径，攻击者拿到的是**每分钟一次以 root 执行**的机会，且不依赖服务是否在跑。
- `Persistent=true` 缺失（UNT023）：机器关机期间该跑的任务被跳过。审计视角不是安全，而是"你以为在跑的东西没跑"——备份、证书续期都属于这一类。
- timer 指向不存在的 service（UNT105）：定时器永远成功、永远什么也不做。`systemctl list-timers` 显示正常。

## 5. 一个完整的例子

`examples/rootfs` 里的 `web-api.service` 同时具备 1.1、1.2、2.1、2.2、3.1，评审时它在任何人眼里都是"加固过的服务"：

```ini
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

而同一个单元里：

```ini
ExecStart=/bin/sh -c "/tmp/web-api --port 8080"   # 1.1
EnvironmentFile=/tmp/web-api.env                  # 1.2
ReadWritePaths=/etc                               # 2.1
AmbientCapabilities=CAP_SETUID                    # 2.2
StandardOutput=append:/tmp/web-api.log            # 3.1
```

再加上三个月后的一个 drop-in：

```ini
# /etc/systemd/system/web-api.service.d/99-debug.conf
NoNewPrivileges=no
ProtectSystem=no
```

五条独立路径，任意一条都能从"本地普通账户"走到 root，而 `systemctl cat` 的输出里它们分散在四个文件、两个目录中。

## 6. 审计顺序

按"攻击者拿到本地账户后多久能提权"排序，而不是按规则编号：

1. **UNT003 / UNT006 / UNT017**：可写路径 → 代码执行。先修这一类。
2. **UNT101 / UNT102**：合并结果与文件表象不一致。修完前一步，再确认加固真的生效。
3. **UNT011 / UNT010 / UNT012 / UNT013**：权限本身过宽。
4. **UNT009**：加固被打洞。
5. **UNT024 / UNT025**：网络与本机暴露面。
6. 其余：生命周期、定时器、可维护性问题。

`--fail-on high` 大致对应第 1–4 步；把第 5、6 步变成 `medium` 以下的噪音预算。

## 7. 与其它工具的分工

| 工具 | 输入 | 看的是 | 看不到 |
| --- | --- | --- | --- |
| `systemd-analyze security` | 运行中的单元 | 已生效的属性，逐项打分 | 是哪个文件设的；未加载的单元；CI 里跑不了 |
| `systemd-analyze cat-config` | 单元名 | 展开后的全文 | 不判定、不给证据、不比较 |
| grep / 正则扫描 | 文件 | 单文件里的字面量 | drop-in 合并、覆盖、遮蔽 |
| **unitlint** | 文件树 / rootfs | 合并结果 + 来源链 | 运行态；generator 产物 |

## 8. 在流水线里卡住它

容器镜像构建的最后一步是最便宜的位置：

```dockerfile
FROM base
COPY rootfs/ /
RUN pip install unitlint && unitlint scan / --fail-on high
```

镜像里的单元在构建时就固定了，此时失败的成本最低。已经上线的机器用同一份报告做基线对比（`--json` 输出带文件与行号，可直接 diff）。
