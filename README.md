# wechat-mcp

只读的微信聊天记录 MCP 服务，同时支持 Windows 上的微信 3.x 与 4.x。
服务通过 stdio 提供工具，可让 MCP 客户端搜索联系人、读取会话、按时间范围查询消息，并导出为 txt。

- 不修改、不移动微信原始数据库
- 自动从正在运行的微信进程提取 SQLCipher 密钥
- 解密副本只写入本地缓存目录
- 密钥只保存在进程内存中，不写日志、不出现在工具返回值里

## 支持范围

| 项目 | 微信 3.x | 微信 4.x |
| --- | --- | --- |
| 数据库位置 | `WeChat Files\<wxid>\Msg` | `xwechat_files\<wxid>_<suffix>\db_storage` |
| 主库 | `Msg/MicroMsg.db` | `contact/contact.db`、`session/session.db` |
| 消息分片 | `Msg/Multi/MSG*.db`、`Msg/MSG*.db` | `message/message_*.db` |
| 密钥 | 每账号一个 32 字节 key | 4.1+ 每个数据库各有独立 key |
| 密钥定位 | `WeChatWin.dll` 中设备标记附近的指针链 | 进程中 `Config.Cipher` 对象的盐到密钥映射 |
| 页面格式 | SQLCipher 3：PBKDF2-SHA1 64000 次，HMAC-SHA1 | SQLCipher 4：原生 32 字节 key，HMAC-SHA512 |

运行环境：Windows 10/11、Python 3.10+，需要微信已登录并保持运行（用于提取密钥）。

### 客户端版本兼容矩阵

| 客户端 | 状态 | 说明 |
| --- | --- | --- |
| Weixin 4.1.15.13 | 实测通过 | 本机真实账号端到端验证：46 个库密钥、6 个消息分片、807 张消息表 |
| Weixin 4.1.x 其他补丁 | 预期兼容 | 同一 minor 内通常只变补丁号；先用 `wechat_selfcheck` 确认 |
| Weixin 4.0.x | 未实测 | 结构与 4.1 接近，但每库密钥/表名可能不同 |
| Weixin 4.2+ | 未实测 | 新版本优先运行 selfcheck；必要时设置 `WECHAT_MCP_XOR_MASK` 或手动提供 key |
| WeChat 3.9.x | 合成验证 | 无本机 3.x 客户端；密钥、页面、WAL 均用合成数据验证 |
| WeChat 3.x 其他版本 | 未实测 | 3.x 内存布局随版本变化，失败时可手动提供 key |

**一致性边界**：无法保证所有 4.x 小版本的内部内存布局和表结构完全一致。可以保证的是
MCP 工具接口、错误语义、只读行为和缓存策略一致；对未知版本先运行
`wechat_selfcheck`，它会给出 `supported` / `degraded` / `unsupported` 结论和缺失项，
而不是静默返回错误数据。


## 安装

```bash
cd wechat-mcp
python -m pip install -e .
```

依赖：`mcp`、`cryptography`、`zstandard`。代码同时兼容 MCP Python SDK 1.x（`FastMCP`）与 2.x（`MCPServer`）。

## 作为 MCP 服务运行

安装后可直接运行：

```bash
wechat-mcp
```

或以模块方式运行：

```bash
python -m wechat_mcp
```

MCP 客户端配置示例（`mcpServers` 片段，路径按本机修改）：

```json
{
  "mcpServers": {
    "wechat": {
      "command": "C:\\Python312\\python.exe",
      "args": ["-m", "wechat_mcp"],
      "env": {
        "PYTHONPATH": "C:\\path\\to\\wechat-mcp",
        "WECHAT_MCP_DATA_ROOT": "C:\\path\\to\\WeChat Files;C:\\path\\to\\xwechat_files"
      }
    }
  }
}
```

如果使用 `pip install -e .` 安装了控制台脚本，也可以把 `command` 写成 `wechat-mcp` 并省略 `args`。

数据目录一般可自动发现；只有在非默认安装位置时才需要设置 `WECHAT_MCP_DATA_ROOT`（多个路径用 `;` 或 `|` 分隔）。

## MCP 工具

| 工具 | 作用 |
| --- | --- |
| `wechat_status` | 检查微信进程、账号、数据库数量与加密状态，不解密 |
| `wechat_selfcheck` | 诊断客户端版本、密钥来源、表结构与兼容性，可选验证联系人读取链路 |
| `wechat_list_accounts` | 列出可读取的 3.x / 4.x 账号 |
| `wechat_list_contacts` | 按 wxid / 昵称 / 备注 / 微信号搜索联系人 |
| `wechat_list_sessions` | 按会话时间倒序列出最近会话 |
| `wechat_get_messages` | 查询与某联系人的聊天记录，支持时间范围与分页 |
| `wechat_export_chat` | 导出 UTF-8 BOM 的 txt 文件 |
| `wechat_clear_cache` | 删除解密缓存，不影响微信原始文件 |

### 参数说明

`account`：wxid（如 `wxid_example`）或带版本前缀的 `4:wxid_...` / `3:wxid_...`。

`contact`：wxid、昵称、备注或微信号。昵称重复时会返回 `ContactAmbiguous`，此时请改用 wxid 或微信号。

`start_time` / `end_time`：支持 `2026-10-01`、`2026-10-01 12:00:00`、`2026/10/01` 以及 Unix 秒/毫秒时间戳。只写日期时，`end_time` 自动取当天 23:59:59。

`limit` / `offset`：`wechat_get_messages` 最多单次返回 2000 条；`limit=0` 表示不截断（导出会使用全量）。

`refresh=true`：忽略已有缓存，重新解密。微信数据库更新后如果结果明显滞后，可开启。

### 调用示例

```json
{
  "account": "wxid_example",
  "contact": "friend",
  "start_time": "2026-10-01",
  "limit": 100,
  "ascending": true
}
```

导出：

```json
{
  "account": "wxid_example",
  "contact": "friend",
  "output_path": "C:\\path\\to\\output\\chat.txt",
  "start_time": "2026-10-01"
}
```

导出文件使用 UTF-8 BOM、CRLF 换行，正文格式为：

```text
[2026-10-01 00:43:44] me：消息内容
```

多行消息会合并为一行，行间以 ` / ` 分隔。图片、语音、表情、视频、文件、链接、分享、聊天记录、小程序等非文本消息会渲染为 `[类型]` 或 `[类型] 标题`。

## 版本诊断与远端验证

### wechat_selfcheck

接触新版本微信时先调用：

```json
{
  "account": "wxid_example",
  "contact": "friend"
}
```

返回内容节选：

```json
{
  "ok": true,
  "client": {"version": "4.1.15.13", "processes": ["..."]},
  "key": {"ok": true, "count": 46, "sources": ["config-cipher"]},
  "schema": {"contact": {"columns": ["..."]}, "messages": {"tables": 807, "rows": 530076}},
  "compatibility": {
    "status": "supported",
    "core_missing": [],
    "degraded": [],
    "warnings": [],
    "version": {"level": "tested"}
  },
  "probe": {"ok": true, "total": 49743, "first_time": "2025-09-27 12:34:52"}
}
```

- `key.sources` 只会出现 `config-cipher`、`memory-ascii`、`salt-neighborhood`、`manual` 等策略名，不包含密钥本身。
- 传入 `contact` 时只验证联系人解析、消息数量和时间范围，不返回消息正文，也不返回昵称/备注（仅保留 wxid）。
- `compatibility.status`：
  - `supported`：核心表结构齐全。
  - `degraded`：能读消息，但缺少 `Name2Id`、会话表或群聊发送者字段，相关功能可能不准确。
  - `unsupported`：缺少核心联系人/消息列，不应继续依赖消息结果。
  - `unknown`：数据库未成功解密，查看 `error` 与 `key.error`。
- 输出可以安全地用于反馈问题：不含聊天正文，也不含密钥。

### 远端 Windows 服务器

探针不依赖 MCP SDK，可直接在远端运行：

```bash
python -m wechat_mcp.probe --data-root "C:\path\to\WeChat Files" --account wxid_xxx --contact friend --compact
```

安装后等价命令为 `wechat-mcp-probe`。

建议流程：

1. 在远端安装一个未升级的目标微信版本，用一次性测试账号产生少量聊天数据并保持登录。
2. 把本项目复制到远端，安装依赖：`python -m pip install -e .`。
3. 运行上面的 probe，确认 `readable=true`，并检查 `compatibility.status`、`version.level`、`core_missing` 和 `degraded`。
4. 若需要通过 MCP 直接访问远端，可用 SSH stdio 桥接：

```json
{
  "mcpServers": {
    "wechat-remote": {
      "command": "ssh",
      "args": ["-T", "user@host", "python", "-m", "wechat_mcp"],
      "env": {"PYTHONIOENCODING": "utf-8"}
    }
  }
}
```

远端需要已安装本项目（或用 `PYTHONPATH` 指向项目目录）。密钥默认在远端微信进程中自动提取；不要在本地 MCP 配置里硬编码远端 key。

本机虚拟机也是可行方案，但需要至少 30–40 GB 空闲磁盘给 Windows 虚拟机和微信数据。Windows 家庭版默认没有 Windows Sandbox，本机当前磁盘余量也不足，因此远端 Windows 服务器是更现实的第一选择。

## 命令行调试

不接 MCP 客户端也可以直接调试：

```bash
python -m wechat_mcp.cli status
python -m wechat_mcp.cli accounts
python -m wechat_mcp.cli selfcheck wxid_example --contact friend
python -m wechat_mcp.cli contacts wxid_example --query friend
python -m wechat_mcp.cli sessions wxid_example --limit 10
python -m wechat_mcp.cli messages wxid_example friend --start 2026-10-01 --limit 20
python -m wechat_mcp.cli export wxid_example friend C:\\path\\to\\output\\chat.txt --start 2026-10-01 --refresh
```

`cli` 需要 MCP SDK。只想做兼容性诊断时，用不依赖 MCP SDK 的探针：

```bash
python -m wechat_mcp.probe --data-root "C:\\path\\to\\xwechat_files" --account wxid_example --contact friend
```

所有子命令输出 JSON。

## 密钥处理

默认自动提取：

- 4.x：依次尝试
  - `Config.Cipher` 对象（`com.Tencent.WCDB.Config.Cipher` 及常见变体），解码 XOR 混淆的 `x'<key><salt>'`
  - 可读内存中的任意 `x'<hex>'` 串
  - 数据库 salt 附近的原始 32 字节 key 或 96 位十六进制串
- 3.x：参考 PyWxDump 的版本无关做法，在 `WeChatWin.dll` 中搜索 `iphone\0` / `android\0` / `ipad\0`，向前遍历指针槽，读取候选 32 字节 key；若失败，再扫描 `MicroMsg.db` salt 附近的原始 key。
- 所有候选都必须通过真实 page-1 HMAC 校验，未通过不会用于解密。

新版本 4.x 如果更换了 XOR mask，可设置环境变量 `WECHAT_MCP_XOR_MASK`（十六进制）追加尝试：

```bash
set WECHAT_MCP_XOR_MASK=d2c7442458020000004889442450488b450048844c2448488944254048584c24
```

手动提供密钥（可选）：

- 工具参数 `key`
- 环境变量 `WECHAT_MCP_KEY`、`WECHAT_MCP_KEY_4X`、`WECHAT_MCP_KEY_3X`

格式为 64 位十六进制；4.x 也接受带 salt 的 96 位十六进制。4.1+ 每个数据库可能使用不同 key，
可以用 `;`、`,` 或换行一次提供多个 key，服务会逐一校验并按 salt 建立映射：

```text
<key1>;<key2>;<key3>
```

需要与服务进程相同位数、相同用户权限。若微信以管理员身份运行，MCP 服务也需要相应权限，否则无法读取进程内存。

## 缓存与数据安全

解密副本位于：

```text
%LOCALAPPDATA%\wechat-mcp\cache\v3\<wxid>\
%LOCALAPPDATA%\wechat-mcp\cache\v4\<wxid>\
```

可用 `WECHAT_MCP_CACHE_DIR` 修改位置，或用 `wechat_clear_cache` 清理。每种数据库最多保留当前和上一代解密副本，避免反复刷新后无限占用磁盘。

安全设计：

- 只以 `PROCESS_VM_READ` 读取微信进程内存，不注入、不修改进程
- 微信原始数据库只读打开，任何情况下不写入
- 导出路径位于微信数据目录内时直接拒绝
- 密钥不落盘、不写日志；缓存文件名只包含密钥摘要
- `wechat_selfcheck` / `wechat-mcp-probe` 只输出版本、路径、表名、列名、行数、时间范围和密钥来源标签，不输出消息正文，也不输出密钥
- 缓存内是明文聊天数据，请自行保护该目录

## WAL 说明

标准 SQLite/SQLCipher WAL 会在解密后合并进缓存副本：逐帧校验 HMAC、支持 page 1 的 skip-salt / full-page 两种布局、只应用到最后一次提交，并按提交的数据库页数截断。

实测微信 4.x 会遗留帧 salt 与 WAL 头 salt 不一致的 WAL 文件。按 SQLite 自身规则，这类帧属于过期代次，应被忽略；以本机账号为例，强制回放会让 message_0 分片中与该联系人的消息数从 24,743 降回 23,600，并让最新消息时间倒退。因此服务保持 SQLite 语义：salt 不匹配的 WAL 帧不应用，以主数据库为准。

## 3.x 验证说明

本机没有安装 3.x 微信，因此 3.x 适配层通过以下方式验证：

- 按 SQLCipher 3 页面格式生成合成加密数据库，验证密钥派生、HMAC 校验、整库解密与文件流式解密
- 生成标准 WAL 帧（含未提交、salt 不匹配、page 1 HMAC 失败、full-page 布局）验证合并逻辑
- 用模拟进程内存布局验证 PyWxDump 式指针链扫描、salt 邻近扫描和 4.x `Config.Cipher` 扫描
- 4.x 已用本机真实账号完成端到端验证：客户端 4.1.15.13、46 个候选密钥、6 个消息分片、807 张消息表、530,076 行消息；selfcheck 结论为 `supported`
- 2026-10-01 之后的消息导出仍可用同一账号复现（此前导出 30,348 条）

3.x 的已知限制：

- 仅支持 Windows 3.x 客户端，需要 `WeChat.exe` / `WeChatWin.dll` 正在运行
- 群聊中具体发送者需要解析 `BytesExtra`，当前按单聊场景处理；单聊发送者显示正确
- 不同 3.x 小版本的内存布局可能不同，定位失败时可手动传入 key

## 测试

```bash
python -m unittest discover -s tests -t . -v
```

当前共 52 个测试，覆盖：

- SQLCipher 3/4 加解密与错误密钥
- 4.x 每库密钥映射、暴力匹配、多 key 手动输入与 salt 邻近扫描
- WAL 合并、未提交帧、过期 salt、page 1 两种布局、HMAC 损坏
- 4.x `Config.Cipher` 多种类名/无 XOR mask、3.x 指针链扫描（模拟内存）
- schema 别名回退（`type` / `content` / `timestamp`）与 selfcheck 报告
- 兼容性判定：supported / degraded / unsupported / unknown
- 消息类型渲染与导出换行规则

MCP 协议本身已用官方 SDK 客户端做过 stdio 冒烟测试（`initialize`、`tools/list`、`tools/call`）。

## 项目结构

```text
wechat_mcp/
  config.py     发现 3.x / 4.x 数据目录与账号
  paths.py      各版本数据库路径
  winmem.py     Windows 进程内存只读访问、exe 路径与版本号
  keyutil.py    手动 key 解析与多 key 支持
  keys3.py      3.x 密钥定位（指针链 + salt 邻近）
  keys4.py      4.x 多策略密钥提取与 salt → key 映射
  crypto3.py    SQLCipher 3 页面解密
  crypto4.py    SQLCipher 4 页面解密
  wal.py        WAL 帧解析与合并
  cache.py      解密缓存与按库选 key
  chatlog.py    联系人、会话、消息查询与渲染
  compat.py     客户端版本支持级别与 schema 兼容判定
  diagnostics.py selfcheck 报告（版本、密钥来源、表结构、只读探测）
  export.py     txt 导出
  server.py     MCP 工具定义
  cli.py        命令行调试客户端
  probe.py      不依赖 MCP SDK 的远端只读探针
tests/          合成数据库、WAL、schema 与模拟内存测试
```

## 故障排查

- `未发现正在运行的微信进程`：先登录微信；确认进程名是 `Weixin.exe`（4.x）或 `WeChat.exe`（3.x）。
- `未找到 ... 数据库密钥`：稍等微信完成启动后重试，或检查是否需要管理员权限；新版本可先运行 `wechat_selfcheck`，必要时设置 `WECHAT_MCP_XOR_MASK` 或手动提供多个 key。
- `compatibility.status = unsupported`：核心表结构缺失，不要依赖消息结果；把 selfcheck 的 `core_missing` 和 `schema` 发出来以便适配。
- `compatibility.status = degraded`：消息可读，但会话/群聊发送者等辅助功能可能缺失，查看 `degraded` 列表。
- `ContactAmbiguous`：昵称重复，改用 wxid 或微信号。
- 结果比微信界面少：确认微信正在运行，尝试 `refresh=true`；注意过期 WAL 帧按 SQLite 规则被忽略。
- 远端机器排查：运行 `python -m wechat_mcp.probe ...`，它不依赖 MCP SDK，输出可安全分享。
- `python` 找不到：在 MCP 配置中使用 Python 的绝对路径。
