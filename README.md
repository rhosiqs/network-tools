# TCP/53 Block Watch

<p align="center">
  <a href="#tcp53-block-watch"><strong>English</strong></a>
  &nbsp;·&nbsp;
  <a href="#zh-tw"><strong>繁體中文</strong></a>
</p>

Detects and logs cases where TCP port 53 is blocked, causing DNS resolution failures.

Two implementations, both zero external dependencies and no network services, with output
to terminal messages and log files:

| Platform | Implementation | Requirements |
|---|---|---|
| Windows | `*.ps1` in the repo root | Windows' built-in PowerShell 5.1 |
| Linux | `*.py` under `linux/` | The distro's built-in python3 (3.6+), standard library only |

Both share the same `config/tcp53.config.json`, and use identical judgment tables, log
fields, and file names, so Windows and Linux logs from the same network can be compared
directly.

## How it works

DNS normally runs over UDP/53. When a response exceeds a single datagram, the server sets
the `TC` (truncated) bit, and per RFC 1035 the client must retry over TCP/53. So the
symptom of a blocked TCP/53 is:

- Regular domain resolution works fine
- Domains with large responses (DNSSEC, long TXT, many records) fail intermittently

This tool opens sockets directly, using UDP as the control group and TCP as the test
group — only by comparing the two can the problem be pinned on TCP/53. When UDP itself
fails, that sample is not evidence of a TCP/53 block; it's recorded as
`DnsServerUnreachable` and not counted as blocked.

## Usage

### Windows

```
run_tcp53.bat
```

or:

```
powershell -ExecutionPolicy Bypass -File .\Start-Tcp53Watch.ps1
powershell -ExecutionPolicy Bypass -File .\Invoke-Tcp53Diagnose.ps1
powershell -ExecutionPolicy Bypass -File .\Test-Tcp53SelfTest.ps1
```

### Linux

```
linux/run_tcp53.sh
```

or:

```
linux/tcp53-watch.py
linux/tcp53-diagnose.py
linux/tcp53-selftest.py
```

When no log directory is given (Windows `-LogDirectory`, Linux `--log-directory`), the
script asks for an output location before probing starts; pressing Enter uses the config
file's default. For scheduled runs (Task Scheduler, cron, systemd timer), pass this
argument explicitly — the Linux version does not prompt in a non-interactive environment
and just uses the default.

### Monitoring parameters

| Windows | Linux | Description |
|---|---|---|
| `-Once` | `--once` | Run a single round only |
| `-DurationMinutes N` | `--duration-minutes N` | Stop after N minutes; 0 (default) runs until Ctrl+C |
| `-IntervalSeconds N` | `--interval-seconds N` | Sampling interval while healthy |
| `-Target A,B` | `--target A,B` | Test only the given targets |
| `-LogDirectory <path>` | `--log-directory <path>` | Where to write logs |
| `-Quiet` | `--quiet` | Don't print each sample to the screen; still logs fully |

### Diagnostic parameters

| Windows | Linux | Description |
|---|---|---|
| `-OutputPath <file>` | `--output-path <file>` | Full report file name |
| `-LogDirectory <path>` | `--log-directory <path>` | Report directory; file name gets an auto timestamp |
| `-SkipTraceRoute` | `--skip-traceroute` | Skip traceroute (the slowest stage) |

## Per-round flow

For each enabled target:

1. UDP/53 query — control group. A successful UDP query means the link, routing, and
   server are fine.
2. TCP/53 query — test group. Full three-way handshake, send query, read response.
3. TCP/443 control-port connection — a non-DNS port on the same host. If 443 works but
   53 doesn't, that proves the filtering targets port 53 specifically.
4. Truncation fallback test — only runs when TCP fails. Query a large response over UDP
   (default: root `DNSKEY`) to get `TC=1`, then retry over TCP per spec, proving that
   resolution is genuinely broken.

## BlockType

The baseline judgment is UDP working and TCP not working, further broken down by the
stage at which TCP failed.

| BlockType | Meaning | Typical cause | Blocked |
|---|---|---|---|
| `None` | TCP/53 is fine | — | false |
| `TcpSilentDrop` | No response after SYN, until timeout | Firewall DROP rule | true |
| `TcpRejected` | Received RST | REJECT rule, or nothing listens on the port | true |
| `TcpUnreachable` | Received ICMP unreachable | Routing issue or router ACL | true |
| `TcpHandshakeThenNoData` | Handshake succeeds but query gets no response | Transparent proxy / DPI dropping the payload | true |
| `TcpResetAfterQuery` | RST after the query is sent | DPI blocking based on packet content | true |
| `TcpClosedWithoutAnswer` | Connection closes cleanly but with no answer | Proxy server, or TCP DNS unsupported | true |
| `TcpAnswerSuspect` | Response doesn't match the query | DNS interception / tampering | true |
| `UdpBlockedTcpOk` | UDP fails, TCP works | UDP filtering | true |
| `DnsServerUnreachable` | Both transports fail | Host doesn't provide DNS, or is unreachable | false |
| `Indeterminate` | Failure mode not in the table | — | true |

`None` and `DnsServerUnreachable` both have `Blocked = false`: neither is evidence of a
TCP/53 block. A default gateway that doesn't forward DNS falls into the latter case, which
is normal — it isn't logged as blocked, doesn't shorten the sampling interval, and isn't
written to the log every round.

## Scope

Guesses where the block is happening; only evaluated when `Blocked` is true, otherwise
`NotApplicable`:

| Scope | Basis |
|---|---|
| `LocalHost` | A matching local firewall rule exists, or the RST RTT is too low to have left the host |
| `FirstHop` | RST RTT ≈ RTT to the default gateway |
| `NetworkEdge` | Every target that responded over UDP is blocked |
| `ServerOrPath` | Only some UDP-responsive targets are blocked |

`NetworkEdge` and `ServerOrPath` only compare targets that responded over UDP. Targets
where UDP itself failed can't be compared this way — including them would let a host that
doesn't run DNS skew the overall judgment.

## Logs

| File | Content |
|---|---|
| `tcp53-events-YYYYMMDD.jsonl` | One JSON object per line, full field set |
| `tcp53-events-YYYYMMDD.csv` | Fixed columns, UTF-8 BOM |
| `tcp53-session-*.log` | Chronological text log |
| `tcp53-diagnosis-*.log` | Diagnostic report |

Fields:

```
Timestamp, TimestampUtc, Event,
AdapterName, AdapterMac, LocalIp, GatewayIp, GatewayMac, Ssid, Bssid,
TargetName, TargetIp, Port,
BlockType, Blocked, Severity, Confidence, Scope, ScopeReason,
TcpPhase, TcpOutcome, TcpSocketError, TcpConnectMs, TcpElapsedMs,
UdpOutcome, UdpElapsedMs, UdpRcode,
PortSpecific, ControlPort, ControlPortOutcome,
ResolutionImpact, TruncationSeen, TcpFallbackOk,
Description, Evidence
```

Both platforms write the same fields, in the same order, under the same file names, so
they can be merged and analyzed directly. There are only three differences: the
`Evidence` field records `Winsock=` on Windows and `errno=` on Linux; `DhcpEnabled` is left
blank on Linux (there's no cross-distro source for it); and `AdapterDescription` on Linux
comes from the device string under `/sys`.

Why MAC addresses are logged: IPs change, so the adapter MAC identifies which host this
is, while the gateway MAC and Wi-Fi BSSID identify which device was on-path at the time.

Write policy:

- Always written: blocked samples, state transitions (`BlockStarted` / `BlockCleared`)
- Sampled writes: one `Heartbeat` every `LogSuccessEveryNCycles` rounds while healthy
  (default 20)

When a block is detected, the sampling interval automatically shortens from
`IntervalSeconds` to `FastRetrySeconds`, and stays there for `FastRetryHoldSeconds`
seconds after recovery, to catch intermittent blocking.

## Configuration

`config/tcp53.config.json` — both platforms read the same file. Setting `Server` to
`AUTO_GATEWAY` uses the default gateway.

## Self-test

Windows:

```
powershell -ExecutionPolicy Bypass -File .\Test-Tcp53SelfTest.ps1
```

Covers DNS packet encoding/decoding, MAC normalization, the BlockType judgment table,
control-port confidence, Scope inference, and log writing.

Linux:

```
linux/tcp53-selftest.py
```

Covers the above plus errno mapping, and parsing of `/proc/net/route`, `/proc/net/arp`,
`resolv.conf`, `iw`, nftables, iptables, and traceroute output. Requires no network access
and no root.

Both return exit code 0 when everything passes.

For a real-world check, you can temporarily add a rule blocking outbound TCP 53, confirm
that `TcpSilentDrop` with `Scope=LocalHost` shows up, then remove the rule:

| Platform | Add | Remove |
|---|---|---|
| Windows | Add a firewall rule "Block outbound TCP 53" | Delete that rule |
| Linux | `sudo iptables -I OUTPUT -p tcp --dport 53 -j DROP` | `sudo iptables -D OUTPUT -p tcp --dport 53 -j DROP` |

This tool only reads firewall rules; it never modifies them. On Linux, reading the rules
themselves requires running as root.

## Environment limitations

Windows:

- Requires Windows 8 / Server 2012 or later (`Get-NetAdapter`, `Find-NetRoute`,
  `Get-NetNeighbor`)
- Wi-Fi SSID/BSSID come from `netsh wlan`; wired connections have no such field. Windows 11
  additionally requires "Location services" to be enabled — without it, `netsh wlan`
  returns no interface data, so those two fields are left blank while the rest are
  unaffected
- Reading firewall rules does not require administrator privileges; when permissions are
  restricted, that section is left empty

Linux:

- Requires python3 3.6+, standard library only; no pip needed, and PowerShell doesn't need
  to be installed
- Interfaces, MAC, gateway, and ARP are read from `/proc`, `/sys`, and ioctl, so it works
  even without iproute2 installed
- Reading nftables/iptables rules requires CAP_NET_ADMIN (in practice, root). When run as
  non-root, that section is marked "unreadable" rather than "no rules" — these mean
  opposite things and should not be conflated
- Wi-Fi SSID/BSSID come from `iw` (or `iwconfig`); left blank if not installed
- traceroute requires `traceroute` or `tracepath`; the path section of the diagnostic
  report is left blank if neither is installed
- Gateway RTT uses an unprivileged ICMP socket (governed by `net.ipv4.ping_group_range`);
  if unavailable, it falls back to calling `ping`, and if that's unavailable too, it's
  recorded as n/a

---

<details id="zh-tw">
<summary><strong>繁體中文說明</strong></summary>

<br>

偵測並記錄 TCP port 53 被封鎖而導致 DNS 解析失敗的情況。

兩套實作，皆零外部相依、無網路服務，輸出為終端機訊息與記錄檔：

| 平台 | 實作 | 需求 |
|---|---|---|
| Windows | 根目錄的 `*.ps1` | Windows 內建的 PowerShell 5.1 |
| Linux | `linux/` 下的 `*.py` | 發行版內建的 python3（3.6 以上），只用標準函式庫 |

兩者共用同一份 `config/tcp53.config.json`，判定表、記錄欄位與檔名也相同，
所以同一個網路上的 Windows 與 Linux 記錄可以直接放在一起比對。

## 原理

DNS 平常走 UDP/53。回應超過單一 datagram 時，伺服器設定 `TC`（truncated）位元，
客戶端依 RFC 1035 必須改用 TCP/53 重問。因此封鎖 TCP/53 的症狀是：

- 一般網域解析正常
- 大型回應網域（DNSSEC、長 TXT、多筆記錄）間歇性解析失敗

本工具直接開 socket，以 UDP 為對照組、TCP 為受測組，兩者比對才能指出問題出在 TCP/53。
UDP 不通時該次取樣不構成 TCP/53 的證據，記為 `DnsServerUnreachable` 且不算阻擋。

## 使用

### Windows

```
run_tcp53.bat
```

或：

```
powershell -ExecutionPolicy Bypass -File .\Start-Tcp53Watch.ps1
powershell -ExecutionPolicy Bypass -File .\Invoke-Tcp53Diagnose.ps1
powershell -ExecutionPolicy Bypass -File .\Test-Tcp53SelfTest.ps1
```

### Linux

```
linux/run_tcp53.sh
```

或：

```
linux/tcp53-watch.py
linux/tcp53-diagnose.py
linux/tcp53-selftest.py
```

未指定記錄目錄（Windows `-LogDirectory`、Linux `--log-directory`）時，腳本會在探測開始前
詢問輸出位置，Enter 採用設定檔預設值。排程執行（工作排程器、cron、systemd timer）請明確
帶入該參數；Linux 版在非互動環境下不詢問，直接採用預設值。

### 監測參數

| Windows | Linux | 說明 |
|---|---|---|
| `-Once` | `--once` | 只跑一輪 |
| `-DurationMinutes N` | `--duration-minutes N` | N 分鐘後停止；0（預設）持續到 Ctrl+C |
| `-IntervalSeconds N` | `--interval-seconds N` | 正常狀態取樣間隔 |
| `-Target A,B` | `--target A,B` | 只測指定目標 |
| `-LogDirectory <path>` | `--log-directory <path>` | 記錄輸出位置 |
| `-Quiet` | `--quiet` | 不輸出每筆取樣到畫面，仍完整寫檔 |

### 診斷參數

| Windows | Linux | 說明 |
|---|---|---|
| `-OutputPath <file>` | `--output-path <file>` | 報告完整檔名 |
| `-LogDirectory <path>` | `--log-directory <path>` | 報告目錄，檔名自動加時間戳記 |
| `-SkipTraceRoute` | `--skip-traceroute` | 略過 traceroute（最慢的階段） |

## 每輪流程

對每個啟用的目標：

1. UDP/53 查詢 — 對照組。UDP 通表示線路、路由、伺服器正常。
2. TCP/53 查詢 — 受測組。完整三向交握、送查詢、讀回應。
3. TCP/443 控制埠連線 — 同主機的非 DNS 埠。443 通而 53 不通，證明過濾針對 port 53。
4. 截斷回退測試 — 僅在 TCP 失敗時執行。以 UDP 查大回應（預設 root `DNSKEY`）取得
   `TC=1`，再依規範改用 TCP 重問，證明實際解析已損壞。

## BlockType

判定基準為 UDP 通、TCP 不通，再依 TCP 失敗階段細分。

| BlockType | 意義 | 通常成因 | Blocked |
|---|---|---|---|
| `None` | TCP/53 正常 | — | false |
| `TcpSilentDrop` | SYN 後無回應至逾時 | 防火牆 DROP 規則 | true |
| `TcpRejected` | 收到 RST | REJECT 規則，或該埠無服務 | true |
| `TcpUnreachable` | 收到 ICMP unreachable | 路由問題或路由器 ACL | true |
| `TcpHandshakeThenNoData` | 交握成功但查詢無回應 | 透明代理／DPI 丟棄內容 | true |
| `TcpResetAfterQuery` | 送出查詢後被 RST | DPI 依封包內容阻擋 | true |
| `TcpClosedWithoutAnswer` | 正常關閉但無回答 | 代理伺服器，或不支援 TCP DNS | true |
| `TcpAnswerSuspect` | 回應與查詢不符 | DNS 攔截／竄改 | true |
| `UdpBlockedTcpOk` | UDP 不通、TCP 通 | UDP 過濾 | true |
| `DnsServerUnreachable` | 兩種傳輸皆不通 | 該主機未提供 DNS，或無法連線 | false |
| `Indeterminate` | 失敗型態不在對照表內 | — | true |

`None` 與 `DnsServerUnreachable` 的 `Blocked` 為 false：兩者都不構成 TCP/53 被阻擋的
證據。預設閘道未跑 DNS 轉發時會落在後者，屬正常狀況，不會被記為阻擋、不會縮短取樣
間隔，也不會逐輪寫入記錄。

## Scope

阻擋位置推測，僅在 `Blocked` 為 true 時判定，否則為 `NotApplicable`：

| Scope | 判定依據 |
|---|---|
| `LocalHost` | 本機防火牆有符合規則，或 RST RTT 低到不可能離開本機 |
| `FirstHop` | RST RTT ≒ 到預設閘道的 RTT |
| `NetworkEdge` | 所有 UDP 有回應的目標皆被擋 |
| `ServerOrPath` | 僅部分 UDP 有回應的目標被擋 |

`NetworkEdge` 與 `ServerOrPath` 只在 UDP 有回應的目標之間比較。UDP 不通的目標無從
比較，計入會讓一台不跑 DNS 的主機左右整體判定。

## 記錄

| 檔案 | 內容 |
|---|---|
| `tcp53-events-YYYYMMDD.jsonl` | 每行一個 JSON 物件，完整欄位 |
| `tcp53-events-YYYYMMDD.csv` | 固定欄位，UTF-8 BOM |
| `tcp53-session-*.log` | 逐時文字記錄 |
| `tcp53-diagnosis-*.log` | 診斷報告 |

欄位：

```
Timestamp, TimestampUtc, Event,
AdapterName, AdapterMac, LocalIp, GatewayIp, GatewayMac, Ssid, Bssid,
TargetName, TargetIp, Port,
BlockType, Blocked, Severity, Confidence, Scope, ScopeReason,
TcpPhase, TcpOutcome, TcpSocketError, TcpConnectMs, TcpElapsedMs,
UdpOutcome, UdpElapsedMs, UdpRcode,
PortSpecific, ControlPort, ControlPortOutcome,
ResolutionImpact, TruncationSeen, TcpFallbackOk,
Description, Evidence
```

兩個平台寫出的欄位、順序與檔名相同，可直接合併分析。差異只有三處：`Evidence` 欄
Windows 記 `Winsock=`、Linux 記 `errno=`；`DhcpEnabled` 在 Linux 留空（沒有跨發行版的
來源）；`AdapterDescription` 在 Linux 取自 `/sys` 的裝置字串。

記錄 MAC 的原因：IP 會變動，網卡 MAC 指出是哪一台主機，閘道 MAC 與 Wi-Fi BSSID
指出當下路徑上是哪一台設備。

寫入策略：

- 一定寫：被阻擋的取樣、狀態轉換（`BlockStarted` / `BlockCleared`）
- 取樣寫：正常狀態每 `LogSuccessEveryNCycles` 輪寫一筆 `Heartbeat`（預設 20）

偵測到阻擋時取樣間隔自動從 `IntervalSeconds` 縮短為 `FastRetrySeconds`，
恢復後維持 `FastRetryHoldSeconds` 秒，以捕捉間歇性阻擋。

## 設定

`config/tcp53.config.json`，兩個平台讀同一個檔。`Server` 填 `AUTO_GATEWAY` 會帶入預設閘道。

## 自我測試

Windows：

```
powershell -ExecutionPolicy Bypass -File .\Test-Tcp53SelfTest.ps1
```

涵蓋 DNS 封包編解碼、MAC 正規化、BlockType 判定表、控制埠信心度、Scope 推測與記錄寫入。

Linux：

```
linux/tcp53-selftest.py
```

除上述範圍外，另涵蓋 errno 對應，以及 `/proc/net/route`、`/proc/net/arp`、
`resolv.conf`、`iw`、nftables、iptables、traceroute 輸出的解析。不需網路、不需 root。

兩者全數通過回傳 exit code 0。

實機驗證可暫時加一條封鎖對外 TCP 53 的規則，確認出現 `TcpSilentDrop` 且
`Scope=LocalHost`，測後刪除：

| 平台 | 加入 | 刪除 |
|---|---|---|
| Windows | 新增防火牆「封鎖對外 TCP 53」規則 | 刪除該規則 |
| Linux | `sudo iptables -I OUTPUT -p tcp --dport 53 -j DROP` | `sudo iptables -D OUTPUT -p tcp --dport 53 -j DROP` |

本工具只讀取防火牆規則，不會修改。Linux 版要讀到規則本身需以 root 執行。

## 環境限制

Windows：

- 需 Windows 8 / Server 2012 以上（`Get-NetAdapter`、`Find-NetRoute`、`Get-NetNeighbor`）
- Wi-Fi SSID/BSSID 取自 `netsh wlan`；有線連線無此欄位。Windows 11 另需開啟「定位服務」，
  未開啟時 `netsh wlan` 不回傳介面資料，該兩欄留空，其餘欄位不受影響
- 讀取防火牆規則不需管理員權限，權限受限時該區塊為空

Linux：

- 需 python3 3.6 以上，只用標準函式庫；不需 pip，也不需安裝 PowerShell
- 介面、MAC、閘道、ARP 讀自 `/proc`、`/sys` 與 ioctl，未安裝 iproute2 也能運作
- 讀取 nftables/iptables 規則需要 CAP_NET_ADMIN（實務上即 root）。非 root 執行時該區塊
  標示為「無法讀取」而非「沒有規則」——兩者意義相反，不可混為一談
- Wi-Fi SSID/BSSID 取自 `iw`（或 `iwconfig`），未安裝時該欄位留空
- traceroute 需要 `traceroute` 或 `tracepath`，未安裝時診斷報告的路徑段落留空
- 閘道 RTT 走非特權 ICMP socket（受 `net.ipv4.ping_group_range` 控制），不可用時改呼叫 `ping`，
  再不可用則記為 n/a

</details>
