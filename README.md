# TCP/53 Block Watch

偵測並記錄 TCP port 53 被封鎖而導致 DNS 解析失敗的情況。

純 Windows PowerShell 5.1，無外部相依，無網路服務，輸出為終端機訊息與記錄檔。

## 原理

DNS 平常走 UDP/53。回應超過單一 datagram 時，伺服器設定 `TC`（truncated）位元，
客戶端依 RFC 1035 必須改用 TCP/53 重問。因此封鎖 TCP/53 的症狀是：

- 一般網域解析正常
- 大型回應網域（DNSSEC、長 TXT、多筆記錄）間歇性解析失敗

只做 UDP 查詢的監測工具看不到這個問題。本工具直接開 socket，以 UDP 為對照組、
TCP 為受測組，兩者比對才能證明問題出在 TCP/53。

## 使用

```
run_tcp53.bat
```

或：

```
powershell -ExecutionPolicy Bypass -File .\Start-Tcp53Watch.ps1
powershell -ExecutionPolicy Bypass -File .\Invoke-Tcp53Diagnose.ps1
powershell -ExecutionPolicy Bypass -File .\Test-Tcp53SelfTest.ps1
```

未指定 `-LogDirectory` 時，腳本會在探測開始前詢問記錄輸出位置，Enter 採用設定檔預設值。
排程執行請明確帶入 `-LogDirectory`。

### Start-Tcp53Watch.ps1

| 參數 | 說明 |
|---|---|
| `-Once` | 只跑一輪 |
| `-DurationMinutes N` | N 分鐘後停止；0（預設）持續到 Ctrl+C |
| `-IntervalSeconds N` | 正常狀態取樣間隔 |
| `-Target A,B` | 只測指定目標 |
| `-LogDirectory <path>` | 記錄輸出位置 |
| `-Quiet` | 不輸出每筆取樣到畫面，仍完整寫檔 |

### Invoke-Tcp53Diagnose.ps1

| 參數 | 說明 |
|---|---|
| `-OutputPath <file>` | 報告完整檔名 |
| `-LogDirectory <path>` | 報告目錄，檔名自動加時間戳記 |
| `-SkipTraceRoute` | 略過 traceroute（最慢的階段） |

## 每輪流程

對每個啟用的目標：

1. UDP/53 查詢 — 對照組。UDP 通表示線路、路由、伺服器正常。
2. TCP/53 查詢 — 受測組。完整三向交握、送查詢、讀回應。
3. TCP/443 控制埠連線 — 同主機的非 DNS 埠。443 通而 53 不通，證明過濾針對 port 53。
4. 截斷回退測試 — 僅在 TCP 失敗時執行。以 UDP 查大回應（預設 root `DNSKEY`）取得
   `TC=1`，再依規範改用 TCP 重問，證明實際解析已損壞。

## BlockType

判定基準為 UDP 通、TCP 不通，再依 TCP 失敗階段細分。

| BlockType | 意義 | 通常成因 |
|---|---|---|
| `None` | TCP/53 正常 | — |
| `TcpSilentDrop` | SYN 後無回應至逾時 | 防火牆 DROP 規則 |
| `TcpRejected` | 收到 RST | REJECT 規則，或該埠無服務 |
| `TcpUnreachable` | 收到 ICMP unreachable | 路由問題或路由器 ACL |
| `TcpHandshakeThenNoData` | 交握成功但查詢無回應 | 透明代理／DPI 丟棄內容 |
| `TcpResetAfterQuery` | 送出查詢後被 RST | DPI 依封包內容阻擋 |
| `TcpClosedWithoutAnswer` | 正常關閉但無回答 | 代理伺服器，或不支援 TCP DNS |
| `TcpAnswerSuspect` | 回應與查詢不符 | DNS 攔截／竄改 |
| `UdpBlockedTcpOk` | UDP 不通、TCP 通 | UDP 過濾 |
| `DnsServerUnreachable` | 兩種傳輸皆不通 | 連線問題，非 TCP/53 議題 |

## Scope

阻擋位置推測：

| Scope | 判定依據 |
|---|---|
| `LocalHost` | 本機防火牆有符合規則，或 RST RTT 低到不可能離開本機 |
| `FirstHop` | RST RTT ≒ 到預設閘道的 RTT |
| `NetworkEdge` | 所有目標皆被擋 |
| `ServerOrPath` | 僅部分目標被擋 |

## 記錄

| 檔案 | 內容 |
|---|---|
| `tcp53-events-YYYYMMDD.jsonl` | 每行一個 JSON 物件，完整欄位 |
| `tcp53-events-YYYYMMDD.csv` | 固定欄位，UTF-8 BOM |
| `tcp53-session-*.log` | 逐時文字記錄 |
| `tcp53-diagnosis-*.txt` | 診斷報告 |

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

記錄 MAC 的原因：IP 會變動，網卡 MAC 指出是哪一台主機，閘道 MAC 與 Wi-Fi BSSID
指出當下路徑上是哪一台設備。

寫入策略：

- 一定寫：被阻擋的取樣、狀態轉換（`BlockStarted` / `BlockCleared`）
- 取樣寫：正常狀態每 `LogSuccessEveryNCycles` 輪寫一筆 `Heartbeat`（預設 20）

偵測到阻擋時取樣間隔自動從 `IntervalSeconds` 縮短為 `FastRetrySeconds`，
恢復後維持 `FastRetryHoldSeconds` 秒，以捕捉間歇性阻擋。

## 設定

`config/tcp53.config.json`。`Server` 填 `AUTO_GATEWAY` 會帶入預設閘道。

## 自我測試

```
powershell -ExecutionPolicy Bypass -File .\Test-Tcp53SelfTest.ps1
```

39 項測試，涵蓋 DNS 封包編解碼、MAC 正規化、BlockType 判定表、控制埠信心度、
Scope 推測與記錄寫入。全數通過回傳 exit code 0。

實機驗證可暫時新增一條 Windows 防火牆「封鎖對外 TCP 53」規則，確認出現
`TcpSilentDrop` 且 `Scope=LocalHost`，測後刪除。本工具只讀取防火牆規則，不會修改。

## 環境限制

- 需 Windows 8 / Server 2012 以上（`Get-NetAdapter`、`Find-NetRoute`、`Get-NetNeighbor`）
- Wi-Fi BSSID 取自 `netsh wlan`；有線連線無此欄位
- 讀取防火牆規則不需管理員權限，權限受限時該區塊為空
