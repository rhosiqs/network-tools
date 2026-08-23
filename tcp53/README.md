# TCP/53 Block Watch

偵測並記錄 **TCP port 53 被阻擋** 而導致 DNS 解析失敗的情況。

每筆記錄包含 **時間**、**網卡 MAC / 閘道 MAC / Wi-Fi BSSID**、**阻擋型態**，
以及判斷該型態所依據的原始證據。

純 Windows PowerShell 5.1 撰寫。**不需安裝任何程式語言或套件** —— 只用 Windows 內建的元件。

---

## 為什麼要特別測 TCP 53

DNS 平常走 UDP 53。TCP 53 只在回應太大時才會用到：伺服器把回應標上 `TC`
（truncated）位元，客戶端**必須**改用 TCP 重問一次。

所以封鎖 TCP 53 會產生一種很難查的故障：

- `ping`、`nslookup` 常見網域 —— **全部正常**
- 大型回應的網域（DNSSEC、長 TXT、多筆記錄）—— **完全無法解析**

一般的連線監測工具只做 UDP 查詢，永遠看不到這個問題。本工具直接自己開 socket，
把 UDP 當對照組、TCP 當受測組，兩者比對才能證明問題只出在 TCP 53。

---

## 檔案結構

```
tcp53/
├── Start-Tcp53Watch.ps1      持續監測，偵測到阻擋就寫入記錄
├── Invoke-Tcp53Diagnose.ps1  單次深度診斷，輸出可交給網管的報告
├── Test-Tcp53SelfTest.ps1    自我測試（39 項）
├── run_tcp53.bat             選單式啟動器
├── config/
│   └── tcp53.config.json     監測目標與參數
├── lib/
│   ├── Dns.Codec.ps1         DNS 封包編碼／解碼
│   ├── Net.Probe.ps1         UDP／TCP 探測，記錄失敗發生在哪個階段
│   ├── Host.Context.ps1      MAC、閘道、BSSID、本機防火牆規則
│   ├── Block.Classify.ps1    阻擋型態判定表
│   └── Log.Writer.ps1        JSONL／CSV／文字記錄
└── logs/                     產生的記錄（不納入版本控制）
```

> 本分支與 `main` 分支架構完全不同：`main` 是 Python Flask 網頁儀表板，
> 這裡是無相依性的 PowerShell 命令列工具。兩者各自獨立，互不影響。

---

## 使用方式

雙擊 **`run_tcp53.bat`**，或直接執行：

```bash
powershell -ExecutionPolicy Bypass -File .\Start-Tcp53Watch.ps1
```

啟動後、開始探測之前，兩支腳本都會先問記錄要寫在哪裡：

```
Log directory [C:\...\tcp53\logs]:
```

直接按 Enter 採用預設值，或輸入自己指定的路徑。這是為了讓你在動手之前就知道
記錄會出現在哪，而不是跑完才去找。排程／無人值守執行時，加上 `-LogDirectory`
即可跳過詢問。

常用參數：

```bash
powershell -ExecutionPolicy Bypass -File .\Start-Tcp53Watch.ps1 -Once -LogDirectory C:\tcp53-logs
```

```bash
powershell -ExecutionPolicy Bypass -File .\Start-Tcp53Watch.ps1 -DurationMinutes 480 -IntervalSeconds 30 -Quiet -LogDirectory C:\tcp53-logs
```

```bash
powershell -ExecutionPolicy Bypass -File .\Invoke-Tcp53Diagnose.ps1
```

| 參數 | 說明 |
|---|---|
| `-Once` | 只跑一輪就結束（適合排程） |
| `-DurationMinutes N` | 跑 N 分鐘後停止；預設 0 表示持續到 Ctrl+C |
| `-IntervalSeconds N` | 正常狀態下的取樣間隔 |
| `-Target A,B` | 只測指定目標 |
| `-LogDirectory <path>` | 指定記錄輸出位置；省略時會在腳本一開始互動詢問，排程執行請務必帶上這個參數 |
| `-Quiet` | 不輸出每筆取樣到畫面，但仍完整寫檔 |

`Invoke-Tcp53Diagnose.ps1` 另外支援 `-OutputPath <file>` 直接指定完整報告檔名
（會跳過詢問），或同樣用 `-LogDirectory <path>` 指定目錄、檔名自動加時間戳記。

---

## 每輪做什麼

對設定檔中的每一台 DNS 伺服器：

1. **UDP/53 查詢** —— 對照組。UDP 通代表線路、路由、伺服器都正常。
2. **TCP/53 查詢** —— 受測組。完整做完三向交握、送出查詢、讀回應。
3. **控制埠測試**（TCP/443）—— 同一台主機的非 DNS 埠。443 通而 53 不通，
   就證明過濾規則是**針對 port 53**，而不是這台主機不可達。
4. **截斷回退測試** —— 只在 TCP 失敗時執行。先用 UDP 查一筆大回應
   （預設 root `DNSKEY`），伺服器會回 `TC=1`，接著照規範改用 TCP 重問。
   這一步能直接證明「解析真的壞了」，而不只是「某個埠不通」。

---

## 阻擋型態（BlockType）

判定的核心是 **UDP 通、TCP 不通**，再依 TCP 死在哪個階段細分：

| BlockType | 意義 | 通常代表 |
|---|---|---|
| `None` | TCP 53 正常 | 無異常 |
| `TcpSilentDrop` | SYN 送出後無任何回應直到逾時 | 防火牆 DROP／DENY 規則（最常見） |
| `TcpRejected` | 收到 RST | 明確的 REJECT 規則，或該埠無服務 |
| `TcpUnreachable` | 收到 ICMP unreachable | 路由問題或路由器 ACL |
| `TcpHandshakeThenNoData` | 交握成功但查詢無回應 | 透明代理／DPI 接手後丟棄內容 |
| `TcpResetAfterQuery` | 送出查詢後被 RST | DPI 依封包內容阻擋 |
| `TcpClosedWithoutAnswer` | 對方正常關閉但沒回答 | 代理伺服器，或該伺服器不支援 TCP DNS |
| `TcpAnswerSuspect` | 回應內容與查詢不符 | 疑似 DNS 攔截／竄改 |
| `UdpBlockedTcpOk` | UDP 不通但 TCP 通 | 與預期相反，通常是 UDP 過濾 |
| `DnsServerUnreachable` | 兩種傳輸都不通 | **不是** TCP 53 的問題，先查連線 |

同時會給出 **Scope**（阻擋位置推測）：

- `LocalHost` —— 本機 Windows 防火牆有符合的規則，或 RST 快到不可能離開本機
- `FirstHop` —— RST 的往返時間 ≒ 到閘道的 RTT
- `NetworkEdge` —— 所有伺服器都被擋，屬於全網對外政策
- `ServerOrPath` —— 只有部分伺服器被擋

---

## 產生的記錄

寫在 `logs/`（可用 `-LogDirectory` 改）：

| 檔案 | 用途 |
|---|---|
| `tcp53-events-YYYYMMDD.jsonl` | 每行一個 JSON 物件，完整欄位，逐行附加 |
| `tcp53-events-YYYYMMDD.csv` | 固定欄位，含 UTF-8 BOM，Excel 可直接開 |
| `tcp53-session-*.log` | 人類可讀的逐時文字記錄 |
| `tcp53-diagnosis-*.txt` | 診斷報告 |

主要欄位：

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

**為什麼要記 MAC**：IP 是租用的、會變動。網卡 MAC 指出「是哪一台被擋」，
閘道 MAC（無線則另有 BSSID）指出「當下路徑上是哪一台設備」。
這才是網管實際能拿去找到那條規則的線索。

### 寫入策略

全部記錄健康狀態會把真正重要的幾行淹沒，所以：

- **一定寫**：任何被阻擋的取樣、任何狀態轉換（`BlockStarted` / `BlockCleared`）
- **取樣寫**：正常狀態每 N 輪寫一筆 `Heartbeat`（`LogSuccessEveryNCycles`，預設 20）

偵測到阻擋時，取樣間隔會自動從 `IntervalSeconds` 縮短為 `FastRetrySeconds`，
並在恢復後繼續維持一段時間（`FastRetryHoldSeconds`），
以便完整捕捉斷斷續續的阻擋。

---

## 設定

編輯 `config/tcp53.config.json`。`Server` 填 `AUTO_GATEWAY` 會自動帶入預設閘道。

預設目標沿用 `main` 分支的設定：校內 DNS `140.120.1.2`、HiNet `168.95.1.1`、
Google `8.8.8.8`，另加 Cloudflare `1.1.1.1` 作為第二組對照。

---

## 驗證

```bash
powershell -ExecutionPolicy Bypass -File .\Test-Tcp53SelfTest.ps1
```

39 項測試，涵蓋 DNS 封包編解碼、MAC 正規化、完整的阻擋型態判定表、
控制埠信心度、Scope 推測，以及記錄寫入流程。全數通過時回傳 exit code 0。

判定表是用合成的探測結果測試的 —— 真正的阻擋很少見，不能等它發生才驗證工具。

若要做實機驗證，可自行在 Windows 防火牆暫時新增一條「封鎖對外 TCP 53」的規則，
執行監測確認會出現 `TcpSilentDrop` 且 `Scope=LocalHost`，測完務必刪除該規則。
（本工具只讀取防火牆規則，不會自行修改。）

---

## 已知環境限制

- 需要 Windows 8 / Server 2012 以上（用到 `Get-NetAdapter`、`Find-NetRoute`、`Get-NetNeighbor`）。
- Wi-Fi BSSID 透過 `netsh wlan` 取得；有線連線不會有此欄位。
- 讀取本機防火牆規則不需要系統管理員權限，但權限受限時該區塊會顯示為空。
