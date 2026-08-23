# TCP/53 Block Watch

這個分支只做一件事：偵測並記錄 Windows 主機上 **TCP port 53 被封鎖**
而導致 DNS 解析失敗的情況。

純 Windows PowerShell 5.1 撰寫，不需安裝任何直譯器或套件，也沒有網頁介面
（不依賴 localhost/任何本機服務）—— 只在終端機輸出、並把記錄寫成檔案。

完整說明（原理、使用方式、記錄欄位、阻擋型態判定表）請看：
[`tcp53/README.md`](tcp53/README.md)

## 快速開始

```bash
tcp53\run_tcp53.bat
```

或直接執行：

```bash
powershell -ExecutionPolicy Bypass -File tcp53\Start-Tcp53Watch.ps1
```

---

> 本分支與 `main` 分支（Python/Flask 的 Network Connection Test app）
> 架構完全獨立、彼此不相依，不共用任何程式碼或設定。詳見 [`CLAUDE.md`](CLAUDE.md)。
