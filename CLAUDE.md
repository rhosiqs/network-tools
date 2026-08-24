# CLAUDE.md

專案協作守則。

## 分支規則

1. `main` 與 `TCP53` 兩個 branch 彼此不相干、依賴（dependency）也不同，開發時請勿混在一起：
   - `main`：Python/Flask Network Connection Test app（`app.py`、`requirements.txt`、`templates/`、`static/`）
   - `TCP53`：純 PowerShell、零外部依賴的 TCP/53 DNS 阻斷偵測工具（`tcp53/` 目錄）
   - 修改其中一個分支時，不要引入另一分支的依賴或架構假設；不要在兩者之間做不必要的合併。
   - Repo 只維護這兩個 branch，不要額外開其他分支。

## Commit 規則

2. 進行修改時請盡情階段性 commit，將工作拆成多個小而清楚的 commit，而不是累積成一個大 commit。

## PR 規則

3. 每次修正都需開 PR，指向所屬的分支（`main` 或 `TCP53`），不要直接 commit 到該分支；CI/CD 檢查通過後才能將 PR merge 回目標分支。
