# LabGuard ◈ 個人攻防實驗室與弱點管理平台

以初學者 Web 滲透測試職涯為方向的本機作品：建立隔離環境、重現漏洞、修復、複測並保留報告。

**僅使用本人擁有且明確授權的固定本機資產。沒有任意網址掃描、任意命令或公網部署功能。**

## 這個版本包含什麼

- 繁體中文管理介面：總覽、資產與授權、工作佇列、弱點、報告及稽核。
- TaskBoard 漏洞版及修復版：登入、任務、搜尋、留言、個人資料。
- SQL Injection、Stored XSS、IDOR 三個受控教學案例。
- 固定目標檢查：健康、安全標頭、SQLi、IDOR、HTML 注入。
- 弱點去重與歷次觀測、人工確認、狀態轉換、相同資產複測與重新開啟。
- Markdown / JSON 報告、安全文字呈現、CSRF、密碼雜湊及 Session 防護。
- Docker Compose、三個獨立 PostgreSQL、單一 worker、Alembic 初始遷移。
- Windows 啟停／重置腳本、SQLite 本機開發模式、自動測試與 GitHub Actions。

目前驗證程度及未完項目見 [驗收紀錄](docs/verification.md)。不能將靜態隔離設定或 SQLite 測試宣稱為 Docker / PostgreSQL 實測通過。

2026-10-17 已完成 Docker / PostgreSQL 的本機啟動、登入、10 個固定檢查、報告匯出及同資產修復複測／重新開啟，48 項測試通過。實驗及資料服務只加入內部網路；只有固定 gateway 發布 localhost 埠。本作品不串接付費 API、不購買雲端主機或訂閱服務。

## 建議啟動方式：Docker

先安裝並啟動 Docker Desktop，使用 Linux containers。初次建置需要下載官方映像與 PyPI 套件。至少預留約 2 GB 可用記憶體與數 GB 磁碟空間；實際依 Docker 設定而異。

在本資料夾開啟 PowerShell：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
```

此參數僅適用當次 PowerShell 程序，不修改系統的執行原則。腳本會建立未追蹤的 `.env` 隨機密碼、建置並啟動環境。

| 介面 | 本機位置 | 登入 |
|---|---|---|
| 管理平台 | http://127.0.0.1:5100 | admin；密碼見 `.env` 的 MANAGER_PASSWORD |
| TaskBoard 漏洞版 | http://127.0.0.1:5101 | alice / bob / admin；密碼 LabOnly-12345 |
| TaskBoard 修復版 | http://127.0.0.1:5102 | 同上，資料庫互相獨立 |

進入管理平台後：
1. 開啟「資產與授權」。
2. 確認本人擁有此實驗環境，填寫聲明，啟用 24 小時授權。
3. 在「檢查工作」選擇固定資產與檢查。
4. 工作由 worker 執行；按「重新整理」查看結果。
5. 在「弱點管理」查看證據，人工確認後依序轉為修復中及待複測。
6. 修復原資產，再執行該弱點的複測。
7. 到「報告中心」下載結果。

授權到期或撤銷後，後續請求會停止。XSS 檢查會在團隊任務加入無害標記留言，可透過本專案重置清除。

### 停止與重置

```powershell
.\scripts\stop.ps1
# 僅預覽重置範圍
.\scripts\reset-lab.ps1
# 明確確認後清除本專案三個資料卷
.\scripts\reset-lab.ps1 -ConfirmReset
```

重置會失去本實驗室資料庫內容；先匯出需要保留的報告。`.env` 保留。不要使用全域 Docker prune。

## 沒有 Docker：本機開發模式

需要 Python 3.12 與網路以安裝套件：

```powershell
.\scripts\dev-start.ps1
```

或自行執行：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.lock
.\.venv\Scripts\python.exe scripts/dev.py --allow-local-lab
```

此模式僅綁定 localhost，使用三個獨立 SQLite 檔案。密碼在 `runtime/local-secrets.json`，不得提交。**這是開發模式，沒有容器網路隔離。** Ctrl+C 會停止腳本建立的子程序；不要在分享主機或正式環境使用。

## 修復與複測原資產

固定修復版是行為比較工具。對固定修復版測試通過，不能直接關閉漏洞版的弱點。

Docker：在 `.env` 將 `REPAIRED_SERVICE=vulnerable` 改成 `REPAIRED_SERVICE=fixed`，再執行：

```powershell
docker compose -p labguard up -d --force-recreate vulnerable-web
```

這會讓原本的 asset #1、同一 IP / port / database 改為修復行為。回到平台對該筆待複測弱點執行複測。恢復 vulnerable 後再檢查，相同指紋會重新開啟。

本機模式：Ctrl+C 停止，再以 `scripts/dev.py --allow-local-lab --repair-original` 啟動，保留原資產 ID 與資料庫。這個切換方便展示；真正開發修復時也可修改根因程式與提交差異。

## 開發驗證

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check labguard tests scripts
.\.venv\Scripts\python.exe scripts/check_compose.py
# 啟動完整環境後；僅連線固定 localhost，並新增假資料與檢查工作
.\.venv\Scripts\python.exe scripts/smoke.py
# Docker 執行時隔離檢查
.\scripts\verify-lab.ps1
```

`smoke.py` 應在乾淨且未修改的漏洞／修復組合執行，成功後撤銷授權。它會把實測報告存入 `reports/samples/actual-local-report.*`。匯入格式見 `reports/samples/import-example.json`。

## 目錄與閱讀順序

1. `docs/architecture.md`：架構、資料流與原始規格對照。
2. `docs/threat-model.md`、`authorization.md`、`isolation.md`：邊界。
3. `docs/cases/`：三個漏洞案例。
4. `docs/development-stages.md`：循序開發與 Codex 提示詞。
5. `docs/demo.md`：5～8 分鐘展示流程。
6. `docs/verification.md`、`limitations.md`：已測試內容與限制。

分享版本未收錄原始專案規格；架構與使用方式請參閱本 README 及 docs 文件。後端模組放在 `labguard/`，模板及 CSS 共用；各服務以不同程序、秘密與資料庫執行。此佈局減少重複 Dockerfile，功能責任仍分離。

## 故障排除

- 找不到 docker：安裝／啟動 Docker Desktop；未裝時可用開發模式。
- 連接埠衝突：停止占用 5100～5102 的服務；不要任意改 manifest 或放寬目標限制。
- Docker 網段衝突：目前 lab_net 為 172.30.77.0/24；需同時審查修改 Compose 靜態 IP 與 assets.yaml。
- 工作被拒絕：查看授權是否啟用、過期、資產是否停用。
- 工作卡住：查看 `docker compose -p labguard logs worker`；worker 重啟後會將心跳逾期工作標成逾時。
- 更改 `.env` 密碼後無法登入：資料庫內既有帳號不會自動改密碼，避免誤以為換環境變數即已輪替。請先備份報告再按需重置本專案。
- 遠端 CI、主機邊界或壓力測試：依 verification.md 的待驗清單執行；本機功能通過不代表其他範圍也已通過。

## 參考資料

- Docker Compose networking：https://docs.docker.com/compose/how-tos/networking/
- Flask security：https://flask.palletsprojects.com/en/stable/web-security/
- SQLAlchemy connections：https://docs.sqlalchemy.org/en/20/core/connections.html

