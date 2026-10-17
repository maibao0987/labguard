# 實際驗收紀錄

## 2026-10-17 Docker / PostgreSQL 補驗（目前狀態）

重開機後，Docker Engine 29.8.2 正常，Docker Desktop 4.95.0、WSL 3.0.3。以下已實際執行，不再只是 SQLite 開發模式：

- 官方 Python / PostgreSQL 映像拉取及 Linux 應用映像建置成功。
- 8 個本專案容器運行；3 個 PostgreSQL、3 個 Web、gateway 共 7 個健康檢查通過。worker 已成功執行工作。
- Windows localhost :5100 / :5101 / :5102 均通過健康與功能檢查。
- 平台登入、6 個主要頁面、10 個固定假資料檢查、Markdown / JSON 匯出通過。
- 漏洞版產生 4 筆預期發現；修復版未觸發這些固定案例。
- 原 asset #1 的 IDOR 經人工狀態流程、原服務切換為修復行為、實際複測後 resolved；恢復漏洞行為再檢查後 reopened。共 12 個成功工作，使用 PostgreSQL 實際保存觀測、稽核與複測。
- 恢復原本的漏洞／修復對照配置，測試授權已撤銷；服務保持啟動供使用者操作。
- 檢查實際容器發布埠僅綁 127.0.0.1；資料庫不發布埠；app 非 root、唯讀 rootfs、cap_drop、資源限制有效。
- worker 中的固定目標可達、無預設路由、TaskBoard DB DNS 分隔檢查通過。
- 新增 tmpfs YAML 及固定轉送器回歸檢查後，48 項自動測試全部通過。

### 本次修正

1. tmpfs flow-list 內含逗號，必須把整段字串加引號，否則產生非法 mount path。
2. 本機 Docker 在服務僅加入 internal 網路時沒有實際發布 host port。加入 `gateway` 固定 TCP 入口：只有 gateway 連接一般 ingress 網路，且只轉送 manager／vulnerable-web／fixed-web；禁止任意目標及 IP forwarding。漏洞服務、worker、資料庫仍只接內部網路。

### 證據與限制

`reports/samples/docker-runtime-verification.json`：實際容器設定。
`reports/samples/docker-verify-report.json`：原資產複測關閉。
`reports/samples/docker-reopen-report.json`：原資產恢復漏洞後重新開啟。

目前未宣稱完成：主機閘道不可達證明、kernel 隔離、長時間／大量資料／多 worker 測試、遠端 GitHub CI、依賴與映像完整弱點稽核。gateway 有一般 ingress 網路，是受信任且目標固定的邊界服務；不能宣稱所有容器均無外連路由。

以下保留 2026-10-16 的歷史紀錄；其中「尚未驗證」描述當日狀態，Docker 核心啟動與功能已由上述補驗更新。

---

日期：2026-10-16（Asia/Taipei）。版本：0.1.0。資料均為本人建立的固定本機假資料。

## 已實際完成

| 項目 | 結果 | 證據 |
|---|---|---|
| 單元／整合／安全回歸 | 46 passed | tests/；pytest 46.06 秒 |
| Ruff 檢查 | 通過 | labguard、tests、scripts、migrations |
| Compose 靜態安全契約 | 通過 | scripts/check_compose.py |
| Alembic SQLite 初始化及重複 seed | 三種服務通過 | tests/test_migrations.py |
| PostgreSQL DDL 編譯 | 通過，僅編譯 | 同上；不代表 PG 執行 |
| 實際 localhost 服務 | :5100 / :5101 / :5102 健康 | scripts/smoke.py |
| 平台登入及六個主要頁面 | HTTP 200 | smoke.py |
| 固定檢查工作 | 每輪 10 個全部完成，已跑兩輪 | actual-local-report.json，20 個工作 |
| 漏洞版結果 | headers / idor / sqli / xss 共 4 筆 | 同上；重跑增加觀測而非弱點 |
| 修復版結果 | 未觸發上述固定案例 | 同上；不推定全面安全 |
| 原資產修復複測 | asset #1 相同 IDOR 弱點 resolved | actual-retest-report.json；21 個工作 |
| 報告匯出 | JSON 與 Markdown 成功 | reports/samples/actual-*.json / md |
| 授權撤銷 | 實測流程結束後已撤銷 | 稽核紀錄；匯出在撤銷前，範例 scope 可能顯示當時啟用 |
| 桌面儀表板 | 1440px 版面檢查 | screenshots/dashboard-desktop.png |
| 手機儀表板 | 390px、頁面無水平溢位 | screenshots/dashboard-mobile.png；DOM scrollWidth 375 ≤ innerWidth 390 |
| Stored XSS 瀏覽器執行 | 漏洞版 body.dataset.labguard = verified | 無害 script 標記，未讀取 Cookie／未外傳 |
| Stored XSS 修復 | fixed 版屬性為 null，腳本文字可見 | screenshots/xss-fixed.png |

實際網路測試使用本機開發模式、獨立 SQLite、Waitress 服務與單 worker。沒有任何外部掃描。XSS 自動 worker 僅偵測 HTML 注入；本次另外用瀏覽器人工流程確認腳本執行與修復結果。

## 尚未驗證

- 本機沒有 Docker 指令，因此未拉取或執行 Docker 容器。
- PostgreSQL 實際連線、交易、row lock、併發及中斷恢復。
- Linux Docker 映像建置、Compose 健康檢查與實際記憶體限制。
- Docker Desktop 主機閘道可達性、執行時外連阻擋與防火牆邊界。
- GitHub Actions 實際遠端執行；只交付 workflow，沒有上傳 repo。
- 完整依賴弱點稽核、映像 digest 固定及軟體供應鏈驗證。
- 多瀏覽器、實體手機、長時間穩定性與大量資料。

## 與原始完成定義對照

核心程式與本機端到端流程已交付。**MVP 的完整 Docker 隔離驗收仍未完成**；必須在具備 Docker 的環境補齊上述項目，才能聲稱原始規格所有驗收均通過。

測試樣本中含假資料及固定教學步驟，不含管理員密碼、Session、.env 或真實資料。交付包排除 runtime、快取、虛擬環境及本次產生的秘密。


GitHub 分享版本未附上述畫面檔案；表格保留原始本機驗收紀錄。
