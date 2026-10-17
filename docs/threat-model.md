# 威脅模型

| 威脅 | 邊界與控制 | 仍需注意 |
|---|---|---|
| 任意目標造成越界請求 | 固定 registry、只收 ID、未知參數拒絕 | 有 repo 修改權者可改設定 |
| DNS 解析改變／重新導向 | 每次解析比對固定 IP，實際連 literal IP；不跟隨重導向 | 主機管理員仍能修改網路 |
| 授權撤銷後繼續 | 入列、領取、每個請求及提交前重新檢查 | 已在進行中的單一請求不能回溯取消 |
| 惡意大回應或慢連線 | 3 秒網路 timeout、64 KB、45 秒工作時限、2 req/s | worker 受 OS 排程影響，非硬即時截止 |
| Worker 濫用 | 固定程式檢查，無 shell/upload；單一 worker | Worker 有平台 DB 存取權，需保護此程序 |
| 漏洞網站影響管理平台 | 分網、分 DB、不同 Session secret | 同一主機 kernel / Docker Desktop 是共同邊界 |
| 證據 Stored XSS | Jinja 編碼、CSP、文字 evidence | 教學 vulnerable 版本刻意不編碼 |
| JSON 匯入濫用 | 128 KB、最多 50 項、固定欄位型別及長度、交易回滾 | 未提供完整 JSON Schema 外部驗證器 |
| 報告注入 | 文字匯出，Markdown 將不可信資料放入跳脫 JSON fence | 使用者另行轉 HTML 時仍要審查渲染器 |
| 密碼與 Session 洩漏 | 雜湊、HttpOnly、SameSite、CSRF、輸出遮罩 | .env / runtime 本機檔案需使用者自行保護 |
| 主機目錄／Docker socket 暴露 | 無主機 bind mount、無 socket、非 root App | PostgreSQL 仍用官方映像預設初始化權限 |
| 錯誤結果被視為修復 | 不成功一律不關閉；原資產精確複測匹配 | 固定案例不代表全面掃描或零弱點 |

本機 HTTP 不設 Secure Cookie，否則瀏覽器無法以本機 HTTP 正常登入。此設定只適合本機；本專案不提供遠端部署流程。

