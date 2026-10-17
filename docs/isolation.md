# Docker 隔離設計與驗證

靜態限制：實驗與資料網路皆 internal；只有固定 TCP gateway 加入一般 ingress 網路，並只發布 127.0.0.1 的三個固定埠。DB 無 published ports；App 與 gateway 非 root、唯讀 rootfs、ALL capabilities dropped、no-new-privileges、tmpfs 及資源限制。

gateway 只轉送三個固定服務，沒有任意 URL／Host 路由、shell 或上傳功能，並設定 net.ipv4.ip_forward=0。實驗網站、worker 與資料庫不加入 ingress 網路。gateway 本身有一般網路，是受信任的邊界元件，不能宣稱整套環境所有容器都無外連路由。

漏洞／修復資料庫另有專用內部網路，Worker 不能直接加入。平台資料庫與管理平台／worker 同管理網路。

## 驗證步驟

1. `python scripts/check_compose.py`：只驗證設定，不證明實際隔離。
2. 啟動 Docker 後執行 `scripts/verify-lab.ps1`。
3. 容器內腳本檢查固定服務可達、無可用預設路由、TaskBoard DB DNS 分隔。
4. 使用 Docker inspect 確認實際 network、bind、user、mount 與 security options 和設定一致。
5. 在額外的可丟棄 VM 中建立「未授權假服務」，以該服務的固定地址做明確的邊界檢查；不要對真實外網或 LAN 做探測。
6. 人工驗證主機閘道與 Docker Desktop 的防火牆邊界。若此項沒有完成，報告必須保留「主機可達性未證明」。

internal network 不是完整容器逃逸防護；也不能直接推定主機服務不可達。不要為了讓隔離檢查通過而新增公網探測。

2026-10-17 已完成本機 Docker／PostgreSQL 啟動與核心功能驗證，以及實際容器限制、worker 無預設路由及資料庫 DNS 分隔檢查。主機閘道與 kernel 邊界仍未證明，詳見 verification.md。

