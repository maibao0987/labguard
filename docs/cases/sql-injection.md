# SQL Injection：搜尋輸入改變查詢邏輯

- 分類：CWE-89。
- 前置條件：僅本機 TaskBoard vulnerable 模式、假帳號 Alice。
- 根因：`labguard/taskboard.py` 的 vulnerable 搜尋分支把 q 拼接進 SQL 字串。固定版使用 SQLAlchemy 參數處理並保留擁有者條件。

## 本機重現

1. 進入 http://127.0.0.1:5101，以 alice / LabOnly-12345 登入。
2. 一般搜尋 NO-MATCH-LABGUARD，確認沒有任務。
3. 在同一搜尋框輸入固定教學案例：`' OR 1=1 -- `。
4. 觀察搜尋結果是否包含 Bob 的私人任務 TASK-2。
5. 在 :5102 修復版重複相同步驟，輸入被視為資料，不會改變權限查詢。

證據：比較基準與注入條件的假任務結果，不刪改資料、不讀取主機檔案。

## 修復

使用 SQLAlchemy 表達式及參數化查詢；輸入處理不能取代授權條件。不要使用字串拼接或以黑名單過濾單引號作為主要修復。DB runtime 最小權限列於後續硬化。

## 測試與限制

`tests/test_taskboard.py::test_sqli` 比較兩種模式；worker 檢查先建立無匹配基準，再比對固定任務。僅涵蓋一個布林案例，不是通用 SQLi 掃描器。語法錯誤記為失敗，不能視為安全。

