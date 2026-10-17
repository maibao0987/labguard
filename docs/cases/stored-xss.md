# Stored XSS：留言資料被當成 HTML

- 分類：CWE-79。
- 前置條件：本人本機 TaskBoard、Alice、團隊任務 3。
- 根因：`templates/task_detail.html` 在 vulnerable 模式使用 `comment.body|safe`；修復版使用 Jinja 預設編碼。

## 先驗證 HTML 注入

1. 開啟 :5101，登入 Alice，進入團隊任務 3。
2. 留言填入 `<span data-labguard-xss="probe">LABGUARD-XSS</span>`。
3. 漏洞版會將它當作 HTML。修復版顯示完整文字標籤。

## 瀏覽器人工驗證腳本執行

僅在上述本人本機假資料頁面提交以下無害標記，不讀取 Cookie、不外傳資料：

```html
<script>document.body.dataset.labguard="verified"</script>
```

重新載入任務頁，使用瀏覽器開發工具檢查 body 是否出現 `data-labguard="verified"`。修復版應只顯示文字，且不產生該屬性。

## 修復與複測

移除不可信留言上的 safe；保留輸出編碼及 CSP。若產品真的需要富文字，另外引入經審查的白名單清理器，不自行以正規表達式清理 HTML。

自動 worker 僅以無害 span 證明 HTML 注入，不能單憑其結果宣稱瀏覽器已執行 JavaScript。人工證據需另行記錄。重新啟動不會清除資料，需使用專案重置。

