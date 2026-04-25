# Hunting for blind XSS vulnerabilities: A complete guide

报告地址: https://www.intigriti.com/researchers/blog/hacking-tools/hunting-for-blind-cross-site-scripting-xss-vulnerabilities-a-complete-guide

## 触发 URL
- 信息不足

## 利用方法
- 将下列 payload 注入到触发 URL 对应的输入点（常见为 query 参数/路径片段/表单字段），观察是否执行：
  - Building your blind XSS payloads
  - More advanced payloads
  - alert() or
  - Blind XSS vulnerabilities also require a specifically crafted payload that helps notify you of any execution as function calls that trigger visual dialogues (like the
  - That said, the delayed execution, hidden injection point and the requirement for a dedicated server that responds to incoming invocations to make your blind XSS payloads work make it much more difficult to exploit.
  - At the end of this article, we will also share with you some advanced blind XSS payloads and guide you on where to inject these.
  - Blind XSS vulnerabilities require a different payload than a simple alert call. We will need to integrate a callback to our server. Let's take a look at some examples.
  - {SERVER} with your server's location in the payloads below.
