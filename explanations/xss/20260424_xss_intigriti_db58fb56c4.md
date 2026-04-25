# Reflected XSS: Advanced Exploitation Guide

报告地址: https://www.intigriti.com/researchers/blog/hacking-tools/hunting-for-reflected-xss-vulnerabilities

## 触发 URL
- https://www.intigriti.com/researchers/blog/hacking-tools/finding-hidden-input-parameters
- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

## 利用方法
- 将下列 payload 注入到触发 URL 对应的输入点（常见为 query 参数/路径片段/表单字段），观察是否执行：
  - Step 3: Payload (proof of concept)
  - DOM-based XSS occurs when unsafe JavaScript code processes user-controllable data (from a DOM source) and passes it to a DOM sink. This allows attackers to craft JavaScript payloads that would be evaluated by the vulnerable application.
  - <script> tag, the injection string will look slightly different. We will discuss this case more in-depth shortly.
  - Now it's time to craft a working proof of concept that executes JavaScript in the victim's browser. To do so, your payload depends on 2 factors: 1) the context in which your input is reflected, and 2) any existing filters preventing you from injecting malicious XSS payloads.
  - Let's take a look at several contexts in which your unsanitized input can appear, and also go through a few payloads that can help us break out of it and achieve code execution.
  - When your input is directly reflected in the HTML body without being wrapped in any specific tags or attributes, you have the most flexibility for exploitation. Start simple with payloads like:
  - <script>alert(1)</script>
  - <img src=x onerror=alert(1)>
