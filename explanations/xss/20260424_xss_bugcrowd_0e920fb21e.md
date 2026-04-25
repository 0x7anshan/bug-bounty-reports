# DOM Based Cross Site Scripting (XSS) - CrowdStream - Bugcrowd

报告地址: https://bugcrowd.com/disclosures/d79469cf-e190-4fcb-8fd3-c0fda8f1eaa1/dom-based-cross-site-scripting-xss

## 触发 URL
- https://www.globe.gov/globe-data/science-honor-roll/honor-roll-recognition

## 利用方法
- 将下列 payload 注入到触发 URL 对应的输入点（常见为 query 参数/路径片段/表单字段），观察是否执行：
  - DOM-Based XSS is a type of web security vulnerability that exploits the Document Object Model (DOM) of a web page to inject and execute malicious JavaScript code in the victim's browser. Unlike other XSS vulnerabilities, the malicious payload isn't stored on the server, but rather manipulated on the client-side (browser) through JavaScript.
  - Enter the payload in the 'School' field: <script>alert('XSS')</script>.
