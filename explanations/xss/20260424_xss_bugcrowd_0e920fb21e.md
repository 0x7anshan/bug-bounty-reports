# DOM Based Cross Site Scripting (XSS) - CrowdStream - Bugcrowd
目标站点: www.globe.gov
报告地址: https://bugcrowd.com/disclosures/d79469cf-e190-4fcb-8fd3-c0fda8f1eaa1/dom-based-cross-site-scripting-xss

## 触发 URL
- https://www.globe.gov/globe-data/science-honor-roll/honor-roll-recognition

## 利用方法
漏洞类型: DOM 型 XSS
关键描述:
- This summary outlines the discovery and mitigation of DOM-Based Cross-Site Scripting (XSS) vulnerabilities within the NASA web application
- DOM-Based Cross-Site Scripting
- DOM-Based XSS is a type of web security vulnerability that exploits the Document Object Model (DOM) of a web page to inject and execute malicious JavaScript code in the victim's browser
关键 Payload:
- `DOM-Based XSS is a type of web security vulnerability that exploits the Document Object Model (DOM) of a web page to inject and execute malicious JavaScript code in the victim's browser. Unlike other XSS vulnerabilities, the malicious payload isn't stored on the server, but rather manipulated on the client-side (browser) through JavaScript.`
- `Enter the payload in the 'School' field: <script>alert('XSS')</script>.`
