# xss - CrowdStream - Bugcrowd
目标站点: bugcrowd.com
报告地址: https://bugcrowd.com/disclosures/fd379503-137e-4d43-9e82-94fdff084820/xss

## 触发 URL
- bugcrowd.com（具体路径见原文）

## 利用方法
关键描述:
- modify_url function that modifies URLs by injecting the provided values into specified parameters
- This allows the program to test modified URLs to detect SQL Injection vulnerabilities
- SQL Injection Testing: In addition to XSS vulnerabilities, the program can also detect SQL Injection vulnerabilities
关键 Payload:
- `<script>,`
- `javascript:, and JavaScript event handler attributes like`
