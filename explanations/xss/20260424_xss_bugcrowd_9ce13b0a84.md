# Reflected cross site scripting in login page - CrowdStream - Bugcrowd

报告地址: https://bugcrowd.com/disclosures/63a1d77c-df3b-4a1a-95fe-d5aa474fb9b7/reflected-cross-site-scripting-in-login-page

## 触发 URL
- https://accountsstage.yoyogames.com/login
- https://accountsstage.yoyogames.com/login?path=javascript:alert(%27KD%27

## 利用方法
- 将下列 payload 注入到触发 URL 对应的输入点（常见为 query 参数/路径片段/表单字段），观察是否执行：
  - 1) Send this link to any user https://accountsstage.yoyogames.com/login?path=javascript:alert(%27KD%27)
