# xss - CrowdStream - Bugcrowd

报告地址: https://bugcrowd.com/disclosures/fd379503-137e-4d43-9e82-94fdff084820/xss

## 触发 URL
- 信息不足

## 利用方法
- 将下列 payload 注入到触发 URL 对应的输入点（常见为 query 参数/路径片段/表单字段），观察是否执行：
  - <script>,
  - javascript:, and JavaScript event handler attributes like
