# Master The Challenge: YesWeHack &amp; Alibaba Hacking Game Write-up | YesWeHack Community

报告地址: https://www.yeswehack.com/community/yeswehack-alibaba-hackinggame-writeup

## 触发 URL
- http://54.254.225.32:4242/medium/loader?key=L3N0YXRpYy9oZWFydC5qcw==.d635f5480983ee9eb49a2f9cbc010141cf2b7899&debug=true&–%3E%3Cscript%3Ealert(document.domain
- http://example.com
- http://example.com/

## 利用方法
- 将下列 payload 注入到触发 URL 对应的输入点（常见为 query 参数/路径片段/表单字段），观察是否执行：
  - It was composed of 3 steps of increasing difficulty in the form of extra security layer. All the payload are tested with Chrome 75.
  - 1<div class="container"> <h1>Js Canvas Gallery (easy)</h1> <ul> <li><a href="#L3N0YXRpYy9oZWFydC5qcw==.d635f5480983ee9eb49a2f9cbc010141cf2b7899">heart</a></li> <li><a href="#L3N0YXRpYy90cmlhbmdsZS5qcw==.bf15ad95b9de4c9b8518b55c6d2e2410e5192e19">triangle</a></li> <li><a href="#L3N0YXRpYy9idWJibGUuanM=.962b9e3c233aff6c36c2ee97e2f91c11dc348714">bubble</a></li> </ul> <iframe id="frame" seamless></ifra…
  - 16 <script>17 const frame = document.getElementById("frame");18
  - 32 window.addEventListener("DOMContentLoaded", e => {33 displayDrawing()34 })35 </script>
  - 1<!doctype html>2<html>3 <head>4 <meta charset="utf8">5 <title></title>6 <script src="data:application/javascript;base64,Y29uc3QgY29uZmlnID0ge3NyYzonL3N0YXRpYy9oZWFydC5qcycsIGFjY2Vzc0tleTogJ2Q2MzVmNTQ4MDk4M2VlOWViNDlhMmY5Y2JjMDEwMTQxY2YyYjc4OTknfTs=" ></script>7 <style >8 *{9 box-sizing: border-box;10 }11 html {12 font-family: helvetica;13 height: 100%;14 margin: 0;15 padding: 0;16 }17 body{18 mar…
  - 3 <body>4 <!-- DEBUG = True5 key = L3N0YXRpYy9oZWFydC5qcw==.d635f5480983ee9eb49a2f9cbc010141cf2b78996 debug = true7 -->8 <canvas id="canvas"></canvas>9 <script >10 document.addEventListener("DOMContentLoaded", e=> {11 console.log(`Access granted to "${config.src}" with "${config.accessKey}"`);12 const script = document.createElement("script")13 script.src = `${config.src}?${Math.random()}`14 docum…
  - With this information, we can now send a new paramter that will close the comment and add a script that will call alert(document.domain)
  - 1GET /easy/loader?key=L3N0YXRpYy9oZWFydC5qcw==.d635f5480983ee9eb49a2f9cbc010141cf2b7899&debug=true&test=--><script>alert('xss')</script><!--2
