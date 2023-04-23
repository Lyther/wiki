# Web Exploitation

> https://ctf101.org/web-exploitation/overview/

Websites all around the world are programmed using various programming languages. While the developer should be aware of specific vulnerabilities in each programming language, there are issues fundamental to the internet that can show up regardless of the chosen language or framework.

These vulnerabilities often show up in CTFs as web security challenges where the user needs to exploit a bug to gain some kind of higher-level privilege.

Common vulnerabilities to see in CTF challenges:

- SQL Injection
- Command Injection
- Directory Traversal
- Cross-Site Request Forgery
- Cross-Site Scripting
- Server-Side Request Forgery

## SQL Injection

SQL Injection is a vulnerability where an application takes input from a user and doesn't validate that the user's input doesn't contain additional SQL.

```
<?php
    $username = $_GET['username']; // kchung
    $result = mysql_query("SELECT * FROM users WHERE username='$username'");
?>
```

If we look at the $username variable, we might expect the username parameter to be a real username (e.g. kchung) under normal operation.

But a malicious user might submit a different kind of data. For example, consider if the input was `'`?

The application would crash because the resulting SQL query is incorrect.

```
SELECT * FROM users WHERE username='''
```

> Notice the extra single quote at the end.

With the knowledge that a single quote will cause an error in the application, we can expand a little more on SQL Injection.

What if our input was `' OR 1=1`?

```
SELECT * FROM users WHERE username='' OR 1=1
```

1 is indeed equal to 1. This equates to true in SQL. If we reinterpret this the SQL statement is really saying

```
SELECT * FROM users WHERE username='' OR true
```

This will return every row in the table because each row that exists must be true.

We can also inject comments and termination characters like `--` or `/*` or `;`. This allows you to terminate SQL queries after your injected statements. For example `'--` is a common SQL injection payload.

```
SELECT * FROM users WHERE username=''-- '
```

This payload sets the username parameter to an empty string to break out of the query and then adds a comment (`--`) that effectively hides the second single quote.

Using this technique of adding SQL statements to an existing query we can force databases to return data that it was not meant to return.

## Command Injection

Command Injection is a vulnerability that allows an attacker to submit system commands to a computer running a website. This happens when the application fails to encode user input that goes into a system shell. It is very common to see this vulnerability when a developer uses the `system()` command or its equivalent in the application's programming language.

```
import os

domain = user_input() # ctf101.org

os.system('ping ' + domain)
```

The above code when used normally will ping the `ctf101.org` domain.

But consider what would happen if the `user_input()` function returned different data.

```
import os

domain = user_input() # ; ls

os.system('ping ' + domain)
```

Because of the additional semicolon, the `os.system()` function is instructed to run two commands.

It looks to the program as:

```
ping ; ls
```

> The semicolon terminates a command in bash and allows you to put another command after it.

Because the `ping` command is being terminated and the `ls` command is being added on, the `ls` command will be run in addition to the empty ping command!

This is the core concept behind command injection. The `ls` command could of course be switched with another command (e.g. wget, curl, bash, etc.)

Command injection is a very common means of privilege escalation within web applications and applications that interface with system commands. Many kinds of home routers take user input and directly append it to a system command. For this reason, many of those home router models are vulnerable to command injection.

### Example Payloads

- `;ls`
- `$(ls)`
- ``ls``

## Directory Traversal

Directory Traversal is a vulnerability where an application takes in user input and uses it in a directory path.

Any kind of path controlled by user input that isn't properly sanitized or properly sandboxed could be vulnerable to directory traversal.

For example, consider an application that allows the user to choose what page to load from a GET parameter.

```
<?php
    $page = $_GET['page']; // index.php
    include("/var/www/html/" . $page);
?>
```

Under normal operation, the page would be `index.php`. But what if a malicious user gave in something different?

```
<?php
    $page = $_GET['page']; // ../../../../../../../../etc/passwd
    include("/var/www/html/" . $page);
?>
```

Here the user is submitting `../../../../../../../../etc/passwd`.

This will result in the PHP interpreter leaving the directory that it is coded to look in ('/var/www/html') and instead be forced up to the root folder.

```
include("/var/www/html/../../../../../../../../etc/passwd");
```

Ultimately this will become `/etc/passwd` because the computer will not go a directory above its top directory.

Thus the application will load the `/etc/passwd` file and emit it to the user like so:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
```

This same concept can be applied to applications where some input is taken from a user and then used to access a file or path or similar. This vulnerability very often can be used to leak sensitive data or extract application source code to find other vulnerabilities.

## Cross-Site Request Forgery (CSRF)

A Cross-Site Request Forgery or CSRF Attack pronounced *see the surf*, is an attack on an authenticated user which uses a state session in order to perform state-changing attacks like a purchase, a transfer of funds, or a change of email address.

The entire premise of CSRF is based on session hijacking, usually by injecting malicious elements within a webpage through a `<img>` tag or a `<iframe>` where references to external resources are unverified.

### Using CSRF

`GET` requests are often used by websites to get user input. Say a user signs in to a banking site that assigns their browser a cookie that keeps them logged in. If they transfer some money, the URL that is sent to the server might have the pattern:

```
http://securibank.com/transfer.do?acct=[RECEPIENT]&amount=[DOLLARS]
```

Knowing this format, an attacker can send an email with a hyperlink to be clicked on or they can include an image tag of 0 by 0 pixels which will automatically be requested by the browser such as:

`<img src="http://securibank.com/transfer.do?acct=[RECEPIENT]&amount=[DOLLARS]" width="0" height="0" border="0">`

## Cross-Site Scripting (XSS)

Cross-Site Scripting or XSS is a vulnerability where one user of an application can send JavaScript that is executed by the browser of another user of the same application.

This is a vulnerability because JavaScript has a high degree of control over a user's web browser.

For example, JavaScript has the ability to:

- Modify the page (called the DOM)
- Send more HTTP requests
- Access cookies

By combining all of these abilities, XSS can maliciously use JavaScript to extract users' cookies and send them to an attacker-controlled server. XSS can also modify the DOM to phishing users for their passwords. This only scratches the surface of what XSS can be used to do.

XSS is typically broken down into three categories:

- Reflected XSS
- Stored XSS
- DOM XSS

### Reflected XSS

Reflected XSS is when an XSS exploit is provided through a URL parameter.

For example:

```
https://ctf101.org?data=<script>alert(1)</script>
```

You can see the XSS exploit provided in the `data` GET parameter. If the application is vulnerable to reflected XSS, the application will take this data parameter value and inject it into the DOM.

For example:

```
<html>
    <body>
        <script>alert(1)</script>
    </body>
</html>
```

Depending on where the exploit gets injected, it may need to be constructed differently.

Also, the exploit payload can change to fit whatever the attacker needs it to do. Whether that is to extract cookies and submit them to an external server, or to simply modify the page to deface it.

One of the deficiencies of reflected XSS however is that it requires the victim to access the vulnerable page from an attacker-controlled resource. Notice that if the data parameter, wasn't provided the exploit wouldn't work.

In many situations, reflected XSS is detected by the browser because it is very simple for a browser to detect malicious XSS payloads in URLs.

### Stored XSS

Stored XSS is different from reflected XSS in one key way. In reflected XSS, the exploit is provided through a GET parameter. But in stored XSS, the exploit is provided from the website itself.

Imagine a website that allows users to post comments. If a user can submit an XSS payload as a comment, and then have others view that malicious comment, it would be an example of stored XSS.

The reason is that the website itself is serving up the XSS payload to other users. This makes it very difficult to detect from the browser's perspective and no browser is capable of generically preventing stored XSS from exploiting a user.

### DOM XSS

DOM XSS is XSS that is due to the browser itself injecting an XSS payload into the DOM. While the server itself may properly prevent XSS, it's possible that the client-side scripts may accidentally take a payload and insert it into the DOM and cause the payload to trigger.

The server itself is not to blame, but the client-side JavaScript files are causing the issue.

## Server Side Request Forgery (SSRF)

Server Side Request Forgery or SSRF is where an attacker is able to cause a web application to send a request that the attacker defines.

For example, say there is a website that lets you take a screenshot of any site on the internet.

Under normal usage, a user might ask it to take a screenshot of a page like Google, or The New York Times. But what if a user does something more nefarious? What if they asked the site to take a picture of http://localhost? Or perhaps tries to access something more useful like http://localhost/server-status?

> 127.0.0.1 (also known as localhost or loopback) represents the computer itself. Accessing localhost means you are accessing the computer's own internal network. Developers often use localhost as a way to access the services they have running on their own computers.

Depending on what the response from the site is the attacker may be able to gain additional information about what's running on the computer itself.

In addition, the requests originating from the server would come from the server's IP, not the attacker's IP. Because of that, it is possible that the attacker might be able to access internal resources that he wouldn't normally be able to access.

Another usage for SSRF is to create a simple port scanner to scan the internal network looking for internal services.