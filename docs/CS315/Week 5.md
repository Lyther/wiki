# Week5 WEB: Vulnerability Exploit

## Web Exploitation

Websites all around the world are programmed using various programming languages. While there are specific vulnerabilities in each programming language that the developer should be aware of, there are issues fundamental to the internet that can show up regardless of the chosen language or framework.

These vulnerabilities often show up in CTFs as web security challenges where the user needs to exploit a bug to gain some kind of higher level privilege.

Common vulnerabilities to see in CTF challenges:

- SQL Injection
- Command Injection
- Directory Traversal
- Cross Site Request Forgery
- Cross Site Scripting
- Server Side Request Forgery

## SQL Injection

SQL Injection is a vulnerability where an application takes input from a user and doesn't validate that the user's input doesn't contain additional SQL.

```
<?php
    $username = $_GET['username']; // kchung
    $result = mysql_query("SELECT * FROM users WHERE username='$username'");
?>
```

If we look at the $username variable, under normal operation we might expect the username parameter to be a real username (e.g. kchung).

But a malicious user might submit different kind of data. For example, consider if the input was `'`?

The application would crash because the resulting SQL query is incorrect.

```
SELECT * FROM users WHERE username='''
```

**Notice the extra single quote at the end.**

With the knowledge that a single quote will cause an error in the application we can expand a little more on SQL Injection.

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

Command Injection is a vulnerability that allows an attacker to submit system commands to a computer running a website. This happens when the application fails to encode user input that goes into a system shell. It is very common to see this vulnerability when a developer uses the `system()` command or its equivalent in the programming language of the application.

```
import os

domain = user_input() # ctf101.org

os.system('ping ' + domain)
```

The above code when used normally will ping the `ctf101.org` domain.

But consider what would happen if the `user_input()` function returned different data?

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

**The semicolon terminates a command in bash and allows you to put another command after it.**

Because the `ping` command is being terminated and the `ls` command is being added on, the `ls` command will be run in addition to the empty ping command!

This is the core concept behind command injection. The `ls` command could of course be switched with another command (e.g. wget, curl, bash, etc.)

Command injection is a very common means of privelege escalation within web applications and applications that interface with system commands. Many kinds of home routers take user input and directly append it to a system command. For this reason, many of those home router models are vulnerable to command injection.

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

Under normal operation the page would be `index.php`. But what if a malicious user gave in something different?

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

## Cross Site Request Forgery (CSRF)

A Cross Site Request Forgery or CSRF Attack, pronounced *see surf*, is an attack on an authenticated user which uses a state session in order to perform state changing attacks like a purchase, a transfer of funds, or a change of email address.

The entire premise of CSRF is based on session hijacking, usually by injecting malicious elements within a webpage through an `<img>` tag or an `<iframe>` where references to external resources are unverified.

### Using CSRF

`GET` requests are often used by websites to get user input. Say a user signs in to an banking site which assigns their browser a cookie which keeps them logged in. If they transfer some money, the URL that is sent to the server might have the pattern:

```
http://securibank.com/transfer.do?acct=[RECEPIENT]&amount=[DOLLARS]
```

Knowing this format, an attacker can send an email with a hyperlink to be clicked on or they can include an image tag of 0 by 0 pixels which will automatically be requested by the browser such as:

```
<img src="http://securibank.com/transfer.do?acct=[RECEPIENT]&amount=[DOLLARS]" width="0" height="0" border="0">
```

## Cross Site Scripting (XSS)

Cross Site Scripting or XSS is a vulnerability where on user of an application can send JavaScript that is executed by the browser of another user of the same application.

This is a vulnerability because JavaScript has a high degree of control over a user's web browser.

For example JavaScript has the ability to:

- Modify the page (called the DOM)
- Send more HTTP requests
- Access cookies

By combining all of these abilities, XSS can maliciously use JavaScript to extract user's cookies and send them to an attacker controlled server. XSS can also modify the DOM to phish users for their passwords. This only scratches the surface of what XSS can be used to do.

XSS is typically broken down into three categories:

- Reflected XSS
- Stored XSS
- DOM XSS

### Reflected XSS

Reflected XSS is when an XSS exploit is provided through a URL paramater.

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

Also, the exploit payload can change to fit whatever the attacker needs it to do. Whether that is to extract cookies and submit it to an external server, or to simply modify the page to deface it.

One of the deficiencies of reflected XSS however is that it requires the victim to access the vulnerable page from an attacker controlled resource. Notice that if the data paramter, wasn't provided the exploit wouldn't work.

In many situations, reflected XSS is detected by the browser because it is very simple for a browser to detect malicous XSS payloads in URLs.

### Stored XSS

Stored XSS is different from reflected XSS in one key way. In reflected XSS, the exploit is provided through a GET parameter. But in stored XSS, the exploit is provided from the website itself.

Imagine a website that allows users to post comments. If a user can submit an XSS payload as a comment, and then have others view that malicious comment, it would be an example of stored XSS.

The reason being that the web site itself is serving up the XSS payload to other users. This makes it very difficult to detect from the browser's perspective and no browser is capable of generically preventing stored XSS from exploiting a user.

### DOM XSS

DOM XSS is XSS that is due to the browser itself injecting an XSS payload into the DOM. While the server itself may properly prevent XSS, it's possible that the client side scripts may accidentally take a payload and insert it into the DOM and cause the payload to trigger.

The server itself is not to blame, but the client side JavaScript files are causing the issue.

## Server Side Request Forgery (SSRF)

Server Side Request Forgery or SSRF is where an attacker is able to cause a web application to send a request that the attacker defines.

For example, say there is a website that lets you take a screenshot of any site on the internet.

Under normal usage a user might ask it to take a screenshot of a page like Google, or The New York Times. But what if a user does something more nefarious? What if they asked the site to take a picture of http://localhost ? Or perhaps tries to access something more useful like http://localhost/server-status ?

*127.0.0.1 (also known as localhost or loopback) represents the computer itself. Accessing localhost means you are accessing the computer's own internal network. Developers often use localhost as a way to access the services they have running on their own computers.*

Depending on what the response from the site is the attacker may be able to gain additional information about what's running on the computer itself.

In addition, the requests originating from the server would come from the server's IP not the attackers IP. Because of that, it is possible that the attacker might be able to access internal resources that he wouldn't normally be able to access.

Another usage for SSRF is to create a simple port scanner to scan the internal network looking for internal services.

## PHP

PHP is one of the most used languages for back-end web development and therefore it has become a target by hackers. PHP is a language which makes it painful to be secure for most instances, making it every hacker's dream target.

### Overview

PHP is a C-like language which uses tags enclosed by `<?php ... ?>` (sometimes just `<? ... ?>`). It is inlined into HTML. A word of advice is to keep the php docs open because function names are strange due to the fact that the length of function name is used to be the key in PHP's internal dictionary, so function names were shortened/lengthened to make the lookup faster. Other things include:

- Variables start with $: `$name`
- Variable variables: `$$name`
- Request-specific dictionaries: `$_GET, $_POST, $_SERVER`

### Example

```
<?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email']) && isset($_POST['password'])) {
        $db = new mysqli('127.0.0.1', 'cs3284', 'cs3284', 'logmein');
        $email = $_POST['email'];
        $password = sha1($_POST['password']);
        $res = $db->query("SELECT * FROM users WHERE email = '$email' AND password = '$password'");
        if ($row = $res->fetch_assoc()) {
            $_SESSION['id'] = $row['id'];
            header('Location: index.php');
            die();
        }
   }
?>
<html>...
```

This example PHP simply checks the POST data for an email and password. If the password is equal to the hashed password in the database, the use is logged in and redirected to the index page.

The line `email = '$email'` uses automatic string interpolation in order to convert $email into a string to compare with the database.

### Type Juggling

PHP will do just about anything to match with a loose comparison (==) which means things can be 'equal' (==) or *really* equal (===). The implicit integer parsing to strings is the root cause of a lot of issues in PHP.

### Type Comparison Table

#### Comparisons of $x with PHP Functions

| Expression            | gettype() | empty() | is_null() | isset() | boolean: `if($x)` |
| :-------------------- | :-------- | :------ | :-------- | :------ | :---------------- |
| $x = "";              | string    | TRUE    | FALSE     | TRUE    | FALSE             |
| $x = null;            | NULL      | TRUE    | TRUE      | FALSE   | FALSE             |
| var $x;               | NULL      | TRUE    | TRUE      | FALSE   | FALSE             |
| $x is undefined       | NULL      | TRUE    | TRUE      | FALSE   | FALSE             |
| $x = array();         | array     | TRUE    | FALSE     | TRUE    | FALSE             |
| $x = array('a', 'b'); | array     | FALSE   | FALSE     | TRUE    | TRUE              |
| $x = false;           | boolean   | TRUE    | FALSE     | TRUE    | FALSE             |
| $x = true;            | boolean   | FALSE   | FALSE     | TRUE    | TRUE              |
| $x = 1;               | integer   | FALSE   | FALSE     | TRUE    | TRUE              |
| $x = 42;              | integer   | FALSE   | FALSE     | TRUE    | TRUE              |
| $x = 0;               | integer   | TRUE    | FALSE     | TRUE    | FALSE             |
| $x = -1;              | integer   | FALSE   | FALSE     | TRUE    | TRUE              |
| $x = "1";             | string    | FALSE   | FALSE     | TRUE    | TRUE              |
| $x = "0";             | string    | TRUE    | FALSE     | TRUE    | FALSE             |
| $x = "-1";            | string    | FALSE   | FALSE     | TRUE    | TRUE              |
| $x = "php";           | string    | FALSE   | FALSE     | TRUE    | TRUE              |
| $x = "true";          | string    | FALSE   | FALSE     | TRUE    | TRUE              |
| $x = "false";         | string    | FALSE   | FALSE     | TRUE    | TRUE              |

#### "==" Comparisons

|         | TRUE  | FALSE | 1     | 0     | -1    | "1"   | "0"   | "-1"  | NULL  | array() | "php" | ""    |
| :------ | :---- | :---- | :---- | :---- | :---- | :---- | :---- | :---- | :---- | :------ | :---- | :---- |
| TRUE    | TRUE  | FALSE | TRUE  | FALSE | TRUE  | TRUE  | FALSE | TRUE  | FALSE | FALSE   | TRUE  | FALSE |
| FALSE   | FALSE | TRUE  | FALSE | TRUE  | FALSE | FALSE | TRUE  | FALSE | TRUE  | TRUE    | FALSE | TRUE  |
| 1       | TRUE  | FALSE | TRUE  | FALSE | FALSE | TRUE  | FALSE | FALSE | FALSE | FALSE   | FALSE | FALSE |
| 0       | FALSE | TRUE  | FALSE | TRUE  | FALSE | FALSE | TRUE  | FALSE | TRUE  | FALSE   | TRUE  | TRUE  |
| -1      | TRUE  | FALSE | FALSE | FALSE | TRUE  | FALSE | FALSE | TRUE  | FALSE | FALSE   | FALSE | FALSE |
| "1"     | TRUE  | FALSE | TRUE  | FALSE | FALSE | TRUE  | FALSE | FALSE | FALSE | FALSE   | FALSE | FALSE |
| "0"     | FALSE | TRUE  | FALSE | TRUE  | FALSE | FALSE | TRUE  | FALSE | FALSE | FALSE   | FALSE | FALSE |
| "-1"    | TRUE  | FALSE | FALSE | FALSE | TRUE  | FALSE | FALSE | TRUE  | FALSE | FALSE   | FALSE | FALSE |
| NULL    | FALSE | TRUE  | FALSE | TRUE  | FALSE | FALSE | FALSE | FALSE | TRUE  | TRUE    | FALSE | TRUE  |
| array() | FALSE | TRUE  | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | TRUE  | TRUE    | FALSE | FALSE |
| "php"   | TRUE  | FALSE | FALSE | TRUE  | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE   | TRUE  | FALSE |
| ""      | FALSE | TRUE  | FALSE | TRUE  | FALSE | FALSE | FALSE | FALSE | TRUE  | FALSE   | FALSE | TRUE  |

#### "===" Comparisons

|         | TRUE  | FALSE | 1     | 0     | -1    | "1"   | "0"   | "-1"  | NULL  | array() | "php" | ""    |
| :------ | :---- | :---- | :---- | :---- | :---- | :---- | :---- | :---- | :---- | :------ | :---- | :---- |
| TRUE    | TRUE  | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE   | FALSE | FALSE |
| FALSE   | FALSE | TRUE  | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE   | FALSE | FALSE |
| 1       | FALSE | FALSE | TRUE  | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE   | FALSE | FALSE |
| 0       | FALSE | FALSE | FALSE | TRUE  | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE   | FALSE | FALSE |
| -1      | FALSE | FALSE | FALSE | FALSE | TRUE  | FALSE | FALSE | FALSE | FALSE | FALSE   | FALSE | FALSE |
| "1"     | FALSE | FALSE | FALSE | FALSE | FALSE | TRUE  | FALSE | FALSE | FALSE | FALSE   | FALSE | FALSE |
| "0"     | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | TRUE  | FALSE | FALSE | FALSE   | FALSE | FALSE |
| "-1"    | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | TRUE  | FALSE | FALSE   | FALSE | FALSE |
| NULL    | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | TRUE  | FALSE   | FALSE | FALSE |
| array() | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | TRUE    | FALSE | FALSE |
| "php"   | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE   | TRUE  | FALSE |
| ""      | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE | FALSE   | FALSE | TRUE  |

### File Inclusion

PHP has multiple ways to include other source files such as require, require_once and include. These can take a dynamic string such as `require $_GET['page'] . ".php";` which is usually seen in templating.

### PHP Stream Filters

PHP has its own URL scheme: `php://...` and its main purpose is to filter output automatically. It can automatically remove certain HTML tags and can base64 encode as well.

#### Example

```
$fp = fopen('php://output', 'w');
stream_filter_append(
       $fp,
       'string.strip_tags',
       STREAM_FILTER_WRITE,
       array('b','i','u'));
fwrite($fp, "<b>bolded text</b> enlarged to a <h1>level 1 heading</h1>\n");
/* <b>bolded text</b> enlarged to a level 1 heading */
```

#### Exploitation

These filters can also be used on input such as:

- `php://filter/convert.base64-encode/resource={file}`
- `include`, `file_get_contents()`, etc. support URLs including PHP stream filter URLs (`php://`)
- `include` normally evaluates any PHP code (in tags) it finds, but if it’s base64 encoded it can be used to leak source

## OWASP Top 10

There are three new categories, four categories with naming and scoping changes, and some consolidation in the Top 10 for 2021.

![img](https://owasp.org/www-project-top-ten/assets/images/mapping.png)

- [**A01:2021-Broken Access Control**](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) moves up from the fifth position; 94% of applications were tested for some form of broken access control. The 34 Common Weakness Enumerations (CWEs) mapped to Broken Access Control had more occurrences in applications than any other category.
- [**A02:2021-Cryptographic Failures**](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) shifts up one position to #2, previously known as Sensitive Data Exposure, which was broad symptom rather than a root cause. The renewed focus here is on failures related to cryptography which often leads to sensitive data exposure or system compromise.
- [**A03:2021-Injection**](https://owasp.org/Top10/A03_2021-Injection/) slides down to the third position. 94% of the applications were tested for some form of injection, and the 33 CWEs mapped into this category have the second most occurrences in applications. Cross-site Scripting is now part of this category in this edition.
- [**A04:2021-Insecure Design**](https://owasp.org/Top10/A04_2021-Insecure_Design/) is a new category for 2021, with a focus on risks related to design flaws. If we genuinely want to “move left” as an industry, it calls for more use of threat modeling, secure design patterns and principles, and reference architectures.
- [**A05:2021-Security Misconfiguration**](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) moves up from #6 in the previous edition; 90% of applications were tested for some form of misconfiguration. With more shifts into highly configurable software, it’s not surprising to see this category move up. The former category for XML External Entities (XXE) is now part of this category.
- [**A06:2021-Vulnerable and Outdated Components**](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) was previously titled Using Components with Known Vulnerabilities and is #2 in the Top 10 community survey, but also had enough data to make the Top 10 via data analysis. This category moves up from #9 in 2017 and is a known issue that we struggle to test and assess risk. It is the only category not to have any Common Vulnerability and Exposures (CVEs) mapped to the included CWEs, so a default exploit and impact weights of 5.0 are factored into their scores.
- [**A07:2021-Identification and Authentication Failures**](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) was previously Broken Authentication and is sliding down from the second position, and now includes CWEs that are more related to identification failures. This category is still an integral part of the Top 10, but the increased availability of standardized frameworks seems to be helping.
- [**A08:2021-Software and Data Integrity Failures**](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) is a new category for 2021, focusing on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. One of the highest weighted impacts from Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) data mapped to the 10 CWEs in this category. Insecure Deserialization from 2017 is now a part of this larger category.
- [**A09:2021-Security Logging and Monitoring Failures**](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) was previously Insufficient Logging & Monitoring and is added from the industry survey (#3), moving up from #10 previously. This category is expanded to include more types of failures, is challenging to test for, and isn’t well represented in the CVE/CVSS data. However, failures in this category can directly impact visibility, incident alerting, and forensics.
- [**A10:2021-Server-Side Request Forgery**](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/) is added from the Top 10 community survey (#1). The data shows a relatively low incidence rate with above average testing coverage, along with above-average ratings for Exploit and Impact potential. This category represents the scenario where the security community members are telling us this is important, even though it’s not illustrated in the data at this time.

## Exercise

### (5 pt) Jiaran!!!

One of my friends loves Jiaran so, so much. I'm not so interested in Vtubers, but I do know vtubers would hide some `flag` in web.

![img](../assets/Week 5-1.jpg)

Now we have the chat page of fans: `http://103.102.44.218:10003/`. Maybe you can find flag in this website.

*Hint: as a fan web, the privilege check is broken.*

[source.zip](../assets/Week 5-1.zip)

### (5 pt) Do you like pickle?

Rick is a famous scientist in our universe. One time he trapped himself into a pickle.

Find some items to save Rick.

`http://103.102.44.218:10004/`

If you want to find some hints from source, here it is: [source.zip](../assets/Week 5-2.zip)

### (BONUS 5 pt) Jason is a cool guy

Seems this website is impossible to broken. But still, nothing can block you hackers from stealing the flag.

`https://81.68.223.245/`

Here's the source code for you: [source.zip](../assets/Week 5-3.zip)

