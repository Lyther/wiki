# Week12 WEB: Attacking Websites

In every pentest web there is several hidden and obvious places that might be vulnerable. This post is meant to be a checklist to confirm that you have searched vulnerabilities in all the possible places.

## Top 10 vulnerabilities

- Injection
- Broken Authentication and Session Management
- Sensitive Data Exposure
- XML External Entity
- Broken Access Control
- Security Misconfiguration
- Cross-Site Scripting
- Insecure deserialization
- Using Components With Known Vulnerabilities
- Insufficient Logging and Monitoring

## Proxies

Nowadays web applications usually uses some kind of intermediary proxies, those may be (ab)used to exploit vulnerabilities. These vulnerabilities need a vulnerable proxy to be in place, but they usually also need some extra vulnerability in the backend.

-  [Abusing hop-by-hop headers](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/abusing-hop-by-hop-headers.md)
-  [Cache Poisoning/Cache Deception](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/cache-deception.md)
-  [HTTP Request Smuggling](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/http-request-smuggling.md)
-  [H2C Smuggling](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/h2c-smuggling.md)
-  [Server Side Inclusion/Edge Side Inclusion](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/server-side-inclusion-edge-side-inclusion-injection.md)
-  [Uncovering Cloudflare](https://github.com/carlospolop/hacktricks/blob/master/pentesting/pentesting-web/uncovering-cloudflare.md)
-  [XSLT Server Side Injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/xslt-server-side-injection-extensible-stylesheet-languaje-transformations.md)

## User input

Most of the web applications will allow users to input some data that will be processed later.
Depending on the structure of the data the server is expecting some vulnerabilities may or may not apply.

### Reflected Values

If the introduced data may somehow being reflected in the response, the page might be vulnerable to several issues.

-  [Client Side Template Injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/client-side-template-injection-csti.md)
-  [Command Injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/command-injection.md)
-  [CRLF](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/crlf-0d-0a.md)
-  [Dangling Markup](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/dangling-markup-html-scriptless-injection.md)
-  [File Inclusion/Path Traversal](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/file-inclusion)
-  [Open Redirect](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/open-redirect.md)
-  [Prototype Pollution to XSS](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/deserialization/nodejs-proto-prototype-pollution.md#client-side-prototype-pollution-to-xss)
-  [Server Side Inclusion/Edge Side Inclusion](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/server-side-inclusion-edge-side-inclusion-injection.md)
-  [Server Side Request Forgery](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ssrf-server-side-request-forgery.md)
-  [Server Side Template Injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ssti-server-side-template-injection)
-  [Reverse Tab Nabbing](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/reverse-tab-nabbing.md)
-  [XSLT Server Side Injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/xslt-server-side-injection-extensible-stylesheet-languaje-transformations.md)
-  [XSS](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/xss-cross-site-scripting)
-  [XSSI](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/xssi-cross-site-script-inclusion.md)
-  [XS-Search](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/xs-search.md)

Some of the mentioned vulnerabilities requires special conditions, others just require the content to be reflected. You can find some interesting polygloths to test quickly the vulnerabilities in:

[Reflecting Techniques - PoCs and Polygloths CheatSheet](https://book.hacktricks.xyz/pentesting-web/pocs-and-polygloths-cheatsheet)

### Search functionalities

If the functionality may be used to search some kind of data inside the backend, maybe you can (ab)use it to search arbitrary data.

-  [File Inclusion/Path Traversal](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/file-inclusion)
-  [NoSQL Injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/nosql-injection.md)
-  [LDAP Injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ldap-injection.md)
-  [ReDoS](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/regular-expression-denial-of-service-redos.md)
-  [SQL Injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/sql-injection)
-  [XAPTH Injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/xpath-injection.md)

### Forms, WebSockets and PostMsgs

When websocket, post message or a form allows user to perform actions vulnerabilities may arise.

-  [Cross Site Request Forgery](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/csrf-cross-site-request-forgery.md)
-  [Cross-site WebSocket hijacking (CSWSH)](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/cross-site-websocket-hijacking-cswsh.md)
-  [PostMessage Vulnerabilities](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/postmessage-vulnerabilities.md)

### HTTP Headers

Depending on the HTTP headers given by the web server some vulnerabilities might be present.

-  [Clickjacking](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/clickjacking.md)
-  [Content Security Policy bypass](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/content-security-policy-csp-bypass.md)
-  [Cookies Hacking](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/hacking-with-cookies.md)
-  [CORS - Misconfigurations & Bypass](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/cors-bypass.md)

### Bypasses

There are several specific functionalities were some workarounds might be useful to bypass them

-  [2FA/OPT Bypass](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/2fa-bypass.md)
-  [Bypass Payment Process](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/bypass-payment-process.md)
-  [Captcha Bypass](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/captcha-bypass.md)
-  [Login Bypass](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/login-bypass)
-  [Race Condition](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/race-condition.md)
-  [Rate Limit Bypass](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/rate-limit-bypass.md)
-  [Reset Forgotten Password Bypass](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/reset-password.md)
-  [Registration Vulnerabilities](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/registration-vulnerabilities.md)

### Structured objects / Specific functionalities

Some functionalities will require the data to be structured on a very specific format (like a language serialized object or a XML). Therefore, it's more easy to identify is the application might be vulnerable as it needs to be processing that kind of data.
Some specific functionalities my be also vulnerable if a specific format of the input is used (like Email Header Injections).

-  [Deserialization](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/deserialization)
-  [Email Header Injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/email-header-injection.md)
-  [JWT Vulnerabilities](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/hacking-jwt-json-web-tokens.md)
-  [XML External Entity](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/xxe-xee-xml-external-entity.md)

### Files

Functionalities that allow to upload files might be vulnerable to several issues.
Functionalities that generates files including user input might execute unexpected code.
Users that open files uploaded by users or automatically generated including user input might be compromised.

-  [File Upload](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/file-upload)
-  [Formula Injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/formula-injection.md)
-  [PDF Injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/xss-cross-site-scripting/pdf-injection.md)
-  [Server Side XSS](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf.md)

### External Identity Management

-  [OAUTH to Account takeover](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/oauth-to-account-takeover.md)
-  [SAML Attacks](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/saml-attacks)

### Other Helpful Vulnerabilities

This vulnerabilities might help to exploit other vulnerabilities.

-  [Domain/Subdomain takeover](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/domain-subdomain-takeover.md)
-  [IDOR](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/idor.md)
-  [Parameter Pollution](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/parameter-pollution.md)
-  [Unicode Normalization vulnerability](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/unicode-normalization-vulnerability.md)