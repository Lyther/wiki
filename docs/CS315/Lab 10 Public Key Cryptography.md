# Lab 10: Public Key Cryptography

> Reference https://ithelp.ithome.com.tw/articles/10251031 by 羊小咩

Today we are going to introduce ECC, which is also a security mechanism based on mathematical difficulties.

Since ECC is originally a difficult algorithm, the ECC process and principles in the text are streamlined with many steps, algorithms, and some terminology in the mathematical field

Geometric addition, Algebraic addition, Scalar multiplication, Abelian group... These are not easy to understand in a few words, but require some basic concepts.

In general, I think it is a simple and concise way to explain

I think it is really difficult to explain ECC concisely.

![image-20201009005151787](https://i.imgur.com/HC131kd.png)

## ECC Introduction

Elliptic Curve Cryptography (ECC) is a public key cryptography algorithm based on the mathematics of elliptic curves. The use of elliptic curves in cryptography was independently proposed by Neal Koblitz and Victor Miller in 1985.

Another advantage of ECC is that it can define bilinear mappings between groups, based on Weil pairs or Tate pairs; bilinear mappings have found numerous applications in cryptography, such as identity-based encryption.

![image-20201009011638394](https://i.imgur.com/rd4O30S.png)

## Concept / Term Definition

### Elliptic Curve

An elliptic curve is a plane curve defined by an equation of the form:

![{\displaystyle y^{2}=x^{3}+ax+b.}](https://wikimedia.org/api/rest_v1/media/math/render/svg/6e95cedff68a4d8584ba4f6f676c4570fb38acf9)

where a and b are real numbers. This class is called the Weierstrass equation

![image-20201009012820496](https://i.imgur.com/kI5v9LO.png)

### Elliptic Curve Rule (Group Rule)

**Addition**

Draw a straight line through two points P and Q on the curve and find the intersection of the straight line and the elliptic curve -R

The point of intersection is defined as P Q. The point of intersection is defined as the symmetric position of the x-axis. As shown in the figure below: PQ = R

![image-20201009013454604](https://i.imgur.com/EaWrb4c.png)

**Multiplicative definition (two-fold operation)**

The above method does not explain the case where P P, i.e., two points coincide. Therefore, in this case, the tangent of the elliptic curve at point P, the intersection with the elliptic curve, and the point of the intersection about the symmetric position of the x-axis are defined as P P, i.e., 2P, which is a doubling operation

![image-20201009013609229](https://i.imgur.com/xmjQKQi.png)

**Infinity point**

If we add A and -A, the straight line through A and -A is parallel to the y-axis, and the straight line intersects the elliptic curve at the infinity point.

![image-20201009013734119](https://i.imgur.com/eJLZXfq.png)

### Definition of Elliptic Curve

According to the definition of the above properties, we can organize

* The equation of elliptic curve is y^2=x^3+ax+b

* This curve is exactly symmetric to the **x-axis (y=0)** of this straight line

* The parameters a and b must satisfy 4a^3+27b^2≠0 to ensure that there are no repeated roots and have a unique solution!

* The additive unit element O is an infinite point and satisfies O = -O

* This additive unit element also needs to satisfy: a point on the elliptic curve that is common to three points whose union is O

### Elliptic Curve Characteristics

* Any point on the curve is reflected by the x-axis (y=0) and remains the same curve (peculiar symmetry)

* Any line not perpendicular to the curve will have at most three points of intersection

**Strange symmetry**

The elliptic curve is drawn. It has several interesting properties.

One of them is horizontal symmetry. Any point on the curve can be reflected on the x-axis and maintain the same curve. An even more interesting property is that any non-perpendicular line will intersect the curve in at most three places.

The elliptic curve is compared to a game of batting, where the ball is clicked from point A to point B. When it hits a point on the curve, the ball is then moved to the next point,
When it hits a point on the curve, it bounces back to point C on the other side (above or below the x-axis).

![img](https://i.imgur.com/OrZNQfE.gif)

First imagine that the ball moves in two points called "dot"

A dot B = C
A dot A = B
A dot C = D
... ... ...

There are only two points here (called: the initial point & final point)

The initial point P is tapped n times by itself (as Private Key) to get a final point Q (as Public Key)

Even if you know the "initial point" and "final point"

It is very, very difficult to find n!

### Finite domain (Galois domain) and discrete logarithm

elliptic curves are continuous and easily extrapolated, and therefore, are not suitable for encryption.

Therefore, we must make the elliptic curve a discrete point

The elliptic curve is defined on a finite field, and then the integer field GF(p) modulo the prime number is used

A finite field GF(p) is a set of integers consisting of 0, 1, 2 ......p-1 with p elements, given a certain prime number p. It is defined by adding, subtracting, multiplying, and dividing.

Suppose the elliptic curve is y² = x³+x+1, which is written as follows when it is over a finite field GF(23)

y² ≡ x³+x+1 (mod 23)

The elliptic curve is no longer smooth at this point, but with some discontinuous points, as shown in the figure below. For example, the point (1,7), 7² ≡ 1³ 1 1 ≡ 3 (mod 23). In this way, there are also points as follows.

```
　　(0,1) (0,22)
　　(1,7) (1,16)
　　(3,10) (3,13)
　　(4,0)
```

This will make the original curve look continuous

![image-20201009013609229](https://i.imgur.com/xmjQKQi.png)

Converting to finite fields

![214729t0hhla1y88quftl1](https://i.imgur.com/CDI9wVH.png)

Then you can play the game of Greedy Snake (?)

The line from point A to point B is not perpendicular to the curved EC line and will only have at most three intersections!

When the collision reaches the third intersection, the third intersection must find a symmetrical point C on the x-axis of the EC curve (above or below)

![214838iuneggurovjwowjv](https://i.imgur.com/HBuWham.gif)

## ECC's simple definition and operation process

### Calculation Example

Set up a finite field Fp

after the selection of the curve and the calculation of the given parameters

The curve is known at two points P(3,10) and Q(9,7) on E23(1,1), find (1) -P, (2) P+Q, (3) 2P

![image-20201009020457980](https://i.imgur.com/3sytWD8.png)

If at a point P on the elliptic curve, there exists the smallest positive integer n such that the number multiplier nP = O∞ , then n is called the order of P

If n does not exist, then P is of infinite order

![image-20201009020508303](https://i.imgur.com/SGgNJLx.png)

Therefore, after selecting n, we can calculate 27P = -P

So 28P=O ∞ The order of P is 28

These points make a cyclic Abelian group, where the generating element is P and the order is 28

and select the basis points from it and start calculating

Consider K=kG , where K and G are points on the elliptic curve Ep(a,b), n is the order of G (nG=O∞), and k is an integer smaller than n.

Then given k and G, it is easy to calculate K according to the law of addition

But conversely, given k and G, it is very difficult to find k

where k and K are the private key and public key respectively.

This is the flow of elliptic curve calculation

An elliptic curve `{p,a,b,G,n,h}`

* p : a prime number decision field
* a , b : the parameters of the curve
* G : the base point
* n : the order of G
* h : the quotient divided by an integer

### Principle of Elliptic Curve Encryption and Decryption Algorithm ECIES

Set the private key and public key as k and K respectively, i.e., K = kG, where G is the G point.

**Public key encryption.**

Choose a random number r to generate a ciphertext C from the message M, which is a point pair, i.e.

C = {rG, M rK}, where K is the public key

**Private key decryption.**

M rK - k(rG) = M r(kG) - k(rG) = M

where k and K are the private key and public key respectively.

It is very difficult to find x for the known G and xG on the elliptic curve, which is the discrete logarithm problem on the elliptic curve. Here x is the private key and xG is the public key.

### Principle of Elliptic Curve Signature Algorithm ECDSA

Set the private key and public key as k and K respectively, i.e., K = kG, where G is the G point.

**Private key signature.**

1. Choose random number r and calculate point rG(x, y).
2. Calculate s = (h kx)/r based on the random number r, hash h of message M, and private key k.
3. Send message M, and signature {rG, s} to the recipient

**Public key verification signature.**

1. Receive message M and signature {rG=(x,y), s} from the receiver.
2. Find hash h based on the message.
3. Use the public key K of the delivery party to calculate: hG/s xK/s and compare with rG, if equal, then the verification is successful.

The principle is as follows.

hG/s xK/s = hG/s x(kG)/s = (h xk)G/s

= r(h xk)G / (h kx) = rG