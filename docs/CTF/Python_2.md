# Python Programming Quick Guide - Syntax and Functions

> https://www.liaoxuefeng.com/wiki/1016959663602400/1017063413904832
>
> https://docs.python.org/3/tutorial/index.html

## Python Basics

Python is a computer programming language. A computer programming language is different from the natural language we use every day. The biggest difference is that natural languages are understood differently in different contexts, and a computer must ensure that the program written in the programming language must not be ambiguous if it is to perform its tasks according to the programming language. Python is no exception.

Python's syntax is relatively simple, indented, and written like the following.

```
# print absolute value of an integer:
a = 100
if a >= 0:
    print(a)
else:
    print(-a)
```

Statements starting with `#` are comments, which are for human eyes and can be anything, and are ignored by the interpreter. Every other line is a statement, and when the statement ends with a colon `:`, the indented statement is considered a block of code.

Indentation has advantages and disadvantages. The advantage is that it forces you to write formatted code, but there is no rule about whether the indent is a few spaces or a tab. by convention, you should always stick to the 4-spaces indent.

Another advantage of indentation is that it forces you to write less indented code, and you will tend to split a long piece of code into several functions to get less indented code.

The downside of indentation is that the "copy-paste" feature is disabled, which is the worst part. When you refactor your code, the pasted code has to be rechecked for correct indentation. In addition, it's hard for the IDE to format Python code the way it formats Java code.

Finally, be sure to note that Python programs are case-sensitive, and if you write the wrong case, the program will report an error.

### Summary

Python uses indentation to organize blocks of code, so be sure to follow the convention and stick to a 4-space indent.

In the text editor, you need to set up the automatic conversion of tabs to 4 spaces to make sure you don't mix tabs and spaces.

## Data types and variables

### Data types

A computer is, as the name implies, a machine that can do mathematical calculations, so it is logical that computer programs can handle all kinds of numerical values. However, computers can handle much more than just numeric values. They can also handle text, graphics, audio, video, web pages, and a wide variety of other data, and different data requires different data types to be defined. In Python, the data types that can be handled directly are as follows.

#### integers

Python can handle integers of any size, including negative integers of course, represented in programs exactly as they are written in mathematics, for example: `1`, `100`, `-8080`, `0`, and so on.

Since computers use binary, it is sometimes easier to represent integers in hexadecimal, which is represented by the `0x` prefix and 0-9, a-f, for example: `0xff00`, `0xa5b4c3d2`, and so on.

For very large numbers, such as `10000000000`, it is difficult to count the number of zeros. python allows numbers to be separated by `_`, so writing `10_000_000_000` is exactly the same as `10000000000`. Hexadecimal numbers can also be written as `0xa1b2_c3d4`.

#### floating point numbers

Floating point numbers, also known as decimals, are called floating point numbers because the position of the decimal point of a floating point number is variable when expressed in scientific notation, for example, 1.23x109 is exactly the same as 12.3x108. Floating point numbers can be written mathematically, such as `1.23`, `3.14`, `-9.01`, and so on. But for very large or small floating point numbers, they must be expressed in scientific notation, replacing 10 with e. 1.23x109 is `1.23e9`, or `12.3e8`, 0.000012 can be written as `1.2e-5`, and so on.

Integers and floating point numbers are stored differently inside the computer, and integer operations are always exact (is division also exact? Yes!) ), while floating-point operations may have rounding errors.

#### strings

A string is any text enclosed in single quotes `'` or double quotes `"`, such as `'abc'`, `'xyz'`, etc. Note that `''` or `""` itself is just a representation, not part of a string, so the string `'abc'` has only the 3 characters `a`, `b`, `c`. If `'` itself is also a character, then it can be enclosed in `""`, for example, `"I'm OK"` contains the 6 characters `I`, `'`, `m`, space, `O`, and `K`.

What if the string contains both `'` and `"` inside? You can use the escape character `\` to identify it, for example.

```
'I\'m \"OK\"!'
```

The content of the string represented is:

```
I'm "OK"!
```

The escape character `\` can escape many characters, such as `\n` for line feeds, `\t` for tabs, and the character `\` itself should be escaped, so the character represented by `\\` is `\`. You can use `print()` on Python's interactive command line to print the string to see.

```
>>> print('I\'m ok.')
I'm ok.
>>> print('I\'m learning\nPython.')
I'm learning
Python.
>>> print('\\\n\\')
\
\
```

If there are many characters inside the string that need to be escaped, you need to add a lot of `\`. For simplicity, Python also allows `r''` to indicate that the string inside `''` is not escaped by default, so you can try it yourself at

```
>>> print('\\\t\\')
\       \
>>> print(r'\\\t\\')
\\\t\\
```

If there are many newlines inside the string, it is not good to read them in one line with `\n`. For simplicity, Python allows to use `'''...''' ` format to represent multiple lines of content, try it yourself:

```
>>> print('''line1
... line2
... line3''')
line1
line2
line3
```

The above is typed within the interactive command line, note that when typing multiple lines, the prompt changes from `>>>`  to `...`,  prompting you to continue typing on the previous line, note that `...`  is a prompt, not part of the code: `.

```ascii
┌────────────────────────────────────────────────────────┐
│Command Prompt - python                           _ □ x │
├────────────────────────────────────────────────────────┤
│>>> print('''line1                                      │
│... line2                                               │
│... line3''')                                           │
│line1                                                   │
│line2                                                   │
│line3                                                   │
│                                                        │
│>>> _                                                   │
│                                                        │
│                                                        │
│                                                        │
└────────────────────────────────────────────────────────┘
```

When the terminator ````` and the brackets `)` have been entered, the statement is executed and the result is printed.

If written as a program and saved as a `.py` file, it would be.

```
print('''line1
line2
line3''')
```

The multi-line string `'''...'''`  can also be used with `r` in front, please test it yourself at:

```
# -*- coding: utf-8 -*-
print(r'''hello,\n
world''')
```

#### Boolean values

Boolean values are identical to the representation of Boolean algebra. A Boolean value has only two values, `True`, `False`, either `True` or `False`. In Python, a Boolean value can be expressed directly as `True`, `False` (please note the case), or it can be calculated by Boolean operations as follows.

```
>>> True
True
>>> False
False
>>> 3 > 2
True
>>> 3 > 5
False
```

Boolean values can be operated on with `and`, `or` and `not`.

The `and` operation is a sum operation, and the result of the `and` operation is `True` only if all are `True`.

```
>>> True and True
True
>>> True and False
False
>>> False and False
False
>>> 5 > 3 and 3 > 1
True
```

The `or` operation is an or operation, and as long as one of them is `True`, the result of the `or` operation is `True`.

```
>>> True or True
True
>>> True or False
True
>>> False or False
False
>>> 5 > 3 or 1 > 3
True
```

The `not` operation is a non-operation; it is a monadic operator that turns `True` into `False` and `False` into `True`.

```
>>> not True
False
>>> not False
True
>>> not 1 > 2
True
```

Boolean values are often used in conditional judgments, e.g.

```
if age >= 18:
    print('adult')
else:
    print('teenager')
```

#### Null values

A null value is a special value in Python, denoted by `None`. `None` cannot be interpreted as `0`, because `0` is meaningful, and `None` is a special null value.

In addition, Python provides a variety of data types, such as lists and dictionaries, and also allows the creation of custom data types, which we will continue to talk about later.

### Variables

The concept of a variable is basically the same as the equation variable in middle school algebra, except that in computer programs, variables can be not only numbers, but also arbitrary data types.

Variables are represented in the program by a variable name, which must be a combination of upper and lower case English, numbers, and `_`, and cannot start with a number, for example.

```
a = 1
```

The variable `a` is an integer.

```
t_007 = 'T007'
```

The variable `t_007` is a string.

```
Answer = True
```

The variable `Answer` is a Boolean value `True`.

In Python, the equal sign `=` is an assignment statement that can assign any data type to a variable, the same variable can be assigned repeatedly, and it can be a different type of variable, for example.

```
# -*- coding: utf-8 -*-
a = 123 # a是整数
print(a)
a = 'ABC' # a变为字符串
print(a)
```

This type of language where the type of the variable itself is not fixed is called a *dynamic language*, and its counterpart is a *static language*. Static languages must specify the variable type when defining a variable, and will report an error if the type does not match when assigning a value. For example, Java is a static language, and the assignment statement is as follows (// indicates a comment)

```
int a = 123; // a是整数类型变量
a = "ABC"; // 错误：不能把字符串赋给整型变量
```

Dynamic languages are more flexible compared to static languages for this reason.

Please don't equate the equal sign of an assignment statement with the equal sign of mathematics. For example, the following code.

```
x = 10
x = x + 2
```

If you understand `x = x + 2` mathematically, that is not true anyway. In the program, the assignment statement first calculates the expression `x + 2` on the right side, gets the result `12`, and then assigns it to the variable `x`. Since the previous value of `x` was `10`, after reassignment, the value of `x` becomes `12`.

Finally, it is also important to understand how variables are represented in computer memory. When we write:

```
a = 'ABC'
```

Here the Python interpreter does two things.

1. creates a string `'ABC'` in memory.
2. creates a variable named `a` in memory and points it to `'ABC'`.

It is also possible to assign a variable `a` to another variable `b`, an operation that actually points the variable `b` to the data pointed to the variable `a`, as in the following code.

```
# -*- coding: utf-8 -*-
a = 'ABC'
b = a
a = 'XYZ'
print(b)
```

Is the last line printing out the contents of variable `b` as `'ABC'` or as `'XYZ'`? If understood in a mathematical sense, one would incorrectly conclude that `b` is the same as `a` and should also be `'XYZ'`, but in fact, the value of `b` is `'ABC'`, so let's execute the code line by line to see what is really happening.

Executing `a = 'ABC'`, the interpreter creates the string `'ABC'` and the variable `a`, and points `a` to `'ABC'`.

![py-var-code-1](https://www.liaoxuefeng.com/files/attachments/923791878255456/0)

Executing `b = a`, the interpreter creates the variable `b` and points `b` to the string `'ABC'` pointed to by `a`.

![py-var-code-2](https://www.liaoxuefeng.com/files/attachments/923792058613440/0)

Executing `a = 'XYZ'`, the interpreter creates the string `XYZ' and changes the pointing of `a` to `'XYZ'`, but `b` does not change.

![py-var-code-3](https://www.liaoxuefeng.com/files/attachments/923792191637760/0)

So, the final result of printing the variable `b` will naturally be `'ABC'`.

### Constants

A constant is a variable that cannot be changed, for example, the common mathematical constant π is a constant. In Python, constants are usually represented by all-caps variable names.

```
PI = 3.14159265359
```

But the fact is that `PI` is still a variable, and Python has no mechanism at all to ensure that `PI` won't be changed, so using all-caps variable names for constants is just a customary usage, and if you must change the value of the variable `PI`, no one can stop you.

Finally, an explanation of why division by integers is also exact. In Python, there are two kinds of division, one of which is `/`.

```
>>> 10 / 3
3.3333333333333335
```

`/` The result of the division calculation is a floating point number, even if two integers are exactly divisible, and the result is a floating point number.

```
>>> 9 / 3
3.0
```

Another type of division is `//`, called floor division, where the division of two integers remains an integer:

```
>>> 10 // 3
3
```

You read that right, the floor of an integer divided by `//` is always an integer, even if the division is not exhaustive. To do exact division, use `/` and you're done.

Because `//` division takes only the integer part of the result, Python also provides a remainder operation that gives you the remainder of the division of two integers by.

```
>>> 10 % 3
1
```

Whether an integer does `//` division or takes a remainder, the result is always an integer, so the result of integer arithmetic is always exact.

### Summary

Python supports a variety of data types, and within the computer, any data can be thought of as an "object", and variables are used in programs to point to these data objects.

Assigning `x = y` to a variable is to point the variable `x` to the real object that the variable `y` points to. Subsequent assignments to the variable `y` *do not affect* the pointing of the variable `x`.

Note: Python's integers have no size limit, while some languages have size limits for integers based on their storage length, for example, Java limits 32-bit integers to `-2147483648`-`2147483647`.

Python's floating point numbers also have no size limit, but beyond a certain range, they are directly represented as `inf` (infinity).