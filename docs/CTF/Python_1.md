# Python Programming Quick Guide - Installation and Basic IO

> https://www.liaoxuefeng.com/wiki/1016959663602400
>
> https://www.w3schools.com/python/python_intro.asp
>
> https://docs.python.org/3/

## What is Python?

Python is a popular programming language. It was created by Guido van Rossum, and released in 1991.

It is used for:

- web development (server-side),
- software development,
- mathematics,
- system scripting.

### What can Python do?

- Python can be used on a server to create web applications.
- Python can be used alongside software to create workflows.
- Python can connect to database systems. It can also read and modify files.
- Python can be used to handle big data and perform complex mathematics.
- Python can be used for rapid prototyping, or for production-ready software development.

### Why Python?

- Python works on different platforms (Windows, Mac, Linux, Raspberry Pi, etc).
- Python has a simple syntax similar to the English language.
- Python has a syntax that allows developers to write programs with fewer lines than some other programming languages.
- Python runs on an interpreter system, meaning that code can be executed as soon as it is written. This means that prototyping can be very quick.
- Python can be treated in a procedural way, an object-oriented way, or a functional way.

### Good to know

- The most recent major version of Python is Python 3, which we shall be using in this tutorial. However, Python 2, although not being updated with anything other than security updates, is still quite popular.
- In this tutorial, Python will be written in a text editor. It is possible to write Python in an Integrated Development Environment, such as Thonny, Pycharm, Netbeans, or Eclipse which are particularly useful when managing larger collections of Python files.

### Python Syntax compared to other programming languages

- Python was designed for readability, and has some similarities to the English language with influence from mathematics.
- Python uses new lines to complete a command, as opposed to other programming languages which often use semicolons or parentheses.
- Python relies on indentation, using whitespace, to define scope; such as the scope of loops, functions, and classes. Other programming languages often use curly brackets for this purpose.

#### Example

```python
print("Hello, World!")
```

## Installing Python

Because Python is cross-platform, it can run on Windows, Mac, and various Linux/Unix systems. Python programs written on Windows are capable of running when put on Linux.

To start learning Python programming, you first have to install Python into your computer. Once installed, you'll get the Python interpreter (which is responsible for running Python programs), a command line interactive environment, and a simple integrated development environment.

### Installing Python 3.8

Currently, there are two versions of Python, version 2.x and version 3.x, which are incompatible. Since version 3.x is becoming more and more popular, our tutorial will be based on the latest Python version 3.8. Please make sure that the version of Python installed on your computer is the latest 3.8.x so that you can learn this tutorial painlessly.

### Installing Python on a Mac

If you are using a Mac with OS X>=10.9, the version of Python that comes with the system is 2.7. To install the latest Python 3.8, there are two methods.

Method 1: Download the [installer](https://www.python.org/downloads/) for Python 3.8 from the official Python website, double-click it after downloading and run it and install it.

Method 2: If [Homebrew](https://brew.sh/) is installed, just install it directly via the command `brew install python3`.

### Installing Python on Linux

If you are using Linux, then I can assume that you have Linux system administration experience and should have no problem installing Python 3 on your own, otherwise, switch back to Windows.

For a large number of students who are currently still using Windows, if you have no plans to switch to a Mac soon, you can continue reading below.

### Installing Python on Windows

First, depending on your version of Windows (64-bit or 32-bit), download the [64-bit installer](https://www.python.org/ftp/python/3.8.0/python-3.8.0-amd64.exe) or [32-bit installer](https://www.python.org/ftp/python/3.8.0/python-3.8.0.exe), then, run the downloaded exe installer:

![install-py35](https://www.liaoxuefeng.com/files/attachments/1048401552601344/l)

Pay special attention to checking `Add Python 3.8 to PATH`, and then click `Install Now` to complete the installation.

### Run Python

After successful installation, open a command prompt window and type in python, two cases will appear.

Scenario one.

```ascii
┌────────────────────────────────────────────────────────┐
│Command Prompt                                    - □ x │
├────────────────────────────────────────────────────────┤
│Microsoft Windows [Version 10.0.0]                      │
│(c) 2015 Microsoft Corporation. All rights reserved.    │
│                                                        │
│C:\> python                                             │
│Python 3.8.x ...                                        │
│[MSC v... 64 bit (AMD64)] on win32                      │
│Type "help", "copyright", "credits" or "license" for mor│
│information.                                            │
│>>> _                                                   │
│                                                        │
│                                                        │
└────────────────────────────────────────────────────────┘
```

Seeing the above screen means that Python was installed successfully!

The fact that you see the prompt `>>>` means that we are in the Python interactive environment and can type any Python code, and you will get the execution result immediately after entering. Now, type `exit()` and enter to exit the Python interactive environment (you can also close the command line window directly).

Case 2: You get an error.

```ascii
┌────────────────────────────────────────────────────────┐
│Command Prompt                                    - □ x │
├────────────────────────────────────────────────────────┤
│Microsoft Windows [Version 10.0.0]                      │
│(c) 2015 Microsoft Corporation. All rights reserved.    │
│                                                        │
│C:\> python                                             │
│'python' is not recognized as an internal or external co│
│mmand, operable program or batch file.                  │
│                                                        │
│C:\> _                                                  │
│                                                        │
│                                                        │
│                                                        │
└────────────────────────────────────────────────────────┘
```

This is because Windows will look for `python.exe` based on the path set by a `Path` environment variable, and if it doesn't find it, it will report an error. If you missed checking `Add Python 3.8 to PATH` during installation, you will have to manually add the path where `python.exe` is located to the Path.

If you don't know how to change the environment variables, we recommend running the Python installer again, making sure to check `Add Python 3.8 to PATH`.

## Python interpreter

When we write Python code, we get a text file with a `.py` extension that contains Python code. To run the code, a Python interpreter is needed to execute the `.py` file.

Since the entire Python language is open source, from the specification to the interpreter, theoretically anyone with a high enough level of proficiency could write a Python interpreter to execute Python code (with great difficulty, of course). In fact, multiple Python interpreters do exist.

### CPython

When we download and install Python 3.x from the [official Python website](https://www.python.org/), we get an official version of the interpreter directly: CPython. This interpreter is developed in C, hence the name CPython. Running `python` at the command line is to start the CPython interpreter.

CPython is the most widely used Python interpreter. All the code in the tutorial is also executed under CPython.

### IPython

IPython is an interactive interpreter based on CPython. That is, IPython is only enhanced in the way it interacts, but the functionality of executing Python code is exactly the same as CPython. It's like many domestic browsers have different appearances, but the kernel is actually calling IE.

CPython uses `>>>` as the prompt, while IPython uses `In [serial number]:` as the prompt.

### PyPy

PyPy is another Python interpreter that targets execution speed. PyPy uses [JIT technology](http://en.wikipedia.org/wiki/Just-in-time_compilation) to dynamically compile (note that it does not interpret) Python code, so it can significantly improve the execution speed of Python code.

The vast majority of Python code will run under PyPy, but PyPy and CPython are somewhat different, which results in the same Python code executing under both interpreters may have different results. If your code is going to be executed under PyPy, you need to understand [the differences between PyPy and CPython](http://pypy.readthedocs.org/en/latest/cpython_differences.html).

### Jython

Jython is a Python interpreter that runs on the Java platform and can compile Python code directly into Java bytecode for execution.

### IronPython

IronPython is similar to Jython, except that IronPython is a Python interpreter that runs on Microsoft.

### Summary

There are many interpreters for Python, but the most widely used is CPython. If you want to interact with Java or .Net.

All code in this tutorial is guaranteed to run under CPython version 3.x only. Be sure to install CPython locally (that is, download the installer from the official Python website).

## First Python program

Before we officially write our first Python program, let's review what command line mode and Python interaction mode are.

### Command Line Mode

Select "Command Prompt" in the Windows Start menu to enter command line mode, which has a prompt similar to `C:\>`.

```ascii
┌────────────────────────────────────────────────────────┐
│Command Prompt                                    - □ x │
├────────────────────────────────────────────────────────┤
│Microsoft Windows [Version 10.0.0]                      │
│(c) 2015 Microsoft Corporation. All rights reserved.    │
│                                                        │
│C:\> _                                                  │
│                                                        │
│                                                        │
│                                                        │
│                                                        │
│                                                        │
│                                                        │
│                                                        │
└────────────────────────────────────────────────────────┘
```

### Python interactive mode

Type the command `python` in command line mode, you will see a bunch of text output like the following, then you will enter Python interactive mode, its prompt is `>>>`.

```ascii
┌────────────────────────────────────────────────────────┐
│Command Prompt - python                           - □ x │
├────────────────────────────────────────────────────────┤
│Microsoft Windows [Version 10.0.0]                      │
│(c) 2015 Microsoft Corporation. All rights reserved.    │
│                                                        │
│C:\> python                                             │
│Python 3.7 ... on win32                                 │
│Type "help", ... for more information.                  │
│>>> _                                                   │
│                                                        │
│                                                        │
│                                                        │
│                                                        │
└────────────────────────────────────────────────────────┘
```

By typing ``exit()` and entering in Python interactive mode, you exit Python interactive mode and return to command line mode:

```ascii
┌────────────────────────────────────────────────────────┐
│Command Prompt                                    - □ x │
├────────────────────────────────────────────────────────┤
│Microsoft Windows [Version 10.0.0]                      │
│(c) 2015 Microsoft Corporation. All rights reserved.    │
│                                                        │
│C:\> python                                             │
│Python 3.7 ... on win32                                 │
│Type "help", ... for more information.                  │
│>>> exit()                                              │
│                                                        │
│C:\> _                                                  │
│                                                        │
│                                                        │
└────────────────────────────────────────────────────────┘
```

You can also select the `Python (command line)` menu item directly from the Start menu to *enter* Python interactive mode directly, but the window will close directly after typing `exit()` and will not return to command line mode.

Once we understand how to start and exit Python's interactive mode, we can officially start writing Python code.

Before writing code, please *never* paste code from a page to your own computer using "copy"-"paste". In the process of writing code, beginners often make mistakes: incorrect spelling, incorrect capitalization, mixed use of English and Chinese punctuation, mixed use of spaces and tabs, so you need to check and cross-check carefully in order to master how to write programs as fast as possible.

![simpson-learn-py3](https://www.liaoxuefeng.com/files/attachments/1017024373322432/l)

At the interactive mode prompt `>>>`, type the code directly and press enter to get the code execution result immediately. Now, try typing `100+200` and see if the calculation results in 300.

```
>>> 100+200
300
```

Pretty simple, right? Any valid mathematical calculation will work out.

To get Python to print out the specified text, use the `print()` function and then enclose the text you wish to print in single or double quotes, but not a mix of single and double quotes:

```
>>> print('hello, world')
hello, world
```

This kind of text enclosed in single or double quotes is called a string in the program, and we will encounter it often in the future.

Finally, exit Python with `exit()` and our first Python program is done! The only downside is that it wasn't saved, so you'll have to type the code again the next time you run it.

### Command line mode and Python interactive mode

Please note the distinction between command line mode and Python interactive mode.

In command line mode, you can execute `python` to enter the Python interactive environment, or you can execute `python hello.py` to run a `.py` file.

Executing a `.py` file *can only* be executed in command line mode. If you hit the command `python hello.py` and see the following error.

```ascii
┌────────────────────────────────────────────────────────┐
│Command Prompt                                    _ □ x │
├────────────────────────────────────────────────────────┤
│Microsoft Windows [Version 10.0.0]                      │
│(c) 2015 Microsoft Corporation. All rights reserved.    │
│                                                        │
│C:\> python hello.py                                    │
│python: can't open file 'hello.py': [Errno 2] No such   │
│file or directory                                       │
│                                                        │
│                                                        │
│                                                        │
│                                                        │
│                                                        │
└────────────────────────────────────────────────────────┘
```

The error message `No such file or directory` indicates that `hello.py` is not found in the current directory, you must first switch the current directory to the directory where `hello.py` is located in order to execute properly.

```ascii
┌────────────────────────────────────────────────────────┐
│Command Prompt                                    _ □ x │
├────────────────────────────────────────────────────────┤
│Microsoft Windows [Version 10.0.0]                      │
│(c) 2015 Microsoft Corporation. All rights reserved.    │
│                                                        │
│C:\> cd work                                            │
│                                                        │
│C:\work> python hello.py                                │
│Hello, world!                                           │
│                                                        │
│                                                        │
│                                                        │
│                                                        │
└────────────────────────────────────────────────────────┘
```

In addition, running a `.py` file in command-line mode is different from running Python code directly in the Python interactive environment, which automatically prints out the result of each line of Python code, but running Python code directly does not.

For example, in the Python interactive environment, type.

```
>>> 100 + 200 + 300
600
```

You can see the result `600` directly.

However, write a `calc.py` file with the following content.

```
100 + 200 + 300
```

Then, in command line mode, execute.

```
C:\work>python calc.py
```

Nothing output was found.

This is normal. To output the result, you must print it out yourself with `print()`. Transform `calc.py` to.

```
print(100 + 200 + 300)
```

Executing it again, you can see the result.

```
C:\work>python calc.py
600
```

Finally, the Python interactive mode code is typed one line and executed one line, while the command line mode directly runs the `.py` file to execute all the code in the file at once. As you can see, Python interactive mode is mainly for debugging Python code and for beginners to learn, it *isn't* an environment to run Python code officially!

### SyntaxError

If `SyntaxError` is encountered, it means that there is a syntax error in the input Python code. The most common type of syntax error is the use of Chinese punctuation, such as the use of Chinese brackets `（` and `）`.

```
>>> print（'hello'）
  File "<stdin>", line 1
    print（'hello'）
         ^
SyntaxError: invalid character '（' (U+FF08)
```

Or the Chinese quotation marks `“` and `”` are used.

```
>>> print(“hello”)
  File "<stdin>", line 1
    print(“hello”)
          ^
SyntaxError: invalid character '“' (U+201C)
```

When an error occurs, be sure to read the cause of the error. For the above `SyntaxError`, the interpreter will explicitly state that the cause of the error is the unrecognized character `"`: `invalid character '"`.

### Summary

In Python interactive mode, you can type code directly, then execute it and get the result immediately.

In command line mode, you can run the `.py` file directly.

## Using a text editor

The advantage of writing a program on Python's interactive command line is that you get the result in a single click, but the disadvantage is that you can't save it and you have to knock it again the next time you want to run it.

So, in practice, we always use a text editor to write the code, and when we're done, we save it as a file so that the program can be run again and again.

Now, let's take the last `'hello, world'` program and write it in a text editor and save it.

So here's the question: which is the best text editor?

### Visual Studio Code!

We recommend [Visual Studio Code](https://code.visualstudio.com/) from Microsoft, it's not the big Visual Studio, it's a streamlined version of Mini Visual Studio, and, Visual Studio Code can be used across! Platforms! Windows, Mac, and Linux universally.

Please note, *do not use Word and Windows Notepad*. Word saves not plain text files, and Notepad will smartly add a few special characters (UTF-8 BOM) at the beginning of the file, which will result in inexplicable errors in running the program.

With the text editor installed, enter the following code.

```
print('hello, world')
```

Note that there should not be any spaces in front of `print`. Then, select a directory, for example, `C:\work`, save the file as `hello.py`, and you can open a command line window, switch the current directory to the directory where `hello.py` is located, and you can run the program as follows.

```
C:\work> python hello.py
hello, world
```

It can also be saved as another name, such as `first.py`, but it must end with `.py`, nothing else will work. In addition, the file name can only be a combination of letters, numbers, and underscores.

If there is no `hello.py` file in the current directory, running `python hello.py` will report the following error.

```
C:\Users\IEUser> python hello.py
python: can't open file 'hello.py': [Errno 2] No such file or directory
```

The error means that the file `hello.py` cannot be opened because it does not exist. In this case, you have to check whether the file exists in the current directory. If `hello.py` is stored in another directory, you should first switch to the current directory with the `cd` command.

## Inputs and Outputs

### Output

Using `print()` with a string in parentheses, you can output the specified text to the screen. For example, outputting `'hello, world'` is implemented in code as follows.

```
>>> print('hello, world')
```

The `print()` function can also accept multiple strings, separated by a comma ",", which can be concatenated into one string of output.

```
>>> print('The quick brown fox', 'jumps over', 'the lazy dog')
The quick brown fox jumps over the lazy dog
```

`print()` will print each string in turn, and will output a space when it encounters a comma ",", so that the output string is spelled out like this:

![print-explain](https://www.liaoxuefeng.com/files/attachments/1017032122300544/l)

`print()` can also print an integer, or the result of a calculation.

```
>>> print(300)
300
>>> print(100 + 200)
300
```

Therefore, we can print the result of calculating `100 + 200` a little more nicely as follows.

```
>>> print('100 + 200 =', 100 + 200)
100 + 200 = 300
```

Note that for `100 + 200`, the Python interpreter automatically calculates the result `300`, however, `'100 + 200 ='` is a string and not a mathematical formula, Python treats it as a string, please interpret the above printout yourself.

### Input

Now, you can already output the result you want with `print()`. But what if you want the user to enter some characters from the computer? Python provides an `input()` that allows the user to enter a string and store it in a variable. For example, enter the user's name.

```
>>> name = input()
Michael
```

Once you type `name = input()` and hit enter, the Python interactive command line is waiting for your input. At this point, you can type any character you want, then press enter and finish typing.

When you're done, there's no prompt, and the Python interactive command line goes back to `>>>`. So where does the content we just typed go? The answer is that it is stored in the `name` variable. You can see the contents of the variable by typing `name` directly.

```
>>> name
'Michael'
```

**What is a variable? **Remind yourself of the basics of algebra learned in junior high school mathematics.

Let the side length of a square be `a`, then the area of the square is `a x a`. Thinking of the side length `a` as a variable, we can calculate the area of the square based on the value of `a`, e.g.

If a = 2, the area is a x a = 2 x 2 = 4.

If a = 3.5, then the area is a x a = 3.5 x 3.5 = 12.25.

In computer programs, variables can be not only integers or floating point numbers, but also strings, so `name` as a variable is a string.

To print out the contents of the `name` variable, in addition to writing `name` directly and pressing enter, the `print()` function can be used.

```
>>> print(name)
Michael
```

With input and output, we can change the last program that printed `hello, world'` to something that makes some sense:

```
name = input()
print('hello,', name)
```

Running the above program, the first line of code will ask the user to enter any character as his or her name, which will then be stored in the `name` variable; the second line of code will say `hello` to the user based on his or her name, for example, enter `Michael`.

```
C:\Workspace> python hello.py
Michael
hello, Michael
```

But the program runs without any prompt message telling the user: "Hey, hurry up and enter your name", which seems very unfriendly. Fortunately, `input()` allows you to display a string to prompt the user, so we changed the code to:

```
name = input('please enter your name: ')
print('hello,', name)
```

Run the program again and you will find that as soon as the program runs, it will first print out `please enter your name:` so that the user can follow the prompt and enter the name and get the output of `hello, xxx` as follows:

```
C:\Workspace> python hello.py
please enter your name: Michael
hello, Michael
```

Each time you run the program, the output will be different depending on the user input.

At the command line, input and output are just that simple.

### Summary

Any computer program is designed to perform a specific task. With input, the user can tell the computer program the information it needs, and with output, the program runs and tells the user the result of the task.

Input is Input and Output is Output, so we refer to input and output collectively as Input/Output, or abbreviated as IO.

`input()` and `print()` are the most basic input and output from the command line, but users can also do input and output through other more advanced graphical interfaces, for example, typing your name in a text box on a web page, clicking "OK" and see the output on the web page.