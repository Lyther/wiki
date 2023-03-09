# Linux OS Installation and Basics

> https://linuxtools-rst.readthedocs.io/zh_CN/latest/base/index.html
>
> https://www.tutorialspoint.com/unix/index.htm
>
> https://www.digitalocean.com/community/tutorials/an-introduction-to-linux-basics

## What is Unix ?

The Unix operating system is a set of programs that act as a link between the computer and the user.

The computer programs that allocate the system resources and coordinate all the details of the computer's internals are called the **operating system** or the **kernel**.

Users communicate with the kernel through a program known as the **shell**. The shell is a command line interpreter; it translates commands entered by the user and converts them into a language that is understood by the kernel.

- Unix was originally developed in 1969 by a group of AT&T employees Ken Thompson, Dennis Ritchie, Douglas McIlroy, and Joe Ossanna at Bell Labs.
- There are various Unix variants available in the market. Solaris Unix, AIX, HP Unix, and BSD are a few examples. Linux is also a freely available flavor of Unix.
- Several people can use a Unix computer at the same time; hence Unix is called a multiuser system.
- A user can also run multiple programs at the same time; hence Unix is a multitasking environment.

## Prerequisites

To follow along with this guide, you will need access to a computer running a Linux-based operating system. This can either be a virtual private server that you’ve connected to with SSH or your local machine. Note that this tutorial was validated using a Linux server running Ubuntu 20.04, but the examples given should work on a computer running any version of any Linux distribution.

If you plan to use a remote server to follow this guide, we encourage you to first complete our [Initial Server Setup guide](https://www.digitalocean.com/community/tutorials/initial-server-setup-with-ubuntu-20-04). Doing so will set you up with a secure server environment — including a non-**root** user with `sudo` privileges and a firewall configured with UFW — which you can use to build your Linux skills.

## The Terminal

The terms “terminal,” “shell,” and “command line interface” are often used interchangeably, but there are subtle differences between them:

- A *terminal* is an input and output environment that presents a text-only window running a shell.
- A *shell* is a program that exposes the computer’s operating system to a user or program. In Linux systems, the shell presented in a terminal is a command line interpreter.
- A *command line interface* is a user interface (managed by a command line interpreter program) that processes commands to a computer program and outputs the results.

When someone refers to one of these three terms in the context of Linux, they generally mean a terminal environment where you can run commands and see the results printed out to the terminal, such as this:

![Terminal window example](https://assets.digitalocean.com/articles/introduction-to-linux-basics/sammy_terminal.png)

Becoming a Linux expert requires you to be comfortable with using a terminal. Any administrative task, including file manipulation, package installation, and user management, can be accomplished through the terminal. The terminal is interactive: you specify commands to run and the terminal outputs the results of those commands. To execute any command, you type it into the prompt and press `ENTER`.

When accessing a cloud server, you’ll most often be doing so through a terminal shell. Although personal computers that run Linux often come with the kind of graphical desktop environment familiar to most computer users, it is often more efficient or practical to perform certain tasks through commands entered into the terminal.

## Learn to use command help

## Overview

In the linux terminal, when we don't know how to use a command, or don't remember the spelling of a command or its parameters, we need to turn to the system's help documentation; the built-in help documentation in linux is very detailed and usually solves our problems, so we need to know how to use it properly.

- in cases where we only remember some of the command keywords, we can search for them by using man -k.
- needing a brief description of a command, we can use what is; for a more detailed description, we can use the info command.
- to see where the command is located, we need to use which.
- and for the specific parameters of a command and how to use it, we need to use the powerful man.

These commands are described below.

## Command usage

### View a brief description of the command

A brief description of what the command does (showing the man category page where the command is located):

```
$whatis command
```

Regular match:

```
$whatis -w "loca*"
```

More detailed documentation:

```
$info command
```

### Using man

Query the documentation for the command command:

```
$man command
eg: man date
```

Using page up and page down to page up and down

In the man help manual, the help documentation is divided into 9 categories, for some keywords that may exist in more than one category, we need to specify a specific category to view; (generally, we query the bash command, categorized in category 1).

man page belongs to the category identification (commonly used is category 1 and category 3)

```.
(1), the user can operate the command or executable file
(2), the core of the system can be called functions and tools, etc.
(3), some common functions and databases
(4), the description of the device file
(5), the format of the settings file or some files
(6), games
(7), conventions and protocols, etc. For example, the Linux standard file system, network protocols, ASCII, code and other descriptions of the content
(8), the system administrator available to manage the order
(9), and kernel-related files
```

As mentioned earlier using whatis will show the specific document category where the command is located, we learn how to use it

```
eg:
$whatis printf
printf (1) - format and print data
printf (1p) - write formatted output
printf (3) - formatted output conversion
printf (3p) - print formatted output
printf [builtins] (1) - bash built-in commands, see bash(1)
```

We see that printf is available in both category 1 and category 3; the pages in category 1 are for help on command operations and executables; while 3 is for instructions on commonly used libraries; if we want to see the use of printf in C, we can specify to see the help in category 3: ``.

```
$man 3 printf

$man -k keyword
```

query keyword Query commands based on some of the keywords in the command, for occasions when only part of the command is remembered.

eg: Find GNOME's config tool command:

```
$man -k GNOME config| grep 1
```

For a word search, you can use /word directly to use: /-a; pay more attention to SEE ALSO to see more exciting content

### Checking paths

Check the path to the program's binary file:

```
$which command
```

eg: Find the path where the make program is installed:

```
$which make
/opt/app/openav/soft/bin/make install
```

Check the search path of the program:

```
$whereis command
```

This command comes in handy when there are multiple versions of the same software installed on the system and you are not sure which version is being used.

# File and directory management

Directory

- File and directory management
  - Create and delete
  - Directory switching
  - List directory entries
  - Find directories and files find/locate
  - View file contents
  - Find the contents of a file
  - Modify file and directory permissions
  - Adding aliases to files
  - Piping and Redirection
  - Set environment variables
  - Bash shortcut input or delete
  - General Application

File management is nothing more than creating, deleting, querying, and moving files or directories, with mkdir/rm/mv

file query as the focus, with found for query; find is parameter rich and very powerful.

viewing file content is a big topic, and there are too many tools for us to use for text processing, which are just pointed out in this chapter, and a special chapter will be devoted to text processing tools later.

Sometimes it is necessary to create an alias for a file, and we need to use ln, using this alias has the same effect as using the original file.

## Create and delete

- Create: mkdir
- Delete: rm
- Delete non-empty directories: rm -rf file directory
- Delete log rm *log (Equivalent: $find . / -name "*log" -exec rm {} ;)
- Move: mv
- Copy: cp (Copy directory: cp -r )

View the number of files in the current directory:

```
$find . / | wc -l
```

Copy the directory:

```
$cp -r source_dir dest_dir
```

## Directory switching

- Find the file/directory location: cd
- Switch to the previous working directory: cd -
- Switch to the home directory: cd or cd ~
- Show current path: pwd
- Change the current working path to path: $cd path

## List directory entries

- Display the files in the current directory ls
- Show directory entries as a list, sorted by time ls -lrt

The above command is used so often that we need to create a shortcut for it:

Set the command alias in .bashrc:

```
alias lsl='ls -lrt'
alias lm='ls -al|more'
```

so that, using lsl, the files in the directory can be displayed sorted by modification time; in a list.

- Add an id number to the front of each file (for a neater look):

  ```
  >ls | cat -n
  ```

  > 1 a 2 a.out 3 app 4 b 5 bin 6 config

Note: .bashrc is stored as a hidden file under the /home/your username/ folder; you can check it with ls -a.

## Find directories and files find/locate

Search for a file or directory:

```
$find . / -name "core*" | xargs file
```

Find if there is an obj file in the target folder:

```
$find . / -name '*.o'
```

Recursively delete all .o files in the current directory and subdirectories:

```
$find . / -name "*.o" -exec rm {} \;
```

find is a real-time lookup, if you need a faster query, try locate; locate will create an index database for the file system, if there are file updates, you need to execute the update command periodically to update the index database:

```
$locate string
```

Find paths that contain string:

```
$updatedb
```

Unlike find, locate is not a real-time lookup. You need to update the database to get the latest file index information.

## View file contents

To view the file: `cat vi head tail more`

Display the file with the line number:

```
$cat -n
```

Show list contents by page:

```
$ls -al | more
```

See only the first 10 lines:

```
$head - 10 **
```

Show the first line of the file:

```
$head -1 filename
```

Show the penultimate line of the file:

```
$tail -5 filename
```

See the difference between the two files:

```
$diff file1 file2
```

Dynamically display the latest information in the text:

```
$tail -f crawler.log
```

## Find the contents of a file

Use egrep to query the contents of a file:

```
egrep '03.1\/CO\/AE' TSF_STAT_111130.log.012
egrep 'A_LMCA777:C' TSF_STAT_111130.log.035 > co.out2
```

## File and directory permission modification

- Change the owner of a file chown
- Change file read, write, execute, etc. attributes chmod
- Recursive subdirectory modification: chown -R tuxapp source/
- Add script executable permissions: chmod a+x myscript

## Add aliases to files

Create symbolic/hard links:

```
ln cc ccAgain :hard link; delete one, will still be found.
ln -s cc ccTo :symbolic link (soft link); delete the source, the other will not be available; (the latter ccTo is a newly created file)
```

## Pipelines and Redirects

- Batch command concatenation execution, using |
- Concatenation: use semicolon ;
- If the previous one succeeds, the next one is executed, otherwise, it is not executed :&&
- If the first one fails, the next one is executed: ||

```
ls /proc && echo suss! || echo failed.
```

The ability to indicate whether the named execution succeeded OR failed.

The same effect as above is :

```
if ls /proc; then echo suss; else echo failed; fi
```

Redirect:

```
ls proc/*.c > list 2> &l Redirects standard output and standard errors to the same file.
```

The equivalent is :

```
ls proc/*.c &> list
```

Clear the file:

```
:> a.txt
```

Redirect:

```
echo aa >> a.txt
```

## Setting environment variables

automatically executed after starting the account is the file .profile, through which you can then set your own environment variables.

The path of the installed software usually needs to be added to the path:

```
PATH=$APPDIR:/opt/app/soft/bin:$PATH:/usr/local/bin:$TUXDIR/bin:$ORACLE_HOME/bin;export PATH
```

## Bash shortcut input or delete

Shortcut keys:

```
Ctl-U deletes all characters from the cursor to the beginning of the line, and in some settings, the entire line
Ctl-W deletes the characters between the current cursor and the nearest preceding space
Ctl-H backspace, delete the character in front of the cursor
Ctl-R match the closest file and output
```

## Integrated Applications

Find the total number of records in record.log that contain AAA, but not BBB:

```
cat -v record.log | grep AAA | grep -v BBB | wc -l
```

# Text processing

Directory

- Text processing
  - find File Find
    - Customized search
    - Follow-up actions after finding
    - Delimiters for -print
  - grep text search
  - xargs command line argument conversion
  - sort sorting
  - uniq Eliminate duplicate rows
  - Convert with tr
  - cut slice text by column
  - paste Splice text by column
  - wc Tools for counting rows and characters
  - sed text replacement tool
  - awk data stream processing tool
    - print prints the current line
    - Special variables: NR NF $0 $1 $2
    - Passing external variables
    - Filtering lines processed by awk with styles
    - Setting delimiters
    - Reading command output
    - Using loops in awk
    - awk combined with grep to find the specified service and kill it
    - awk implements the head and tail commands
    - Print specified columns
    - Print a specified text area
    - Common built-in functions in awk
  - Iterate over lines, words and characters in a file
    - 1. iterate over each line in the file
    - 2. iterate over each word in a line
    - 3. iterate over each character

This section will introduce the most commonly used tools for working with text in the shell under Linux: find, grep, xargs, sort, uniq, tr, cut, paste, wc, sed, awk; the examples and arguments provided are all commonly used; my rule for shell scripts is to write a single line of command, try not to exceed 2 lines; if there are more more complex tasks, consider python.

## Find file search

find txt and pdf files:

```
find . \( -name "*.txt" -o -name "*.pdf" \) -print
```

regular way to find .txt and pdf:

```
find . -regex ". *\(\.txt|\.pdf\)$"
```

-iregex: ignore case-sensitive regularity

Negate arguments , find all non-txt text:

```
find . ! -name "*.txt" -print
```

Specify the search depth, print out the files in the current directory (depth 1):

```
find . -maxdepth 1 -type f
```

### Custom search

- Search by type

```
find . -type d -print // list all directories only
```

-type f files / l symbolic links / d directories

the file search types supported by find can distinguish between ordinary files and symbolic links, directories, etc., but binary and text files cannot be distinguished directly by the types of find

The file command can check the specific type of file (binary or text):

```
$file redis-cli # binary file
redis-cli: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.9, not stripped
$file redis.pid # Text file
redis.pid: ASCII text
redis.pid: ASCII text
```

So, you can use the following combination of commands to find all the binary files in your local directory:

```
ls -lrt | awk '{print $9}'|xargs file|grep ELF| awk '{print $1}'|tr -d ':'
```

- Search by time

    -atime access time (in days, or -amin in minutes, similar below) -mtime modification time (content was modified) -ctime change time (metadata or permission changes)

All files that have been accessed in the last 7 days:

```
find . -atime 7 -type f -print
```

All files that have been accessed in the last 7 days:

```
find . -atime -7 -type f -print
```

Search for all files accessed 7 days ago:

```
find . -atime +7 type f -print
```

- Search by size.

w word k M G Find files larger than 2k:

```
find . -type f -size +2k
```

Find by permissions:

```
find . -type f -perm 644 -print //find all files with executable permissions
```

Find by user:

```
find . -type f -user weber -print// Find files owned by user weber
```

### Follow-up actions after finding

- Delete

Delete all swp files in the current directory:

```
find . -type f -name "*.swp" -delete
```

Another syntax:

```
find . type f -name "*.swp" | xargs rm
```

- Execute action (powerful exec)

Change the ownership of the current directory to weber:

```
find . -type f -user root -exec chown weber {} \;
```

Note: {} is a special string, and for each matching file, {} is replaced with the corresponding filename.

Copy all the files found to another directory:

```
find . -type f -mtime +10 -name "*.txt" -exec cp {} OLD \;
```

- Combining multiple commands

If you need to execute multiple commands subsequently, you can write multiple commands as one script. Then just execute the script when -exec is called:

```
-exec . /commands.sh {} \;
```

### -print's delimiter

Use '\n' as the delimiter for the file by default.

-print0 uses '\0' as the file delimiter so that it can search for files containing spaces.


## Grep text search

```
grep match_patten file // default access to matching lines
```

Common parameters

-o only output matching text lines **VS** -v only output text lines that do not match

-c counts the number of times the file contains text

    grep -c "text" filename

-n Print matching line numbers

-i Ignore case when searching

-l prints only the file name

Recursive search for text in multi-level directories (a favorite of programmers searching for code):

```
grep "class" . -R -n
```

Match multiple patterns:

```
grep -e "class" -e "vitural" file
```

grep output file names with a 0 as the ending character (-z):

```
grep "test" file* -lZ| xargs -0 rm
```

Comprehensive application: find all sql lookups with where conditions in the log:

```
cat LOG.* | tr a-z A-Z | grep "FROM " | grep "WHERE" > b
```

find Chinese example: project directory in utf-8 format and gb2312 format two kinds of files, to find the word is Chinese.

1. find out its utf-8 encoding and gb2312 encoding are E4B8ADE69687 and D6D0CEC4 respectively

2. query :

```
   grep: grep -rnP "\xE4\xB8\xAD\xE6\x96\x87|\xD6\xD0\xCE\xC4" * can be
```

Chinese character code lookup: http://bm.kdd.cc/

## Xargs Command Line Parameter Conversion

xargs is able to convert input data into command line arguments for a specific command; in this way, it can be used in combination with many commands. e.g. grep, e.g. find; - Converting multi-line output to single-line output

   ```
cat file.txt| xargs
   ```

n is a delimiter between multiple lines of text

- Convert single line to multi-line output

```
cat single.txt | xargs -n 3
```

-n: specifies the number of fields to display per line

Description of xargs parameters

-d defines the delimiter (the default is a space. The delimiter for multiple lines is n)
-n specifies that the output is multi-line
-I {} specifies the replacement string that will be replaced when xargs is expanded, used when the command to be executed requires multiple arguments
-0: specify 0 as input delimiter

Example:

```
cat file.txt | xargs -I {} . /command.sh -p {} -1

# Count the number of lines in the program
find source_dir/ -type f -name "*.cpp" -print0 |xargs -0 wc -l

#redis stores data by string and indexes by set, and needs to look up all values by index.
. /redis-cli smembers $1 | awk '{print $1}'|xargs -I {} . /redis-cli get {}
```

## Sort

Field Description

-n Sort by number VS -d Sort by dictionary order
-r Sort in reverse order
-k N specifies sorting by column N

Example:

```
sort -nrk 1 data.txt
sort -bd data // ignore leading whitespace characters like spaces
```

## Uniq Eliminate duplicate rows

- Eliminate duplicate rows

```
sort unsort.txt | uniq
```

- Count the number of times each row appears in the file

```
sort unsort.txt | uniq -c
```

- Find duplicate rows

```
sort unsort.txt | uniq -d
```

You can specify the duplicates to be compared in each line: -s start position -w number of characters to compare

## Converting with tr

- General usage

```
echo 12345 | tr '0-9' '9876543210' // encryption and decryption conversion, replacing the corresponding characters
cat text| tr '\t' ' ' //tab to space conversion
```

- tr delete characters

```
cat file | tr -d '0-9' // delete all numbers
```

-c find the complement

```
cat file | tr -c '0-9' // Get all the numbers in the file
cat file | tr -d -c '0-9 \n' // delete non-numeric data
```

- tr compress characters

tr -s compresses repetitive characters in text; most often used to compress extra spaces:

```
cat file | tr -s ' '
```

- Character classes

- Various character classes are available in tr.

  alnum: letters and numbers alpha: letters digit: numbers space: blank characters lower: lowercase upper: uppercase cntrl: control (non-printable) characters print: printable characters

Usage: tr [:class:] [:class:]

```
tr '[:lower:]' '[:upper:]'
```

## Cut cut text by column

- Truncate the second and fourth columns of the file

```
cut -f2,4 filename
```

- Remove all columns from the file except column 3

```
cut -f3 --complement filename
```

-d Specify delimiters

```
cat -f2 -d";" filename
```

-cut The range to take

    N - Nth field to the end -M 1st field for MN-M N to M fields

- The unit to be fetched by cut

    -b in bytes -c in characters -f in fields (using delimiters)

Example:

```
cut -c1-5 file // print first to 5 characters
cut -c-2 file //Print the first 2 characters
```

Truncate columns 5 to 7 of the text

```
$echo string | cut -c5-7
```

## Paste Splice text by column

Splices two pieces of text together by column;

```
cat file1
1
2

cat file2
colin
book

paste file1 file2
1 colin
2 book
```

The default delimiter is tab, you can use -d to specify the delimiter:

```
paste file1 file2 -d ","
1,colin
2,book
```

## Wc Tools for counting lines and characters

```
$wc -l file // count the number of lines

$wc -w file // count the number of words

$wc -c file // count the number of characters
```

## Sed text replacement tool

- First substitution

```
sed 's/text/replace_text/' file // Replace the first matching text on each line
```

- Global replacement

```
sed 's/text/replace_text/g' file
```

Default replace, output the replaced content, if you need to replace the original file directly, use -i:

```
sed -i 's/text/repalce_text/g' file
```

- Remove blank lines

```
sed '/^$/d' file
```

- Variable conversion

Matched strings are referenced by the & marker.

```
echo this is en example | sed 's/\w+/[&]/g'
$>[this] [is] [en] [example]
```

- Substring matching tokens

The contents of the first matching bracket are referenced using token 1

```
sed 's/hello\([0-9]\)/\1/'
```

- Double quotes for values

sed is usually quoted in single quotes; double quotes can also be used, and when used, double quotes will evaluate the expression:

```
sed 's/$var/HLLOE/'
```

when using double quotes, we can specify variables in sed style and in replacement strings.

```
eg:
p=patten
r=replaced
echo "line con a patten" | sed "s/$p/$r/g"
$>line con a replaced
```

- Other examples

String insertion character: converts each line of text (ABCDEF) to ABC/DEF:

```
sed 's/^. \{3\}/&\/g' file
```

## Awk data stream processing tool

- The awk script structure

```
awk ' BEGIN{ statements } statements2 END{ statements } '
```

- How it works

1. executing the block of statements in begin.

2. reads a line from the file or stdin and executes statements2, repeating the process until the file has been read in its entirety.

3. Execute the end statement block.

### print prints the current line

- When using print without arguments, the current line is printed

```
echo -e "line1\nline2" | awk 'BEGIN{print "start"} {print } END{ print "End" }'
```

- print When split by commas, arguments are delimited by spaces;

```
echo | awk ' {var1 = "v1" ; var2 = "V2"; var3 = "v3"; \
print var1, var2 , var3; }'
$>v1 V2 v3
```

- Using the -splicer approach ("" as a splice character) ;

```
echo | awk ' {var1 = "v1" ; var2 = "V2"; var3 = "v3"; \
print var1"-"var2"-"var3; }'
$>v1-V2-v3
```

### Special variables: NR NF $0 $1 $2

NR:indicates the number of records, corresponding to the line number that should precede it during execution.

NF:indicates the number of fields, which always pairs up with the number of fields that should go forward during execution.

$0:this variable contains the text content of the current line during execution.

$1:the text content of the first field.

$2:the text content of the second field.

```
echo -e "line1 f2 f3 \n line2 \n line 3" | awk '{print NR":"$0"-"$1"-"$2}'
```

- Print the second and third fields of each line

```
awk '{print $2, $3}' file
```

- Count the number of lines in the file

```
awk ' END {print NR}' file
```

- Accumulate the first field of each line

```
echo -e "1\n 2\n 3\n 4\n" | awk 'BEGIN{num = 0 ;
print "begin";} {sum += $1;} END {print "=="; print sum }'
```

### Passing external variables

```
var=1000
echo | awk '{print vara}' vara=$var # Input from stdin
awk '{print vara}' vara=$var file # Input from file
```

### Filter the lines processed by awk with the style

```
awk 'NR < 5' # line number less than 5
awk 'NR == 1,NR == 4 {print}' file # Print out line numbers equal to 1 and 4
awk '/linux/' # lines containing linux text (can be specified with regular expressions, super powerful)
awk '! /linux/' # lines that do not contain linux text
```

### Set delimiters

Use -F to set delimiters (default is spaces):

```
awk -F: '{print $NF}' /etc/passwd
```

### Read command output

Use getline to read the output of an external shell command into the variable cmdout:

```
echo | awk '{"grep root /etc/passwd" | getline cmdout; print cmdout }'
```

### Using loops in awk

```
for(i=0;i<10;i++){print $i;}
for(i in array){print array[i];}
```

eg:The following string, print out the time string:

```
2015_04_02 20:20:08: mysqli connect failed, please check connect info
$echo '2015_04_02 20:20:08: mysqli connect failed, please check connect info'|awk -F ":" '{ for(i=1;i<=;i++) printf("%s:",$i)}'
>2015_04_02 20:20:08: # This way will print the last colon
$echo '2015_04_02 20:20:08: mysqli connect failed, please check connect info'|awk -F':' '{print $1 ":" $2 ":" $3; }'
>2015_04_02 20:20:08 # This way satisfies the requirement
```

And if you need to print out the later part as well (the time part is printed separately from the later text) :

```
$echo '2015_04_02 20:20:08: mysqli connect failed, please check connect info'|awk -F':' '{print $1 ":" $2 ":" $3; print $4;}'
>2015_04_02 20:20:08
>mysqli connect failed, please check connect info
```

Print the rows in reverse order: (implementation of the tac command):

```
seq 9| \
awk '{lifo[NR] = $0; lno=NR} \
END{ for(;lno>-1;lno--){print lifo[lno];}
} '
```

### awk combined with grep finds the specified service and kills it

```
ps -fe| grep msv8 | grep -v MFORWARD | awk '{print $2}' | xargs kill -9;
```

### awk implementation of head and tail commands

- head

```
awk 'NR<=10{print}' filename
```

- tail

```
awk '{buffer[NR%10] = $0;} END{for(i=0;i<11;i++){ \
print buffer[i %10]} } ' filename
```

### Print the specified column

- awk way to implement

```
ls -lrt | awk '{print $6}'
```

- The cut method

```
ls -lrt | cut -f6
```

### Print the specified text area

- Determine the line number

```
seq 100| awk 'NR==4,NR==6{print}'
```

- Determine the text

Print the text between start_pattern and end_pattern:

```
awk '/start_pattern/, /end_pattern/' filename
```

Example:

```
seq 100 | awk '/13/,/15/'
cat /etc/passwd| awk '/mai.*mail/,/news.*news/'
```

### awk common built-in functions

index(string,search_string):return the position of search_string in string

sub(regex,replacement_str,string):replace the first regular match with replacement_str;

match(regex,string):check if the regular expression can match the string.

length(string):return the length of the string

```
echo | awk '{"grep root /etc/passwd" | getline cmdout; print length(cmdout) }'
```

printf is similar to printf in c, and formats the output:

```
seq 10 | awk '{printf "->%4s\n", $1}'
```

## Iterate over lines, words and characters in a file

### Iterate over each line in the file

- while loop method

```
while read line;
do
echo $line;
done < file.txt

Change to a subshell:
cat file.txt | (while read line;do echo $line;done)
```

- awk method

```
cat file.txt| awk '{print}'
```

### Iterate over each word in a line

```
for word in $line;
do
echo $word;
done
```

### Iterate over each character

${string:start_pos:num_of_chars}: extract a character from the string; (bash text slicing)

${#word}:return the length of the variable word

```
for((i=0;i<${#word};i++))
do
echo ${word:i:1);
done
```

Display the file in ASCII characters:

```
$od -c filename
```