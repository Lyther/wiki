# bread-making

Category: Reverse Engineering

Source: redpwn CTF 2021

Author: KyleForkBomb

Score: 10

## Description

My parents aren't home! Quick, help me make some bread please...

```
nc mc.ax 31796
```

## Downloads

[bread](https://static.redpwn.net/uploads/9eee9f077b941e88e1fe75d404582d4f286d9c74729f3ad0d1bb44a527579af8/bread)

## My Solution

(I overthought this problem too much and spent around 3+ hours on this problem. Do not overthink problems, it's a bad habit of mine)

The first thing I did was not put it into Ghidra, but open it in notepad++.(Which is *definitely*(no, not really) the best thing to do for reverse engineering problems) Somehow, I got lucky and saw text in the file. Dual-booting into Ubuntu, I downloaded the file and used Strings on the file. (Later on, I would use a Kali-Linux virtual machine which is much easier)

The output of the strings'd file:

#### first page

[![file](https://github.com/dudnamedcyan/Redpwn2021_Writeup/raw/main/rev/images/String1.png)](https://github.com/dudnamedcyan/Redpwn2021_Writeup/blob/main/rev/images/String1.png)

#### second page

[![file](https://github.com/dudnamedcyan/Redpwn2021_Writeup/raw/main/rev/images/String2.png)](https://github.com/dudnamedcyan/Redpwn2021_Writeup/blob/main/rev/images/String2.png)

#### third page

[![file](https://github.com/dudnamedcyan/Redpwn2021_Writeup/raw/main/rev/images/String3.png)](https://github.com/dudnamedcyan/Redpwn2021_Writeup/blob/main/rev/images/String3.png)

So we have a bunch of text, what does it all mean?

(I decided that it was probably some really hard problem, and I decided to use a reverse engineering program and my team told me to use Ghidra) (I looked at the file with Ghidra for around 3/4 of the time mentioned above, and it didn't help me) (I found the same text)

So, I decided to backtrack and look at the text which I strings'd out. I decided to ignore everything that looked like something that helped the file run and wasn't something that seemed like a certain instruction or situation while making bread. I copied all of the instructions or situations. This is what I got:

```
it's the next morning
mom doesn't suspect a thing, but asks about some white dots on the bathroom floor
couldn't open/read flag file, contact an admin if running on server
mom finds flour in the sink and accuses you of making bread
mom finds flour on the counter and accuses you of making bread
mom finds burnt bread on the counter and accuses you of making bread
mom finds the window opened and accuses you of making bread
mom finds the fire alarm in the laundry room and accuses you of making bread
the tray burns you and you drop the pan on the floor, waking up the entire house
the flaming loaf sizzles in the sink
the flaming loaf sets the kitchen on fire, setting off the fire alarm and waking up the entire house
pull the tray out with a towel
there's no time to waste
pull the tray out
the window is closed
the fire alarm is replaced
you sleep very well
time to go to sleep
close the window
replace the fire alarm
brush teeth and go to bed
you've taken too long and fall asleep
the dough has risen, but mom is still awake
the dough has been forgotten, making an awful smell the next morning
the dough has risen
the bread needs to rise
wait 2 hours
wait 3 hours
the oven makes too much noise, waking up the entire house
the oven glows a soft red-orange
the dough is done, and needs to be baked
the dough wants to be baked
preheat the oven
preheat the toaster oven
mom comes home and finds the bowl
mom comes home and brings you food, then sees the bowl
the ingredients are added and stirred into a lumpy dough
mom comes home before you find a place to put the bowl
the box is nice and warm
leave the bowl on the counter
put the bowl on the bookshelf
hide the bowl inside a box
the kitchen catches fire, setting off the fire alarm and waking up the entire house
the bread has risen, touching the top of the oven and catching fire
45 minutes is an awfully long time
you've moved around too much and mom wakes up, seeing you bake bread
return upstairs
watch the bread bake
the sink is cleaned
the counters are cleaned
everything appears to be okay
the kitchen is a mess
wash the sink
clean the counters
get ready to sleep
the half-baked bread is disposed of
flush the bread down the toilet
the oven shuts off
cold air rushes in
there's smoke in the air
unplug the oven
unplug the fire alarm
open the window
you put the fire alarm in another room
one of the fire alarms in the house triggers, waking up the entire house
brother is still awake, and sees you making bread
you bring a bottle of oil and a tray
it is time to finish the dough
you've shuffled around too long, mom wakes up and sees you making bread
work in the kitchen
work in the basement
flour has been added
yeast has been added
salt has been added
water has been added
add ingredients to the bowl
add flour
add yeast
add salt
add water
we don't have that ingredient at home!
the timer makes too much noise, waking up the entire house
the bread is in the oven, and bakes for 45 minutes
you've forgotten how long the bread bakes
the timer ticks down
use the oven timer
set a timer on your phone
```

So one thing I didn't do yet was running the code. I decided to run the code and the program outputted:

```
add ingredients to the bowl
```

Now, looking at the long list of instructions and situations, we can use logic to solve this problem. Also, the instructions to input are usually somewhere near the situations in the big block of text.

First example: At the first prompt, we have to add ingredients. If we seach for the same statement in that big block of text, right below it, we can find:

```
add flour
add yeast
add salt
add water
```

So we input that and we get the second prompt. However, there are some wrong inputs, so we have to trial and error with them until we get the right ones. There are also time limits, so make sure that you type in the inputs quick. Continue with that until we get to the end of the program where the flag is. You can use the netcat command or just run the file on your own system. (During this part, I forgot that the input and output lanes/streams are actually different. That means I could've just pasted all of the instructions into the terminal instead of typing all of it out, but I didn't do that) (There was one part which I had to tyep really fast for, and that would've been solved if I just pasted the whole input in. I already had all the inputs in a txt file, and I just forgot that I could paste the input into the terminal)

So, by using some logic and searching, we get these instructions as the correct answers:

```
add ingredients to the bowl
add flour
add yeast
add salt
add water
hide the bowl inside a box
wait 3 hours
work in the basement
preheat the toaster oven
set a timer on your phone
watch the bread bake
pull the tray out with a towel
unplug the fire alarm
open the window
unplug the oven
clean the counters
flush the bread down the toilet
wash the sink
get ready to sleep
close the window
replace the fire alarm
brush teeth and go to bed
```

By pasting all of those inputs, we get the flag. The flag is: flag{m4yb3_try_f0ccac1a_n3xt_t1m3???0r_dont_b4k3_br3ad_at_m1dnight}

I think there might have been a way to decompile all of the code and just take all of the inputs without having to use logic and look at all of the inputs. If there is, feel free to open a new issue in this repository and tell me about it. That is, if there isn't already one.

**thanks for reading my writeup!**

## Reference

https://github.com/dudnamedcyan/Redpwn2021_Writeup/blob/main/rev/bread-making.md