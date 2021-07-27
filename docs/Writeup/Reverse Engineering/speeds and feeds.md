# speeds and feeds

Category: Reverse Engineering

Source: picoCTF 2021

Author: RYAN RAMSEYER

Score: 5

## Description

There is something on my shop network running at `nc mercury.picoctf.net 20301`, but I can't tell what it is. Can you?

## Hints

What language does a CNC machine use?

## Approach

Connecting to `mercury.picoctf.net:53740` (through web) results in [instructions.gcode](https://github.com/vivian-dai/PicoCTF2021-Writeup/blob/main/Reverse Engineering/speeds and feeds/instructions.gcode)

A quick Google search says a CNC machine uses GCode which can have a file extension of `.gcode` so I pasted that section of code into a text editor and saved it as a `.gcode` file. [NC Viewer](https://ncviewer.com/) can view GCode files:

[![flag](https://github.com/vivian-dai/PicoCTF2021-Writeup/raw/main/Reverse%20Engineering/speeds%20and%20feeds/flag.png)](https://github.com/vivian-dai/PicoCTF2021-Writeup/blob/main/Reverse Engineering/speeds and feeds/flag.png)

## Flag

picoCTF{num3r1cal_c0ntr0l_775375c7}

## Reference

Writeup from https://github.com/vivian-dai/PicoCTF2021-Writeup/blob/main/Reverse%20Engineering/speeds%20and%20feeds/speeds%20and%20feeds.md