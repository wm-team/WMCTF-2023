from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import md5
from sympy import isprime
from tqdm import tqdm 
import random

flag = b"***********************************"
def pad(message):
    return message + b"\x00"*((16-len(message)%16)%16)

def myfastexp(m,d,N,j,N_):
    A = 1
    d = bin(d)[2:]
    n = len(d)
    for i in range(n-1,-1,-1):
        if i < j:
            #print(A)
            N = N_
        A = A*A % N
        if d[i] == "1":
            A = A * m % N
    return A

def encrypt(message,key):
    key = bytes.fromhex(md5(str(key).encode()).hexdigest())
    enc = AES.new(key,mode=AES.MODE_ECB)
    c   = enc.encrypt(pad(message))
    return c


border = "|"
print(border*75)
print(border, "Hi all, I have created an algorithm that can quickly calculate powers. ", border)
print(border, "But it looks like there's something wrong with it. Your task is to get ", border)
print(border, "its private key,and decrypt the cipher to cat the flag ^-^             ", border)
print(border*75)


while True:
# generate
    p = getPrime(512)
    q = getPrime(512)
    n = p*q
    e = 17
    if GCD(e,(p-1)*(q-1)) == 1:
        d = inverse(e,(p-1)*(q-1))
        n_ = n 
        break

msg = bytes_to_long(b"Welcome_come_to_WMCTF")
sig = pow(msg,d,n)

CHANGE = True
while True:
    try:
        ans = input("| Options: \n|\t[G]et data \n|\t[S]ignatrue \n|\t[F]ault injection \n|\t[Q]uit\n").lower().strip()
        
        if ans == 'f':
            if CHANGE:
                print(border,"You have one chance to change one byte of N. ")
                temp,index = input("bytes, and index:").strip().split(",")
                assert 0<= int(temp) <=255
                assert 0<= int(index) <= 1023 
                n_ = n ^ (int(temp)<<int(index))
                print(border,f"[+] update: n_ -> \"{n_}\"")
                CHANGE = False
            else:
                print(border,"Greedy...")
        elif ans == 'g':
            print(border,f"n = {n}")
            print(border,f"flag_ciphertext = {encrypt(flag,d).hex()}")
        elif ans == 's':
            index = input("Where your want to interfere:").strip()
            sig_ = myfastexp(msg,d,n,int(index),n_)
            print(border,f"signature of \"Welcome_come_to_WMCTF\" is {sig_}")
        elif ans == 'q':
            quit()
    except Exception as e:
        print(border,"Err...")
        quit()
