import base64


def rc4_main(key="init_key", message="init_message"):
    print("RC4解密主函数调用成功")
    print('\n')
    s_box = rc4_init_sbox(key)
    crypt = rc4_excrypt(message, s_box)
    return crypt


def rc4_init_sbox(key):
    s_box = list(range(256))
    print("原来的 s 盒：%s" % s_box)
    print('\n')
    j = 0
    for i in range(256):
        j = (j + s_box[i] + ord(key[i % len(key)])) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    print("混乱后的 s 盒：%s" % s_box)
    print('\n')
    return s_box


def rc4_excrypt(plain, box):
    print("调用解密程序成功。")
    print('\n')
    plain = base64.b64decode(plain.encode('utf-8'))
    plain = bytes.decode(plain)
    res = []
    i = j = 0
    for s in plain:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        t = (box[i] + box[j]) % 256
        k = box[t]
        res.append(chr(ord(s) ^ k))
    print("res用于解密字符串，解密后是：%res" % res)
    print('\n')
    cipher = "".join(res)
    print("解密后的字符串是：%s" % cipher)
    print('\n')
    print("解密后的输出(没经过任何编码):")
    print('\n')
    return cipher


if __name__ == '__main__':
    a = [
        0xc6,
        0x21,
        0xca,
        0xbf,
        0x51,
        0x43,
        0x37,
        0x31,
        0x75,
        0xe4,
        0x8e,
        0xc0,
        0x54,
        0x6f,
        0x8f,
        0xee,
        0xf8,
        0x5a,
        0xa2,
        0xc1,
        0xeb,
        0xa5,
        0x34,
        0x6d,
        0x71,
        0x55,
        0x8,
        0x7,
        0xb2,
        0xa8,
        0x2f,
        0xf4,
        0x51,
        0x8e,
        0xc,
        0xcc,
        0x33,
        0x53,
        0x31,
        0x0,
        0x40,
        0xd6,
        0xca,
        0xec,
        0xd4,
    ]  # cipher
    key = "Nu1Lctf233"
    s = ""
    for i in a:
        print(i)
        s += chr(i)
    s = str(base64.b64encode(s.encode('utf-8')), 'utf-8')
    rc4_main(key, s)
