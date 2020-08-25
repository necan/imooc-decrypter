import base64

from Crypto.Cipher import AES


def f1(data, t):
    a = []
    for index, value in enumerate(data):
        a.append(value ^ ord(t[index % len(t)]))
    return a


def f2(data):
    data = list(data)
    index = 0
    while index < len(data):
        x = data[index] % 3
        if x != 0 and index + x < len(data):
            data[index + 1], data[index + x] = data[index + x], data[index + 1]
            index = index + x + 1
        index += 1
    return data


def f3(data):
    data = list(data)
    n = 0
    index = 0
    while index < len(data):
        if data[index] % 2:
            index += 1
        n += 1
        index += 1

    s = [None] * n
    index1 = 0
    index2 = 0
    while index1 < len(data):
        if data[index1] % 2:
            s[index2] = data[index1]
            index1 += 1
        else:
            s[index2] = data[index1]
        index2 += 1
        index1 += 1
    return s


def f4(data, t):
    data = list(data)
    i = 0
    while i < len(data):
        r = data[i] % 5
        if r % 5 and r != 1 and i + r < len(data):
            data[i + 1], data[i + r] = data[i + r], data[i + 1]
            n = i + 2
            i = i + r + 1
            while i - 2 > n:
                data[n] = data[n] ^ ord(t[n % len(t)])
                n += 1
        i += 1

    i = 0
    while i < len(data):
        data[i] = data[i] ^ ord(t[i % len(t)])
        i += 1
    return data


# 解密 m3u8 和 key.hxk
def decrypt_info(data: str):
    f = {
        "q": f1,
        "h": f2,
        "m": f3,
        "k": f4
    }

    encrypt_table = []
    for x in [ord(x) % 4 for x in data[-4:][::-1]]:
        encrypt_table.append(data[x + 1])
        data = data[:x + 1] + data[x + 2:]

    key_table = []
    for x in encrypt_table:
        if "q" == x or "k" == x:
            key_table.append(data[len(data) - 12:])
            data = data[:len(data) - 12]
    key_table.reverse()
    data = base64.standard_b64decode(data)

    for x in encrypt_table:
        if "q" == x or "k" == x:
            data = f[x](data, key_table.pop())
        else:
            data = f[x](data)

    return bytes(data)


# 解密 ts
def decrypt_ts(data: bytes, key: bytes, iv=b'\x00' * 16):
    decryptor = AES.new(key, AES.MODE_CBC, iv=iv)
    return decryptor.decrypt(data)
