import math
import unittest
import wx


def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF


rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

constants = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]

functions = 16 * [lambda b, c, d: (b & c) | (~b & d)] + \
            16 * [lambda b, c, d: (d & b) | (~d & c)] + \
            16 * [lambda b, c, d: b ^ c ^ d] + \
            16 * [lambda b, c, d: c ^ (b | ~d)]


index_functions = 16 * [lambda i: i] + \
                  16 * [lambda i: (5 * i + 1) % 16] + \
                  16 * [lambda i: (3 * i + 5) % 16] + \
                  16 * [lambda i: (7 * i) % 16]


def md5(message):
    if isinstance(message, (bytes, bytearray)):
        message = bytearray(message)
    elif isinstance(message, str):
        message = bytearray(message.encode())
    else:
        raise TypeError("Очікується str, bytes або bytearray, отримано: {}".format(type(message)))

    orig_len_in_bits = (8 * len(message)) & 0xffffffffffffffff
    message.append(0x80)
    
    while len(message) % 64 != 56:
        message.append(0)
    
    message += orig_len_in_bits.to_bytes(8, byteorder='little')

    hash_pieces = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    for chunk_offset in range(0, len(message), 64):
        a, b, c, d = hash_pieces
        chunk = message[chunk_offset:chunk_offset + 64]

        for i in range(64):
            f = functions[i](b, c, d)
            g = index_functions[i](i)
            to_rotate = a + f + constants[i] + int.from_bytes(chunk[4 * g:4 * g + 4], byteorder='little')
            new_b = (b + left_rotate(to_rotate, rotate_amounts[i])) & 0xFFFFFFFF

            a, b, c, d = d, new_b, b, c

        for i, val in enumerate([a, b, c, d]):

            hash_pieces[i] += val
            hash_pieces[i] &= 0xFFFFFFFF

    message = sum(x << (32 * i) for i, x in enumerate(hash_pieces)).to_bytes(16, byteorder='little')
    message = '{:032x}'.format(int.from_bytes(message, byteorder='big'))
    return message


def md5_for_data(input_data, block_size=2048, is_file=True):
    hash_pieces = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    file_size = 0

    if is_file:
        def read_chunks():
            with open(input_data, "rb") as file:
                while True:
                    chunk = file.read(block_size)
                    if not chunk:
                        break
                    yield chunk
    else:
        text_data = input_data.encode('utf-8')

        def read_chunks():
            for i in range(0, len(text_data), block_size):
                yield text_data[i:i + block_size]

    for chunk in read_chunks():
        file_size += len(chunk)

        if len(chunk) < block_size:
            chunk += b'\x80'
            while len(chunk) % 64 != 56:
                chunk += b'\x00'

            file_size_in_bits = (file_size * 8) & 0xFFFFFFFFFFFFFFFF
            chunk += file_size_in_bits.to_bytes(8, byteorder='little')

        a, b, c, d = hash_pieces

        for chunk_offset in range(0, len(chunk), 64):
            block = chunk[chunk_offset:chunk_offset + 64]
            original_a, original_b, original_c, original_d = a, b, c, d

            for i in range(64):
                f = functions[i](b, c, d)
                g = index_functions[i](i)
                to_rotate = a + f + constants[i] + int.from_bytes(block[4 * g:4 * g + 4], byteorder='little')
                new_b = (b + left_rotate(to_rotate, rotate_amounts[i])) & 0xFFFFFFFF

                a, b, c, d = d, new_b, b, c

            a = (a + original_a) & 0xFFFFFFFF
            b = (b + original_b) & 0xFFFFFFFF
            c = (c + original_c) & 0xFFFFFFFF
            d = (d + original_d) & 0xFFFFFFFF

        hash_pieces = [a, b, c, d]

    message = sum(x << (32 * i) for i, x in enumerate(hash_pieces)).to_bytes(16, byteorder='little')
    message = '{:032x}'.format(int.from_bytes(message, byteorder='big'))
    return message


def save_to_file(md5_hash, message):
    app = wx.GetApp()
    with wx.FileDialog(app.GetTopWindow(), "Зберегти файл", wildcard="Text files (*.txt)|*.txt|All files (*.*)|*.*",
                       style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT) as file_dialog:
        if file_dialog.ShowModal() == wx.ID_OK:
            filepath = file_dialog.GetPath()
            if not filepath.endswith(".txt"):
                filepath += ".txt"

            with open(filepath, "w") as file:
                file.write(f"MD5 hashed value from text `{message}`: {md5_hash}\n")


class TestMD5(unittest.TestCase):
    def test_md5(self):
        expectations = {
            b"": "d41d8cd98f00b204e9800998ecf8427e",
            b"a": "0cc175b9c0f1b6a831c399e269772661",
            b"abc": "900150983cd24fb0d6963f7d28e17f72",
            b"message digest": "f96b697d7cb7938d525a2f31aaf161d0",
            b"abcdefghijklmnopqrstuvwxyz": "c3fcd3d76192e4007dfb496cca67e13b",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": "d174ab98d277d9f5a5611c2c9f419d9f",
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890": "57edf4a22be3c955ac49da2e2107b67a",
        }

        for string, md5_hash in expectations.items():
            with self.subTest(string=string, md5_hash=md5_hash):
                self.assertEqual(md5(string), md5_hash)
