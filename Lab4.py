import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

import Lab1
from Lab3 import RC5, get_key_from_passphrase


RSA_KEY_SIZE = 2048

RC5_KEY_SIZE = 64
BLOCK_SIZE = 128


def generate_rsa_keys(private_key_file, public_key_file):
    key = RSA.generate(RSA_KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(private_key_file, 'wb') as priv_file:
        priv_file.write(private_key)
    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(public_key)


def read_rsa_keys(private_key_file, public_key_file):
    with open(private_key_file, 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())
    with open(public_key_file, 'rb') as pub_file:
        public_key = RSA.import_key(pub_file.read())
    return private_key, public_key


def rsa_encrypt(data, public_key_file):
    with open(public_key_file, 'rb') as pub_file:
        public_key = RSA.import_key(pub_file.read())

    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data


def rsa_decrypt(encrypted_data, private_key_file):
    with open(private_key_file, 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())

    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data


def rsa_encrypt_file(input_file, output_file, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while chunk := f_in.read(BLOCK_SIZE):
            encrypted_chunk = cipher_rsa.encrypt(chunk)
            f_out.write(encrypted_chunk)


def rsa_decrypt_file(input_file, output_file, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while chunk := f_in.read(private_key.size_in_bytes()):
            decrypted_chunk = cipher_rsa.decrypt(chunk)
            f_out.write(decrypted_chunk)


def to_base64(data):
    return base64.b64encode(data).decode('utf-8')

def from_base64(base64_str):
    return base64.b64decode(base64_str)


def benchmark(input_file, rsa_private, rsa_public, rc5_key, iv):
    start = time.time()
    rsa_encrypt_file(input_file, 'rsa_encrypted.dat', rsa_public)
    rsa_encrypt_time = time.time() - start

    rc5 = RC5(16, 16, rc5_key)
    start = time.time()
    rc5.encrypt_file(iv, input_file, 'rc5_encrypted.dat')
    rc5_encrypt_time = time.time() - start

    return rsa_encrypt_time, rc5_encrypt_time


def main():
    private_key_file = 'private.pem'
    public_key_file = 'public.pem'
    passcode = "sigma"

    generate_rsa_keys(private_key_file, public_key_file)
    rsa_private, rsa_public = read_rsa_keys(private_key_file, public_key_file)

    rc5_key = get_key_from_passphrase(passcode, RC5_KEY_SIZE)

    input_file = 'big.txt'
    open(input_file, 'wb').write(b'This is a test file for encryption!' * 100)

    iv_numbers = Lab1.lcg(2**16, 1103515245, 12345, int.from_bytes(rc5_key, "little"), 1)
    iv = iv_numbers[0]

    rsa_time, rc5_time = benchmark(input_file, rsa_private, rsa_public, rc5_key, iv)

    print(f"RSA encryption time: {rsa_time:.4f} seconds")
    print(f"RC5 encryption time: {rc5_time:.4f} seconds")
    print(f"RSA is {rsa_time / rc5_time:.2f} times slower than RC5.")


if __name__ == '__main__':
    main()
