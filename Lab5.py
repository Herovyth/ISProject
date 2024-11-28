from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


def generate_keys(private_key_path="private_key.pem", public_key_path="public_key.pem"):
    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()

    with open(private_key_path, "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(public_key_path, "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )


def sign_message(message, private_key_path="private_key.pem"):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    signature = private_key.sign(message.encode(), hashes.SHA256())
    return signature.hex()


def verify_signature(message, signature_hex, public_key_path="public_key.pem"):
    signature = bytes.fromhex(signature_hex)

    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    try:
        public_key.verify(signature, message.encode(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
