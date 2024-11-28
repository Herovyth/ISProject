import pytest
from Lab1 import lcg, find_period, Chezaro_theorem
from Lab2 import md5, md5_for_data
from Lab3 import RC5, get_key_from_passphrase
from Crypto.Random import get_random_bytes


TEST_KEY = get_random_bytes(16)
TEST_IV = 12345
TEST_MESSAGE = b"This is a test message"
TEST_FILE = "test_file.txt"
TEST_ENCRYPTED = "encrypted_file.bin"
TEST_DECRYPTED = "decrypted_file.txt"
RSA_PRIVATE = "private_test.pem"
RSA_PUBLIC = "public_test.pem"
BLOCK_SIZE = 16


class TestLCG:
    def test_normal_case(self):
        result = lcg(16, 5, 3, 7, 10)
        assert result == [6, 1, 8, 11, 10, 5, 12, 15, 14, 9], "Normal case failed"

    def test_edge_case(self):
        result = lcg(1, 0, 0, 0, 5)  # Minimal parameters
        assert result == [0, 0, 0, 0, 0], "Edge case failed"

    def test_invalid_input(self):
        with pytest.raises(ZeroDivisionError):  # Example: m=0
            lcg(0, 1, 1, 1, 10)


class TestFindPeriod:
    def test_normal_case(self):
        result = find_period([1, 2, 3, 1, 2, 3, 1])
        assert result == 3, "Period calculation failed"

    def test_no_period(self):
        result = find_period([1, 2, 3, 4])
        assert result == -1, "No-period case failed"

    def test_single_element(self):
        result = find_period([1])
        assert result == -1, "Single element case failed"


class TestChezaroTheorem:
    def test_normal_case(self):
        random_numbers = [15, 21, 35, 77]
        result = Chezaro_theorem(random_numbers, num_threads=2)
        assert result is not None, "Normal case failed"

    def test_edge_case_empty_list(self):
        result = Chezaro_theorem([], num_threads=4)
        assert result is None, "Empty list case failed"

    def test_invalid_threads(self):
        random_numbers = [15, 21, 35]
        result = Chezaro_theorem(random_numbers, num_threads=0)
        assert result is None, "Invalid threads case failed"


class TestMD5:
    def test_normal_case(self):
        assert md5("abc") == "900150983cd24fb0d6963f7d28e17f72", "Normal case failed"

    def test_empty_string(self):
        assert md5("") == "d41d8cd98f00b204e9800998ecf8427e", "Empty string case failed"

    def test_invalid_input(self):
        with pytest.raises(TypeError):
            md5(123)  # Invalid input type


class TestMD5ForData:
    def test_string_input(self):
        result = md5_for_data("abc", is_file=False)
        assert result == "900150983cd24fb0d6963f7d28e17f72", "String input case failed"

    def test_file_input(self, tmp_path):
        # Create a temporary file
        file = tmp_path / "test.txt"
        file.write_text("abc")
        result = md5_for_data(str(file), is_file=True)
        assert result == "900150983cd24fb0d6963f7d28e17f72", "File input case failed"

    def test_empty_file(self, tmp_path):
        file = tmp_path / "empty.txt"
        file.write_text("")
        result = md5_for_data(str(file), is_file=True)
        assert result == "d41d8cd98f00b204e9800998ecf8427e", "Empty file case failed"


class TestRC5:
    def test_encrypt_decrypt_message_normal(self):
        rc5 = RC5(16, 12, TEST_KEY)
        encrypted = rc5.encrypt_message(TEST_IV)
        decrypted = rc5.decrypt_message(encrypted)
        assert decrypted == TEST_IV, "RC5 normal case failed"

    def test_encrypt_decrypt_message_edge(self):
        rc5 = RC5(16, 12, TEST_KEY)
        encrypted = rc5.encrypt_message(0)
        decrypted = rc5.decrypt_message(encrypted)
        assert decrypted == 0, "RC5 edge case failed"

    def test_encrypt_decrypt_message_invalid(self):
        rc5 = RC5(16, 12, TEST_KEY)
        with pytest.raises(TypeError):
            rc5.encrypt_message("invalid_input")

    def test_encrypt_decrypt_file_normal(self, tmp_path):
        input_file = tmp_path / TEST_FILE
        encrypted_file = tmp_path / TEST_ENCRYPTED
        decrypted_file = tmp_path / TEST_DECRYPTED

        input_file.write_bytes(TEST_MESSAGE)

        rc5 = RC5(16, 12, TEST_KEY)
        rc5.encrypt_file(TEST_IV, input_file, encrypted_file)
        rc5.decrypt_file(encrypted_file, decrypted_file)

        decrypted_content = decrypted_file.read_bytes()
        assert TEST_MESSAGE.rstrip(b"\x00") == decrypted_content, "RC5 file encryption/decryption failed"

    def test_encrypt_decrypt_file_edge(self, tmp_path):
        input_file = tmp_path / TEST_FILE
        encrypted_file = tmp_path / TEST_ENCRYPTED
        decrypted_file = tmp_path / TEST_DECRYPTED

        input_file.write_bytes(b"")

        rc5 = RC5(16, 12, TEST_KEY)
        rc5.encrypt_file(TEST_IV, input_file, encrypted_file)
        rc5.decrypt_file(encrypted_file, decrypted_file)

        decrypted_content = decrypted_file.read_bytes()
        assert decrypted_content == b"", "RC5 edge case with empty file failed"

    def test_encrypt_decrypt_file_invalid(self, tmp_path):
        input_file = tmp_path / "nonexistent_file.txt"
        encrypted_file = tmp_path / TEST_ENCRYPTED

        rc5 = RC5(16, 12, TEST_KEY)
        with pytest.raises(FileNotFoundError):
            rc5.encrypt_file(TEST_IV, input_file, encrypted_file)


# --- Допоміжні функції ---
def test_get_key_from_passphrase_normal():
    key = get_key_from_passphrase("test_passphrase", 64)
    assert len(key) == 8, "64-bit key generation failed"

    key = get_key_from_passphrase("test_passphrase", 256)
    assert len(key) == 32, "256-bit key generation failed"


def test_get_key_from_passphrase_invalid():
    with pytest.raises(ValueError):
        get_key_from_passphrase("test_passphrase", 128)  # Некоректна довжина


if __name__ == "__main__":
    pytest.main()

