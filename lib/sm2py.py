# 导入依赖库
import time

from gmssl import sm2
import lib.key_gen as key_gen


class SM2Cipher:
    def __init__(self):
        # 生成 SM2 对象
        self.private_key, self.public_key = key_gen.generate_sm2_key()
        self.sm2_instance = sm2.CryptSM2(public_key=self.public_key, private_key=self.private_key)

    def set_keypair(self, private_key, public_key):
        self.private_key, self.public_key = private_key, public_key
        self.sm2_instance = sm2.CryptSM2(public_key=self.public_key, private_key=self.private_key)

    def encrypt_text(self, plaintext: str) -> bytes:
        # 使用公钥加密文本
        cipher = self.sm2_instance.encrypt(plaintext.encode('utf-8'))
        return bytes(cipher)

    def decrypt_text(self, ciphertext: bytes) -> str:
        # 使用私钥解密文本
        plaintext = self.sm2_instance.decrypt(bytes(ciphertext))
        return bytes(plaintext).decode('utf-8')

    def encrypt_text_use_pubkey(self, plaintext: str, public_key: str) -> bytes:
        # 使用公钥加密文本
        temp_sm2 = sm2.CryptSM2(public_key=self.public_key, private_key=self.private_key)
        temp_sm2.public_key = public_key
        cipher = temp_sm2.encrypt(plaintext.encode('utf-8'))
        return bytes(cipher)

    def decrypt_text_use_prikey(self, ciphertext: bytes, private_key) -> str:
        # 使用私钥解密文本
        temp_sm2 = sm2.CryptSM2(public_key=self.public_key, private_key=self.private_key)
        temp_sm2.private_key = private_key
        plaintext = self.sm2_instance.decrypt(bytes(ciphertext))
        return bytes(plaintext).decode('utf-8')

    def encrypt_file(self, input_file: str, output_file: str):
        # 使用公钥加密文件
        with open(input_file, 'rb') as fin, open(output_file, 'wb') as fout:
            while True:
                chunk = fin.read(2048)
                if not chunk:
                    break
                cipher = self.sm2_instance.encrypt(chunk)
                fout.write(bytearray(cipher))

    def decrypt_file(self, input_file: str, output_file: str):
        # 使用私钥解密文件
        with open(input_file, 'rb') as fin, open(output_file, 'wb') as fout:
            while True:
                chunk = fin.read(2048)
                if not chunk:
                    break
                plaintext = self.sm2_instance.decrypt(chunk)
                fout.write(bytearray(plaintext))
