import socket
from lib.sm2py import SM2Cipher

# 初始化socket
host = 'localhost'
port = 12345
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
print('Connected to {}:{}'.format(host, port))

# 接收服务端公钥
public_key = s.recv(1024).decode('utf-8')
sm2cipher = SM2Cipher()

while True:
    # 向服务端发送消息，并加密
    message = input("Enter your message: ")
    if message == 'exit':
        break
    ciphertext = sm2cipher.encrypt_text_use_pubkey(message, public_key)
    s.sendall(ciphertext)

s.close()
