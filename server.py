import socket
from lib.sm2py import SM2Cipher

# 生成SM2密钥对
sm2cipher = SM2Cipher()
private_key, public_key = sm2cipher.private_key, sm2cipher.public_key

# 初始化socket
host = 'localhost'
port = 12345
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))
print('Server started on {}:{}'.format(host, port))

while True:
    # 监听客户端连接
    s.listen(1)
    conn, addr = s.accept()
    print('Connected by', addr)

    # 发送公钥给客户端
    conn.sendall(public_key.encode('utf-8'))

    while True:
        # 接收客户端发来的消息，并解密
        ciphertext = conn.recv(1024)
        if not ciphertext:
            break
        plaintext = sm2cipher.decrypt_text_use_prikey(ciphertext, private_key)
        print('Received:', plaintext)

    conn.close()
