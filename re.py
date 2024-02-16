import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(data):
    padding_length = AES.block_size - (len(data) % AES.block_size)
    padding_char = chr(padding_length).encode()
    return data + padding_length * padding_char

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(data))
    return cipher.iv + cipher_text

def decrypt(cipher_text, key):
    iv = cipher_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = cipher.decrypt(cipher_text[AES.block_size:])
    return plain_text.rstrip(b"\0")

def main():
    server_ip = '192.168.100.228'  # Replace with your server's IP address
    server_port = 12345
    encryption_key = b'Sixteen byte key'  # Replace with your encryption key

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((server_ip, server_port))
        print("Connected to the server.")

        message = "Hello, server!"
        encrypted_message = encrypt(message.encode(), encryption_key)
        client_socket.sendall(encrypted_message)

        cipher_text = client_socket.recv(1024)
        decrypted_text = decrypt(cipher_text, encryption_key)
        print("Received from server:", decrypted_text.decode())

    except ConnectionRefusedError:
        print("Connection to the server failed. Please check the server address and port.")

    finally:
        client_socket.close()

if __name__ == "__main__":
    main()
