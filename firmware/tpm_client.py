import socket

def client():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect('/tmp/serial.sock')

    # Example TPM GetRandom command (as in your kernel)
    cmd = bytes([
        0x80, 0x01,             # Tag
        0x00, 0x00, 0x00, 0x0E, # Length
        0x00, 0x00, 0x01, 0x7B, # CommandCode: GetRandom
        0x00, 0x04              # 4 bytes requested
    ])

    sock.sendall(cmd)
    resp = sock.recv(1024)
    print("Response:", resp.hex())
    sock.close()

if __name__ == '__main__':
    client()

