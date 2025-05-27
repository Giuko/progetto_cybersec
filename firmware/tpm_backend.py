import socket
import struct

# TPM response constants
TPM_ST_NO_SESS = 0x8001
TPM_RC_SUCCESS = 0x000
TPM_CC_GetRandom = 0x0000017B

# Example random bytes to return
RANDOM_BYTES = b'\xAA\xBB\xCC\xDD'

def build_response(data: bytes) -> bytes:
    # TPM 2.0 response format: Tag (2) + Length (4) + Response Code (4) + Data
    tag = TPM_ST_NO_SESS
    response_size = 10 + len(data)  # header + data
    return struct.pack(">HII", tag, response_size, TPM_RC_SUCCESS) + data

def handle_command(cmd: bytes) -> bytes:
    if len(cmd) < 10:
        print("Received too short command")
        return build_response(b'')

    tag, length, command_code = struct.unpack(">HII", cmd[:10])
    print(f"Received TPM command: tag=0x{tag:04X}, len={length}, cc=0x{command_code:08X}")

    if command_code == TPM_CC_GetRandom:
        # Return structure: size (2 bytes) + bytes
        data = struct.pack(">H", len(RANDOM_BYTES)) + RANDOM_BYTES
        return build_response(data)
    else:
        print("Unsupported command")
        return build_response(b'\x00')  # Dummy fallback

def main():
    socket_path = '/tmp/serial.sock'
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(1)
    print(f"TPM backend listening on {socket_path}")

    conn, _ = server.accept()
    print("Connection from QEMU accepted")

    try:
        while True:
            cmd = conn.recv(1024)
            if not cmd:
                break
            print("Raw command bytes:", cmd.hex())

            response = handle_command(cmd)
            print("Sending response:", response.hex())
            conn.sendall(response)
    finally:
        conn.close()
        server.close()

if __name__ == "__main__":
    import os
    main()

