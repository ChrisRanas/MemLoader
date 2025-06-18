import os
import argparse
from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes


def format_buffer_to_cpp(var_name, buffer):
    """Format a byte buffer into a C-style unsigned char array."""
    lines = [
        '"' + ''.join(f"\\x{b:02x}" for b in buffer[i:i + 16]) + '"'
        for i in range(0, len(buffer), 16)
    ]
    return f"unsigned char {var_name}[] = \n" + "\n".join(lines) + ";"

def add_padding(buffer, chunk_size=1024):
    """Add padding to buffer after every `chunk_size` bytes."""
    padded = bytearray()
    for i in range(0, len(buffer), chunk_size):
        padded.extend(buffer[i:i + chunk_size])
        padded.extend(b'\x00' * chunk_size)
    return bytes(padded)

def read_file(path):
    """Read file content safely."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")
    with open(path, "rb") as f:
        return f.read()

def write_text_file(path, text):
    with open(path, "w") as f:
        f.write(text)

def main():
    parser = argparse.ArgumentParser(description="Encrypt and format a binary payload into C-style arrays.")
    parser.add_argument("-p", "--payload", required=True, help="Path of the payload to pack")
    parser.add_argument("-o", "--output", required=True, help="Output encrypted header file")

    args = parser.parse_args()

    payload_path = args.payload
    output_path = args.output

    print(f"[+] Payload: {payload_path}")
    print(f"[+] Output: {output_path}")

    content = read_file(payload_path)
    encryption_key = get_random_bytes(16)

    cipher = ARC4.new(encryption_key)
    encrypted_payload = cipher.encrypt(content)
    padded_payload = add_padding(encrypted_payload)

    print(f"[+] Encryption key (hex): {encryption_key.hex()}")

    cpp_payload = format_buffer_to_cpp("payload", padded_payload)
    cpp_key = format_buffer_to_cpp("key", encryption_key)


    header_output = (
        f"#define REAL_SIZE\t{len(content)}\n"
        f"{cpp_key}\n\n"
        f"{cpp_payload}\n"
    )
    write_text_file(output_path, header_output)

    print("[+] Finished generating header and encrypted payload.")


if __name__ == "__main__":
    main()
