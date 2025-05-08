#!/usr/bin/env python3
import socket, binascii, itertools, re

HOST, PORT = "10.10.118.202", 1337

with socket.create_connection((HOST, PORT)) as s:
    # ──────────────────────────────────────────────────
    banner = s.recv(4096).decode()
    print("[+] Server banner:\n" + banner.strip())
    # ──────────────────────────────────────────────────
    # Extract the hex ciphertext from the banner
    cipher_hex = re.search(r":\s*([0-9a-f]+)", banner).group(1)
    print(f"[+] Ciphertext (hex): {cipher_hex}")
    cipher = binascii.unhexlify(cipher_hex)

    # We know the dummy plaintext in the source
    plain  = b"THM{thisisafakeflag}"

    # Recover the 5-byte key with a known-plaintext XOR
    key = bytes(c ^ p for c, p in zip(cipher, itertools.cycle(plain)))[:5]
    key_str = key.decode()
    print(f"[+] Recovered key: {key_str}")

    # Send the key to the server
    s.sendall(key + b"\n")
    reply = s.recv(4096).decode()
    print("[+] Server reply:\n" + reply.strip())

    # Decrypt flag 1 locally for completeness
    flag1 = bytes(c ^ k for c, k in zip(cipher, itertools.cycle(key))).decode()
    print(f"[+] Decrypted flag 1: {flag1}")
