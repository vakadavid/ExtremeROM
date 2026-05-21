#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import shutil
import struct
import subprocess
from pathlib import Path

MASTER_KEY = bytes.fromhex("E83420592B7FC371C6734501C767D38E982C6584B1518E1C450A362A57F1C50E")
MASTER_IV = bytes.fromhex("C3471249DDF13D50180AB6C8A9589294")
USERBOOT_HASH_MARKER = b"ub_tzar_walk_cb\x00"
AES_BLOCK_SIZE = 16


def _aes_cbc_crypto(data: bytes, key: bytes, iv: bytes, decrypt: bool) -> bytes:
    from Crypto.Cipher import AES  # type: ignore

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data) if decrypt else cipher.encrypt(data)


def _aes_cbc_cryptodome(data: bytes, key: bytes, iv: bytes, decrypt: bool) -> bytes:
    from Cryptodome.Cipher import AES  # type: ignore

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data) if decrypt else cipher.encrypt(data)


def _aes_cbc_openssl(data: bytes, key: bytes, iv: bytes, decrypt: bool) -> bytes:
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("openssl binary not found in PATH")

    cmd = [
        openssl,
        "enc",
        "-aes-256-cbc",
        "-K",
        key.hex(),
        "-iv",
        iv.hex(),
        "-nopad",
        "-nosalt",
    ]
    if decrypt:
        cmd.append("-d")

    proc = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"openssl failed ({proc.returncode}): {err}")
    return proc.stdout


def select_aes_backend():
    backends = [
        ("pycrypto/pycryptodome (Crypto)", _aes_cbc_crypto),
        ("pycryptodomex (Cryptodome)", _aes_cbc_cryptodome),
        ("openssl", _aes_cbc_openssl),
    ]

    probe = b"\x00" * AES_BLOCK_SIZE
    key = b"\x00" * 32
    iv = b"\x00" * AES_BLOCK_SIZE
    errors = []

    for name, fn in backends:
        try:
            out = fn(probe, key, iv, False)
            if len(out) != len(probe):
                raise RuntimeError(f"probe returned {len(out)} bytes, expected {len(probe)}")
            return name, fn
        except Exception as exc:
            errors.append(f"{name}: {exc}")

    joined = "; ".join(errors)
    raise RuntimeError(f"no working AES backend found ({joined})")


AES_BACKEND_NAME, aes_cbc = select_aes_backend()


def read_u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def tzsw_region(data: bytes | bytearray) -> tuple[int, int]:
    if len(data) < 0x70:
        raise ValueError("tzsw.img is too small for the Exynos9830 TZSW crypto header")
    start = read_u32(data, 0x28)
    end = read_u32(data, 0x2C)
    if start >= end or end > len(data):
        raise ValueError(f"Invalid TZSW encrypted region: start=0x{start:X} end=0x{end:X} image=0x{len(data):X}")
    if (end - start) % AES_BLOCK_SIZE:
        raise ValueError(f"TZSW encrypted region is not AES-block aligned: size=0x{end - start:X}")
    return start, end


def tzsw_key(data: bytes | bytearray) -> bytes:
    return aes_cbc(bytes(data[0x40:0x60]), MASTER_KEY, MASTER_IV, True)


def tzsw_iv(data: bytes | bytearray) -> bytes:
    return bytes(data[0x60:0x70])


def is_clear_tzsw(data: bytes | bytearray) -> bool:
    return USERBOOT_HASH_MARKER in data


def transform_tzsw(data: bytes | bytearray, *, decrypt: bool) -> bytes:
    start, end = tzsw_region(data)
    key = tzsw_key(data)
    iv = tzsw_iv(data)
    out = bytearray(data)
    block = bytes(out[start:end])
    out[start:end] = aes_cbc(block, key, iv, decrypt)
    return bytes(out)


def decrypt_tzsw(data: bytes | bytearray) -> bytes:
    return transform_tzsw(data, decrypt=True)


def encrypt_tzsw(data: bytes | bytearray) -> bytes:
    return transform_tzsw(data, decrypt=False)


def command_status(args: argparse.Namespace) -> None:
    data = Path(args.input).read_bytes()
    start, end = tzsw_region(data)
    print(f"Input: {args.input}")
    print(f"Region: 0x{start:X}-0x{end:X} size=0x{end - start:X}")
    print(f"Key: {tzsw_key(data).hex()}")
    print(f"IV: {tzsw_iv(data).hex()}")
    print(f"Clear marker: {'yes' if is_clear_tzsw(data) else 'no'}")


def command_decrypt(args: argparse.Namespace) -> None:
    data = Path(args.input).read_bytes()
    out = decrypt_tzsw(data)
    if args.require_marker and not is_clear_tzsw(out):
        raise ValueError("Decrypted TZSW does not contain the expected userboot hash marker")
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_bytes(out)
    print(f"Decrypted TZSW written to {args.output}")


def command_encrypt(args: argparse.Namespace) -> None:
    data = Path(args.input).read_bytes()
    if args.require_marker and not is_clear_tzsw(data):
        raise ValueError("Input TZSW does not contain the expected clear userboot hash marker")
    out = encrypt_tzsw(data)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_bytes(out)
    print(f"Encrypted TZSW written to {args.output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Decrypt or recrypt Exynos9830 tzsw.img payloads")
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="Print TZSW crypto header info")
    status.add_argument("-i", "--input", required=True)
    status.set_defaults(func=command_status)

    decrypt = sub.add_parser("decrypt", help="Decrypt the TZSW encrypted region")
    decrypt.add_argument("-i", "--input", required=True)
    decrypt.add_argument("-o", "--output", required=True)
    decrypt.add_argument("--no-require-marker", dest="require_marker", action="store_false")
    decrypt.set_defaults(func=command_decrypt, require_marker=True)

    encrypt = sub.add_parser("encrypt", help="Encrypt the TZSW clear region")
    encrypt.add_argument("-i", "--input", required=True)
    encrypt.add_argument("-o", "--output", required=True)
    encrypt.add_argument("--no-require-marker", dest="require_marker", action="store_false")
    encrypt.set_defaults(func=command_encrypt, require_marker=True)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
