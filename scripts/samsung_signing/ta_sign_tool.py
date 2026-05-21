#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Creeeeger <104427569+Creeeeger@users.noreply.github.com>

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

SEC_MAGICS = {b"SEC2", b"SEC3", b"SEC4"}
SEC3_MAGICS = {b"SEC3", b"SEC4"}
DEFAULT_ROOT_TYPE = 1
DEFAULT_PACKAGE_TYPE = 4
ROOT_CERT_SYMBOLS = (
    ("RELEASE_ROOT_CERT", "RELEASE_ROOT_CERT_END"),
    ("CHIPSET_COMMON_ROOT_CERT", "CHIPSET_COMMON_ROOT_CERT_END"),
)


@dataclass
class TAPackage:
    path: Path
    data: bytes
    magic: bytes
    sec_len: int
    trailer_offset: int
    package_type: int
    root_type: int
    authority: str
    signature: bytes
    cert_der: bytes
    sec2_flags: bytes = b""

    @property
    def payload(self):
        return self.data[8:self.trailer_offset]

    @property
    def signed_region(self):
        if self.magic == b"SEC2":
            return self.payload
        return self.payload + struct.pack(">II", self.package_type, self.root_type)


def read_file(path):
    return Path(path).read_bytes()


def write_file(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def write_private_key(path, key):
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    write_file(path, data)


def write_cert_pem(path, cert):
    write_file(path, cert.public_bytes(serialization.Encoding.PEM))


def write_cert_der(path, cert):
    write_file(path, cert.public_bytes(serialization.Encoding.DER))


def load_cert(path):
    data = read_file(path)
    if data.startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def fixed_size_serial():
    # The stock TEEgris root certs use a 64-bit positive serial that encodes to
    # 9 DER bytes because the high bit is set. Keeping that shape makes the
    # generated root cert fit the fixed 770-byte librootcert slots exactly.
    return int.from_bytes(os.urandom(8), "big") | (1 << 63)


def cert_cn(cert):
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def parse_ta(path):
    path = Path(path)
    data = path.read_bytes()
    if len(data) < 16 or data[:4] not in SEC_MAGICS:
        raise ValueError(f"{path}: only SEC2/SEC3/SEC4 TA packages are supported")
    sec_len = int.from_bytes(data[4:8], "big")
    trailer_offset = 8 + sec_len
    if trailer_offset + 13 > len(data):
        raise ValueError(f"{path}: missing SEC3/SEC4 trailer")
    if data[8:12] != b"\x7fELF":
        raise ValueError(f"{path}: SEC payload is not an ELF at offset 8")

    trailer = data[trailer_offset:]

    if data[:4] == b"SEC2":
        authority_len = trailer[0]
        pos = 1
        authority_raw = trailer[pos:pos + authority_len]
        pos += authority_len
        if pos + 2 + 256 + 2 > len(trailer):
            raise ValueError(f"{path}: truncated SEC2 trailer")
        sec2_flags = trailer[pos:pos + 2]
        pos += 2
        signature = trailer[pos:pos + 256]
        pos += 256
        cert_len = int.from_bytes(trailer[pos:pos + 2], "big")
        pos += 2
        cert_der = trailer[pos:pos + cert_len]
        if len(cert_der) != cert_len or pos + cert_len != len(trailer):
            raise ValueError(f"{path}: truncated SEC2 certificate")
        return TAPackage(
            path=path,
            data=data,
            magic=data[:4],
            sec_len=sec_len,
            trailer_offset=trailer_offset,
            package_type=2,
            root_type=DEFAULT_ROOT_TYPE,
            authority=authority_raw.decode("ascii", "replace"),
            signature=signature,
            cert_der=cert_der,
            sec2_flags=sec2_flags,
        )

    package_type, root_type = struct.unpack_from(">II", trailer, 0)
    authority_len = trailer[8]
    pos = 9
    authority_raw = trailer[pos:pos + authority_len]
    pos += authority_len
    if pos + 2 > len(trailer):
        raise ValueError(f"{path}: truncated signature length")
    signature_len = int.from_bytes(trailer[pos:pos + 2], "big")
    pos += 2
    signature = trailer[pos:pos + signature_len]
    pos += signature_len
    if len(signature) != signature_len or pos + 2 > len(trailer):
        raise ValueError(f"{path}: truncated signature")
    cert_len = int.from_bytes(trailer[pos:pos + 2], "big")
    pos += 2
    cert_der = trailer[pos:pos + cert_len]
    if len(cert_der) != cert_len:
        raise ValueError(f"{path}: truncated certificate")

    return TAPackage(
        path=path,
        data=data,
        magic=data[:4],
        sec_len=sec_len,
        trailer_offset=trailer_offset,
        package_type=package_type,
        root_type=root_type,
        authority=authority_raw.decode("ascii", "replace"),
        signature=signature,
        cert_der=cert_der,
    )


def ta_signature_padding(package_type):
    if package_type == 2:
        return padding.PKCS1v15()
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def verify_ta_signature(pkg):
    cert = x509.load_der_x509_certificate(pkg.cert_der)
    pub = cert.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(pkg.signature, pkg.signed_region, ta_signature_padding(pkg.package_type), hashes.SHA256())
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(pkg.signature, pkg.signed_region, ec.ECDSA(hashes.SHA256()))
        else:
            return False, "unsupported public key type"
        return True, ""
    except InvalidSignature:
        return False, "signature mismatch"


def verify_cert_with_root(cert, root_cert):
    pub = root_cert.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        else:
            return False, "unsupported root public key type"
        return True, ""
    except InvalidSignature:
        return False, "leaf certificate signature mismatch"


def inspect_command(args):
    root_cert = load_cert(args.root_cert) if args.root_cert else None
    for path in args.ta:
        pkg = parse_ta(path)
        cert = x509.load_der_x509_certificate(pkg.cert_der)
        pub = cert.public_key()
        ok, reason = verify_ta_signature(pkg)
        key_desc = "unknown"
        if isinstance(pub, rsa.RSAPublicKey):
            key_desc = f"RSA-{pub.key_size}"
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            key_desc = pub.curve.name

        print(f"{pkg.path}")
        print(f"  magic/sec_len: {pkg.magic.decode()} / 0x{pkg.sec_len:X}")
        print(f"  trailer:       0x{pkg.trailer_offset:X} ({len(pkg.data) - pkg.trailer_offset} bytes)")
        print(f"  package/root:  {pkg.package_type} / {pkg.root_type}")
        print(f"  authority:     {pkg.authority}")
        print(f"  cert subject:  {cert.subject.rfc4514_string()}")
        print(f"  cert issuer:   {cert.issuer.rfc4514_string()}")
        print(f"  cert key:      {key_desc}")
        print(
            f"  signature:     {len(pkg.signature)} bytes, {'OK' if ok else 'FAIL'}{(': ' + reason) if reason else ''}")
        if root_cert:
            chain_ok, chain_reason = verify_cert_with_root(cert, root_cert)
            print(f"  leaf chain:    {'OK' if chain_ok else 'FAIL'}{(': ' + chain_reason) if chain_reason else ''}")
        print()


def validity_window():
    return (
        datetime(2020, 1, 1, tzinfo=timezone.utc),
        datetime(2049, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
    )


def gen_root_command(args):
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=args.bits)
    not_before, not_after = validity_window()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(fixed_size_serial())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    write_private_key(out_dir / "ta_root_key.pem", key)
    write_cert_pem(out_dir / "ta_root_cert.pem", cert)
    write_cert_der(out_dir / "ta_root_cert.der", cert)
    print(f"Wrote {out_dir / 'ta_root_key.pem'}")
    print(f"Wrote {out_dir / 'ta_root_cert.der'} ({len(cert.public_bytes(serialization.Encoding.DER))} bytes)")


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_")


def build_leaf(root_key, root_cert, cn, bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    not_before, not_after = validity_window()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(fixed_size_serial())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return key, cert


def gen_leaf_command(args):
    root_key = load_private_key(args.root_key)
    root_cert = load_cert(args.root_cert)
    key, cert = build_leaf(root_key, root_cert, args.cn, args.bits)
    prefix = Path(args.out_prefix)
    write_private_key(prefix.with_suffix(".key.pem"), key)
    write_cert_pem(prefix.with_suffix(".cert.pem"), cert)
    write_cert_der(prefix.with_suffix(".cert.der"), cert)
    print(f"Wrote {prefix.with_suffix('.key.pem')}")
    print(f"Wrote {prefix.with_suffix('.cert.der')} ({len(cert.public_bytes(serialization.Encoding.DER))} bytes)")


def validate_leaf(pkg, cert, key):
    if cert_cn(cert) != pkg.authority:
        raise ValueError(f"{pkg.path}: leaf cert CN '{cert_cn(cert)}' does not match TA authority '{pkg.authority}'")
    if not isinstance(cert.public_key(), rsa.RSAPublicKey):
        raise ValueError("leaf cert public key must be RSA for Exynos990 root_task")
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise ValueError("leaf cert does not match private key")


def sign_package(pkg, cert, key, package_type, root_type):
    validate_leaf(pkg, cert, key)
    if len(pkg.authority.encode("ascii")) > 0xFF:
        raise ValueError("authority string is too long")
    if pkg.magic == b"SEC2":
        signature = key.sign(pkg.payload, padding.PKCS1v15(), hashes.SHA256())
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        if len(signature) != 256:
            raise ValueError("SEC2 signer currently expects a 2048-bit RSA leaf key")
        if len(cert_der) > 0xFFFF:
            raise ValueError("certificate is too large for SEC2 trailer")
        trailer = (
                bytes([len(pkg.authority)])
                + pkg.authority.encode("ascii")
                + (pkg.sec2_flags or b"\x01\x00")
                + signature
                + len(cert_der).to_bytes(2, "big")
                + cert_der
        )
        return pkg.data[:pkg.trailer_offset] + trailer

    prefix = struct.pack(">II", package_type, root_type) + bytes([len(pkg.authority)]) + pkg.authority.encode("ascii")
    signed_region = pkg.payload + prefix[:8]
    signature = key.sign(signed_region, ta_signature_padding(package_type), hashes.SHA256())
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    if len(signature) > 0xFFFF or len(cert_der) > 0xFFFF:
        raise ValueError("signature or certificate is too large for SEC3 trailer")
    trailer = prefix + len(signature).to_bytes(2, "big") + signature + len(cert_der).to_bytes(2, "big") + cert_der
    return pkg.data[:pkg.trailer_offset] + trailer


def sign_command(args):
    pkg = parse_ta(args.input)
    cert = load_cert(args.leaf_cert)
    key = load_private_key(args.leaf_key)
    package_type = args.package_type if args.package_type is not None else pkg.package_type
    root_type = args.root_type
    output = sign_package(pkg, cert, key, package_type, root_type)
    write_file(args.output, output)
    signed = parse_ta(args.output)
    ok, reason = verify_ta_signature(signed)
    if not ok:
        raise ValueError(f"self-check failed after signing: {reason}")
    print(f"Signed {pkg.path} -> {args.output}")
    print(f"  authority={pkg.authority} package/root={package_type}/{root_type} size=0x{len(output):X}")


def leaf_paths(keys_dir, authority):
    base = Path(keys_dir) / safe_name(authority)
    return base.with_suffix(".key.pem"), base.with_suffix(".cert.der")


def resign_dir_command(args):
    in_dir = Path(args.input_dir)
    out_dir = Path(args.output_dir)
    keys_dir = Path(args.leaf_keys_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    keys_dir.mkdir(parents=True, exist_ok=True)
    root_key = load_private_key(args.root_key)
    root_cert = load_cert(args.root_cert)

    signed = skipped = 0
    for src in sorted(p for p in in_dir.rglob("*") if p.is_file()):
        rel = src.relative_to(in_dir)
        dest = out_dir / rel
        try:
            pkg = parse_ta(src)
        except Exception:
            if args.copy_unsupported:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
            skipped += 1
            continue

        key_path, cert_path = leaf_paths(keys_dir, pkg.authority)
        if key_path.is_file() and cert_path.is_file():
            leaf_key = load_private_key(key_path)
            leaf_cert = load_cert(cert_path)
        else:
            leaf_key, leaf_cert = build_leaf(root_key, root_cert, pkg.authority)
            write_private_key(key_path, leaf_key)
            write_cert_der(cert_path, leaf_cert)

        output = sign_package(
            pkg,
            leaf_cert,
            leaf_key,
            args.package_type if args.package_type is not None else pkg.package_type,
            args.root_type,
        )
        write_file(dest, output)
        signed += 1
        print(f"signed {rel}: {pkg.authority}")

    print(f"Signed {signed} TA packages, skipped/copied {skipped} unsupported files")


def parse_elf_symbols(data):
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    elf_class = data[4]
    endian = "<" if data[5] == 1 else ">"
    if elf_class == 1:
        eh = struct.unpack_from(endian + "16sHHIIIIIHHHHHH", data, 0)
        e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = (
            eh[5], eh[6], eh[9], eh[10], eh[11], eh[12], eh[13]
        )
        ph_fmt, sh_fmt, sym_fmt = endian + "IIIIIIII", endian + "IIIIIIIIII", endian + "IIIBBH"
    else:
        eh = struct.unpack_from(endian + "16sHHIQQQIHHHHHH", data, 0)
        e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = (
            eh[5], eh[6], eh[9], eh[10], eh[11], eh[12], eh[13]
        )
        ph_fmt, sh_fmt, sym_fmt = endian + "IIQQQQQQ", endian + "IIQQQQIIQQ", endian + "IBBHQQ"

    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        ph = struct.unpack_from(ph_fmt, data, off)
        if ph[0] != 1:
            continue
        if elf_class == 1:
            _, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_flags, _p_align = ph
        else:
            _, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = ph
        segments.append((p_vaddr, p_offset, p_filesz))

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh = struct.unpack_from(sh_fmt, data, off)
        if elf_class == 1:
            sh_name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link, _info, _align, sh_entsize = sh
        else:
            sh_name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link, _info, _align, sh_entsize = sh
        sections.append((sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize))

    def section_data(index):
        _name, _type, off, size, _link, _entsize = sections[index]
        return data[off:off + size]

    symbols = {}
    for sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        if sh_type not in (2, 11) or sh_entsize == 0:
            continue
        strtab = section_data(sh_link)
        count = sh_size // sh_entsize
        for i in range(count):
            raw = data[sh_offset + i * sh_entsize:sh_offset + (i + 1) * sh_entsize]
            if elf_class == 1:
                st_name, st_value, st_size, _info, _other, _shndx = struct.unpack(sym_fmt, raw)
            else:
                st_name, _info, _other, _shndx, st_value, st_size = struct.unpack(sym_fmt, raw)
            if st_name >= len(strtab):
                continue
            name = strtab[st_name:].split(b"\0", 1)[0].decode("ascii", "replace")
            if name:
                symbols[name.split("@", 1)[0]] = (st_value, st_size)

    def vaddr_to_offset(vaddr):
        for seg_vaddr, seg_offset, seg_size in segments:
            if seg_vaddr <= vaddr < seg_vaddr + seg_size:
                return seg_offset + (vaddr - seg_vaddr)
        return vaddr

    return {name: (vaddr_to_offset(value), size) for name, (value, size) in symbols.items()}


def patch_slot(data, symbols, start_name, end_name, cert_der):
    if start_name not in symbols or end_name not in symbols:
        raise ValueError(f"missing rootcert symbols {start_name}/{end_name}")
    start = symbols[start_name][0]
    end = symbols[end_name][0]
    if end <= start:
        raise ValueError(f"bad rootcert symbol range for {start_name}")
    slot_size = end - start
    if len(cert_der) > slot_size:
        raise ValueError(f"{start_name}: cert is {len(cert_der)} bytes, slot is {slot_size} bytes")
    out = bytearray(data)
    out[start:end] = cert_der + b"\0" * (slot_size - len(cert_der))
    return bytes(out), slot_size


def patch_rootcert_command(args):
    data = read_file(args.input)
    out, release_slot, chipset_slot, release_len, chipset_len = patch_rootcert_data(
        data,
        args.release_cert,
        args.chipset_cert,
    )
    write_file(args.output, out)
    print(f"Patched {args.input} -> {args.output}")
    print(f"  release cert: {release_len} / {release_slot} bytes")
    print(f"  chipset cert: {chipset_len} / {chipset_slot} bytes")


def patch_rootcert_data(data, release_cert, chipset_cert=None):
    symbols = parse_elf_symbols(data)
    release = load_cert(release_cert).public_bytes(serialization.Encoding.DER)
    chipset = load_cert(chipset_cert).public_bytes(serialization.Encoding.DER) if chipset_cert else release
    out = data
    out, release_slot = patch_slot(out, symbols, "RELEASE_ROOT_CERT", "RELEASE_ROOT_CERT_END", release)
    out, chipset_slot = patch_slot(out, symbols, "CHIPSET_COMMON_ROOT_CERT", "CHIPSET_COMMON_ROOT_CERT_END", chipset)
    return out, release_slot, chipset_slot, len(release), len(chipset)


def run_checked(cmd):
    print("+ " + " ".join(str(part) for part in cmd))
    subprocess.run([str(part) for part in cmd], check=True)


def append_optional_arg(cmd, flag, value):
    if value is not None:
        cmd.extend([flag, value])


def patch_tzar_command(args):
    tzar_tool = Path(__file__).with_name("tzar_tool.py")
    if not tzar_tool.is_file():
        raise FileNotFoundError(f"Missing sibling tool: {tzar_tool}")

    temp_dir = None
    if args.work_dir:
        work_dir = Path(args.work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)
    else:
        temp_dir = tempfile.mkdtemp(prefix="ta-sign-tzar-")
        work_dir = Path(temp_dir)

    extract_dir = work_dir / "extract"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)

    try:
        run_checked([sys.executable, tzar_tool, "extract", "-i", args.input, "-o", extract_dir])

        for arch in ("lib32", "lib64"):
            lib_path = extract_dir / "files" / arch / "librootcert.so"
            patched, release_slot, chipset_slot, release_len, chipset_len = patch_rootcert_data(
                lib_path.read_bytes(),
                args.release_cert,
                args.chipset_cert,
            )
            write_file(lib_path, patched)
            print(f"Patched TZAR member /{arch}/librootcert.so")
            print(f"  release cert: {release_len} / {release_slot} bytes")
            print(f"  chipset cert: {chipset_len} / {chipset_slot} bytes")

        cmd = [sys.executable, tzar_tool, "pack", "-i", extract_dir, "-o", args.output]
        append_optional_arg(cmd, "--keys-dir", args.keys_dir)
        append_optional_arg(cmd, "--key-file", args.key_file)
        append_optional_arg(cmd, "--pub-key", args.pub_key)
        append_optional_arg(cmd, "--rp-cnt", args.rp_cnt)
        append_optional_arg(cmd, "--key-type", args.key_type)
        append_optional_arg(cmd, "--key-index", args.key_index)
        append_optional_arg(cmd, "--signed-size", args.signed_size)
        append_optional_arg(cmd, "--grow-align", args.grow_align)
        append_optional_arg(cmd, "--outer-lz4", args.outer_lz4)
        append_optional_arg(cmd, "--soc", args.soc)
        if args.allow_grow:
            cmd.append("--allow-grow")
        if args.no_sign:
            cmd.append("--no-sign")
        run_checked(cmd)
        print(f"Updated TZAR written to {args.output}")
        if args.keep_work:
            print(f"Kept work dir: {work_dir}")
    finally:
        if temp_dir and not args.keep_work:
            shutil.rmtree(temp_dir, ignore_errors=True)


def parse_int(value):
    return int(value, 0)


def main():
    parser = argparse.ArgumentParser(description="Inspect and resign Samsung SEC2/SEC3/SEC4 TA packages")
    sub = parser.add_subparsers(dest="command", required=True)

    inspect = sub.add_parser("inspect")
    inspect.add_argument("--root-cert")
    inspect.add_argument("ta", nargs="+")
    inspect.set_defaults(func=inspect_command)

    gen_root = sub.add_parser("gen-root")
    gen_root.add_argument("-o", "--out-dir", required=True)
    gen_root.add_argument("--common-name", default="root")
    gen_root.add_argument("--bits", type=int, default=2048)
    gen_root.set_defaults(func=gen_root_command)

    gen_leaf = sub.add_parser("gen-leaf")
    gen_leaf.add_argument("--root-key", required=True)
    gen_leaf.add_argument("--root-cert", required=True)
    gen_leaf.add_argument("--cn", required=True)
    gen_leaf.add_argument("-o", "--out-prefix", required=True)
    gen_leaf.add_argument("--bits", type=int, default=2048)
    gen_leaf.set_defaults(func=gen_leaf_command)

    sign = sub.add_parser("sign")
    sign.add_argument("-i", "--input", required=True)
    sign.add_argument("-o", "--output", required=True)
    sign.add_argument("--leaf-key", required=True)
    sign.add_argument("--leaf-cert", required=True)
    sign.add_argument("--package-type", type=parse_int)
    sign.add_argument("--root-type", type=parse_int, default=DEFAULT_ROOT_TYPE)
    sign.set_defaults(func=sign_command)

    resign_dir = sub.add_parser("resign-dir")
    resign_dir.add_argument("-i", "--input-dir", required=True)
    resign_dir.add_argument("-o", "--output-dir", required=True)
    resign_dir.add_argument("--root-key", required=True)
    resign_dir.add_argument("--root-cert", required=True)
    resign_dir.add_argument("--leaf-keys-dir", required=True)
    resign_dir.add_argument("--package-type", type=parse_int)
    resign_dir.add_argument("--root-type", type=parse_int, default=DEFAULT_ROOT_TYPE)
    resign_dir.add_argument("--copy-unsupported", action=argparse.BooleanOptionalAction, default=True)
    resign_dir.set_defaults(func=resign_dir_command)

    patch_rootcert = sub.add_parser("patch-rootcert")
    patch_rootcert.add_argument("-i", "--input", required=True)
    patch_rootcert.add_argument("-o", "--output", required=True)
    patch_rootcert.add_argument("--release-cert", required=True)
    patch_rootcert.add_argument("--chipset-cert")
    patch_rootcert.set_defaults(func=patch_rootcert_command)

    patch_tzar = sub.add_parser("patch-tzar")
    patch_tzar.add_argument("-i", "--input", required=True, help="Input tzar.img.lz4 or raw tzar.img")
    patch_tzar.add_argument("-o", "--output", required=True, help="Output tzar.img.lz4 or raw tzar.img")
    patch_tzar.add_argument("--release-cert", required=True)
    patch_tzar.add_argument("--chipset-cert")
    patch_tzar.add_argument("--work-dir", help="Optional persistent extraction work directory")
    patch_tzar.add_argument("--keep-work", action="store_true", help="Keep temporary extraction directory")
    patch_tzar.add_argument("--keys-dir", help="Directory containing Stage-2 TEE keys for tzar_tool.py")
    patch_tzar.add_argument("--key-file", help="Stage-2 TEE private key PEM for tzar_tool.py")
    patch_tzar.add_argument("--pub-key", help="Stage-2 TEE public key blob for tzar_tool.py verification")
    patch_tzar.add_argument("--rp-cnt", type=str, help="Rollback counter passed to tzar_tool.py")
    patch_tzar.add_argument("--key-type", type=str, help="Footer key type passed to tzar_tool.py")
    patch_tzar.add_argument("--key-index", type=str, help="Footer key index passed to tzar_tool.py")
    patch_tzar.add_argument("--signed-size", type=str, help="Signed TZAR size passed to tzar_tool.py")
    patch_tzar.add_argument("--grow-align", type=str, help="Growth alignment passed to tzar_tool.py")
    patch_tzar.add_argument("--outer-lz4", choices=("auto", "yes", "no"))
    patch_tzar.add_argument("--soc", help="SoC passed to tzar_tool.py")
    patch_tzar.add_argument("--allow-grow", action="store_true")
    patch_tzar.add_argument("--no-sign", action="store_true")
    patch_tzar.set_defaults(func=patch_tzar_command)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
