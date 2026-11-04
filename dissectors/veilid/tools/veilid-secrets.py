#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# SPDX-License-Identifier: MPL-2.0

"""Derive Veilid envelope shared secrets for the Wireshark dissector.

Wireshark's Lua has no X25519 or BLAKE3, so the key agreement half of Veilid's
envelope encryption is done here and the finished secrets are handed to the
dissector through a sidecar file -- the same arrangement as a TLS keylog.

For crypto kind VLD0 (veilid-core crypto_system/vld0/mod.rs):

    shared = BLAKE3(b"VLD0_CRYPT" || X25519(ed25519_to_x25519(our_secret),
                                            ed25519_to_x25519(peer_public)))

The result is symmetric, so one line per peer covers both directions.

Usage
-----
    # Read the secret from a file (or '-' for stdin) so it never appears in
    # `ps` output or shell history:
    sudo cat /path/to/node.key | cut -d: -f3 \\
      | veilid-secrets.py --secret-key-file - \\
                          --from-pcap veilid-packets.pcapng > secrets.txt

    # Specific peers:
    veilid-secrets.py --secret-key-file key.txt \\
                      --peer VLD0:CAAD0fhi... --peer VLD0:7yRv... > secrets.txt

Then set Wireshark's "Shared secrets file" preference (veilid.secrets_file) to
the output path, or pass -o veilid.secrets_file:secrets.txt to tshark.

The output file is itself sensitive: it decrypts every message exchanged with
the listed peers. It does not, however, contain your node's secret key.

Requires: pip install cryptography   (BLAKE3 is implemented here, no extra dep)
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import struct
import subprocess
import sys

VLD0_DOMAIN_CRYPT = b"VLD0_CRYPT"
DEFAULT_CRYPTO_KIND = "VLD0"

# Offsets within an ENV0 envelope (veilid-core crypto/envelope/mod.rs).
ENV0_OFF_CRYPTO_KIND = 0x04
ENV0_OFF_SENDER = 0x2A
ENV0_OFF_RECIPIENT = 0x4A
ENV0_KEY_LEN = 32
ENV0_MIN_SIZE = 0x6A + 0x40

ASSEMBLY_HEADER_LEN = 8
TCP_FRAME_MAGIC = b"VL"


def b64url_decode(s: str) -> bytes:
    s = s.split(":", 1)[-1]  # tolerate a "VLD0:" prefix
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


# --- Ed25519 -> X25519 (RFC 7748 birational map) ----------------------------
P = 2**255 - 19


def _decompress_ed25519_y(pub: bytes) -> int:
    """Return the Edwards y coordinate encoded in an Ed25519 public key."""
    if len(pub) != 32:
        raise ValueError("ed25519 public key must be 32 bytes")
    return int.from_bytes(pub, "little") & ((1 << 255) - 1)


def ed25519_pub_to_x25519(pub: bytes) -> bytes:
    """u = (1 + y) / (1 - y)  mod p."""
    y = _decompress_ed25519_y(pub)
    denom = (1 - y) % P
    if denom == 0:
        raise ValueError("degenerate ed25519 public key")
    u = ((1 + y) * pow(denom, P - 2, P)) % P
    return u.to_bytes(32, "little")


def ed25519_secret_to_x25519(secret: bytes) -> bytes:
    """SHA-512 the seed, clamp the low half -- the standard conversion."""
    import hashlib

    if len(secret) != 32:
        raise ValueError("ed25519 secret key must be a 32-byte seed")
    h = bytearray(hashlib.sha512(secret).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)


def x25519(scalar: bytes, u: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    priv = X25519PrivateKey.from_private_bytes(scalar)
    pub = X25519PublicKey.from_public_bytes(u)
    return priv.exchange(pub)


# --- BLAKE3 -----------------------------------------------------------------
# Implemented here rather than pulled in as a dependency: the only input this
# tool ever hashes is 10 bytes of domain separator plus a 32-byte DH output, so
# the single-chunk path is all that is needed and `pip install blake3` (which
# needs a compiler or a matching wheel, and trips over PEP 668 on system
# Pythons) would be a disproportionate requirement.
#
# Verified against the reference test vectors for input lengths 0, 1, 3, 63 and
# 64 -- the last two covering the block boundary. Inputs above one chunk would
# need parent-node chaining, so they are refused rather than silently wrong.
_B3_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
          0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
_B3_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
_B3_CHUNK_START, _B3_CHUNK_END, _B3_ROOT = 1, 2, 8
_M32 = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _M32


def _b3_g(s, a, b, c, d, mx, my):
    s[a] = (s[a] + s[b] + mx) & _M32; s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _M32;      s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & _M32; s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _M32;      s[b] = _rotr(s[b] ^ s[c], 7)


def _b3_round(s, m):
    _b3_g(s, 0, 4, 8, 12, m[0], m[1]);   _b3_g(s, 1, 5, 9, 13, m[2], m[3])
    _b3_g(s, 2, 6, 10, 14, m[4], m[5]);  _b3_g(s, 3, 7, 11, 15, m[6], m[7])
    _b3_g(s, 0, 5, 10, 15, m[8], m[9]);  _b3_g(s, 1, 6, 11, 12, m[10], m[11])
    _b3_g(s, 2, 7, 8, 13, m[12], m[13]); _b3_g(s, 3, 4, 9, 14, m[14], m[15])


def _b3_compress(cv, block_words, counter, block_len, flags):
    s = cv[:8] + _B3_IV[:4] + [counter & _M32, (counter >> 32) & _M32,
                               block_len, flags]
    m = list(block_words)
    for i in range(7):
        _b3_round(s, m)
        if i < 6:
            m = [m[p] for p in _B3_PERM]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def blake3_256(data: bytes) -> bytes:
    """BLAKE3-256 of a single chunk (at most 1024 bytes)."""
    if len(data) > 1024:
        raise ValueError("blake3_256 here handles a single chunk only")
    blocks = [data[i:i + 64] for i in range(0, len(data), 64)] or [b""]
    cv = _B3_IV[:]
    for i, blk in enumerate(blocks):
        flags = 0
        if i == 0:
            flags |= _B3_CHUNK_START
        if i == len(blocks) - 1:
            flags |= _B3_CHUNK_END | _B3_ROOT
        words = list(struct.unpack("<16I", blk + b"\x00" * (64 - len(blk))))
        cv = _b3_compress(cv, words, 0, len(blk), flags)[:8]
    return struct.pack("<8I", *cv)


def _blake3_selftest() -> None:
    """Refuse to derive anything if the hash is wrong."""
    cases = {
        b"": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        b"abc": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
        bytes(i % 251 for i in range(63)):
            "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
        bytes(i % 251 for i in range(64)):
            "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
    }
    for data, want in cases.items():
        if blake3_256(data).hex() != want:
            raise SystemExit("error: BLAKE3 self-test failed; refusing to derive keys")


def derive_shared_secret(our_ed_secret: bytes, peer_ed_public: bytes) -> bytes:
    dh = x25519(ed25519_secret_to_x25519(our_ed_secret),
                ed25519_pub_to_x25519(peer_ed_public))
    return blake3_256(VLD0_DOMAIN_CRYPT + dh)


def ed25519_public_from_seed(seed: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)


# --- Peer discovery from a capture ------------------------------------------
def _iter_envelopes(payload: bytes):
    """Yield (crypto_kind, sender, recipient) from a UDP or WebSocket payload."""
    if len(payload) >= ASSEMBLY_HEADER_LEN:
        ver, flags, _seq, off, total = struct.unpack(
            ">BBHHH", payload[:ASSEMBLY_HEADER_LEN])
        if ver == 1 and flags == 0:
            body = payload[ASSEMBLY_HEADER_LEN:]
            if off == 0 and len(body) == total:
                yield from _parse_message(body)
                return
    yield from _parse_message(payload)


def _parse_message(msg: bytes):
    if len(msg) < ENV0_MIN_SIZE or msg[:3] != b"ENV":
        return
    kind = msg[ENV0_OFF_CRYPTO_KIND:ENV0_OFF_CRYPTO_KIND + 4].decode("ascii", "replace")
    yield (kind,
           msg[ENV0_OFF_SENDER:ENV0_OFF_SENDER + ENV0_KEY_LEN],
           msg[ENV0_OFF_RECIPIENT:ENV0_OFF_RECIPIENT + ENV0_KEY_LEN])


def _dissector_loaded(tshark: str) -> bool:
    out = subprocess.run([tshark, "-G", "protocols"],
                         capture_output=True, text=True).stdout
    return any(line.split("\t")[2:3] == ["veilid"] for line in out.splitlines())


def peers_via_dissector(path: str, tshark: str, plugin: str | None,
                        our_pub: bytes | None):
    """Collect peers using the Veilid dissector.

    Preferred over parsing packets here: the dissector already handles TCP
    framing and desegmentation, UDP fragment reassembly and WebSocket, so it
    sees peers that a payload-level scan misses entirely.
    """
    load: list[str] = []
    if not _dissector_loaded(tshark):
        if not (plugin and os.path.exists(plugin)):
            return None
        load = ["-X", f"lua_script:{plugin}"]
    # Passing -X when the plugin is already installed is a hard error
    # ("there cannot be two protocols with the same description"), hence the
    # check above rather than always injecting it.

    cmd = [tshark, *load, "-r", path,
           "-o", "tcp.reassemble_out_of_order:TRUE",
           "-Y", "veilid",
           "-T", "fields", "-e", "veilid.sender_str", "-e", "veilid.recipient_str"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return None

    seen: dict[tuple[str, bytes], None] = {}
    for line in proc.stdout.splitlines():
        for field in line.split("\t"):
            for typed in field.split(","):
                typed = typed.strip()
                if not typed or ":" not in typed:
                    continue
                kind, _, b64 = typed.partition(":")
                try:
                    node = b64url_decode(b64)
                except Exception:
                    continue
                if our_pub is not None and node == our_pub:
                    continue
                seen.setdefault((kind, node), None)
    return list(seen)


def peers_from_pcap(path: str, tshark: str, our_pub: bytes | None):
    """Fallback peer scan: parse UDP and WebSocket payloads directly.

    Only sees unfragmented UDP datagrams and WebSocket frames -- it does not
    reassemble TCP, so it will miss any peer reached solely over TCP. Used only
    when the dissector is unavailable.
    """
    cmd = [tshark, "-r", path, "-Y",
           "udp.payload || websocket.payload",
           "-T", "fields", "-e", "udp.payload", "-e", "websocket.payload"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout

    seen: dict[tuple[str, bytes], None] = {}
    for line in out.splitlines():
        for field in line.split("\t"):
            for hexstr in field.split(","):
                hexstr = hexstr.strip().replace(":", "")
                if not hexstr:
                    continue
                try:
                    payload = binascii.unhexlify(hexstr)
                except binascii.Error:
                    continue
                for kind, snd, rcp in _iter_envelopes(payload):
                    for node in (snd, rcp):
                        if our_pub is not None and node == our_pub:
                            continue
                        seen.setdefault((kind, node), None)
    return list(seen)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Derive Veilid envelope shared secrets for Wireshark.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--secret-key-file",
                     help="File containing our node's Ed25519 secret key "
                          "(32-byte seed, base64url); '-' reads stdin. Preferred: "
                          "keeps the key out of `ps` output and shell history.")
    src.add_argument("--secret-key",
                     help="Our node's secret key on the command line. Exposed to "
                          "other users via `ps` and saved in shell history; use "
                          "--secret-key-file instead where possible.")
    ap.add_argument("--public-key",
                    help="Our node's public key (base64url). Used to exclude "
                         "ourselves from --from-pcap discovery; derived "
                         "automatically if omitted.")
    ap.add_argument("--peer", action="append", default=[],
                    help="Peer node ID, with or without a 'VLD0:' prefix. Repeatable.")
    ap.add_argument("--from-pcap",
                    help="Capture file to scan for peers")
    ap.add_argument("--tshark", default="tshark",
                    help="Path to tshark (default: tshark)")
    ap.add_argument("--plugin",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         os.pardir, "veilid.lua"),
                    help="Path to veilid.lua, used for peer discovery when the "
                         "dissector is not already installed (default: the "
                         "sibling checkout)")
    ap.add_argument("--crypto-kind", default=DEFAULT_CRYPTO_KIND,
                    help=f"Crypto kind to emit (default: {DEFAULT_CRYPTO_KIND})")
    args = ap.parse_args()

    if args.crypto_kind != DEFAULT_CRYPTO_KIND:
        print(f"error: only {DEFAULT_CRYPTO_KIND} key agreement is implemented; "
              f"got {args.crypto_kind!r}. Add its DH/hash construction here "
              f"before using it.", file=sys.stderr)
        return 2

    _blake3_selftest()

    if args.secret_key_file:
        if args.secret_key_file == "-":
            raw = sys.stdin.read()
        else:
            with open(args.secret_key_file) as fh:
                raw = fh.read()
        # Tolerate a whole "VLD0:<public>:<secret>" keypair line as well as a
        # bare secret, so `cut`-ing the field out is optional.
        raw = raw.strip().splitlines()[0].strip() if raw.strip() else ""
        parts = raw.split(":")
        secret_text = parts[-1] if parts else ""
    else:
        secret_text = args.secret_key

    try:
        secret = b64url_decode(secret_text)
    except Exception as exc:
        print(f"error: could not decode the secret key: {exc}", file=sys.stderr)
        return 2
    if len(secret) != 32:
        print(f"error: secret key decoded to {len(secret)} bytes, expected 32",
              file=sys.stderr)
        return 2

    # Derive our own public key so we can exclude ourselves from discovery and
    # let the caller confirm this is the node they meant -- without ever
    # printing the secret.
    try:
        derived_pub = ed25519_public_from_seed(secret)
    except Exception as exc:
        print(f"error: could not derive the public key: {exc}", file=sys.stderr)
        return 2
    print(f"# derived node ID: {DEFAULT_CRYPTO_KIND}:{b64url_encode(derived_pub)}",
          file=sys.stderr)

    our_pub = b64url_decode(args.public_key) if args.public_key else derived_pub
    if args.public_key and our_pub != derived_pub:
        print("error: --public-key does not match the key derived from "
              "--secret-key; wrong keypair?", file=sys.stderr)
        return 2

    targets: list[tuple[str, bytes]] = [
        (args.crypto_kind, b64url_decode(p)) for p in args.peer
    ]
    if args.from_pcap:
        found = peers_via_dissector(args.from_pcap, args.tshark, args.plugin, our_pub)
        if found is None:
            print("# note: Veilid dissector unavailable; falling back to a "
                  "UDP/WebSocket-only scan, which misses TCP-only peers",
                  file=sys.stderr)
            found = peers_from_pcap(args.from_pcap, args.tshark, our_pub)
        targets += found

    # De-duplicate while preserving order.
    unique: dict[tuple[str, bytes], None] = {}
    for t in targets:
        unique.setdefault(t, None)

    if not unique:
        print("error: no peers given; use --peer and/or --from-pcap",
              file=sys.stderr)
        return 2

    print("# veilid shared secrets v1")
    print("# <crypto_kind> <peer_node_id_base64url> <shared_secret_hex>")
    emitted = skipped = 0
    # Iterate the keys: each is a (crypto_kind, public_key) tuple. Using
    # .items() here would bind peer_pub to the dict value (None).
    for kind, peer_pub in unique:
        if kind != DEFAULT_CRYPTO_KIND:
            print(f"# skipped {b64url_encode(peer_pub)}: unsupported crypto kind {kind}")
            skipped += 1
            continue
        if len(peer_pub) != 32:
            print(f"# skipped: peer key is {len(peer_pub)} bytes, expected 32")
            skipped += 1
            continue
        try:
            shared = derive_shared_secret(secret, peer_pub)
        except Exception as exc:
            print(f"# skipped {b64url_encode(peer_pub)}: {exc}")
            skipped += 1
            continue
        print(f"{kind} {b64url_encode(peer_pub)} {shared.hex()}")
        emitted += 1

    print(f"# {emitted} secret(s) derived, {skipped} skipped", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
