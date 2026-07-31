#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography"]
# ///
"""End-to-end exercise of the Sequester agent over its Unix socket.

Speaks the SSH agent protocol as a raw client: optionally binds the
connection with session-bind@openssh.com (with a fabricated host key, which
v1 records but does not verify), lists identities, requests a signature
with the named key, and verifies the returned ECDSA P-256 signature against
the key's public point.

Run with: uv run scripts/agent-e2e.py --key-name <name>

A key with the "allow local, ask when forwarded" behavior and no Touch ID
requirement signs without any UI, which makes this scriptable. Keys that
require approval pop the app's dialog; expect to interact or time out.
"""

import argparse
import os
import socket
import struct
import sys

SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
SSH_AGENTC_EXTENSION = 27
SSH_AGENT_SUCCESS = 6


def sshstr(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def read_sshstr(buf: bytes, offset: int) -> tuple[bytes, int]:
    (length,) = struct.unpack_from(">I", buf, offset)
    offset += 4
    return buf[offset : offset + length], offset + length


def roundtrip(sock: socket.socket, payload: bytes) -> bytes:
    sock.sendall(sshstr(payload))
    header = sock.recv(4, socket.MSG_WAITALL)
    (length,) = struct.unpack(">I", header)
    return sock.recv(length, socket.MSG_WAITALL)


def send_session_bind(sock: socket.socket, forwarding: bool) -> None:
    host_key = sshstr(b"ssh-ed25519") + sshstr(b"\x00" * 32)
    payload = (
        bytes([SSH_AGENTC_EXTENSION])
        + sshstr(b"session-bind@openssh.com")
        + sshstr(host_key)
        + sshstr(os.urandom(32))
        + sshstr(b"fabricated")
        + bytes([1 if forwarding else 0])
    )
    response = roundtrip(sock, payload)
    if response != bytes([SSH_AGENT_SUCCESS]):
        sys.exit(f"FAIL session-bind: expected SUCCESS, got {response.hex()}")
    print(f"OK session-bind (forwarding={forwarding})")


def find_identity(sock: socket.socket, key_name: str) -> bytes:
    response = roundtrip(sock, bytes([SSH_AGENTC_REQUEST_IDENTITIES]))
    if response[0] != SSH_AGENT_IDENTITIES_ANSWER:
        sys.exit(f"FAIL list: unexpected response type {response[0]}")
    (count,) = struct.unpack_from(">I", response, 1)
    offset = 5
    for _ in range(count):
        blob, offset = read_sshstr(response, offset)
        comment, offset = read_sshstr(response, offset)
        if comment.decode() == key_name:
            print(f"OK identity listed ({count} total)")
            return blob
    sys.exit(f"FAIL list: no identity named {key_name!r} among {count}")


def verify(blob: bytes, signature_blob: bytes, message: bytes) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    algo, off = read_sshstr(blob, 0)
    curve, off = read_sshstr(blob, off)
    point, off = read_sshstr(blob, off)
    assert algo == b"ecdsa-sha2-nistp256" and curve == b"nistp256", "unexpected key type"
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)

    sig_algo, off = read_sshstr(signature_blob, 0)
    inner, off = read_sshstr(signature_blob, off)
    assert sig_algo == b"ecdsa-sha2-nistp256", "unexpected signature type"
    r_bytes, off2 = read_sshstr(inner, 0)
    s_bytes, _ = read_sshstr(inner, off2)
    der = encode_dss_signature(
        int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")
    )
    public_key.verify(der, message, ec.ECDSA(hashes.SHA256()))
    print("OK signature verified")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="End-to-end exercise of the Sequester agent over its Unix socket."
    )
    parser.add_argument("--key-name", required=True, help="key to sign with (its agent comment)")
    parser.add_argument(
        "--socket",
        default=os.path.expanduser("~/.sequester/agent.sock"),
        help="agent socket path (default: %(default)s)",
    )
    bind = parser.add_mutually_exclusive_group()
    bind.add_argument(
        "--forwarded",
        action="store_true",
        help="bind the session as a forwarded connection",
    )
    bind.add_argument(
        "--no-bind",
        action="store_true",
        help="skip session-bind, leaving the connection unbound",
    )
    args = parser.parse_args()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(args.socket)
    print(f"OK connected to {args.socket}")

    if not args.no_bind:
        send_session_bind(sock, forwarding=args.forwarded)

    blob = find_identity(sock, args.key_name)

    message = os.urandom(64)
    response = roundtrip(
        sock,
        bytes([SSH_AGENTC_SIGN_REQUEST])
        + sshstr(blob)
        + sshstr(message)
        + struct.pack(">I", 0),
    )
    if response[0] != SSH_AGENT_SIGN_RESPONSE:
        sys.exit(f"FAIL sign: agent refused (response type {response[0]})")
    signature_blob, _ = read_sshstr(response, 1)
    verify(blob, signature_blob, message)
    print("PASS e2e")


if __name__ == "__main__":
    main()
