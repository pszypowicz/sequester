#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography"]
# ///
"""Concurrency and throughput benchmark for the Sequester SSH agent.

Drives the agent socket directly with the SSH agent protocol: for each
request it opens a connection, binds it with a valid session-bind record,
and asks for one signature. A temporary auto-approve key is created so
signing happens with no dialog in the path, isolating the agent's raw
signing throughput and its behavior under concurrent load.

Reports, per concurrency level, the achieved throughput (signatures per
second) and the latency distribution, plus any errors. Rising concurrency
with flat latency and rising throughput means the agent parallelizes;
climbing latency or errors would flag serialization or deadlock.

Run with: uv run scripts/agent-bench.py
"""
import argparse
import os
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REQ_IDENTITIES, IDENTITIES_ANSWER = 11, 12
SIGN_REQUEST, SIGN_RESPONSE = 13, 14
EXTENSION, SUCCESS = 27, 6

DEFAULT_SOCKET = os.path.expanduser(
    "~/Library/Containers/cz.szypowi.sequester/Data/.sequester/agent.sock"
)
DEFAULT_BINARY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".build/Sequester.app/Contents/MacOS/Sequester",
)


def sshstr(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def read_str(buf: bytes, off: int):
    (n,) = struct.unpack_from(">I", buf, off)
    off += 4
    return buf[off:off + n], off + n


def roundtrip(sock: socket.socket, payload: bytes) -> bytes:
    sock.sendall(sshstr(payload))
    hdr = sock.recv(4, socket.MSG_WAITALL)
    (n,) = struct.unpack(">I", hdr)
    return sock.recv(n, socket.MSG_WAITALL)


def key_blob(sock: socket.socket, key_name: str) -> bytes:
    resp = roundtrip(sock, bytes([REQ_IDENTITIES]))
    (count,) = struct.unpack_from(">I", resp, 1)
    off = 5
    for _ in range(count):
        blob, off = read_str(resp, off)
        comment, off = read_str(resp, off)
        if comment.decode() == key_name:
            return blob
    sys.exit(f"key {key_name!r} not offered by the agent")


def one_request(args) -> float:
    """One connect + bind + sign cycle; returns latency in milliseconds."""
    socket_path, blob = args
    start = time.perf_counter()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(socket_path)
    try:
        host = Ed25519PrivateKey.generate()
        pub = host.public_key().public_bytes_raw()
        session_id = os.urandom(32)
        hostkey = sshstr(b"ssh-ed25519") + sshstr(pub)
        sig = sshstr(b"ssh-ed25519") + sshstr(host.sign(session_id))
        bind = (bytes([EXTENSION]) + sshstr(b"session-bind@openssh.com")
                + sshstr(hostkey) + sshstr(session_id) + sshstr(sig) + bytes([0]))
        if roundtrip(sock, bind) != bytes([SUCCESS]):
            raise RuntimeError("session-bind rejected")
        message = sshstr(session_id) + os.urandom(32)
        resp = roundtrip(sock, bytes([SIGN_REQUEST]) + sshstr(blob) + sshstr(message) + struct.pack(">I", 0))
        if not resp or resp[0] != SIGN_RESPONSE:
            raise RuntimeError(f"sign refused (type {resp[0] if resp else 'none'})")
    finally:
        sock.close()
    return (time.perf_counter() - start) * 1000.0


def percentile(sorted_vals, p):
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, int(round((p / 100.0) * (len(sorted_vals) - 1))))
    return sorted_vals[idx]


def run_level(socket_path, blob, concurrency, total):
    payload = (socket_path, blob)
    latencies = []
    errors = 0
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(one_request, payload) for _ in range(total)]
        for f in futures:
            try:
                latencies.append(f.result())
            except Exception:
                errors += 1
    elapsed = time.perf_counter() - start
    latencies.sort()
    ok = len(latencies)
    tput = ok / elapsed if elapsed else 0.0
    return {
        "concurrency": concurrency, "requests": total, "ok": ok, "errors": errors,
        "elapsed_s": elapsed, "throughput": tput,
        "min": latencies[0] if latencies else 0.0,
        "mean": sum(latencies) / ok if ok else 0.0,
        "p50": percentile(latencies, 50), "p95": percentile(latencies, 95),
        "max": latencies[-1] if latencies else 0.0,
    }


def main():
    ap = argparse.ArgumentParser(description="Benchmark the Sequester agent under concurrent load.")
    ap.add_argument("--socket", default=DEFAULT_SOCKET, help="agent socket path")
    ap.add_argument("--binary", default=DEFAULT_BINARY, help="Sequester binary for creating the bench key")
    ap.add_argument("--key-name", default="bench-tmp", help="temporary auto-approve key name")
    ap.add_argument("--concurrency", type=int, nargs="+", default=[1, 2, 4, 8, 16, 32, 64],
                    help="concurrency levels to test")
    ap.add_argument("--requests", type=int, default=300, help="requests per concurrency level")
    ap.add_argument("--keep-key", action="store_true", help="do not delete the bench key afterwards")
    args = ap.parse_args()

    subprocess.run([args.binary, "--selftest-create-key", args.key_name],
                   check=True, capture_output=True)
    try:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.connect(args.socket)
        blob = key_blob(probe, args.key_name)
        probe.close()

        # Warm up (first Enclave use pays one-time setup) and correctness check.
        one_request((args.socket, blob))

        print(f"{'conc':>5} {'reqs':>6} {'ok':>5} {'err':>4} {'tput/s':>9} "
              f"{'min':>7} {'mean':>7} {'p50':>7} {'p95':>7} {'max':>7}")
        for c in args.concurrency:
            r = run_level(args.socket, blob, c, args.requests)
            print(f"{r['concurrency']:>5} {r['requests']:>6} {r['ok']:>5} {r['errors']:>4} "
                  f"{r['throughput']:>9.1f} {r['min']:>7.1f} {r['mean']:>7.1f} "
                  f"{r['p50']:>7.1f} {r['p95']:>7.1f} {r['max']:>7.1f}  (ms)")
    finally:
        if not args.keep_key:
            subprocess.run([args.binary, "--selftest-delete-key", args.key_name],
                           capture_output=True)


if __name__ == "__main__":
    main()
