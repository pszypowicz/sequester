#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""End-to-end test of the Sequester secrets socket.

Speaks the raw framed-JSON protocol of the bundled CLI against the live
socket served by the running app. Needs two fixed-content test profiles
created dialog-free beforehand (policy-only tier plus approve-all):

  APP=.build/Sequester.app/Contents/MacOS/Sequester
  "$APP" --selftest-create-profile seq-e2e
  "$APP" --selftest-create-profile-noexport seq-e2e-noexp
  uv run scripts/secrets-e2e.py
  "$APP" --selftest-delete-profile seq-e2e
  "$APP" --selftest-delete-profile seq-e2e-noexp

Covers: list, a silent read, the export refusal on a no-export profile,
the not-found and unsupported-version errors, a malformed frame, and an
oversized length header. Exits non-zero on the first failure.
"""

import argparse
import json
import os
import socket
import struct
import sys

EXPECTED_VALUES = {"SEQ_TEST_A": "alpha", "SEQ_TEST_B": "beta"}

DEFAULT_SOCKET = os.path.expanduser(
    "~/Library/Containers/cz.szypowi.sequester/Data/.sequester/secrets.sock"
)


def connect(path: str) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
    except OSError as error:
        sys.exit(f"FAIL connect {path}: {error} (is Sequester running?)")
    return sock


def frame(payload: dict) -> bytes:
    data = json.dumps(payload).encode()
    return struct.pack(">I", len(data)) + data


def roundtrip(sock: socket.socket, payload: dict) -> dict:
    sock.sendall(frame(payload))
    return read_response(sock)


def read_response(sock: socket.socket) -> dict:
    header = sock.recv(4, socket.MSG_WAITALL)
    if len(header) != 4:
        sys.exit("FAIL: connection closed instead of a response")
    (length,) = struct.unpack(">I", header)
    body = sock.recv(length, socket.MSG_WAITALL)
    return json.loads(body)


def expect_error(reply: dict, code: str, label: str) -> None:
    if reply.get("ok") is not False or reply.get("error") != code:
        sys.exit(f"FAIL {label}: expected error {code}, got {reply}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--socket", default=DEFAULT_SOCKET,
                        help="secrets socket path (default: the app container's secrets.sock)")
    parser.add_argument("--profile", default="seq-e2e",
                        help="name of the exportable test profile (default: seq-e2e)")
    parser.add_argument("--noexport-profile", default="seq-e2e-noexp",
                        help="name of the no-export test profile (default: seq-e2e-noexp)")
    args = parser.parse_args()

    sock = connect(args.socket)
    print(f"OK connected to {args.socket}")

    reply = roundtrip(sock, {"v": 1, "op": "list"})
    if not reply.get("ok"):
        sys.exit(f"FAIL list: {reply}")
    profiles = {p["name"]: p for p in reply.get("profiles", [])}
    for name in (args.profile, args.noexport_profile):
        if name not in profiles:
            sys.exit(f"FAIL list: profile {name} not found; create it with --selftest-create-profile")
    entry = profiles[args.profile]
    if entry["tier"] != "policyOnly" or entry["variables"] != sorted(EXPECTED_VALUES):
        sys.exit(f"FAIL list: unexpected test profile entry {entry}")
    if profiles[args.noexport_profile]["exportDisabled"] is not True:
        sys.exit(f"FAIL list: {args.noexport_profile} should be export-disabled")
    print(f"OK list ({len(profiles)} profiles)")

    reply = roundtrip(sock, {"v": 1, "op": "get", "profile": args.profile, "purpose": "exec"})
    if not reply.get("ok") or reply.get("values") != EXPECTED_VALUES:
        sys.exit(f"FAIL get: {reply}")
    print("OK get (exec, silent via approve-all)")

    reply = roundtrip(sock, {"v": 1, "op": "get", "profile": args.noexport_profile,
                             "purpose": "export"})
    expect_error(reply, "exportDisabled", "export on no-export profile")
    print("OK export refused on no-export profile")

    reply = roundtrip(sock, {"v": 1, "op": "get", "profile": "seq-e2e-does-not-exist",
                             "purpose": "exec"})
    expect_error(reply, "notFound", "get on missing profile")
    print("OK missing profile refused")

    reply = roundtrip(sock, {"v": 99, "op": "list"})
    expect_error(reply, "unsupportedVersion", "future protocol version")
    print("OK unsupported version refused")

    garbage = b"not json at all"
    sock.sendall(struct.pack(">I", len(garbage)) + garbage)
    expect_error(read_response(sock), "invalidRequest", "malformed frame")
    print("OK malformed frame refused")

    # An oversized length header must end the connection, not allocate.
    sock2 = connect(args.socket)
    sock2.sendall(struct.pack(">I", 0x200000))
    if sock2.recv(1) != b"":
        sys.exit("FAIL: oversized frame did not close the connection")
    sock2.close()
    print("OK oversized frame closed the connection")

    sock.close()
    print("PASS secrets e2e")


if __name__ == "__main__":
    main()
