#!/usr/bin/env python3
"""
RustDesk public-server transport probe (standard library only).

Speaks the RustDesk rendezvous/relay wire protocol directly, as a third-party
client would, to test whether RustDesk's free public community servers can be
used as generic NAT-traversal infrastructure by a non-RustDesk application.

Protocol references (all in rustdesk/rustdesk-server @ AGPL-3.0):
  libs/hbb_common/protos/rendezvous.proto   message + field numbers
  libs/hbb_common/src/bytes_codec.rs         frame header encoding
  libs/hbb_common/src/tcp.rs                  FramedStream
  src/rendezvous_server.rs                    hbbs behaviour
  src/relay_server.rs                         hbbr behaviour

Frame header (bytes_codec.rs):
  len <= 0x3F        -> 1 byte,  (len << 2) | 0
  len <= 0x3FFF      -> 2 bytes, (len << 2) | 1        little endian
  len <= 0x3FFFFF    -> 3 bytes, (len << 2) | 2        little endian
  len <= 0x3FFFFFFF  -> 4 bytes, (len << 2) | 3        little endian

Usage:
  python3 probe.py                 # run all stages against rs-ny.rustdesk.com
  python3 probe.py --server host   # target a different rendezvous server
"""

from __future__ import annotations

import argparse
import os
import random
import socket
import string
import sys
import time

# rustdesk/hbb_common/src/config.rs:117
RS_PUB_KEY = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw="
DEFAULT_RENDEZVOUS = "rs-ny.rustdesk.com"
RENDEZVOUS_PORT = 21116
RELAY_PORT = 21117

# RendezvousMessage oneof field numbers (rendezvous.proto)
F_REGISTER_PEER = 6
F_REGISTER_PK = 15
F_PUNCH_HOLE_REQUEST = 8
F_PUNCH_HOLE_RESPONSE = 11
F_REQUEST_RELAY = 18
F_RELAY_RESPONSE = 19
F_REGISTER_PK_RESPONSE = 16
F_CONFIG_UPDATE = 14
F_FETCH_LOCAL_ADDR = 12

# RegisterPkResponse.Result
REGISTER_PK_RESULT = {0: "OK", 2: "UUID_MISMATCH", 3: "ID_EXISTS", 4: "TOO_FREQUENT",
                      5: "INVALID_ID_FORMAT", 6: "NOT_SUPPORT", 7: "SERVER_ERROR", 8: "NOT_DEPLOYED"}
# PunchHoleResponse.Failure
PUNCH_FAILURE = {0: "ID_NOT_EXIST", 2: "OFFLINE", 3: "LICENSE_MISMATCH", 4: "LICENSE_OVERUSE"}


# --------------------------------------------------------------------------- protobuf


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def tag(field: int, wire: int) -> bytes:
    return varint((field << 3) | wire)


def f_str(field: int, s: str) -> bytes:
    b = s.encode()
    return tag(field, 2) + varint(len(b)) + b


def f_bytes(field: int, b: bytes) -> bytes:
    return tag(field, 2) + varint(len(b)) + b


def f_varint(field: int, n: int) -> bytes:
    return tag(field, 0) + varint(n)


def read_varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = 0
    val = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def parse(buf: bytes) -> dict[int, list]:
    """Decode a protobuf message into {field_number: [values]}. Wire-type agnostic."""
    fields: dict[int, list] = {}
    i = 0
    while i < len(buf):
        key, i = read_varint(buf, i)
        field, wire = key >> 3, key & 0x7
        if wire == 0:
            v, i = read_varint(buf, i)
        elif wire == 2:
            ln, i = read_varint(buf, i)
            v = buf[i:i + ln]
            i += ln
        elif wire == 5:
            v = buf[i:i + 4]
            i += 4
        elif wire == 1:
            v = buf[i:i + 8]
            i += 8
        else:
            raise ValueError(f"unsupported wire type {wire}")
        fields.setdefault(field, []).append(v)
    return fields


def enc_frame(payload: bytes) -> bytes:
    """Length-prefix a protobuf payload using RustDesk's BytesCodec header."""
    n = len(payload)
    if n <= 0x3F:
        return bytes([(n << 2) | 0]) + payload
    if n <= 0x3FFF:
        h = (n << 2) | 1
        return h.to_bytes(2, "little") + payload
    if n <= 0x3FFFFF:
        h = (n << 2) | 2
        return h.to_bytes(3, "little") + payload
    h = (n << 2) | 3
    return h.to_bytes(4, "little") + payload


class FrameReader:
    """Incremental decoder for the BytesCodec framing."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()

    def _fill(self, n: int) -> bool:
        while len(self.buf) < n:
            try:
                chunk = self.sock.recv(65536)
            except (socket.timeout, TimeoutError):
                return False
            if not chunk:
                return False
            self.buf.extend(chunk)
        return True

    def read_frame(self, timeout: float = 5.0) -> bytes | None:
        self.sock.settimeout(timeout)
        while True:
            if len(self.buf) >= 1:
                head_len = (self.buf[0] & 0x3) + 1
                if len(self.buf) >= head_len:
                    break
            if not self._fill(len(self.buf) + 1):
                return None
        head_len = (self.buf[0] & 0x3) + 1
        head = int.from_bytes(self.buf[:head_len], "little")
        n = head >> 2
        if not self._fill(head_len + n):
            return None
        payload = bytes(self.buf[head_len:head_len + n])
        del self.buf[:head_len + n]
        return payload


def connect(host: str, port: int, timeout: float = 8.0) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def rand_id(n: int = 9) -> str:
    return "".join(random.choice(string.digits) for _ in range(n))


def rand_token(n: int = 12) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


# --------------------------------------------------------------------------- stages


class Result:
    def __init__(self):
        self.lines: list[str] = []
        self.ok = True

    def log(self, msg: str, ok: bool | None = None):
        mark = "   "
        if ok is True:
            mark = " OK"
        elif ok is False:
            mark = "FAIL"
        self.lines.append(f"[{mark}] {msg}")
        if ok is False:
            self.ok = False

    def dump(self):
        print("\n".join(self.lines))


def stage_register(server: str, port: int, r: Result) -> tuple[str, socket.socket, socket.socket]:
    """Stage 1: register a peer (the 'controlled' side) with the rendezvous server."""
    peer_id = rand_id(9)
    uuid = os.urandom(16)
    pk = os.urandom(32)

    sock = connect(server, port)
    reader = FrameReader(sock)

    reg_peer = f_str(1, peer_id) + f_varint(2, 0)
    sock.sendall(enc_frame(tag(F_REGISTER_PEER, 2) + varint(len(reg_peer)) + reg_peer))

    reg_pk = f_str(1, peer_id) + f_bytes(2, uuid) + f_bytes(3, pk)
    sock.sendall(enc_frame(tag(F_REGISTER_PK, 2) + varint(len(reg_pk)) + reg_pk))

    frame = reader.read_frame(timeout=6.0)
    if frame is None:
        r.log(f"register: no response from {server}:{port}", False)
        return peer_id, sock, sock

    fields = parse(frame)
    if F_REGISTER_PK_RESPONSE in fields:
        resp = parse(fields[F_REGISTER_PK_RESPONSE][0])
        result = resp.get(1, [0])[0]
        name = REGISTER_PK_RESULT.get(result, f"UNKNOWN({result})")
        r.log(f"RegisterPkResponse -> {name}", result == 0)
    elif F_CONFIG_UPDATE in fields:
        r.log("server replied ConfigUpdate (accepted registration)", True)
    else:
        r.log(f"unexpected reply fields {sorted(fields)}", False)
    return peer_id, sock, sock


def stage_punch(server: str, port: int, peer_id: str, licence_key: str, r: Result,
                label: str) -> tuple[str | None, bytes | None]:
    """Stage 2: ask the rendezvous server for the peer's address / relay server."""
    sock = connect(server, port)
    reader = FrameReader(sock)

    req = (f_str(1, peer_id)                       # id
           + f_varint(2, 1)                        # nat_type = ASYMMETRIC
           + f_str(3, licence_key)                 # licence_key
           + f_varint(4, 0)                        # conn_type = DEFAULT_CONN
           + f_str(6, "1.0.0"))                    # version
    sock.sendall(enc_frame(tag(F_PUNCH_HOLE_REQUEST, 2) + varint(len(req)) + req))

    frame = reader.read_frame(timeout=8.0)
    sock.close()
    if frame is None:
        r.log(f"{label}: no PunchHoleResponse", False)
        return None, None

    fields = parse(frame)
    if F_PUNCH_HOLE_RESPONSE not in fields:
        # hbbs answers with FetchLocalAddr when it believes both peers sit on the
        # same LAN (src/rendezvous_server.rs:823). It carries the same relay_server.
        if F_FETCH_LOCAL_ADDR in fields:
            local = parse(fields[F_FETCH_LOCAL_ADDR][0])
            relay = local.get(2, [None])[0]
            relay = relay.decode() if isinstance(relay, bytes) else relay
            r.log(f"{label}: accepted (FetchLocalAddr). relay_server={relay!r}", True)
            return relay, None
        r.log(f"{label}: unexpected reply fields {sorted(fields)}", False)
        return None, None

    resp = parse(fields[F_PUNCH_HOLE_RESPONSE][0])
    failure = resp.get(3, [0])[0]
    if failure:
        r.log(f"{label}: PunchHoleResponse.failure = {PUNCH_FAILURE.get(failure, failure)}", False)
        return None, None

    relay = resp.get(4, [None])[0]
    relay = relay.decode() if isinstance(relay, bytes) else relay
    pk = resp.get(2, [b""])[0]
    r.log(f"{label}: accepted. relay_server={relay!r} pk_len={len(pk)}", True)
    return relay, pk


def stage_relay_echo(relay: str, r: Result) -> bool:
    """Stage 3/4: pair two of our own clients through the public relay and exchange bytes."""
    host, _, port_s = relay.partition(":")
    port = int(port_s) if port_s else RELAY_PORT

    token = "t3code-poc-" + rand_token(10)
    peer_id = rand_id(9)

    def relay_client(name: str) -> tuple[socket.socket, FrameReader]:
        s = connect(host, port, timeout=10.0)
        fr = FrameReader(s)
        req = (f_str(1, peer_id)
               + f_str(2, token)
               + f_str(6, RS_PUB_KEY))
        s.sendall(enc_frame(tag(F_REQUEST_RELAY, 2) + varint(len(req)) + req))
        return s, fr

    try:
        a_sock, _ = relay_client("A")
        time.sleep(0.6)
        b_sock, _ = relay_client("B")
    except OSError as exc:
        r.log(f"relay connect failed: {exc}", False)
        return False

    time.sleep(1.0)

    payload_a = b"T3CODE-POC-PING"
    payload_b = b"T3CODE-POC-PONG"
    try:
        a_sock.sendall(payload_a)
        b_sock.sendall(payload_b)
        a_sock.settimeout(8.0)
        b_sock.settimeout(8.0)
        got_b = a_sock.recv(4096)
        got_a = b_sock.recv(4096)
    except OSError as exc:
        r.log(f"relay exchange failed: {exc}", False)
        return False
    finally:
        try:
            a_sock.close()
            b_sock.close()
        except OSError:
            pass

    ok = got_b == payload_a and got_a == payload_b
    r.log(f"relay byte exchange: A received {got_b!r}, B received {got_a!r}", ok)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default=DEFAULT_RENDEZVOUS)
    ap.add_argument("--port", type=int, default=RENDEZVOUS_PORT)
    ap.add_argument("--skip-relay", action="store_true",
                    help="stop after the rendezvous stages (do not touch a relay)")
    args = ap.parse_args()

    r = Result()
    print(f"# RustDesk public-server transport probe")
    print(f"# rendezvous: {args.server}:{args.port}")
    print(f"# published RS_PUB_KEY: {RS_PUB_KEY}\n")

    # --- negative control: a wrong key must be rejected. -----------------------
    peer_id, sock, _ = stage_register(args.server, args.port, r)
    relay, pk = stage_punch(args.server, args.port, peer_id, RS_PUB_KEY, r,
                            "punch-hole (correct RS_PUB_KEY)")
    stage_punch(args.server, args.port, peer_id, "not-the-real-key", r,
                "punch-hole (wrong key, negative control)")
    sock.close()

    if relay and not args.skip_relay:
        stage_relay_echo(relay, r)
    elif relay:
        r.log(f"relay stage skipped; relay would be {relay}")

    print()
    r.dump()
    print()
    print("RESULT:", "PASS" if r.ok else "PARTIAL/FAIL")
    return 0 if r.ok else 1


if __name__ == "__main__":
    sys.exit(main())
