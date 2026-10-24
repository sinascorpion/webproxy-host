#!/usr/bin/env python3
# Copyright (c) 2026 sinascorpion. SPDX-License-Identifier: GPL-3.0-or-later
"""sinascorpion deployment probe: HTTPS/WSS WEB carriers and a Telegram req_pq_multi, without login.

Requires cryptography only for --telegram. Secret from MTP_SECRET or --state.
Never prints the proxy secret, capability, bootstrap, or bearer.
"""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import struct
import time
import urllib.parse


def frame(kind, stream=0, body=b''):
    return bytes([kind]) + stream.to_bytes(3, 'big') + len(body).to_bytes(4, 'big') + body


def frames(data):
    result = []
    while data:
        if len(data) < 8:
            raise AssertionError('Truncated WEB frame')
        kind, stream, size = data[0], int.from_bytes(data[1:4], 'big'), int.from_bytes(data[4:8], 'big')
        if len(data) < size + 8:
            raise AssertionError('Truncated WEB payload')
        result.append((kind, stream, data[8:8 + size]))
        data = data[8 + size:]
    return result


class Probe:
    def __init__(self, host, secret, connect_ip=None, connect_port=443):
        self.host, self.secret, self.connect_ip = host, secret, connect_ip
        self.connect_port = connect_port
        self.context = ssl.create_default_context()
        self.context.set_alpn_protocols(['http/1.1'])

    def connection(self):
        c = http.client.HTTPSConnection(self.host, timeout=40, context=self.context)
        if self.connect_ip or self.connect_port != 443:
            def connect():
                c.sock = self.context.wrap_socket(socket.create_connection((self.connect_ip or self.host, self.connect_port), timeout=40), server_hostname=self.host)
            c.connect = connect
        return c

    def request(self, method, path, body=None, headers=None):
        c = self.connection()
        c.request(method, path, body, headers or {})
        r = c.getresponse()
        result = (r.status, {k.lower(): v for k, v in r.getheaders()}, r.read())
        c.close()
        return result

    def session(self, carrier):
        key = b'\xdd' + bytes.fromhex(self.secret)
        cap = base64.urlsafe_b64encode(hmac.new(key, b'tdesktop-web-proxy-bridge-v1\n' + self.host.encode(), hashlib.sha256).digest()).decode().rstrip('=')
        status, headers, body = self.request('GET', '/?bridge=' + cap)
        assert status == 200 and b'bootstrap="' in body, 'Authenticated bridge did not load'
        token = re.search(rb'bootstrap="([^"]+)"', body).group(1).decode()
        status, headers, body = self.request('POST', '/api/v1/session', frame(0x10, body=b'\x01'), {
            'Authorization': 'Bearer ' + token, 'Content-Type': 'application/octet-stream',
            'X-Carrier-Capabilities': carrier, 'X-Carrier-Attempt': '1',
        })
        assert status == 200, f'Session returned HTTP {status}'
        assert headers.get('x-carrier-mode') == carrier, 'Carrier negotiation mismatch'
        assert frames(body)[0][0] == 0x11, 'Missing WELCOME'
        return headers['x-session-token']

    def websocket(self, token, lanes=False):
        c = self.connection()
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        protocol = ('tproxy-auto-lane-v1.' + token + '.1') if lanes else ('tproxy-auto-v1.' + token)
        c.request('GET', '/api/v1/ws', headers={'Connection': 'Upgrade', 'Upgrade': 'websocket',
                  'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': key, 'Sec-WebSocket-Protocol': protocol})
        r = c.getresponse()
        assert r.status == 101, f'WebSocket Upgrade returned {r.status}'
        expected = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        assert r.getheader('Sec-WebSocket-Accept') == expected
        assert r.getheader('Sec-WebSocket-Protocol') == protocol
        return c, r.fp


def ws_send(sock, payload, opcode=2):
    mask = secrets.token_bytes(4)
    size = len(payload)
    header = bytes([0x80 | opcode, 0x80 | size]) if size < 126 else bytes([0x80 | opcode, 0xfe]) + struct.pack('!H', size)
    sock.sendall(header + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(payload)))


def read_exact(fp, size):
    output = b''
    while len(output) < size:
        part = fp.read(size - len(output))
        if not part:
            raise EOFError('WebSocket closed')
        output += part
    return output


def ws_recv(sock, fp):
    while True:
        a, b = read_exact(fp, 2)
        size = b & 127
        if size == 126:
            size = struct.unpack('!H', read_exact(fp, 2))[0]
        elif size == 127:
            size = struct.unpack('!Q', read_exact(fp, 8))[0]
        payload = read_exact(fp, size)
        if a & 15 == 9:
            ws_send(sock, payload, opcode=10)
        elif a & 15 == 2:
            return payload
        elif a & 15 == 8:
            raise EOFError('WebSocket close frame')


def telegram_handshake(secret):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    header = bytearray(secrets.token_bytes(64))
    header[0] = 0x42
    reversed_header = bytes(header)[::-1]
    key = hashlib.sha256(bytes(header[8:40]) + bytes.fromhex(secret)).digest()
    decrypt_key = hashlib.sha256(reversed_header[8:40] + bytes.fromhex(secret)).digest()
    enc = Cipher(algorithms.AES(key), modes.CTR(bytes(header[40:56]))).encryptor()
    dec = Cipher(algorithms.AES(decrypt_key), modes.CTR(reversed_header[40:56])).decryptor()
    header[56:60] = b'\xdd' * 4
    header[60:62] = struct.pack('<h', 2)
    encrypted_header = enc.update(bytes(header))
    header[56:64] = encrypted_header[56:64]
    nonce = secrets.token_bytes(16)
    query = struct.pack('<I', 0xbe7e8ef1) + nonce
    packet = b'\0' * 8 + struct.pack('<Q', int(time.time() * 2**32) & ~3) + struct.pack('<I', len(query)) + query
    padding = secrets.token_bytes(7)
    payload = bytes(header) + enc.update(struct.pack('<I', len(packet + padding)) + packet + padding)
    return payload, dec, nonce


def check_telegram(data, decryptor, nonce):
    decoded = decryptor.update(data)
    # Intermediate packet starts with length then unencrypted MTProto header.
    assert len(decoded) >= 44, 'Telegram response too short'
    assert decoded[4:12] == b'\0' * 8, 'Unexpected Telegram auth key'
    assert struct.unpack('<I', decoded[24:28])[0] == 0x05162463, 'Expected resPQ'
    assert decoded[28:44] == nonce, 'Telegram nonce mismatch'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host')
    p.add_argument('--state', type=Path)
    p.add_argument('--profile', type=int, default=1, help='One-based profile number when reading state')
    p.add_argument('--connect-ip', help='Override DNS, retaining certificate hostname verification')
    p.add_argument('--connect-port', type=int, default=443, help='Override origin socket port for testing; Telegram WEB client links remain on public 443')
    p.add_argument('--telegram', action='store_true')
    args = p.parse_args()
    state = json.loads(args.state.read_text()) if args.state else {}
    if state:
        items = state.get('profiles') or [state]
        if not 1 <= args.profile <= len(items):
            p.error('Invalid profile number')
        state = items[args.profile - 1]
    host = args.host or state.get('domain')
    secret = os.environ.get('MTP_SECRET') or state.get('secret')
    if not host or not secret:
        p.error('Provide --state, or --host plus MTP_SECRET environment variable')
    probe = Probe(host, secret, args.connect_ip, args.connect_port)
    status, _, body = probe.request('GET', '/')
    assert status == 200 and b'<html' in body, 'Decoy failed'
    status, _, body = probe.request('GET', '/?bridge=' + 'A' * 43)
    assert b'bootstrap="' not in body, 'Wrong secret exposed authenticated bridge'
    print('PASS: public TLS certificate, decoy and wrong-secret rejection')
    for carrier in ('https', 'https-lanes', 'websocket', 'websocket-lanes'):
        token = probe.session(carrier)
        auth = {'Authorization': 'Bearer ' + token}
        if carrier.startswith('https'):
            lane = {'X-Lane-ID': '1'} if carrier.endswith('-lanes') else {}
            payload = frame(0x06)
            dec = nonce = None
            if args.telegram:
                handshake, dec, nonce = telegram_handshake(secret)
                payload = frame(1, 1) + frame(2, 1, handshake)
            # A lane is opened with stream OPEN, not the stream-zero keepalive.
            if lane and not args.telegram:
                payload = frame(1, 1)
            status, _, _ = probe.request('POST', '/api/v1/up', payload, {**auth, **lane, 'Content-Type': 'application/octet-stream', 'X-Up-Seq': '1'})
            assert status == 204, 'HTTPS uplink failed'
            if args.telegram:
                received = b''
                cursor = '0'
                for _ in range(5):
                    status, headers, body = probe.request('POST', '/api/v1/down', b'', {**auth, **lane, 'X-Down-Cursor': cursor})
                    cursor = headers.get('x-down-cursor', cursor)
                    for kind, stream, data in frames(body):
                        if kind == 2 and stream == 1:
                            received += data
                    if len(received) >= 44:
                        break
                check_telegram(received, dec, nonce)
        else:
            c, fp = probe.websocket(token, lanes=carrier.endswith('-lanes'))
            if args.telegram:
                handshake, dec, nonce = telegram_handshake(secret)
                ws_send(c.sock, frame(1, 1) + frame(2, 1, handshake))
                received = b''
                for _ in range(8):
                    for kind, stream, data in frames(ws_recv(c.sock, fp)):
                        if kind == 2 and stream == 1:
                            received += data
                    if len(received) >= 44:
                        break
                check_telegram(received, dec, nonce)
            ws_send(c.sock, b'', opcode=8)
            c.close()
        status, _, _ = probe.request('DELETE', '/api/v1/session', b'', auth)
        assert status == 204, 'Session close failed'
        print(f'PASS: {carrier} bridge, authenticated session, carrier' + (', real Telegram resPQ nonce verified' if args.telegram else ''))


if __name__ == '__main__':
    main()
