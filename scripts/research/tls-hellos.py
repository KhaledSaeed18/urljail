# Extract TLS ClientHello random, session id and key shares from guest-originated packets in
# urljail run pcaps. Usage: python3 -I hellos.py <runs-dir> > out.tsv
# Untrusted input: lengths are bounds-checked; any malformed packet is skipped.
import os, struct, sys, json
GUEST = bytes([172,16,0,2])  # guest address inside its VM namespace

def packets(path):
    with open(path, 'rb') as f:
        hdr = f.read(24)
        if len(hdr) < 24: return
        magic = hdr[:4]
        if magic == b'\xd4\xc3\xb2\xa1' or magic == b'\x4d\x3c\xb2\xa1': e = '<'
        elif magic == b'\xa1\xb2\xc3\xd4' or magic == b'\xa1\xb2\x3c\x4d': e = '>'
        else: return
        linktype = struct.unpack(e+'I', hdr[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16: return
            _, _, incl, _ = struct.unpack(e+'IIII', ph)
            if incl > 1 << 20: return
            data = f.read(incl)
            if len(data) < incl: return
            yield linktype, data

def ip_payload(linktype, d):
    if linktype == 1:  # ethernet
        if len(d) < 14: return None
        et = struct.unpack('>H', d[12:14])[0]; d = d[14:]
        if et == 0x8100 and len(d) >= 4: et = struct.unpack('>H', d[2:4])[0]; d = d[4:]
        if et != 0x0800: return None
    elif linktype == 113:  # linux cooked
        if len(d) < 16: return None
        d = d[16:]
    elif linktype == 276:  # linux cooked v2
        if len(d) < 20: return None
        d = d[20:]
    elif linktype not in (101, 12, 228):  # raw IPv4
        return None
    if len(d) < 20 or d[0] >> 4 != 4: return None
    ihl = (d[0] & 15) * 4
    if d[9] != 6 or len(d) < ihl + 20: return None
    src = d[12:16]
    tcp = d[ihl:]
    off = (tcp[12] >> 4) * 4
    return src, tcp[off:]

def client_hello(p):
    # one TLS record holding (the start of) a ClientHello
    if len(p) < 9 or p[0] != 0x16 or p[5] != 0x01: return None
    hs = p[5:]
    if len(hs) < 4 + 2 + 32 + 1: return None
    body = hs[4:]
    rnd = body[2:34]
    i = 34
    sl = body[i]; i += 1
    sid = body[i:i+sl]; i += sl
    if i + 2 > len(body): return None
    cl = struct.unpack('>H', body[i:i+2])[0]; i += 2 + cl
    if i >= len(body): return None
    ml = body[i]; i += 1 + ml
    if i + 2 > len(body): return rnd, sid, []
    el = struct.unpack('>H', body[i:i+2])[0]; i += 2
    end = min(len(body), i + el)
    shares = []
    while i + 4 <= end:
        t, l = struct.unpack('>HH', body[i:i+4]); i += 4
        ext = body[i:i+l]; i += l
        if t == 0x0033 and len(ext) >= 2:
            j = 2
            while j + 4 <= len(ext):
                g, kl = struct.unpack('>HH', ext[j:j+4]); j += 4
                key = ext[j:j+kl]; j += kl
                if len(key) == kl and g == 0x001d:  # x25519: complete in the first segment
                    shares.append(key.hex())
    return rnd, sid, shares

root = sys.argv[1]
for run in sorted(os.listdir(root)):
    pc = os.path.join(root, run, 'host', 'capture.pcap')
    if not os.path.isfile(pc): continue
    try:
        meta = json.load(open(os.path.join(root, run, 'meta.json')))
    except Exception:
        meta = {}
    snap = (meta.get('clone') or {}).get('snapshot', '') if isinstance(meta, dict) else ''
    try:
        for lt, d in packets(pc):
            r = ip_payload(lt, d)
            if not r or r[0] != GUEST: continue
            ch = client_hello(r[1])
            if not ch: continue
            rnd, sid, shares = ch
            print(f"{run}\t{snap}\t{rnd.hex()}\t{sid.hex()}\t{','.join(shares)}")
    except Exception as e:
        print(f"# {run}: {e}", file=sys.stderr)
