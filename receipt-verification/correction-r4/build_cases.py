# r4 correction note: case builder (imports nothing from any verifier). Writes case folders (receipt.json + registry.json) under argv[1].
#   ok        an ordinary RFC 8032 signature (R = r*B)
#   nc        R = the identity point written NON-canonically (y = p + 1); S = H(R||A||M)*a mod L
#   c         R = the identity point written canonically (y = 1), a point of small order; S = H(R||A||M)*a mod L
#   win_ok    ordinary valid signature; the key's window starts 2027-01-01, after the signed occurred_at
#   win_bad   as win_ok, one bit of S flipped (a signature over nothing)
#   idkey1/2  registry key = the identity point (small order); signature R = identity, S = 0; two different payloads
import base64, hashlib, json, os, sys
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)
def xrecover(y):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P: x = (x * I) % P
    if x % 2: x = P - x
    return x
By = 4 * pow(5, P - 2, P) % P
B = (xrecover(By), By)
def add(p1, p2):
    x1, y1 = p1; x2, y2 = p2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + D * x1 * x2 * y1 * y2, P - 2, P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - D * x1 * x2 * y1 * y2, P - 2, P)
    return (x3 % P, y3 % P)
def mul(pt, e):
    r = (0, 1)
    while e:
        if e & 1: r = add(r, pt)
        pt = add(pt, pt); e >>= 1
    return r
def enc(pt):
    x, y = pt
    return (y | ((x & 1) << 255)).to_bytes(32, "little")
a = int.from_bytes(hashlib.sha512(b"r4 correction note scalar").digest(), "little") % L
pub = enc(mul(B, a))
ident = (1).to_bytes(32, "little")
def payload(n): return json.dumps({"occurred_at": "2026-11-13T00:00:00Z", "sequence": n})
def h(R, A, M): return int.from_bytes(hashlib.sha512(R + A + M).digest(), "little")
def sign(M):
    r = int.from_bytes(hashlib.sha512(b"r4 correction note nonce" + M).digest(), "little") % L
    R = enc(mul(B, r)); return R + ((r + h(R, pub, M) * a) % L).to_bytes(32, "little")
M1 = payload(1).encode()
R_nc = (1 + P).to_bytes(32, "little")
flip = lambda s: s[:40] + bytes([s[40] ^ 1]) + s[41:]
b = lambda x: base64.b64encode(x).decode()
def reg(key, valid_from="2026-01-01T00:00:00Z"):
    return {"entries": [{"status": "active", "public_key": b(key), "key_id": "probe_k", "algorithm": "ed25519",
             "public_key_fingerprint": hashlib.sha256(key).hexdigest(), "valid_from": valid_from, "valid_to": None,
             "status_changed_at": "2026-01-01T00:00:00Z"}]}
cases = {
  "ok": (sign(M1), payload(1), reg(pub)),
  "nc": (R_nc + ((h(R_nc, pub, M1) * a) % L).to_bytes(32, "little"), payload(1), reg(pub)),
  "c": (ident + ((h(ident, pub, M1) * a) % L).to_bytes(32, "little"), payload(1), reg(pub)),
  "win_ok": (sign(M1), payload(1), reg(pub, "2027-01-01T00:00:00Z")),
  "win_bad": (flip(sign(M1)), payload(1), reg(pub, "2027-01-01T00:00:00Z")),
  "idkey1": (ident + bytes(32), payload(1), reg(ident)),
  "idkey2": (ident + bytes(32), payload(2), reg(ident)),
}
for name, (sig, pl, rg) in cases.items():
    d = os.path.join(sys.argv[1], name); os.makedirs(d, exist_ok=True)
    json.dump({"signature": b(sig), "key_id": "probe_k", "signed_payload": pl,
               "receipt_hash": hashlib.sha256(pl.encode()).hexdigest()}, open(os.path.join(d, "receipt.json"), "w"))
    json.dump(rg, open(os.path.join(d, "registry.json"), "w"))
    print(name, "R =", sig[:32].hex(), "S =", sig[32:].hex(), "key =", rg["entries"][0]["public_key"])
