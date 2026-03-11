#!/usr/bin/env sage
from pwn import *
import ast
import sys


if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} HOST PORT")
    raise SystemExit(1)

HOST = sys.argv[1]
PORT = int(sys.argv[2])

context.log_level = "info"
io = remote(HOST, PORT)


def recv_assignment(name):
    io.recvuntil(f"{name} = ".encode())
    return io.recvline().decode().strip()


p = int(recv_assignment("p"))
pub = ast.literal_eval(recv_assignment("pub"))

o = (p + 1) // 6
Fp = GF(p)
E = EllipticCurve(Fp, [0, 1])
G = E.gens()[0] * 6

PR.<u> = PolynomialRing(Fp)
Fp2 = GF(p^2, name="w", modulus=u^2 + u + 1)
w = Fp2.gen()
E2 = EllipticCurve(Fp2, [0, 1])
INF = E(0)
INF2 = E2(0)


def lift(P):
    if P == INF:
        return INF2
    return E2((Fp2(P[0]), Fp2(P[1])))


def psi(P):
    if P == INF2:
        return P
    return E2((w * P[0], P[1]))


def pair(P, Q):
    return lift(P).weil_pairing(psi(lift(Q)), o)


def key(v):
    return str(v)


pts = []
coeff_of = {}
for xy, c in pub:
    P = E((Fp(xy[0]), Fp(xy[1])))
    pts.append(P)
    coeff_of[(ZZ(P[0]), ZZ(P[1]))] = ZZ(c) % o

P0 = G
assert P0 in pts

# Labels identify the hidden exponent alpha^i through g^(alpha^i).
base = {}
for P in pts:
    lab = key(pair(P0, P))
    assert lab not in base
    base[lab] = P


def add_exp(A, B):
    # If A = alpha^i G and B = alpha^j G, returns alpha^(i+j) G when it is public.
    return base.get(key(pair(A, B)), None)


def chain_len(X):
    cur = X
    seen = {P0, X}
    length = 1
    while True:
        nxt = add_exp(cur, X)
        if nxt is None or nxt in seen:
            return length
        seen.add(nxt)
        cur = nxt
        length += 1


# alpha * G is the unique point whose repeated products walk all the way to alpha^39 * G.
candidates = [P for P in pts if P != P0]
P1 = max(candidates, key=chain_len)
assert chain_len(P1) == 39

ordered = [P0]
cur = P0
for _ in range(39):
    cur = add_exp(cur, P1)
    assert cur is not None
    ordered.append(cur)

assert len(set(ordered)) == 40

coeffs = [coeff_of[(ZZ(P[0]), ZZ(P[1]))] for P in ordered]
check = INF
for i in range(40):
    if coeffs[i]:
        check += int(coeffs[i]) * ordered[i]
assert check == INF

d = max(i for i, c in enumerate(coeffs) if c != 0)
inv_lead = inverse_mod(coeffs[d], o)

# Extend the SRS with the public recurrence induced by sum coeffs[i] * alpha^i = 0.
WANT = 41
srs = ordered[:]
while len(srs) <= WANT:
    m = len(srs)
    acc = INF
    for i in range(d):
        if coeffs[i]:
            acc += int(coeffs[i]) * srs[m - d + i]
    srs.append(int((-inv_lead) % o) * acc)


def send_point(prompt, P):
    assert P != INF
    io.sendlineafter(prompt.encode(), f"{ZZ(P[0])},{ZZ(P[1])}".encode())


# Commit to f(X) = X^41.
C = srs[41]
send_point("C = ", C)

for _ in range(100):
    z = int(recv_assignment("z"))
    zq = ZZ(z) % o

    y = pow(int(zq), 41, o)
    io.sendlineafter(b"y = ", str(y).encode())

    # (X^41 - z^41) / (X - z) = X^40 + z X^39 + ... + z^40
    pi = INF
    zp = 1
    for deg in range(40, -1, -1):
        if zp:
            pi += int(zp) * srs[deg]
        zp = (zp * zq) % o

    send_point("pi = ", pi)

io.interactive()
