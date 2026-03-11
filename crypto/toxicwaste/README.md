# toxicwaste

`toxicwaste` is a KZG-style commitment challenge built on the supersingular curve

```text
E / F_p : y^2 = x^3 + 1
```

The setup publishes 40 shuffled pairs

```text
(alpha^i * G1, c_i)
```

with the hidden relation

```text
sum(c_i * alpha^i) = 0 mod o
```

and also exposes `alpha * G2`. We may choose one commitment `C`, then answer 100 KZG opening queries at random points `z`. If the interpolated polynomial has degree strictly larger than 40, the server prints the flag.

The intended protection is that the SRS points are shuffled, so we should not know which published point is `G1`, `alpha G1`, `alpha^2 G1`, and so on. That is not enough here.

## Vulnerability

### 1. The shuffle does not hide multiplicative structure

The curve is supersingular, so we can build our own non-degenerate pairing with a distortion map. In the solver this is

```python
psi((x, y)) = (w * x, y)
```

where `w` is a root of `u^2 + u + 1` in `F_{p^2}`.

For each published point `P_i = alpha^i G1`, define

```text
L(P_i) = e(G1, psi(P_i)) = g^(alpha^i)
```

If `A = alpha^i G1` and `B = alpha^j G1`, then bilinearity gives

```text
e(A, psi(B)) = g^(alpha^(i + j))
```

So the pairing of two published points tells us which published point corresponds to `alpha^(i+j) G1`, as long as `i + j <= 39` and that point is still inside the published list.

This turns the shuffled SRS into a small multiplication table in the exponent. The unique point that generates the longest chain

```text
alpha G1, alpha^2 G1, ..., alpha^39 G1
```

is `alpha G1`, so we can recover the full ordered SRS

```text
G1, alpha G1, ..., alpha^39 G1.
```

### 2. The leaked relation lets us extend the SRS

Once the points are back in order, the shuffled coefficients become the coefficients of a polynomial relation

```text
c_0 + c_1 alpha + ... + c_d alpha^d = 0 mod o
```

with `c_d != 0`.

Multiplying by `alpha^(m-d) G1` gives a linear recurrence:

```text
alpha^m G1 = -c_d^(-1) * sum(c_i * alpha^(m-d+i) G1 for i in [0, d-1]).
```

Therefore the public relation does not merely certify that the published SRS is valid; it lets us derive new SRS elements beyond degree 39. In particular we can compute `alpha^41 G1`.

### 3. Forge a commitment to a degree-41 polynomial

Pick

```text
f(X) = X^41.
```

This degree is larger than the advertised maximum `40`, but still well below the `100` evaluation points used by the server, so interpolation recovers it exactly.

The forged commitment is simply

```text
C = alpha^41 G1.
```

For each verifier challenge `z`, answer with

```text
y = z^41
q(X) = (X^41 - z^41) / (X - z) = X^40 + z X^39 + ... + z^40
pi = q(alpha) G1.
```

Because we extended the SRS up to degree 41, we can evaluate both `f(alpha)` and `q(alpha)` and the KZG equation checked by the server holds:

```text
e(pi, alpha G2 - z G2) = e(C - y G1, G2).
```

After 100 correct openings, the server interpolates the returned evaluations and recovers `X^41`, whose degree is greater than 40, so it prints the flag.

## Exploit script

The script in [solve_toxicwaste.sage](./solve_toxicwaste.sage) performs the full attack:

1. Recover the order of the shuffled SRS with pairings.
2. Use the published toxic-waste relation as a recurrence to derive `alpha^40 G1` and `alpha^41 G1`.
3. Commit to `X^41`.
4. Answer each opening query with the witness for `(X^41 - z^41) / (X - z)`.

Run it with:

```bash
sage solve_toxicwaste.sage HOST PORT
```

## Solver Notes

- The challenge source uses `y` values modulo the subgroup order `o`, because all scalar multiplications happen in the order-`o` subgroup.
- The interpolation is done over `GF(o)`, so the queried `z` values are effectively reduced modulo `o`.
- The attack only needs any non-degenerate bilinear map on the same subgroup; it does not need the challenge's random `G2`.
