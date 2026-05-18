# Elliptic Curve Cryptography — From Scratch (Educational)

> **⚠️ Not for production use.** This repository implements ECC primitives (point
> arithmetic, ECDSA, ECIES, SPAKE2) by hand for learning purposes. The code is
> **not** constant-time, does **not** validate inputs against every known attack,
> and relies on `pow(x, p-2, p)` for modular inversion (only valid when `p` is
> prime). Use a vetted library such as `pycryptodome`, `cryptography`, or
> `libsodium` for anything that matters.

This project walks through the building blocks of Elliptic Curve Cryptography
on the NIST **P-256** curve, then composes them into three real protocols:

| File              | What it implements                                                    |
|-------------------|-----------------------------------------------------------------------|
| `ecc_ops.py`      | P-256 curve constants and raw point arithmetic                        |
| `manual_ecdsa.py` | ECDSA signing and verification, built on `ecc_ops`                    |
| `manual_ecies.py` | ECIES hybrid encryption, built on `ecc_ops`                           |
| `manual_spake.py` | SPAKE2 password-authenticated key exchange (PAKE), build on `ecc_ops` |
| `ecies.py`        | Same ECIES, but using `pycryptodome` instead of hand-rolled ECC       |
| `proper_ecies.py` | ECIES variant compatible with Go's `crypto/ecdh` output               |

---

## 1. The Math: Elliptic Curves over a Prime Field

An **elliptic curve** in short Weierstrass form is the set of points `(x, y)`
satisfying

```
y² ≡ x³ + a·x + b   (mod p)
```

together with a "point at infinity" `O` that acts as the additive identity.

This project uses **NIST P-256** (a.k.a. `secp256r1` / `prime256v1`):

```python
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551  # order of G
G = (0x6b17d1f2…, 0x4fe342e2…)                                          # generator
```

- `p` defines the prime field `F_p`. Coordinates live in `{0, …, p-1}`.
- `a`, `b` define the curve shape.
- `G` is a fixed generator point; everyone agrees on it.
- `n` is the order of `G` — the smallest positive integer with `n·G = O`.
  All private scalars must be in `[1, n-1]`.

### Group law: adding two points

For `P = (x₁, y₁)`, `Q = (x₂, y₂)` with `P ≠ -Q`, the sum `R = (x₃, y₃)` is
the third intersection of the line through `P` and `Q` with the curve,
reflected across the x-axis. The closed-form is:

```
λ = (y₂ - y₁) / (x₂ - x₁)            (mod p)        # if P ≠ Q
λ = (3·x₁² + a) / (2·y₁)             (mod p)        # if P = Q (doubling)
x₃ = λ² - x₁ - x₂                    (mod p)
y₃ = λ·(x₁ - x₃) - y₁                (mod p)
```

In `ecc_ops.py` this is `point_add(P, Q)`. The "division" is modular: it's
multiplication by the modular inverse.

### Modular inverse via Fermat's little theorem

Because `p` is prime, Fermat's little theorem gives `a^(p-1) ≡ 1 (mod p)` for
any `a` coprime with `p`. Therefore `a^(p-2)` is the inverse of `a`:

```python
def inv_mod(self, nr, mod):
    return pow(nr, mod-2, mod)
```

This is short but slower than the extended Euclidean algorithm and only works
when `mod` is prime. It also doesn't check `nr != 0`.

### Scalar multiplication (double-and-add)

`k·P` means adding `P` to itself `k` times. Naively that's `O(k)`, which is
infeasible for 256-bit scalars. The standard trick is "double-and-add":
iterate over bits of `k`, doubling each step and adding `P` whenever the bit
is set. That brings the cost down to `O(log k)`.

```python
def scalar_mult(self, k, P):
    result = None      # represents the point at infinity
    addend = P
    while k > 0:
        if k & 1:
            result = self.point_add(result, addend)
        addend = self.point_add(addend, addend)   # double
        k >>= 1
    return result
```

> **Why this is not safe in production:** the timing and memory-access pattern
> depends on the bits of `k` — the private key. A side-channel attacker who
> can measure timing can recover bits. Real libraries use Montgomery ladders
> or fixed-window algorithms with constant-time conditional moves.

### Why ECC is "hard"

Given `G` and `Q = k·G`, recovering `k` is the **Elliptic Curve Discrete
Logarithm Problem (ECDLP)**. The best known classical algorithm
(Pollard-rho) takes ~`√n` operations — about 2¹²⁸ for P-256. That's the
asymmetric foundation every protocol below leans on.

---

## 2. ECDSA — Digital Signatures (`manual_ecdsa.py`)

**Goal:** prove you possess a private key `d` without revealing it, by
producing a signature `(r, s)` on a message `m` that anyone can verify with
your public key `Q = d·G`.

### Signing

```
1. e = SHA256(m)                  # hash and treat as integer mod n
2. pick k in [1, n-1]             # nonce — must be unique per signature
3. (x₁, y₁) = k·G
4. r = x₁ mod n                   (if r == 0, retry with new k)
5. s = k⁻¹ · (e + d·r) mod n      (if s == 0, retry)
6. signature = (r, s)
```

### Verification

```
1. e = SHA256(m)
2. w = s⁻¹ mod n
3. (x₁, y₁) = (e·w)·G + (r·w)·Q
4. accept iff x₁ mod n == r
```

The verification works because algebra:
`(e·w)·G + (r·w)·Q = (w·(e + d·r))·G = k·G`, so the x-coordinate matches.

### The `k` nonce — and the deliberate bug in this code

The choice of `k` is **catastrophically important**. If you ever reuse `k`
across two different messages, anyone can recover the private key by solving
two linear equations. If `k` is biased (even a few predictable bits), lattice
attacks can recover `d`. This is famously how Sony's PS3 ECDSA keys were
stolen.

RFC 6979 defines a deterministic `k` derived from `(d, m)` via HMAC, which
this repo *attempts*:

```python
def deterministic_k(hash, privKey):
    hmac = HMAC.new(privKey.to_bytes(...), digestmod=SHA256)
    hmac.update(hash)
    return int.from_bytes(hmac.digest(), 'big')
```

**This is not real RFC 6979.** Real RFC 6979 uses a multi-round HMAC-DRBG and
rejects `k` values outside `[1, n-1]`. The toy version above is enough for
the message to verify in this script, but it should not be copied anywhere.
It's a great exercise to compare it side-by-side with [RFC 6979 §3.2](https://datatracker.ietf.org/doc/html/rfc6979#section-3.2).

---

## 3. ECIES — Hybrid Encryption (`manual_ecies.py`, `ecies.py`, `proper_ecies.py`)

**Goal:** encrypt a message to a recipient who only published a public key
`Q = d·G`, without any prior interaction.

ECIES (Elliptic Curve Integrated Encryption Scheme) is a *hybrid* scheme: it
uses ECC to derive a shared symmetric key, then encrypts the actual payload
with a fast symmetric cipher (here AES-GCM).

### Encrypt to public key `Q`

```
1. eph_priv = random scalar
2. eph_pub  = eph_priv · G          # ephemeral keypair, fresh per message
3. S = eph_priv · Q                 # ECDH shared point
4. shared_secret = S.x || S.y       # serialize the shared point
5. salt = 16 random bytes
6. key = HKDF(shared_secret, salt, "SHA256", out_len=32)
7. ciphertext, tag = AES-GCM(key).encrypt(plaintext)
8. send {eph_pub, salt, nonce, ciphertext, tag}
```

### Decrypt with private key `d`

```
1. S = d · eph_pub                  # same point, because d·(eph_priv·G) = eph_priv·(d·G)
2. shared_secret = S.x || S.y
3. key = HKDF(shared_secret, salt, "SHA256", 32)
4. plaintext = AES-GCM(key, nonce).decrypt_and_verify(ciphertext, tag)
```

The "magic" is step 1's symmetry: ECDH gives both parties the same point
because scalar multiplication is commutative on the group.

### Why HKDF and not "just use S.x as the key"?

Two reasons:

1. **Bias.** The x-coordinate of an ECDH point is not uniformly random over
   256-bit strings — it's uniform over a subset of the field. HKDF
   "extracts" the entropy into a uniform key.
2. **Domain separation.** HKDF's `salt` and `info` parameters let you derive
   multiple independent keys (encryption key, MAC key, …) from one secret
   without them being correlated.

### Why AES-GCM and not AES-CBC + MAC?

GCM is an **AEAD** (Authenticated Encryption with Associated Data) mode —
it produces both ciphertext and an authentication tag in one pass. Naive
"encrypt-then-MAC" with CBC has been the source of many real-world
vulnerabilities (padding-oracle attacks). AEAD is the modern default.

### Variants in this repo

- **`manual_ecies.py`** — uses the from-scratch `ecc_ops.ECC` for the ECDH
  step.
- **`ecies.py`** — same protocol but built on `pycryptodome`'s `ECC` module.
  Useful as a reference: the protocol logic is identical, only the curve
  arithmetic is delegated.
- **`proper_ecies.py`** — interoperable variant that mirrors Go's
  `crypto/ecdh` output. Two notable differences:
  - Shared secret is **only** `S.x` (32 bytes), matching Go's `ECDH()` return
    value.
  - Ephemeral public key is exported in **SEC1 uncompressed** form
    (`0x04 || X || Y`) instead of DER.
  - HKDF uses `context=b"encryption key"` so Go and Python derive the same
    key.

### Subtle bugs in the manual version (left as study material)

- `shared_point[0].to_bytes((shared_point[0].bit_length() + 7) // 8, 'big')`
  produces a **variable-length** encoding. If `S.x` happens to have a leading
  zero byte, encryption and decryption will derive the same shorter key, but
  interop with any other implementation will silently break. Always pad to
  the curve size: `S.x.to_bytes(32, 'big')`.
- The ephemeral private key is only 20 bytes (160 bits) — `token_bytes(20)`.
  This shrinks the effective security to ~80 bits. Use 32 bytes (256 bits)
  and reduce mod `n`.

---

## 4. SPAKE2 — Password-Authenticated Key Exchange (`manual_spake.py`)

**Goal:** two parties who share only a low-entropy password (`"helloworld"`)
want to derive a strong shared key, in a way that an eavesdropper *cannot*
brute-force the password offline.

Plain ECDH doesn't help here — there's no public-key infrastructure, and if
you encrypted ECDH messages with the password, an attacker could try every
candidate password offline. SPAKE2 fixes this by **blinding** each side's
public ephemeral with a password-derived point.

### The two extra generators `M` and `N`

SPAKE2 needs two extra public points `M` and `N`, in addition to the
curve generator `G`. They must have an unknown discrete log relative to `G`
(otherwise the protocol breaks). The values in `ecc_ops.py`:

```python
M = (61709…59, 43399…72)
N = (98031…13, 35443…95)
```

are the standard SPAKE2 points for P-256. In a clean implementation they're
generated by hashing a fixed string to a curve point.

### Protocol

Both sides have password `w`.

**Party A:**
```
x ← random scalar
X = x·G                       # ephemeral ECDH share
T_A = X + w·M                 # blinded with password using M
send T_A
```

**Party B:**
```
y ← random scalar
Y = y·G
T_B = Y + w·N                 # B uses N instead of M
send T_B
```

**Shared secret derivation (each party):**
```
A computes: K = x · (T_B - w·N)   # = x · Y = xy·G
B computes: K = y · (T_A - w·M)   # = y · X = xy·G
```

Both end up with `K = xy·G`. An eavesdropper sees only `T_A`, `T_B`. To
guess the password offline, they'd need to "unblind" `T_A` by computing
`T_A - w'·M` and check it — but without `x` or `y` they can't verify a
guess. They'd need to participate live in the protocol to test each
password, turning offline brute-force into online attempts.

### Inside `manual_spake.py`

- `Spake_A` uses `M` as its own blinder, `N` to unblind the peer.
- `Spake_B` is mirrored: blinds with `N`, unblinds with `M`.
- `start()` returns `T = part1 + part2` serialized as `X(32) || Y(32)` (64
  bytes, uncompressed without the `0x04` tag).
- `finish(remote_T)` strips the peer's blind and multiplies by the local
  private scalar, returning the x-coordinate of `K` as the 32-byte shared
  secret.

### What this toy version skips

- **Confirmation step.** Real SPAKE2(+) hashes `(T_A, T_B, K, w)` and
  exchanges confirmation MACs so both sides know they ended up with the
  same key before using it.
- **Point validation.** A real implementation checks that received points
  are on the curve and not in a small subgroup. Skipping this on a curve
  with cofactor > 1 leads to small-subgroup attacks (P-256 has cofactor 1,
  so this is less catastrophic here, but the check should still be there).
- **Password hashing.** The password is read straight into an integer.
  In real SPAKE2 it goes through a memory-hard KDF (Argon2, scrypt) first.

---

## 5. The Supporting Files

- `pubKey.bin` — a 65-byte uncompressed P-256 public key (`0x04 || X || Y`)
  as produced by Go's `crypto/ecdh`. Consumed by `proper_ecies.py` to
  demonstrate Python→Go interop.
- `shamir_public.json`, `ecc_share3.pem`, `root_key.json`, `root.crt`,
  `test.py` — a separate experiment that uses Shamir Secret Sharing to
  reconstruct an ECC private key from `t-of-n` PEM-encoded shares, then
  uses it to decrypt an ECIES-protected "root key". The `Shamir` module
  is not in this directory.
- `requirements.txt` — pinned `pycryptodome==3.23.0`.

---

## 6. Running the Demos

```bash
python -m venv .venv && source .venv/bin/activate.fish
pip install -r requirements.txt

python ecc_ops.py          # derive a public key from a hard-coded private key
python manual_ecdsa.py     # sign and verify "helloworld"
python manual_ecies.py     # encrypt and decrypt "helloworld"
python manual_spake.py     # two SPAKE2 parties agree on a key, asserted equal
python ecies.py            # ECIES via pycryptodome
```

---

## 7. Recap: Why Each Primitive Exists

| Primitive | Solves                                                       | Toy file |
|-----------|--------------------------------------------------------------|----------|
| ECDH      | Two parties already-authenticated derive a shared symmetric key | (inside ECIES / SPAKE2) |
| ECDSA     | Prove possession of a private key without revealing it       | `manual_ecdsa.py` |
| ECIES     | Encrypt a message to a recipient given only their public key | `manual_ecies.py` |
| SPAKE2    | Two parties bootstrap a strong key from a weak password      | `manual_spake.py` |

Read the source alongside this README — that's where the actual learning
happens. Every "raise ValueError" and every shortcut is an invitation to
ask *why* a hardened implementation would handle it differently.
