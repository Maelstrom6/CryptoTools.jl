"""
This is the main class for block ciphers.
"""

"""
    Cipher

A cipher is an algorithm used to translate plaintext into ciphertext.


# Attack models
Attack model - assumptions about what the attacker can and cannot do.

1. Ciphertext-only attackers (COA) observe ciphertexts but don't know
the associated plaintexts, and don't know how the plaintexts were
selected. Attackers in the COA model are passive and can't perform
encryption or decryption queries.
2. Known-plaintext attackers (KPA) observe ciphertexts and do know the
associated plaintexts. Attackers in the KPA model thus get a list of
plaintext–ciphertext pairs, where plaintexts are assumed to be
randomly selected. Again, KPA is a passive attacker model.
3. Chosen-plaintext attackers (CPA) can perform encryption queries for
plaintexts of their choice and observe the resulting ciphertexts. This
model captures situations where attackers can choose all or part of
the plaintexts that are encrypted and then get to see the ciphertexts.
Unlike COA or KPA, which are passive models, CPA are active
attackers, because they influence the encryption processes rather
than passively eavesdropping.
4. Chosen-ciphertext attackers (CCA) can both encrypt and decrypt; that
is, they get to perform encryption queries and decryption queries. CDs
could use this method since attackers can encrypt and decrypt but they want
the key so that they can distribute CDs.


# Security models
Security model - states that we consider a successful attack.

Intuitively, a cipher is secure if, even given a large number of plaintext–
ciphertext pairs, nothing can be learned about the cipher’s behavior when
applied to other plaintexts or ciphertexts.

In mathematical terms this means
1. Indistinguishability (IND) - Ciphertexts should be indistinguishable
from random strings. This is usually illustrated with this hypothetical
game: if an attacker picks two plaintexts and then receives a ciphertext
of one of the two (chosen at random), they shouldn’t be able to tell
which plaintext was encrypted, even by performing encryption queries
with the two plaintexts
2. Non-malleability (NM) - Given a ciphertext C1 = E(K, P1), it should be
impossible to create another ciphertext, C2, whose corresponding
plaintext, P2, is related to P1 in a meaningful way.


# Combining the two
Security notion - the combination of some security goal with some
attack model. We'll say that a cipher achieves a certain security notion if
any attacker working in a given model can't achieve the security goal.
The notion is described as GOAL-MODEL.

Semantic security - IND-CPA. That is, ciphertexts shouldn't leak any
information about plaintexts as long as the key is secret. To achieve IND-CPA
security, encryption must return different ciphertexts if called twice
on the same plaintext; otherwise, an attacker could identify duplicate
plaintexts from their ciphertexts, contradicting the definition that
ciphertexts shouldn't reveal any information.

Some relations
- IND-CCA implies IND-CPA
- NM-CCA implies NM-CPA
- NM-CPA implies IND-CPA

So encryption often is randomised with R, some fresh random bits
each time the system is called.

Kerckhoffs's principle - the security of a cipher should rely only on the secrecy
of the key and not on the secrecy of the cipher.

Entropy = - sum over x of P(X=x)*lb(P(X=x))
The binary logarithm expresses the information in bits and yields integer
values when probabilities are powers of two. Entropy is the level of surprise
of the outcome.


# Mersenne Twister
Why Mersenne Twister (MT) algorithm is insecure.
Its internal state is an array, S, consisting of 624 32-bit words.
This array is initially set to S1, S2, . . . , S624 and evolves to S2, . . . , S625,
then S3, . . . , S626, and so on, according to this equation:
S(k + 624) := S(k + 397) ⊕ A((Sk ∧ 0x80000000) ∨ (S(k + 1) ∧ 0xfffffff))
all instructions are bitwise and A is a function that transforms some
32-bit word, x, to (x >> 1), if x's most significant bit is 0,
or to (x >> 1) ⊕ 0x9908b0df otherwise.

Notice in this equation that bits of S interact with each other only
through XORs. The operators ∧ and ∨ never combine two bits of S
together, but just bits of S with bits from the constants 0x80000000 and
0x7fffffff. This way, any bit from S625 can be expressed as an XOR of bits
from S398, S1, and S2, and any bit from any future state can be expressed
as an XOR combination of bits from the initial state S1, . . . , S624.

Because there are exactly 624 × 32 = 19,968 bits in the initial state (or
624 32-bit words), any output bit can be expressed as an equation with at
most 19,969 terms (19,968 bits plus one constant bit). That’s just about
2.5 kilobytes of data. The converse is also true: bits from the initial state
can be expressed as an XOR of output bits.


A cipher is informationally
secure only if, even given unlimited computation time and memory, it
cannot be broken. Computational security views a cipher as
secure if it cannot be broken within a reasonable amount of time, and with
reasonable resources such as memory, hardware, budget, energy, and so
on.

Computational security is sometimes expressed in terms of two values
t and epsilon. We then say that a cryptographic scheme is (t, ε)-secure if an attacker
performing at most t operations - whatever those operations are - has a
probability of success that is no higher than ε. We can conclude that
a cipher with a key of n bits is at best (t, t/2^n)-secure, for any t between 1 and 2^n.

t-secure = (t, 1)-secure
n-bit security = 2^n-secure
Does not provide much information on the cost of the attack
because the attacker can break the cipher with less than expected
number of operations.


"""
abstract type Cipher end
encrypt(cipher, plaintext::String) = String(encrypt(cipher, Vector{UInt8}(plaintext)))
decrypt(cipher, ciphertext::String) = String(encrypt(cipher, Vector{UInt8}(ciphertext)))

"""
    OneTimePad

The one time pad is a symmetric block cipher and it is the most secure cipher
but the most pointless. It requires a key the same size as the plaintext.
It then produces a ciphertext the same length as the plaintext as well by
XORing the key and plaintext. Decryption works exactly the same.

Keys should only be used one time otherwise an attacker will be able to
determine `XOR(plaintext1, plaintext2)` by calculating `XOR(ciphertext1, ciphertext2)`.
Further, if an attacker can identify `plaintext1` then they can calculate `plaintext2`.

As long as the key is random, the ciphertext will appear completely random
because the XOR of a random key and a nonrandom plaintext appears random.
The attacker can only identify the plaintext's length.
"""
struct OneTimePad <: Cipher
    key::Vector{UInt8}
end

#using Base.xor
#xor(a::Array{Uint8, 1}, b::Array{Uint8, 1}) = xor()
encrypt(cipher::OneTimePad, plaintext::Vector{UInt8}) = xor.(cipher.key, plaintext)
decrypt(cipher::OneTimePad, ciphertext::Vector{UInt8}) = xor.(cipher.key, ciphertext)
