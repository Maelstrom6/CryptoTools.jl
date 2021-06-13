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

Confusion means that the input
(plaintext and encryption key) undergoes complex transformations, and
diffusion means that these transformations depend equally on all bits of
the input.
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

struct FeiselScheme <: Cipher
    key::Vector{UInt8}
end

function encrypt(cipher::FeiselScheme, plaintext::Vector{UInt8}, block_size=64, rounds=15)
    left = plaintext[1:(block_size ÷ 2)]
    right = plaintext[(block_size ÷ 2 + 1):end]
    subkeys = rijndael_key_schedule(cipher.key, rounds)

    for i in 1:rounds
        temp = xor.(left, round_function(right, subkeys[i]))
        left = right
        right = temp
    end
end

"""
The cipher key used for encryption is 128, 192 or 256 bits long.

If you want to encrypt only a single block of exactly 16 bytes, use padding=false.

Without KeyExpansion, all rounds would use the same key, K, and
AES would be vulnerable to slide attacks.
Without AddRoundKey, encryption wouldn’t depend on the key;
hence, anyone could decrypt any ciphertext without the key.
SubBytes brings nonlinear operations, which add cryptographic
strength. Without it, AES would just be a large system of linear
equations that is solvable using high-school algebra.
Without ShiftRows, changes in a given column would never affect
the other columns, meaning you could break AES by building four
232-element codebooks for each column. (Remember that in a secure
block cipher, flipping a bit in the input should affect all the output
bits.)
Without MixColumns, changes in a byte would not affect any other
bytes of the state. A chosen-plaintext attacker could then decrypt any
ciphertext after storing 16 lookup tables of 256 bytes each that hold
the encrypted values of each possible value of a byte.

You should never encrypt blocks independently. This reveals patterns and
identical plaintext values because the ciphertext will be the same. This is
called electronic codebook and should be avoided. One should rather use
cipher block chaining.
"""
struct AES <: Cipher
    key::Vector{UInt8}
    rounds::Int64
end

function AES(key)
    n = length(key) * 8

    # Determine the number of rounds to run
    n == 128 ? rounds = 10 : nothing
    n == 192 ? rounds = 12 : nothing
    n == 256 ? rounds = 14 : nothing
    return AES(key, rounds)
end

function encrypt(cipher::AES, plaintext::Vector{UInt8}, padding=true)
    padding ? plaintext = pad(plaintext, 16) : nothing

    if length(plaintext) > 16
        result = encrypt(cipher, plaintext[1:16], false)  # should be xored with nonce
        for i in 17:16:16fld(length(plaintext), 16)
            input = xor.(plaintext[i:(i+15)], result[(i-16):(i-1)])
            append!(result, encrypt(cipher, input, false))
        end
        return result
    end

    rounds = cipher.rounds

    # Generate the roundkeys from the key
    subkeys = rijndael_key_schedule(cipher.key, rounds)
    roundkeys = [hcat(subkeys[i:(i+3)]...) for i in 1:4:length(subkeys)]  # transposable

    # Define the 4 central functions
    xorkeys(s, i) = xor.(s, roundkeys[i])
    subbytes(s) = sbox(s)
    function shiftrows(s)
        result = []
        n = size(s, 1)
        for (i, row) in enumerate(eachrow(s))
            # push!(result, vcat(row[(n-i+2):end], row[1:(n-i+1)]))
            push!(result, vcat(row[i:end], row[1:(i-1)]))
        end
        return hcat(result...)'
    end
    function mixcolumns(s)  # https://en.wikipedia.org/wiki/Rijndael_MixColumns
        ss = copy(s)
        for j in 1:size(s, 2)
            ss[1, j] = xor(gmul(0x02, s[1, j]), gmul(0x03, s[2, j]), s[3, j], s[4, j])
            ss[2, j] = xor(s[1, j], gmul(0x02, s[2, j]), gmul(0x03, s[3, j]), s[4, j])
            ss[3, j] = xor(s[1, j], s[2, j], gmul(0x02, s[3, j]), gmul(0x03, s[4, j]))
            ss[4, j] = xor(gmul(0x03, s[1, j]), s[2, j], s[3, j], gmul(0x02, s[4, j]))
        end
        return ss
    end

    # main algo
    s = reshape(plaintext, (4, 4))  # transposable
    s = xorkeys(s, 1)
    for i in 2:rounds
        s = subbytes(s)
        s = shiftrows(s)
        s = mixcolumns(s)
        s = xorkeys(s, i)
    end
    s = subbytes(s)
    s = shiftrows(s)
    s = xorkeys(s, rounds+1)

    return reshape(s, 16)  # transposable
end

"""
If you encrypted only a single block of exactly 16 bytes, use padding=false.
"""
function decrypt(cipher::AES, ciphertext::Vector{UInt8}, padding=true)
    if length(ciphertext) > 16
        result = decrypt(cipher, ciphertext[1:16], false)
        for i in 17:16:16fld(length(ciphertext), 16)
            input = decrypt(cipher, ciphertext[i:(i+15)], false)
            input = xor.(input, ciphertext[(i-16):(i-1)])
            append!(result, input)
        end

        padding ? result = unpad(result) : nothing
        return result
    end

    rounds = cipher.rounds

    # Generate the roundkeys from the key
    subkeys = rijndael_key_schedule(cipher.key, rounds)
    roundkeys = [hcat(subkeys[i:(i+3)]...) for i in 1:4:length(subkeys)]  # transposable

    # Define the 4 central functions
    xorkeys(s, i) = xor.(s, roundkeys[i])
    invsubbytes(s) = invsbox(s)
    function invshiftrows(s)
        result = []
        n = size(s, 1)
        for (i, row) in enumerate(eachrow(s))
            push!(result, vcat(row[(n-i+2):end], row[1:(n-i+1)]))
        end
        return hcat(result...)'
    end
    function invmixcolumns(s)  # https://en.wikipedia.org/wiki/Rijndael_MixColumns
        ss = copy(s)
        for j in 1:size(s, 2)
            ss[1, j] = xor(gmul(0x0e, s[1, j]), gmul(0x0b, s[2, j]), gmul(0x0d, s[3, j]), gmul(0x09, s[4, j]))
            ss[2, j] = xor(gmul(0x09, s[1, j]), gmul(0x0e, s[2, j]), gmul(0x0b, s[3, j]), gmul(0x0d, s[4, j]))
            ss[3, j] = xor(gmul(0x0d, s[1, j]), gmul(0x09, s[2, j]), gmul(0x0e, s[3, j]), gmul(0x0b, s[4, j]))
            ss[4, j] = xor(gmul(0x0b, s[1, j]), gmul(0x0d, s[2, j]), gmul(0x09, s[3, j]), gmul(0x0e, s[4, j]))
        end
        return ss
    end

    # main algo
    s = reshape(ciphertext, (4, 4))  # transposable
    s = xorkeys(s, rounds+1)
    s = invshiftrows(s)
    s = invsubbytes(s)
    for i in rounds:-1:2
        s = xorkeys(s, i)
        s = invmixcolumns(s)
        s = invshiftrows(s)
        s = invsubbytes(s)
    end
    s = xorkeys(s, 1)
    s = reshape(s, 16) # transposable

    padding ? s = unpad(s) : nothing
    return s
end
