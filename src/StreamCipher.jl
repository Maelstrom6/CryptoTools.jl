"""
Stream ciphers produce a pseudorandom stream of bits called the
keystream. The keystream is XORed to a plaintext to encrypt it and then
XORed again to the ciphertext to decrypt it.

From a high-level perspective, there are two types of stream ciphers:
stateful and counter based. Stateful stream ciphers have a secret internal
state that evolves throughout keystream generation.
Counter-based stream ciphers produce chunks of keystream from a key, a
nonce, and a counter value.

A feedback shift register (FSR) is simply an array of bits equipped with an update
feedback function, which I’ll denote as f. FSRs have a period.
Linear feedback shift registers (LFSRs) are FSRs with a linear feedback
function - namely, a function that’s the XOR of some bits of the state.
To mitigate the insecurity of LFSRs, you can hide their linearity by
passing their output bits through a nonlinear function before returning
them to produce what is called a filtered LFSR.
Nonlinear FSRs (NFSRs) are like LFSRs but with a nonlinear feedback
function instead of a linear one. That is, instead of just bitwise XORs, the
feedback function can include bitwise AND and OR operations.

    Grain-128a combines NFSR and LFSR

Salsa20
RC4

To be primitive, the
polynomial must have the following qualities:
The polynomial must be irreducible, meaning that it can’t be
factorized; that is, written as a product of smaller polynomials. For
example, X + X 3 is not irreducible because it’s equal to (1 + X)(X +
X2):
(1 + X)(X + X2) = X + X2 + X2 + X3 = X + X3
The polynomial must satisfy certain other mathematical properties
that cannot be easily explained without nontrivial mathematical
notions but are easy to test.
"""
struct SteamCipher
    key::Vector{UInt8}
    nonce::Vector{UInt8}
 end

 struct ChaCha20
    key::Vector{UInt32}  # 256 bit
    nonce::Vector{UInt32}  # 96 bit
 end

 ChaCha20(key::Vector{UInt8}, nonce::Vector{UInt8}) = ChaCha20(reinterpret(UInt32, key), reinterpret(UInt32, nonce))

 function encrypt(cipher::ChaCha20, plaintext::Vector{UInt8}, rounds::Int64=10)
    function quarter_round!(s, a, b, c, d)
        s[a] += s[b]; s[d] ⊻= s[a]; s[d] = (s[d] << 16) + (s[d] >> (32-16));
        s[c] += s[d]; s[b] ⊻= s[c]; s[b] = (s[b] << 12) + (s[b] >> (32-12));
        s[a] += s[b]; s[d] ⊻= s[a]; s[d] = (s[d] << 8) + (s[d] >> (32-8));
        s[c] += s[d]; s[b] ⊻= s[c]; s[b] = (s[b] << 7) + (s[b] >> (32-7));
    end

    function double_round!(s)
        quarter_round!(s, 1, 5,  9, 13)	# 1st column
        quarter_round!(s, 2, 6, 10, 14)	# 2nd column
        quarter_round!(s, 3, 7, 11, 15)	# 3rd column
        quarter_round!(s, 4, 8, 12, 16)	# 4th column

        quarter_round!(s, 1, 6, 11, 16)	# diagonal 1 (main diagonal)
        quarter_round!(s, 2, 7, 12, 13)	# diagonal 2
        quarter_round!(s, 3, 8,  9, 14)	# diagonal 3
        quarter_round!(s, 4, 5, 10, 15) # diagonal 4
    end

    k = cipher.key
    n = cipher.nonce

    result = UInt8[]
    for counter in 0x00000001:cld(length(plaintext), 64)
        s0 = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            k[1], k[2], k[3], k[4],
            k[5], k[6], k[7], k[8],
            counter, n[1], n[2], n[3],
        ]
        s = copy(s0)

        for _ in 1:2:rounds
            double_round!(s)
        end

        for i in 1:length(s)
            append!(result, reinterpret(UInt8, [s[i] + s0[i]]))
        end
    end

    ciphertext = xor.(plaintext, result[1:length(plaintext)])
    return ciphertext
 end

 function decrypt(cipher::ChaCha20, ciphertext::Vector{UInt8}, rounds::Int64=10)
    return encrypt(cipher, ciphertext, 20-rounds)
 end
