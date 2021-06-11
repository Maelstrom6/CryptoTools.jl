var documenterSearchIndex = {"docs":
[{"location":"","page":"Home","title":"Home","text":"CurrentModule = CryptoTools","category":"page"},{"location":"#CryptoTools","page":"Home","title":"CryptoTools","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"Documentation for CryptoTools.","category":"page"},{"location":"","page":"Home","title":"Home","text":"","category":"page"},{"location":"","page":"Home","title":"Home","text":"Modules = [CryptoTools]","category":"page"},{"location":"#CryptoTools.DEFAULT_SECURITY","page":"Home","title":"CryptoTools.DEFAULT_SECURITY","text":"The default number of byes of security (256-bit).\n\n\n\n\n\n","category":"constant"},{"location":"#CryptoTools.AES","page":"Home","title":"CryptoTools.AES","text":"The cipher key used for encryption is 128, 192 or 256 bits long.\n\nWithout KeyExpansion, all rounds would use the same key, K, and AES would be vulnerable to slide attacks. Without AddRoundKey, encryption wouldn’t depend on the key; hence, anyone could decrypt any ciphertext without the key. SubBytes brings nonlinear operations, which add cryptographic strength. Without it, AES would just be a large system of linear equations that is solvable using high-school algebra. Without ShiftRows, changes in a given column would never affect the other columns, meaning you could break AES by building four 232-element codebooks for each column. (Remember that in a secure block cipher, flipping a bit in the input should affect all the output bits.) Without MixColumns, changes in a byte would not affect any other bytes of the state. A chosen-plaintext attacker could then decrypt any ciphertext after storing 16 lookup tables of 256 bytes each that hold the encrypted values of each possible value of a byte.\n\nYou should never encrypt blocks independently. This reveals patterns and identical plaintext values because the ciphertext will be the same. This is called electronic codebook and should be avoided. One should rather use cipher block chaining.\n\n\n\n\n\n","category":"type"},{"location":"#CryptoTools.Cipher","page":"Home","title":"CryptoTools.Cipher","text":"Cipher\n\nA cipher is an algorithm used to translate plaintext into ciphertext.\n\nAttack models\n\nAttack model - assumptions about what the attacker can and cannot do.\n\nCiphertext-only attackers (COA) observe ciphertexts but don't know\n\nthe associated plaintexts, and don't know how the plaintexts were selected. Attackers in the COA model are passive and can't perform encryption or decryption queries.\n\nKnown-plaintext attackers (KPA) observe ciphertexts and do know the\n\nassociated plaintexts. Attackers in the KPA model thus get a list of plaintext–ciphertext pairs, where plaintexts are assumed to be randomly selected. Again, KPA is a passive attacker model.\n\nChosen-plaintext attackers (CPA) can perform encryption queries for\n\nplaintexts of their choice and observe the resulting ciphertexts. This model captures situations where attackers can choose all or part of the plaintexts that are encrypted and then get to see the ciphertexts. Unlike COA or KPA, which are passive models, CPA are active attackers, because they influence the encryption processes rather than passively eavesdropping.\n\nChosen-ciphertext attackers (CCA) can both encrypt and decrypt; that\n\nis, they get to perform encryption queries and decryption queries. CDs could use this method since attackers can encrypt and decrypt but they want the key so that they can distribute CDs.\n\nSecurity models\n\nSecurity model - states that we consider a successful attack.\n\nIntuitively, a cipher is secure if, even given a large number of plaintext– ciphertext pairs, nothing can be learned about the cipher’s behavior when applied to other plaintexts or ciphertexts.\n\nIn mathematical terms this means\n\nIndistinguishability (IND) - Ciphertexts should be indistinguishable\n\nfrom random strings. This is usually illustrated with this hypothetical game: if an attacker picks two plaintexts and then receives a ciphertext of one of the two (chosen at random), they shouldn’t be able to tell which plaintext was encrypted, even by performing encryption queries with the two plaintexts\n\nNon-malleability (NM) - Given a ciphertext C1 = E(K, P1), it should be\n\nimpossible to create another ciphertext, C2, whose corresponding plaintext, P2, is related to P1 in a meaningful way.\n\nCombining the two\n\nSecurity notion - the combination of some security goal with some attack model. We'll say that a cipher achieves a certain security notion if any attacker working in a given model can't achieve the security goal. The notion is described as GOAL-MODEL.\n\nSemantic security - IND-CPA. That is, ciphertexts shouldn't leak any information about plaintexts as long as the key is secret. To achieve IND-CPA security, encryption must return different ciphertexts if called twice on the same plaintext; otherwise, an attacker could identify duplicate plaintexts from their ciphertexts, contradicting the definition that ciphertexts shouldn't reveal any information.\n\nSome relations\n\nIND-CCA implies IND-CPA\nNM-CCA implies NM-CPA\nNM-CPA implies IND-CPA\n\nSo encryption often is randomised with R, some fresh random bits each time the system is called.\n\nKerckhoffs's principle - the security of a cipher should rely only on the secrecy of the key and not on the secrecy of the cipher.\n\nEntropy = - sum over x of P(X=x)*lb(P(X=x)) The binary logarithm expresses the information in bits and yields integer values when probabilities are powers of two. Entropy is the level of surprise of the outcome.\n\nMersenne Twister\n\nWhy Mersenne Twister (MT) algorithm is insecure. Its internal state is an array, S, consisting of 624 32-bit words. This array is initially set to S1, S2, . . . , S624 and evolves to S2, . . . , S625, then S3, . . . , S626, and so on, according to this equation: S(k + 624) := S(k + 397) ⊕ A((Sk ∧ 0x80000000) ∨ (S(k + 1) ∧ 0xfffffff)) all instructions are bitwise and A is a function that transforms some 32-bit word, x, to (x >> 1), if x's most significant bit is 0, or to (x >> 1) ⊕ 0x9908b0df otherwise.\n\nNotice in this equation that bits of S interact with each other only through XORs. The operators ∧ and ∨ never combine two bits of S together, but just bits of S with bits from the constants 0x80000000 and 0x7fffffff. This way, any bit from S625 can be expressed as an XOR of bits from S398, S1, and S2, and any bit from any future state can be expressed as an XOR combination of bits from the initial state S1, . . . , S624.\n\nBecause there are exactly 624 × 32 = 19,968 bits in the initial state (or 624 32-bit words), any output bit can be expressed as an equation with at most 19,969 terms (19,968 bits plus one constant bit). That’s just about 2.5 kilobytes of data. The converse is also true: bits from the initial state can be expressed as an XOR of output bits.\n\nA cipher is informationally secure only if, even given unlimited computation time and memory, it cannot be broken. Computational security views a cipher as secure if it cannot be broken within a reasonable amount of time, and with reasonable resources such as memory, hardware, budget, energy, and so on.\n\nComputational security is sometimes expressed in terms of two values t and epsilon. We then say that a cryptographic scheme is (t, ε)-secure if an attacker performing at most t operations - whatever those operations are - has a probability of success that is no higher than ε. We can conclude that a cipher with a key of n bits is at best (t, t/2^n)-secure, for any t between 1 and 2^n.\n\nt-secure = (t, 1)-secure n-bit security = 2^n-secure Does not provide much information on the cost of the attack because the attacker can break the cipher with less than expected number of operations.\n\nConfusion means that the input (plaintext and encryption key) undergoes complex transformations, and diffusion means that these transformations depend equally on all bits of the input.\n\n\n\n\n\n","category":"type"},{"location":"#CryptoTools.OneTimePad","page":"Home","title":"CryptoTools.OneTimePad","text":"OneTimePad\n\nThe one time pad is a symmetric block cipher and it is the most secure cipher but the most pointless. It requires a key the same size as the plaintext. It then produces a ciphertext the same length as the plaintext as well by XORing the key and plaintext. Decryption works exactly the same.\n\nKeys should only be used one time otherwise an attacker will be able to determine XOR(plaintext1, plaintext2) by calculating XOR(ciphertext1, ciphertext2). Further, if an attacker can identify plaintext1 then they can calculate plaintext2.\n\nAs long as the key is random, the ciphertext will appear completely random because the XOR of a random key and a nonrandom plaintext appears random. The attacker can only identify the plaintext's length.\n\n\n\n\n\n","category":"type"},{"location":"#CryptoTools.gmul-Tuple{UInt8, UInt8}","page":"Home","title":"CryptoTools.gmul","text":"Galois Field (256) Multiplication of two Bytes\n\n\n\n\n\n","category":"method"},{"location":"#CryptoTools.rijndael_key_schedule-Tuple{Vector{UInt8}, Any}","page":"Home","title":"CryptoTools.rijndael_key_schedule","text":"Generate the subkeys for the AES encryption standard given a key.     https://embeddedsw.net/CipherReferenceHome.html     https://en.wikipedia.org/wiki/AESkeyschedule     https://cryptography.fandom.com/wiki/Rijndaelkeyschedule\n\n\n\n\n\n","category":"method"},{"location":"#CryptoTools.symmetric_key-Tuple{Int64}","page":"Home","title":"CryptoTools.symmetric_key","text":"symmetric_key(bytes::Int64)\n\nGenerates a symmetric key with the number of bytes given by bytes.\n\n\n\n\n\n","category":"method"}]
}
