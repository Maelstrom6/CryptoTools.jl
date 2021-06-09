module CryptoTools

using Core: Bits
export encrypt, decrypt
export OneTimePad

"""
The default number of byes of security (256-bit).
"""
const DEFAULT_SECURITY = 32

include("KeyGen.jl")
include("BlockCipher.jl")

end
