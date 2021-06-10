module CryptoTools

export encrypt, decrypt
export OneTimePad, AES

"""
The default number of byes of security (256-bit).
"""
const DEFAULT_SECURITY = 32

include("Utils.jl")
include("KeyGen.jl")
include("BlockCipher.jl")

end
