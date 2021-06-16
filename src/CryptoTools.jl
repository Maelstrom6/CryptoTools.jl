module CryptoTools

using Base: split, join

export encrypt, decrypt
export OneTimePad, AES, ChaCha20, ShamirSecretSharing

"""
The default number of byes of security (256-bit).
"""
const DEFAULT_SECURITY = 32

include("Utils.jl")
include("KeyGen.jl")
include("BlockCipher.jl")
include("StreamCipher.jl")
include("SecretSharing.jl")

end
