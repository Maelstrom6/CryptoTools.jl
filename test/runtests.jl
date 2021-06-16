using CryptoTools
using Test
using SafeTestsets

@testset "CryptoTools.jl" begin
    @time @safetestset "Block Cipher" begin include("BlockCipher.jl") end
    @time @safetestset "Stream Cipher" begin include("StreamCipher.jl") end
    @time @safetestset "Secret Sharing" begin include("SecretSharing.jl") end
end
