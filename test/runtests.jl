using CryptoTools
using Test
using SafeTestsets

@testset "CryptoTools.jl" begin
    @time @safetestset "Basics" begin include("BlockCipher.jl") end
end
