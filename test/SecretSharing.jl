using CryptoTools
using Test
using Random

@testset "Shamir" begin
    scheme = ShamirSecretSharing()
    secret = BigInt(1234931)
    shares = split(scheme, secret, 6, 3)
    @test join(scheme, shares) == secret
    @test join(scheme, shares[1:3]) == secret
    @test join(scheme, shares[4:6]) == secret
end
