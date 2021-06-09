using CryptoTools
using Test
using Random

@testset "Baseline" begin
    @test 1 == 1
end

@testset "OneTimePad" begin
    plaintext = "I am plaintext"
    key = rand(RandomDevice(), UInt8, length(plaintext))
    cipher = OneTimePad(key)
    @test decrypt(cipher, encrypt(cipher, plaintext)) == plaintext

    plaintext = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
    key = rand(RandomDevice(), UInt8, length(plaintext))
    cipher = OneTimePad(key)
    @test decrypt(cipher, encrypt(cipher, plaintext)) == plaintext

    
end
