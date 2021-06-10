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

@testset "AES" begin
    plaintext = hex2bytes("00112233445566778899aabbccddeeff")
    key = hex2bytes("000102030405060708090a0b0c0d0e0f")
    cipher = AES(key)
    @test encrypt(cipher, plaintext) == hex2bytes("69c4e0d86a7b0430d8cdb78070b4c55a")

    plaintext = hex2bytes("00000000000000000000000000000000")
    key = hex2bytes("2c6202f9a582668aa96d511862d8a279")
    cipher = AES(key)
    @test encrypt(cipher, plaintext) == hex2bytes("12b620bb5eddcde9a07523e59292a6d7")
end
