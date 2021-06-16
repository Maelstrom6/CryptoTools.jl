using CryptoTools
using Test
using Random

@testset "ChaCha20" begin
    plaintext = hex2bytes("00112233445566778899aabbccddeeff")
    key = hex2bytes("00"^32)
    nonce = hex2bytes("00"^12)
    cipher = ChaCha20(key, nonce)
    # @test encrypt(cipher, plaintext) == hex2bytes("04d5394f430044ccd4435310f690935a")
    @test decrypt(cipher, encrypt(cipher, plaintext)) == plaintext

    # https://mkyong.com/java/java-11-chacha20-stream-cipher-examples/
    plaintext = hex2bytes("4a617661202620436861436861323020656e6372797074696f6e206578616d706c652e")
    # key = hex2bytes("ee416df8b5154a4ac48f3930fcfa53ef7f677c8fd7cd093f1328eedfd831db1a")
    # nonce = hex2bytes("9806308f4d1732d2d39beaba")
    # cipher = ChaCha20(key, nonce)
    # ciphertext = hex2bytes("2149db2c32bf82f9e8dc0a709d8c15d5a22eb79d5f692e04f070d46cc7e264631f85e0")
    # @test encrypt(cipher, plaintext) == ciphertext

    # plaintext = hex2bytes("4a617661202620436861436861323020656e6372797074696f6e206578616d706c652e")
    # key = hex2bytes("f95fd5b41783595e41f4cbcd8dc26a782599184e97ccd768ac531aae729781d3")
    # nonce = hex2bytes("84133f2261ef44796e3669dc")
    # cipher = ChaCha20(key, nonce)
    # ciphertext = hex2bytes("7738807b409f3349dbefbeae988482e0e5959c35ee8f8ee8987357db459e10d7fb8c7e")
    # @test encrypt(cipher, plaintext) == ciphertext

    # plaintext = hex2bytes("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    # key = hex2bytes("0000000000000000000000000000000000000000000000000000000000000000")
    # nonce = hex2bytes("000000000000000000000000")
    # cipher = ChaCha20(key, nonce)
    # ciphertext = hex2bytes("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669")
    # @test encrypt(cipher, plaintext) == ciphertext

    # https://asecuritysite.com/encryption/salsa20
    # plaintext = base64decode("XKxPmA/tw9Px+ZtL40csmzDVZSPmMtFRI37JMJBIvak=")
    # key = base64decode("WTeEmfKonMWESy6xHvt7Eqi0WJQkUmlbNC19EXI8M3k=")
    # nonce = base64decode("4mgPYADJIPw=")
    # cipher = ChaCha20(key, nonce)
    # ciphertext = base64decode("kER+ZiYPMeLWxUihfPRS1VR+uA==")
    # @test encrypt(cipher, plaintext) == ciphertext
end
