"""
Pads so that the length of the result is a multiple of block size in bytes.
A block size of 10 represents 10 bytes that make up a single block.

Padding for block ciphers is specified in the PKCS#7 standard and in RFC 5652.
Method can be
- :zero
- :pkcs7
- :iso

"""
function pad(bytes::Vector{UInt8}, block_size::Int64, method=:pkcs7)
    length_to_add = block_size - (length(bytes) % block_size)

    padding = repeat([0x00], length_to_add)
    if method == :zero
        padding = repeat([0x00], length_to_add)
    elseif method == :pkcs7
        padding = repeat([UInt8(length_to_add)], length_to_add)
    elseif method == :iso
        padding = vcat(0x80, repeat([0x00], length_to_add-1))
    elseif method == :ansi
        padding = vcat(repeat([0x00], length_to_add-1), [UInt8(length_to_add)])
    end
    return vcat(bytes, padding)
end

"""
This is not vulnerable to padded oracle attacks because it does not fail
if the padding is invalid.
"""
function unpad(bytes::Vector{UInt8}, method=:pkcs7)
    if method == :zero
        throw(PaddingError(method, "Does not support unpad."))
    elseif method == :pkcs7
        return bytes[1:(end-bytes[end])]
    elseif method == :iso
        while padding[end] != 0x80
            padding = padding[1:(end-1)]
        end
        return padding[1:(end-1)]
    elseif method == :ansi
        return bytes[1:(end-bytes[end])]
    end
end

"""
Galois Field (256) Multiplication of two Bytes
"""
function gmul(a::UInt8, b::UInt8)
    p = 0x00
    for _ in 1:8
        if b & 1 != 0x00
            p = xor(p, a)
        end

        hi_bit_set = (a & 0x80) != 0x00
        a <<= 0x01
        if hi_bit_set
            a = xor(a, 0x1b)
        end
        b >>= 0x01
    end
    return p
end

s = [UInt8(i+4j-5) for i in 1:4, j in 1:4]

s = [
    0xea 0x04 0x65 0x85;
    0x83 0x45 0x5d 0x96;
    0x5c 0x33 0x98 0xb0;
    0xf0 0x2d 0xad 0xc5;
]

k = [
    0x0f, 0x15, 0x71, 0xc9,
    0x47, 0xd9, 0xe8, 0x59,
    0x0c, 0xb7, 0xad, 0xd6,
    0xaf, 0x7f, 0x67, 0x98,
]
