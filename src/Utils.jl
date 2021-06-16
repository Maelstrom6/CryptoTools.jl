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

function eval_poly(polynomial, x, modulus)
    accum = zero(eltype(polynomial))
    for coeff in reverse(polynomial)
        accum *= x
        accum += coeff
        accum %= modulus
    end
    return accum
end

function lagrange_interpolate(x, xs, ys, modulus)
    k = length(xs)
    nums = []
    dens = []
    for i in 1:k
        curr = xs[i]
        others = vcat(xs[1:(i-1)], xs[(i+1):end])
        push!(nums, prod(x .- others))
        push!(dens, prod(curr .- others))
    end

    den = prod(dens)
    num = sum(nums[i] * den * ys[i] * invmod(dens[i], modulus) % modulus for i in 1:k)
    return (num * invmod(den, modulus) % modulus + modulus) % modulus
end
