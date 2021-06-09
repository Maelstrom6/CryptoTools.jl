using Random: rand, RandomDevice
using Primes: nextprime
"""
    symmetric_key(bytes::Int64)

Generates a symmetric key with the number of bytes given by `bytes`.
"""
symmetric_key(bytes::Int64) = rand(RandomDevice(), UInt8, bytes)

function asymmetric_key(bits=20, e=2^16+1)
    lower = big(1) << (bits - 1)
    upper = (big(1) << bits) - 1

    p = nextprime(rand(RandomDevice(), lower:upper))
    q = nextprime(rand(RandomDevice(), lower:upper))

    n = p * q
    # lambda = lcm(p-1, q-1)
    d = invmod(e, (p - 1) * (q - 1))

    public_key = (n, e)
    private_key = (n, d)

    return (public_key, private_key)
end
