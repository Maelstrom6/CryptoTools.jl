struct ShamirSecretSharing
    prime::BigInt
end

ShamirSecretSharing() = ShamirSecretSharing(BigInt(2)^127 - 1)

"""
n is the number of shares.
k is the threshold.

"""
function Base.split(scheme::ShamirSecretSharing, secret::BigInt, n::Int64, k::Int64)
    prime = scheme.prime
    polynomial = [secret]
    for i in 2:k
        push!(polynomial, rand(RandomDevice(), 0:(prime-1)))
    end

    points = []
    for i in 1:n
        push!(points, (i, eval_poly(polynomial, i, prime)))
    end
    return points
end

function Base.join(scheme::ShamirSecretSharing, points)
    prime = scheme.prime
    xs, ys = zip(points...)
    return lagrange_interpolate(0, [xs...], [ys...], prime)
end
