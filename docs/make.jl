using CryptoTools
using Documenter

DocMeta.setdocmeta!(CryptoTools, :DocTestSetup, :(using CryptoTools); recursive=true)

makedocs(;
    modules=[CryptoTools],
    authors="Chris du Plessis",
    repo="https://github.com/Maelstrom6/CryptoTools.jl/blob/{commit}{path}#{line}",
    sitename="CryptoTools.jl",
    format=Documenter.HTML(;
        prettyurls=get(ENV, "CI", "false") == "true",
        canonical="https://Maelstrom6.github.io/CryptoTools.jl",
        assets=String[],
    ),
    pages=[
        "Home" => "index.md",
    ],
)

deploydocs(;
    repo="github.com/Maelstrom6/CryptoTools.jl",
)
