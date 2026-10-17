using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// The JWA algorithm the library names a key type by (<see cref="CryptoFormatConversions.ResolveJwaAlgorithm"/>): the
/// algorithm, or the resolution that the library names the key type by none.
/// </summary>
[DebuggerDisplay("JwaAlgorithmResolution Algorithm={Algorithm,nq}")]
public sealed record JwaAlgorithmResolution
{
    /// <summary>The resolution naming no algorithm, for a key type the library names by none.</summary>
    public static JwaAlgorithmResolution NoneNamed { get; } = new(algorithm: null);


    /// <summary>The JWA algorithm named; <see langword="null"/> when none is.</summary>
    public string? Algorithm { get; }


    /// <summary>Whether an algorithm is named.</summary>
    [MemberNotNullWhen(true, nameof(Algorithm))]
    public bool IsNamed => Algorithm is not null;


    /// <summary>Creates a resolution.</summary>
    /// <param name="algorithm">The JWA algorithm named, or <see langword="null"/> for none.</param>
    private JwaAlgorithmResolution(string? algorithm)
    {
        Algorithm = algorithm;
    }


    /// <summary>The resolution naming <paramref name="algorithm"/>.</summary>
    /// <param name="algorithm">The JWA algorithm named.</param>
    /// <returns>The resolution.</returns>
    public static JwaAlgorithmResolution Named(string algorithm)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);

        return new JwaAlgorithmResolution(algorithm);
    }
}
