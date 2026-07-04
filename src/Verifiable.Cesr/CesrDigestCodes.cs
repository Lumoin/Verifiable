using System.Collections.Frozen;

namespace Verifiable.Cesr;

/// <summary>
/// The well-known CESR digest derivation codes — the codes whose primitive value is a cryptographic digest,
/// and which therefore may serve as a Self-Addressing IDentifier (<see cref="CesrSaid"/>) derivation code.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR master code table, <see href="https://trustoverip.github.io/kswg-cesr-specification/#master-code-table-for-genusversion--_aaacaa-keriacdc-protocol-stack-version-200">
/// genus/version <c>-_AAACAA</c></see>: the 256-bit digests (codes <c>E</c>–<c>I</c>) render to 44-character
/// primitives and the 512-bit digests (codes <c>0D</c>–<c>0G</c>) to 88-character primitives. Naming the codes
/// here keeps the bare two- and one-character wire strings out of calling code. Which of these a given build
/// can actually compute depends on the registered digest seam; <see cref="CesrSaid"/> owns that narrower set.
/// </para>
/// </remarks>
public static class CesrDigestCodes
{
    /// <summary>The Blake3-256 digest code (<c>E</c>).</summary>
    public static string Blake3Bits256 { get; } = "E";

    /// <summary>The Blake2b-256 digest code (<c>F</c>).</summary>
    public static string Blake2bBits256 { get; } = "F";

    /// <summary>The Blake2s-256 digest code (<c>G</c>).</summary>
    public static string Blake2sBits256 { get; } = "G";

    /// <summary>The SHA3-256 digest code (<c>H</c>).</summary>
    public static string Sha3Bits256 { get; } = "H";

    /// <summary>The SHA2-256 digest code (<c>I</c>).</summary>
    public static string Sha2Bits256 { get; } = "I";

    /// <summary>The Blake3-512 digest code (<c>0D</c>).</summary>
    public static string Blake3Bits512 { get; } = "0D";

    /// <summary>The Blake2b-512 digest code (<c>0E</c>).</summary>
    public static string Blake2bBits512 { get; } = "0E";

    /// <summary>The SHA3-512 digest code (<c>0F</c>).</summary>
    public static string Sha3Bits512 { get; } = "0F";

    /// <summary>The SHA2-512 digest code (<c>0G</c>).</summary>
    public static string Sha2Bits512 { get; } = "0G";

    /// <summary>
    /// Every CESR digest derivation code defined by the master code table.
    /// </summary>
    private static FrozenSet<string> AllDigestCodes { get; } = new[]
    {
        Blake3Bits256, Blake2bBits256, Blake2sBits256, Sha3Bits256, Sha2Bits256,
        Blake3Bits512, Blake2bBits512, Sha3Bits512, Sha2Bits512
    }.ToFrozenSet();


    /// <summary>
    /// Whether the given stable code is a CESR digest derivation code (and so an admissible SAID code) per the
    /// master code table. Being a digest code does not by itself imply the running build can compute it.
    /// </summary>
    /// <param name="code">The stable (hard) code.</param>
    /// <returns><see langword="true"/> when the code names a digest.</returns>
    public static bool IsDigestCode(string code)
    {
        ArgumentNullException.ThrowIfNull(code);

        return AllDigestCodes.Contains(code);
    }
}
