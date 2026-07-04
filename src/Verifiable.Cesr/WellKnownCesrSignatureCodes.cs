using System;
using Verifiable.Cryptography.Text;

namespace Verifiable.Cesr;

/// <summary>
/// The well-known CESR indexed-signature derivation codes — the codes an attached signature in a signature group
/// carries, pairing a signature with the index of the signing key that made it. Naming them keeps the bare wire
/// strings out of encoding code (a signer framing a signature group, a test minting one).
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR master code table, <see href="https://trustoverip.github.io/kswg-cesr-specification/#master-code-table-for-genusversion--_aaacaa-keriacdc-protocol-stack-version-200">
/// genus/version <c>-_AAACAA</c></see>. Only Ed25519 is named today; other algorithms are added here as the build
/// gains the ability to produce their signatures. The sizing of each code is in <see cref="CesrIndexedCodeTables"/>.
/// The codes are case-sensitive Base64URL primitives, so the comparisons here are ordinal.
/// </para>
/// </remarks>
public static class WellKnownCesrSignatureCodes
{
    /// <summary>The UTF-8 source literal of <see cref="Ed25519"/>.</summary>
    public static ReadOnlySpan<byte> Ed25519Utf8 => "A"u8;

    /// <summary>
    /// The Ed25519 indexed-signature code (<c>A</c>): a single- or dual-indexed Ed25519 signature (the index is
    /// the signing key's position in the current-key list; a distinct prior-rotation index may also be carried).
    /// </summary>
    public static string Ed25519 { get; } = Utf8Constants.ToInternedString(Ed25519Utf8);

    /// <summary>The UTF-8 source literal of <see cref="Ed25519CurrentIndexOnly"/>.</summary>
    public static ReadOnlySpan<byte> Ed25519CurrentIndexOnlyUtf8 => "B"u8;

    /// <summary>
    /// The current-list-only Ed25519 indexed-signature code (<c>B</c>): an Ed25519 signature whose index refers
    /// only to the current-key list, carrying no prior-rotation index.
    /// </summary>
    public static string Ed25519CurrentIndexOnly { get; } = Utf8Constants.ToInternedString(Ed25519CurrentIndexOnlyUtf8);


    /// <summary>
    /// Whether <paramref name="code"/> is <see cref="Ed25519"/>.
    /// </summary>
    /// <param name="code">The indexed-signature code.</param>
    /// <returns><see langword="true"/> if <paramref name="code"/> is <see cref="Ed25519"/>; otherwise, <see langword="false"/>.</returns>
    public static bool IsEd25519(string code) => Equals(code, Ed25519);


    /// <summary>
    /// Whether <paramref name="code"/> is <see cref="Ed25519CurrentIndexOnly"/>.
    /// </summary>
    /// <param name="code">The indexed-signature code.</param>
    /// <returns><see langword="true"/> if <paramref name="code"/> is <see cref="Ed25519CurrentIndexOnly"/>; otherwise, <see langword="false"/>.</returns>
    public static bool IsEd25519CurrentIndexOnly(string code) => Equals(code, Ed25519CurrentIndexOnly);


    /// <summary>
    /// Returns the equivalent interned instance for the given code, or the original instance if none match. This
    /// conversion is optional but allows reference-equality comparisons elsewhere.
    /// </summary>
    /// <param name="code">The code to canonicalize.</param>
    /// <returns>The equivalent interned instance of <paramref name="code"/>, or the original instance if none match.</returns>
    public static string GetCanonicalizedValue(string code) => code switch
    {
        string _ when IsEd25519(code) => Ed25519,
        string _ when IsEd25519CurrentIndexOnly(code) => Ed25519CurrentIndexOnly,
        string _ => code
    };


    /// <summary>
    /// Returns a value that indicates whether the two codes are the same, comparing ordinally (CESR codes are
    /// case-sensitive Base64URL).
    /// </summary>
    /// <param name="codeA">The first code to compare.</param>
    /// <param name="codeB">The second code to compare.</param>
    /// <returns><see langword="true"/> if the codes are the same; otherwise, <see langword="false"/>.</returns>
    public static bool Equals(string codeA, string codeB)
    {
        return ReferenceEquals(codeA, codeB) || StringComparer.Ordinal.Equals(codeA, codeB);
    }
}
