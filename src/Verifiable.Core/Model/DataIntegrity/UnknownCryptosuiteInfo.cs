using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Represents an unknown or unsupported cryptosuite encountered during deserialization.
/// </summary>
/// <remarks>
/// <para>
/// This class enables the "parse-as-far-as-possible" pattern, allowing documents
/// containing unknown cryptosuites to be deserialized and round-tripped without
/// data loss. The original cryptosuite name is preserved for serialization.
/// </para>
/// <para>
/// Code that processes proofs should check for this type and handle it appropriately,
/// typically by rejecting verification attempts while still allowing the document
/// to be read and displayed.
/// </para>
/// <para>
/// <strong>Usage:</strong>
/// </para>
/// <code>
/// if(proof.Cryptosuite is UnknownCryptosuiteInfo unknown)
/// {
///     //Log or report that this cryptosuite is not supported.
///     Console.WriteLine($"Unsupported cryptosuite: {unknown.CryptosuiteName}");
/// }
/// </code>
/// </remarks>
public sealed class UnknownCryptosuiteInfo: CryptosuiteInfo
{
    private static readonly IReadOnlyList<string> EmptyContexts = Array.Empty<string>();

    /// <summary>
    /// Creates an unknown cryptosuite info with the specified name.
    /// </summary>
    /// <param name="cryptosuiteName">The cryptosuite identifier from the proof.</param>
    [SetsRequiredMembers]
    public UnknownCryptosuiteInfo(string cryptosuiteName)
    {
        CryptosuiteName = cryptosuiteName;
        Canonicalization = CanonicalizationAlgorithm.None;
        HashAlgorithm = "Unknown";
        SignatureAlgorithm = CryptoAlgorithm.Unknown;
        Contexts = EmptyContexts;
        IsCompatibleWith = _ => false;
    }
}