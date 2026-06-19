using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Components of a bbs-2023 derived proof value as serialized in CBOR.
/// </summary>
/// <remarks>
/// <para>
/// This type represents the deserialized contents of a derived proof value.
/// It contains exactly what is encoded in the CBOR structure, nothing more.
/// </para>
/// <para>
/// Unlike ecdsa-sd-2023, bbs-2023 carries a single BBS proof rather than a
/// per-statement signature array, and adds a presentation header that binds
/// the proof to a presentation context.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#parsederivedproofvalue">
/// VC Data Integrity BBS Cryptosuites: parseDerivedProofValue</see>.
/// </para>
/// </remarks>
[SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Wire-format POCO representing parsed proof components.")]
public sealed class Bbs2023DerivedProofValue: IDisposable
{
    /// <summary>
    /// Gets the BBS proof over the disclosed messages.
    /// </summary>
    public required byte[] BbsProof { get; init; }

    /// <summary>
    /// Gets the label map for blank node relabeling.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Maps canonical identifiers (e.g., <c>"c14n0"</c>) to HMAC-derived identifiers
    /// (e.g., <c>"b2"</c>) using bare format without the <c>"_:"</c> prefix. The codec
    /// compresses and decompresses both sides as integers.
    /// </para>
    /// </remarks>
    public required IReadOnlyDictionary<string, string> LabelMap { get; init; }

    /// <summary>
    /// Gets the indexes of mandatory statements.
    /// </summary>
    public required IReadOnlyList<int> MandatoryIndexes { get; init; }

    /// <summary>
    /// Gets the indexes of selectively disclosed statements.
    /// </summary>
    public required IReadOnlyList<int> SelectiveIndexes { get; init; }

    /// <summary>
    /// Gets the presentation header bound into the BBS proof.
    /// </summary>
    public required byte[] PresentationHeader { get; init; }

    /// <inheritdoc/>
    public void Dispose()
    {
    }
}
