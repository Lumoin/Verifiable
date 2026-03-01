using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Components of an ecdsa-sd-2023 derived proof value as serialized in CBOR.
/// </summary>
/// <remarks>
/// <para>
/// This type represents the deserialized contents of a derived proof value.
/// It contains exactly what is encoded in the CBOR structure, nothing more.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#parsederivedproofvalue">
/// VC Data Integrity ECDSA Cryptosuites: parseDerivedProofValue</see>.
/// </para>
/// </remarks>
public sealed class DerivedProofValue: IDisposable
{
    /// <summary>
    /// Gets the issuer's base signature.
    /// </summary>
    public required Signature BaseSignature { get; init; }

    /// <summary>
    /// Gets the ephemeral public key with multicodec header.
    /// </summary>
    public required PublicKeyMemory EphemeralPublicKey { get; init; }

    /// <summary>
    /// Gets the signatures for disclosed statements.
    /// </summary>
    public required IReadOnlyList<Signature> Signatures { get; init; }

    /// <summary>
    /// Gets the label map for blank node relabeling.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Maps canonical identifiers (e.g., <c>"c14n0"</c>) to HMAC-derived identifiers
    /// (e.g., <c>"uXYZ..."</c>) using bare format without the <c>"_:"</c> prefix, per
    /// the compressed label map format in
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#compresslabelmap">
    /// VC Data Integrity ECDSA §3.5.5 compressLabelMap</see>.
    /// </para>
    /// </remarks>
    public required IReadOnlyDictionary<string, string> LabelMap { get; init; }

    /// <summary>
    /// Gets the indexes of mandatory statements.
    /// </summary>
    public required IReadOnlyList<int> MandatoryIndexes { get; init; }

    /// <inheritdoc/>
    public void Dispose()
    {
        BaseSignature.Dispose();
        EphemeralPublicKey.Dispose();

        foreach(var signature in Signatures)
        {
            signature.Dispose();
        }
    }
}