using System;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Components of an ecdsa-sd-2023 base proof value as serialized in CBOR.
/// </summary>
/// <remarks>
/// <para>
/// This type represents the deserialized contents of a base proof value.
/// It contains exactly what is encoded in the CBOR structure, nothing more.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#parsebaseproofvalue">
/// VC Data Integrity ECDSA Cryptosuites: parseBaseProofValue</see>.
/// </para>
/// </remarks>
public sealed class BaseProofValue: IDisposable
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
    /// Gets the HMAC key used for blank node relabeling.
    /// </summary>
    public required byte[] HmacKey { get; init; }

    /// <summary>
    /// Gets the signatures for each non-mandatory statement.
    /// </summary>
    public required IReadOnlyList<Signature> Signatures { get; init; }

    /// <summary>
    /// Gets the mandatory JSON Pointers.
    /// </summary>
    public required IReadOnlyList<JsonPointer.JsonPointer> MandatoryPointers { get; init; }

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