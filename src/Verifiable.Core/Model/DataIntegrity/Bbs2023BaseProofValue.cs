using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Components of a bbs-2023 base proof value as serialized in CBOR.
/// </summary>
/// <remarks>
/// <para>
/// This type represents the deserialized contents of a base proof value.
/// It contains exactly what is encoded in the CBOR structure, nothing more.
/// </para>
/// <para>
/// Unlike ecdsa-sd-2023, bbs-2023 carries a single BBS signature over all
/// messages rather than a per-statement signature array, and has no ephemeral
/// key. Selective disclosure is achieved through BBS proof derivation.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#parsebaseproofvalue">
/// VC Data Integrity BBS Cryptosuites: parseBaseProofValue</see>.
/// </para>
/// </remarks>
[SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Wire-format POCO representing parsed proof components.")]
public sealed class Bbs2023BaseProofValue: IDisposable
{
    /// <summary>
    /// Gets the issuer's BBS signature over the BBS header and messages.
    /// </summary>
    /// <remarks>
    /// This is an 80-byte BBS signature.
    /// </remarks>
    public required byte[] BbsSignature { get; init; }

    /// <summary>
    /// Gets the BBS header bound into the signature.
    /// </summary>
    /// <remarks>
    /// This is 64 bytes formed as <c>proofHash || mandatoryHash</c>.
    /// </remarks>
    public required byte[] BbsHeader { get; init; }

    /// <summary>
    /// Gets the issuer's BLS12-381 G2 public key bytes.
    /// </summary>
    /// <remarks>
    /// These are the raw 96-byte G2 public key bytes after the multicodec header
    /// has been stripped during parsing.
    /// </remarks>
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// Gets the HMAC key used for blank node relabeling.
    /// </summary>
    /// <remarks>
    /// This is a 32-byte key for SHA-256.
    /// </remarks>
    public required byte[] HmacKey { get; init; }

    /// <summary>
    /// Gets the mandatory JSON Pointers.
    /// </summary>
    public required IReadOnlyList<JsonPointer.JsonPointer> MandatoryPointers { get; init; }

    /// <inheritdoc/>
    public void Dispose()
    {
    }
}
