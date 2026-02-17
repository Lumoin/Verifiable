using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;

namespace Verifiable.Cbor.Sd;

/// <summary>
/// SD-CWT issuance convenience method for <c>Verifiable.Cbor</c>.
/// </summary>
/// <remarks>
/// <para>
/// Wraps <see cref="SdIssuance.IssueAsync"/> with the internal <see cref="SdCwtPipeline"/>
/// implementation so callers never handle delegates directly:
/// </para>
/// <code>
/// var result = await SdCwtIssuance.IssueAsync(
///     cborBytes, disclosablePaths,
///     SaltGenerator.Create,
///     privateKey, "did:example:issuer#key-1", pool);
/// </code>
/// <para>
/// For custom serialization backends, use <see cref="SdIssuance.IssueAsync"/> in
/// <c>Verifiable.Core</c> directly with your own <see cref="RedactPayloadDelegate"/>
/// and <see cref="SignPayloadDelegate"/> implementations.
/// </para>
/// </remarks>
public static class SdCwtIssuance
{
    /// <summary>
    /// Issues an SD-CWT by redacting claims from a CBOR payload and signing the result.
    /// </summary>
    /// <param name="payload">The CBOR-encoded CWT claims set bytes.</param>
    /// <param name="disclosablePaths">
    /// Paths identifying claims that should be selectively disclosable.
    /// For CWT integer keys, use the integer string representation (e.g., <c>/501</c>).
    /// </param>
    /// <param name="saltFactory">Factory for generating 128-bit cryptographic salt.</param>
    /// <param name="privateKey">The issuer's signing key.</param>
    /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
    /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
    /// <param name="hashAlgorithm">
    /// The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.
    /// </param>
    /// <param name="mediaType">
    /// The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults
    /// to <see cref="WellKnownMediaTypes.Application.SdCwt"/> (<c>"application/sd-cwt"</c>).
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An <see cref="SdTokenResult"/> with the COSE_Sign1 bytes and disclosures.</returns>
    public static ValueTask<SdTokenResult> IssueAsync(
        ReadOnlyMemory<byte> payload,
        IReadOnlySet<CredentialPath> disclosablePaths,
        SaltFactoryDelegate saltFactory,
        PrivateKeyMemory privateKey,
        string keyId,
        MemoryPool<byte> memoryPool,
        string? hashAlgorithm = null,
        string? mediaType = null,
        CancellationToken cancellationToken = default)
    {
        return SdIssuance.IssueAsync(
            payload, disclosablePaths,
            SdCwtPipeline.Redact,
            SdCwtPipeline.Sign,
            saltFactory, privateKey, keyId, memoryPool,
            hashAlgorithm, mediaType, cancellationToken);
    }
}