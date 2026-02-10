using System.Buffers;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Json.Sd;

/// <summary>
/// SD-JWT issuance convenience method for <c>Verifiable.Json</c>.
/// </summary>
/// <remarks>
/// <para>
/// Wraps <see cref="SdIssuance.IssueAsync"/> with the internal <see cref="SdJwtPipeline"/>
/// implementation so callers never handle delegates directly:
/// </para>
/// <code>
/// var result = await SdJwtIssuance.IssueAsync(
///     jsonBytes, disclosablePaths,
///     SaltGenerator.Create,
///     privateKey, "did:example:issuer#key-1", pool);
/// </code>
/// <para>
/// For custom serialization backends, use <see cref="SdIssuance.IssueAsync"/> in
/// <c>Verifiable.Core</c> directly with your own <see cref="RedactPayloadDelegate"/>
/// and <see cref="SignPayloadDelegate"/> implementations.
/// </para>
/// </remarks>
public static class SdJwtIssuance
{
    /// <summary>
    /// Issues an SD-JWT by redacting claims from a JSON payload and signing the result.
    /// </summary>
    /// <param name="payload">The UTF-8 JSON payload bytes.</param>
    /// <param name="disclosablePaths">
    /// Paths identifying claims that should be selectively disclosable.
    /// </param>
    /// <param name="saltFactory">Factory for generating cryptographic salt for each disclosure.</param>
    /// <param name="privateKey">The issuer's signing key.</param>
    /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
    /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
    /// <param name="hashAlgorithm">
    /// The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.
    /// </param>
    /// <param name="mediaType">
    /// The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults
    /// to <see cref="WellKnownMediaTypes.Jwt.SdJwt"/> (<c>"sd-jwt"</c>).
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An <see cref="SdTokenResult"/> with the compact JWS bytes and disclosures.</returns>
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
            SdJwtPipeline.Redact,
            SdJwtPipeline.Sign,
            saltFactory, privateKey, keyId, memoryPool,
            hashAlgorithm, mediaType, cancellationToken);
    }
}