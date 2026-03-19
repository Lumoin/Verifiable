using System.Buffers;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;

namespace Verifiable.Json.Sd;

/// <summary>
/// SD-JWT issuance convenience method for <c>Verifiable.Json</c>.
/// </summary>
/// <remarks>
/// <para>
/// Wraps <see cref="SdIssuance.IssueAsync"/> with the internal <see cref="SdJwtPipeline"/>
/// implementation so callers do not handle redact/sign delegates directly. The
/// application supplies a <see cref="GenerateDisclosureSaltDelegate"/> bound to its
/// entropy backend and memory pool:
/// </para>
/// <code>
/// var result = await SdJwtIssuance.IssueAsync(
///     jsonBytes, disclosablePaths,
///     () => Salt.Generate(byteLength: 16, tag, pool),
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
    /// <param name="generateSalt">
    /// Delegate that allocates and fills a <see cref="Salt"/> per disclosable claim.
    /// Each returned salt's ownership transfers to a new <see cref="SdDisclosure"/>;
    /// the returned <see cref="SdTokenResult"/> carries the disclosures, and the caller
    /// owns them (typically by handing them to an <see cref="SdToken{TEnvelope}"/>
    /// whose disposal flows to them).
    /// </param>
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
        GenerateDisclosureSaltDelegate generateSalt,
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
            generateSalt, privateKey, keyId, memoryPool,
            hashAlgorithm, mediaType, cancellationToken);
    }
}
