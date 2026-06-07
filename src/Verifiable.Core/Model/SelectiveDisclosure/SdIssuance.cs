using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Redacts selectively disclosable claims from a raw payload, producing a ready-to-sign
/// payload and the corresponding disclosures.
/// </summary>
/// <remarks>
/// <para>
/// This delegate defines the contract between <see cref="SdIssuance"/> and format-specific
/// redaction logic. Implementations handle all format internals: parsing, disclosure creation,
/// digest computation, and digest placement.
/// </para>
/// <para>
/// Format libraries implement this internally and wire it into their convenience
/// <c>IssueAsync</c> method. Custom format implementations (e.g., MessagePack) provide
/// their own method matching this signature, call <see cref="SdIssuance.IssueAsync"/>
/// directly, and wrap it in a similar convenience method.
/// </para>
/// </remarks>
/// <param name="payload">The raw payload bytes in the source format.</param>
/// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
/// <param name="generateSalt">
/// Delegate that allocates and fills a <see cref="Salt"/> per disclosable claim.
/// Each returned salt's ownership transfers to the disclosure produced from it.
/// </param>
/// <param name="hashAlgorithm">The hash algorithm identifier in IANA format (e.g., <c>"sha-256"</c>).</param>
/// <param name="decoyOptions">
/// Optional decoy-digest configuration (count policy plus per-call state) threaded explicitly from the
/// issuance entry point. <see cref="DecoyDigestOptions.None"/> (the default) means no decoys. The implementation invokes the policy
/// once per <c>_sd</c> location. Passed as a parameter — never captured by a closure.
/// </param>
/// <returns>
/// A tuple of the redacted payload bytes (ready to sign, in the same format as the input)
/// and the list of disclosures produced.
/// </returns>
public delegate (ReadOnlyMemory<byte> RedactedPayload, IReadOnlyList<SdDisclosure> Disclosures) RedactPayloadDelegate(
    ReadOnlyMemory<byte> payload,
    IReadOnlySet<CredentialPath> disclosablePaths,
    GenerateDisclosureSaltDelegate generateSalt,
    string hashAlgorithm,
    DecoyDigestOptions decoyOptions);


/// <summary>
/// Signs a redacted payload and produces the final serialized token bytes.
/// </summary>
/// <remarks>
/// <para>
/// This delegate defines the contract between <see cref="SdIssuance"/> and format-specific
/// signing logic. Implementations handle header construction, cryptographic signing, and
/// wire format serialization.
/// </para>
/// <para>
/// Format libraries implement this internally and wire it into their convenience
/// <c>IssueAsync</c> method. Custom format implementations provide their own method
/// matching this signature.
/// </para>
/// </remarks>
/// <param name="signingDelegate">
/// The signing function to use, threaded explicitly so the format-specific signer is passed as a
/// method group rather than captured by a closure.
/// </param>
/// <param name="redactedPayload">The redacted payload bytes to sign.</param>
/// <param name="hashAlgorithm">The hash algorithm identifier in IANA format.</param>
/// <param name="mediaType">
/// The media type for the token header. Empty string signals the implementation to use
/// its format-specific default.
/// </param>
/// <param name="privateKey">The issuer's signing key.</param>
/// <param name="keyId">The key identifier for the token header.</param>
/// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The signed token in its wire format encoding.</returns>
public delegate ValueTask<ReadOnlyMemory<byte>> SignPayloadDelegate(
    SigningDelegate signingDelegate,
    ReadOnlyMemory<byte> redactedPayload,
    string hashAlgorithm,
    string mediaType,
    PrivateKeyMemory privateKey,
    string keyId,
    MemoryPool<byte> memoryPool,
    CancellationToken cancellationToken);


/// <summary>
/// The result of format-agnostic SD token issuance, containing the signed token bytes
/// and all disclosures.
/// </summary>
/// <remarks>
/// <para>
/// Format-specific convenience methods return this directly. Callers that need
/// format-specific types (e.g., <c>SdJwtToken</c> or <c>SdCwtToken</c>) convert from
/// the <see cref="SignedToken"/> bytes at the boundary.
/// </para>
/// </remarks>
/// <param name="SignedToken">The signed token bytes in the format-specific wire encoding.</param>
/// <param name="Disclosures">The selectively disclosable claims produced during redaction.</param>
public sealed record SdTokenResult(
    ReadOnlyMemory<byte> SignedToken,
    IReadOnlyList<SdDisclosure> Disclosures);


/// <summary>
/// Format-agnostic selective disclosure token issuance.
/// </summary>
/// <remarks>
/// <para>
/// Orchestrates the two-phase issuance pipeline without depending on any serialization library:
/// </para>
/// <list type="number">
/// <item><description>
/// <strong>Redact</strong> via <see cref="RedactPayloadDelegate"/>: A format-specific
/// implementation parses the payload, creates disclosures, computes digests, and produces
/// a ready-to-sign payload with digest placeholders.
/// </description></item>
/// <item><description>
/// <strong>Sign</strong> via <see cref="SignPayloadDelegate"/>: A format-specific
/// implementation constructs headers, signs the redacted payload, and serializes the result.
/// </description></item>
/// </list>
/// <para>
/// Most callers use format-specific convenience methods instead of calling this directly:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <c>SdJwtIssuance.IssueAsync</c> in <c>Verifiable.Json</c> for SD-JWT.
/// </description></item>
/// <item><description>
/// <c>SdCwtIssuance.IssueAsync</c> in <c>Verifiable.Cbor</c> for SD-CWT.
/// </description></item>
/// </list>
/// <para>
/// This method is the extensibility point for custom serialization formats. A custom
/// format library implements <see cref="RedactPayloadDelegate"/> and
/// <see cref="SignPayloadDelegate"/>, calls this method, and wraps it in a convenience
/// method with the same delegate-free signature as the built-in format libraries.
/// </para>
/// </remarks>
public static class SdIssuance
{
    /// <summary>
    /// Issues a selective disclosure token by redacting claims and signing the result.
    /// </summary>
    /// <param name="payload">The raw payload bytes (JSON, CBOR, or other format).</param>
    /// <param name="disclosablePaths">
    /// Paths identifying claims that should be selectively disclosable.
    /// </param>
    /// <param name="redact">
    /// Format-specific delegate that parses the payload, creates disclosures, and
    /// produces a ready-to-sign payload with digest placeholders.
    /// </param>
    /// <param name="sign">
    /// Format-specific delegate that constructs headers, signs the redacted payload,
    /// and serializes the result.
    /// </param>
    /// <param name="generateSalt">
    /// Delegate that allocates and fills a <see cref="Salt"/> per disclosable claim.
    /// Each returned salt's ownership transfers to the disclosure produced from it;
    /// the disclosures are returned in the result for the caller to own.
    /// </param>
    /// <param name="privateKey">The issuer's signing key.</param>
    /// <param name="keyId">The key identifier for the token header.</param>
    /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
    /// <param name="hashAlgorithm">
    /// The hash algorithm identifier in IANA format. Defaults to
    /// <see cref="WellKnownHashAlgorithms.Sha256Iana"/> (<c>"sha-256"</c>).
    /// </param>
    /// <param name="signingDelegate">The signing function, threaded to <paramref name="sign"/> explicitly (no closure).</param>
    /// <param name="mediaType">
    /// The media type for the token header. When <see langword="null"/>, the format-specific
    /// signer uses its own default.
    /// </param>
    /// <param name="decoyOptions">Optional decoy-digest configuration, threaded to <paramref name="redact"/> explicitly (no closure). <see cref="DecoyDigestOptions.None"/> (the default) means no decoys.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An <see cref="SdTokenResult"/> with the signed token bytes and disclosures.</returns>
    public static async ValueTask<SdTokenResult> IssueAsync(
        ReadOnlyMemory<byte> payload,
        IReadOnlySet<CredentialPath> disclosablePaths,
        RedactPayloadDelegate redact,
        SignPayloadDelegate sign,
        GenerateDisclosureSaltDelegate generateSalt,
        PrivateKeyMemory privateKey,
        string keyId,
        MemoryPool<byte> memoryPool,
        SigningDelegate signingDelegate,
        string? hashAlgorithm = null,
        string? mediaType = null,
        DecoyDigestOptions decoyOptions = default,
        CancellationToken cancellationToken = default)
    {
        (SdTokenResult result, _) = await IssueVerboseAsync(
            payload, disclosablePaths, redact, sign, generateSalt,
            privateKey, keyId, memoryPool, signingDelegate, hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

        return result;
    }


    /// <summary>
    /// Issues a selective disclosure token and additionally returns the redacted payload —
    /// the parameter-taking canonical body that <see cref="IssueAsync"/> delegates to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The redacted payload is the ready-to-sign bytes the <paramref name="redact"/> step
    /// produced (mandatory claims with digest placeholders) and the <paramref name="sign"/>
    /// step covered. <see cref="IssueAsync"/> discards it; this overload exposes it for
    /// spec-vector validation, where a test compares the signed bytes against a known vector.
    /// It is the redacted (public) claims set, not sensitive material — the disclosures, which
    /// own the salts, are carried in the returned <see cref="SdTokenResult"/> and not copied.
    /// </para>
    /// </remarks>
    /// <param name="payload">The raw payload bytes (JSON, CBOR, or other format).</param>
    /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
    /// <param name="redact">Format-specific redaction delegate.</param>
    /// <param name="sign">Format-specific signing delegate.</param>
    /// <param name="generateSalt">Delegate that allocates a <see cref="Salt"/> per disclosable claim.</param>
    /// <param name="privateKey">The issuer's signing key.</param>
    /// <param name="keyId">The key identifier for the token header.</param>
    /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
    /// <param name="signingDelegate">The signing function, threaded to <paramref name="sign"/> explicitly (no closure).</param>
    /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
    /// <param name="mediaType">The media type for the token header. When <see langword="null"/>, the signer uses its default.</param>
    /// <param name="decoyOptions">Optional decoy-digest configuration, threaded to <paramref name="redact"/> explicitly (no closure). <see cref="DecoyDigestOptions.None"/> (the default) means no decoys.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issuance result and the redacted payload bytes that were signed.</returns>
    public static async ValueTask<(SdTokenResult Result, ReadOnlyMemory<byte> RedactedPayload)> IssueVerboseAsync(
        ReadOnlyMemory<byte> payload,
        IReadOnlySet<CredentialPath> disclosablePaths,
        RedactPayloadDelegate redact,
        SignPayloadDelegate sign,
        GenerateDisclosureSaltDelegate generateSalt,
        PrivateKeyMemory privateKey,
        string keyId,
        MemoryPool<byte> memoryPool,
        SigningDelegate signingDelegate,
        string? hashAlgorithm = null,
        string? mediaType = null,
        DecoyDigestOptions decoyOptions = default,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(disclosablePaths);
        ArgumentNullException.ThrowIfNull(redact);
        ArgumentNullException.ThrowIfNull(sign);
        ArgumentNullException.ThrowIfNull(generateSalt);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(memoryPool);
        ArgumentNullException.ThrowIfNull(signingDelegate);

        string resolvedHashAlgorithm = hashAlgorithm ?? WellKnownHashAlgorithms.Sha256Iana;
        string resolvedMediaType = mediaType ?? string.Empty;

        var (redactedPayload, disclosures) = redact(
            payload, disclosablePaths, generateSalt, resolvedHashAlgorithm, decoyOptions);

        //RFC 9901 §9.4: every disclosure MUST use a unique salt — a repeated salt lets a verifier
        //correlate the disclosures and defeats the unlinkability the salt exists to provide. This
        //guards against a broken or misconfigured salt generator; on violation the disclosures
        //(which own their salts) are disposed before the failure propagates.
        EnsureDistinctSalts(disclosures);

        ReadOnlyMemory<byte> signedToken = await sign(
            signingDelegate, redactedPayload, resolvedHashAlgorithm, resolvedMediaType,
            privateKey, keyId, memoryPool, cancellationToken).ConfigureAwait(false);

        return (new SdTokenResult(signedToken, disclosures), redactedPayload);
    }


    /// <summary>
    /// Verifies that the salt generator produced a unique salt for every disclosure
    /// (RFC 9901 §9.4). Disposes every disclosure before throwing on a violation, since the
    /// caller never receives them.
    /// </summary>
    private static void EnsureDistinctSalts(IReadOnlyList<SdDisclosure> disclosures)
    {
        //SdDisclosure equality is salt-bytes equality, so a HashSet rejects a repeated salt.
        var seen = new HashSet<SdDisclosure>(disclosures.Count);
        foreach(SdDisclosure disclosure in disclosures)
        {
            if(!seen.Add(disclosure))
            {
                foreach(SdDisclosure toDispose in disclosures)
                {
                    toDispose.Dispose();
                }

                throw new InvalidOperationException(
                    "The salt generator produced a duplicate salt; each disclosure must use a unique " +
                    "salt (RFC 9901 §9.4). A repeated salt would let a verifier correlate disclosures.");
            }
        }
    }
}
