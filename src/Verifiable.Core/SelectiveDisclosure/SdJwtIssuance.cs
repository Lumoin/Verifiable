using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Issues SD-JWT tokens by computing disclosure digests, assembling the payload
/// with <c>_sd</c> and <c>_sd_alg</c>, signing as JWS, and wrapping into <see cref="SdJwtToken"/>.
/// </summary>
/// <remarks>
/// <para>
/// This class encapsulates the issuer-side SD-JWT construction pipeline:
/// </para>
/// <list type="number">
/// <item><description>Serialize each <see cref="SdDisclosure"/> via a caller-supplied
/// <see cref="SerializeDisclosureDelegate{TDisclosure}"/>.</description></item>
/// <item><description>Compute each encoded disclosure's digest via a caller-supplied
/// <see cref="ComputeDisclosureDigestDelegate"/>.</description></item>
/// <item><description>Place <c>_sd</c> digest arrays at the correct locations in the
/// caller's claims tree via <see cref="DigestPlacement.PlaceDigests"/>, and add
/// <c>_sd_alg</c> at the root.</description></item>
/// <item><description>Create an <see cref="UnsignedJwt"/> and sign it via
/// <see cref="JwtSigningExtensions.SignAsync"/>.</description></item>
/// <item><description>Serialize to compact JWS and wrap with disclosures into
/// <see cref="SdJwtToken"/>.</description></item>
/// </list>
/// <para>
/// Per <see href="https://datatracker.ietf.org/doc/rfc9901/#section-5.1">RFC 9901 Section 5.1</see>,
/// the <c>_sd</c> array is a sibling of the claims it replaces. This method places all
/// digests in the root-level <c>_sd</c> array, which is correct for flat payloads
/// (e.g., SD-JWT VC with <c>iss</c>, <c>vct</c>, top-level claims per
/// <see href="https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/">SD-JWT VC</see>).
/// For nested payloads (e.g., W3C VCs with <c>credentialSubject</c>), use
/// <c>SdJwtClaimRedaction.Redact</c> in <c>Verifiable.Json</c> which embeds <c>_sd</c>
/// arrays at the correct nesting levels.
/// </para>
/// <para>
/// All serialization is performed via caller-supplied delegates, keeping this class
/// independent of concrete JSON libraries. The two delegates mirror the two-phase
/// digest pipeline: <see cref="SerializeDisclosureDelegate{TDisclosure}"/> encodes
/// the disclosure, then <see cref="ComputeDisclosureDigestDelegate"/> hashes the
/// encoded form. Verifiers reuse <see cref="ComputeDisclosureDigestDelegate"/> alone
/// since they already have the encoded disclosure strings from the wire format.
/// </para>
/// <para>
/// See <see href="https://datatracker.ietf.org/doc/rfc9901/">RFC 9901 (SD-JWT)</see>
/// and <see href="https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/">SD-JWT VC</see>.
/// </para>
/// </remarks>
public static class SdJwtIssuance
{
    /// <summary>
    /// Issues an SD-JWT token by computing digests, assembling the payload, signing, and wrapping.
    /// </summary>
    /// <param name="claims">
    /// Non-redacted claims to include directly in the JWT payload. These are always
    /// visible to verifiers (e.g., <c>iss</c>, <c>vct</c>, <c>iat</c>).
    /// All digests are placed in the root-level <c>_sd</c> array. For correct nested
    /// <c>_sd</c> placement, use <c>SdJwtClaimRedaction.Redact</c> instead.
    /// </param>
    /// <param name="disclosures">The selectively disclosable claims.</param>
    /// <param name="serializeDisclosure">
    /// Delegate for serializing a single disclosure to its encoded form.
    /// The issuer calls this first, then passes the result to <paramref name="computeDigest"/>.
    /// </param>
    /// <param name="computeDigest">
    /// Delegate for computing the digest of an already-encoded disclosure string.
    /// This same delegate can be reused by verifiers to independently confirm that
    /// presented disclosures match the signed <c>_sd</c> array.
    /// </param>
    /// <param name="privateKey">The issuer's signing key.</param>
    /// <param name="keyId">The key identifier for the <c>kid</c> header parameter.</param>
    /// <param name="hashAlgorithm">
    /// The hash algorithm identifier in IANA format (e.g., <c>"sha-256"</c>).
    /// Stored in the <c>_sd_alg</c> claim per
    /// <see href="https://datatracker.ietf.org/doc/rfc9901/#section-5.1.1">RFC 9901 Section 5.1.1</see>.
    /// Use <see cref="WellKnownHashAlgorithms.Sha256Iana"/>.
    /// </param>
    /// <param name="mediaType">The media type for the <c>typ</c> header (e.g., <c>"vc+sd-jwt"</c>).</param>
    /// <param name="headerSerializer">Delegate for serializing the JWT header to UTF-8 bytes.</param>
    /// <param name="payloadSerializer">Delegate for serializing the JWT payload to UTF-8 bytes.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An <see cref="SdJwtToken"/> containing the signed issuer JWT and all disclosures.</returns>
    public static async ValueTask<SdJwtToken> IssueAsync(
        JwtPayload claims,
        IReadOnlyList<SdDisclosure> disclosures,
        SerializeDisclosureDelegate<SdDisclosure> serializeDisclosure,
        ComputeDisclosureDigestDelegate computeDigest,
        PrivateKeyMemory privateKey,
        string keyId,
        string hashAlgorithm,
        string mediaType,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        EncodeDelegate encoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(disclosures);
        ArgumentNullException.ThrowIfNull(serializeDisclosure);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentException.ThrowIfNullOrWhiteSpace(hashAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(mediaType);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //Serialize each disclosure then compute its digest.
        string[] digests = disclosures
            .Select(d => serializeDisclosure(d, encoder))
            .Select(encoded => computeDigest(encoded, encoder))
            .ToArray();

        //Place all digests at the root level and add _sd_alg.
        var payload = new JwtPayload(claims);
        var digestsByParent = new Dictionary<CredentialPath, List<string>>
        {
            [CredentialPath.Root] = [.. digests]
        };

        DigestPlacement.PlaceDigests(payload, digestsByParent, hashAlgorithm);

        //Sign via UnsignedJwt -> SignAsync pipeline.
        UnsignedJwt unsigned = UnsignedJwt.ForSigning(privateKey, keyId, payload, mediaType);

        using JwsMessage jwsMessage = await unsigned.SignAsync(
            privateKey, headerSerializer, payloadSerializer,
            encoder, memoryPool, cancellationToken).ConfigureAwait(false);

        string issuerJwt = JwsSerialization.SerializeCompact(jwsMessage, encoder);

        return new SdJwtToken(issuerJwt, disclosures.ToList());
    }
}