using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.Jose;
using JCoseHeaderSerializer = Verifiable.JCose.JwtHeaderSerializer;
using JCosePayloadSerializer = Verifiable.JCose.JwtPayloadSerializer;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Extension methods for securing Verifiable Credentials using SD-JWT.
/// </summary>
/// <remarks>
/// <para>
/// These extensions provide the credential-level API for SD-JWT enveloping as defined by
/// <see href="https://www.w3.org/TR/vc-jose-cose/#with-sd-jwt">W3C VC-JOSE-COSE Section 3.2</see>.
/// </para>
/// <para>
/// <strong>Specification landscape:</strong> Four specifications govern how SD-JWT relates
/// to Verifiable Credentials. Each has a distinct role, and understanding which applies
/// is essential for correct implementation.
/// </para>
/// <code>
/// ┌──────────────────────────────────────────────────────────────────────────────┐
/// │ Specification                        Payload   Signing  SD   Role           │
/// ├──────────────────────────────────────────────────────────────────────────────┤
/// │ VC Data Model 2.0                    VC only   abstract  -  Defines what    │
/// │ https://www.w3.org/TR/               ...                    a VC is.        │
/// │   vc-data-model-2.0/                                                        │
/// │                                                                             │
/// │ VC-JOSE-COSE                         VC only   YES      partial             │
/// │ https://www.w3.org/TR/               ...                    How to sign     │
/// │   vc-jose-cose/                                             VCs with JOSE,  │
/// │                                                             SD-JWT, COSE.   │
/// │                                                                             │
/// │ SD-JWT VC (draft)                    VC only   YES      YES                 │
/// │ https://datatracker.ietf.org/        ...                    VC profile      │
/// │   doc/draft-ietf-oauth-sd-jwt-vc/                           over SD-JWT.    │
/// │                                                                             │
/// │ RFC 9901 (SD-JWT)                    any       YES      YES                 │
/// │ https://datatracker.ietf.org/        ...                    Generic SD      │
/// │   doc/rfc9901/                                              token format.   │
/// └──────────────────────────────────────────────────────────────────────────────┘
///
/// Rule: Specs that say "VC" require a VC payload. RFC 9901 does not.
///
/// Library mapping:
///   VerifiableCredential → CredentialSdJwtExtensions.SignSdJwtAsync  (this class)
///   JwtPayload (any)     → SdJwtIssuance.IssueAsync                 (RFC 9901 flat only)
/// </code>
/// <para>
/// This class implements the VC path: it takes a <see cref="VerifiableCredential"/>,
/// serializes it via <see cref="CredentialSerializeDelegate"/>, splits it into a payload
/// with nested <c>_sd</c> digest arrays via <see cref="RedactCredentialDelegate"/>,
/// and signs the result. The media type defaults to <c>vc+sd-jwt</c> per
/// <see href="https://www.w3.org/TR/vc-jose-cose/#vc-json-sd-jwt">VC-JOSE-COSE Section 6.1.3</see>.
/// </para>
/// <para>
/// For the generic SD-JWT path (RFC 9901, flat JWT claims, no VC required), use
/// <see cref="SdJwtIssuance.IssueAsync"/> directly with a <see cref="JwtPayload"/>.
/// </para>
/// </remarks>
public static class CredentialSdJwtExtensions
{
    /// <summary>
    /// Signs the credential as an SD-JWT with selective disclosure.
    /// </summary>
    /// <param name="credential">The credential to sign.</param>
    /// <param name="disclosablePaths">
    /// The set of JSON Pointer paths identifying claims that should be selectively
    /// disclosable. Claims not in this set become mandatory (always visible).
    /// For example, <c>/credentialSubject/degree</c> makes the degree claim disclosable
    /// while <c>/issuer</c> remains mandatory. The <c>_sd</c> digest array is placed
    /// as a sibling of the replaced claims per
    /// <see href="https://datatracker.ietf.org/doc/rfc9901/#section-5.1">RFC 9901 Section 5.1</see>.
    /// </param>
    /// <param name="credentialSerializer">
    /// Delegate for serializing the credential to a JSON string.
    /// </param>
    /// <param name="redact">
    /// Delegate for splitting the serialized credential JSON into a ready-to-sign
    /// payload with embedded <c>_sd</c> digest arrays and the corresponding disclosures.
    /// The implementation in <c>Verifiable.Json</c> is <c>SdJwtClaimRedaction.Redact</c>.
    /// </param>
    /// <param name="saltFactory">
    /// Factory delegate for generating cryptographic salt for each disclosure.
    /// Use <c>() =&gt; SaltGenerator.Create()</c> for production.
    /// </param>
    /// <param name="serializeDisclosure">
    /// Delegate for serializing a disclosure to its Base64Url-encoded form.
    /// </param>
    /// <param name="computeDigest">
    /// Delegate for computing the digest of an encoded disclosure.
    /// </param>
    /// <param name="privateKey">The issuer's signing key.</param>
    /// <param name="keyId">The key identifier for the <c>kid</c> header parameter.</param>
    /// <param name="hashAlgorithm">
    /// The hash algorithm identifier in IANA format (e.g., <c>"sha-256"</c>).
    /// Stored in the <c>_sd_alg</c> claim per
    /// <see href="https://datatracker.ietf.org/doc/rfc9901/#section-5.1.1">RFC 9901 Section 5.1.1</see>.
    /// </param>
    /// <param name="headerSerializer">Delegate for serializing the JWT header to UTF-8 bytes.</param>
    /// <param name="payloadSerializer">Delegate for serializing the JWT payload to UTF-8 bytes.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
    /// <param name="mediaType">
    /// Optional media type for the <c>typ</c> header. Defaults to
    /// <see cref="WellKnownMediaTypes.Jwt.VcSdJwt"/> (<c>vc+sd-jwt</c>) per
    /// <see href="https://www.w3.org/TR/vc-jose-cose/#vc-json-sd-jwt">VC-JOSE-COSE Section 6.1.3</see>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An <see cref="SdJwtToken"/> containing the signed issuer JWT and all disclosures.</returns>
    public static async ValueTask<SdJwtToken> SignSdJwtAsync(
        this VerifiableCredential credential,
        IReadOnlySet<CredentialPath> disclosablePaths,
        CredentialSerializeDelegate credentialSerializer,
        RedactCredentialDelegate redact,
        Func<byte[]> saltFactory,
        SerializeDisclosureDelegate<SdDisclosure> serializeDisclosure,
        ComputeDisclosureDigestDelegate computeDigest,
        PrivateKeyMemory privateKey,
        string keyId,
        string hashAlgorithm,
        JCoseHeaderSerializer headerSerializer,
        JCosePayloadSerializer payloadSerializer,
        EncodeDelegate encoder,
        MemoryPool<byte> memoryPool,
        string? mediaType = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(disclosablePaths);
        ArgumentNullException.ThrowIfNull(credentialSerializer);
        ArgumentNullException.ThrowIfNull(redact);
        ArgumentNullException.ThrowIfNull(saltFactory);
        ArgumentNullException.ThrowIfNull(serializeDisclosure);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentException.ThrowIfNullOrWhiteSpace(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //Serialize the credential to JSON, then redact disclosable paths.
        //The redact delegate produces a payload with _sd arrays at the correct nesting levels.
        string json = credentialSerializer(credential);
        var (payload, disclosures) = redact(
            json,
            disclosablePaths,
            saltFactory,
            serializeDisclosure,
            computeDigest,
            encoder,
            hashAlgorithm);

        //Sign the complete payload directly. The redact delegate has already placed
        //_sd arrays at the correct nesting levels and _sd_alg at root.
        string resolvedMediaType = mediaType ?? WellKnownMediaTypes.Jwt.VcSdJwt;
        UnsignedJwt unsigned = UnsignedJwt.ForSigning(privateKey, keyId, payload, resolvedMediaType);

        using JwsMessage jwsMessage = await unsigned.SignAsync(
            privateKey, headerSerializer, payloadSerializer,
            encoder, memoryPool, cancellationToken).ConfigureAwait(false);

        string issuerJwt = JwsSerialization.SerializeCompact(jwsMessage, encoder);

        return new SdJwtToken(issuerJwt, disclosures.ToList());
    }
}