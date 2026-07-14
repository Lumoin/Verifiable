using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.OAuth.Oid4Vp;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// Issues a Key-Bound JWT (KB-JWT) that binds an SD-JWT VC presentation to the
/// holder's session with a specific Verifier per
/// <see href="https://www.rfc-editor.org/rfc/rfc9901#section-4.3">RFC 9901 §4.3</see>
/// (SD-JWT VC) and HAIP §9.
/// </summary>
/// <remarks>
/// <para>
/// The KB-JWT is signed by the holder's key — the same key whose JWK is in the
/// SD-JWT VC's <c>cnf</c> claim — and carries four mandatory claims:
/// </para>
/// <list type="bullet">
///   <item><description><c>nonce</c> — Verifier-supplied freshness nonce.</description></item>
///   <item><description><c>aud</c> — Verifier identifier (typically the OID4VP <c>response_uri</c> or <c>client_id</c>).</description></item>
///   <item><description><c>iat</c> — Unix-second issuance timestamp.</description></item>
///   <item><description><c>sd_hash</c> — base64url-encoded SHA-256 over the issuer-signed SD-JWT and the selected disclosures concatenated by <c>~</c>.</description></item>
/// </list>
/// <para>
/// The header is built via <see cref="JwtHeaderExtensions.ForKeyBinding"/> with
/// <c>typ = </c><see cref="WellKnownMediaTypes.Jwt.KbJwt"/> and <c>alg</c> derived from
/// the holder key's <see cref="Tag"/> through
/// <see cref="CryptoFormatConversions.DefaultTagToJwaConverter"/>.
/// </para>
/// <para>
/// Signing flows through <see cref="JwtSigningExtensions.SignAsync"/>, which
/// resolves the per-algorithm <c>SigningDelegate</c> from the holder key's
/// <see cref="Tag"/> via <see cref="CryptoFunctionRegistry{TAlgorithm,TPurpose}"/>.
/// This is the standard JCose composition pattern shared with token issuance,
/// Verifier attestation issuance, and JAR signing — algorithm dispatch lives
/// in the registry, not in per-call-site delegate parameters.
/// </para>
/// </remarks>
[DebuggerDisplay("KbJwtIssuance")]
public static class KbJwtIssuance
{
    private const int Sha256DigestLength = 32;


    /// <summary>
    /// Issues a compact-serialised KB-JWT.
    /// </summary>
    /// <param name="sdJwtCompactWithDisclosures">
    /// The issuer-signed SD-JWT plus the selected disclosures, concatenated by
    /// <c>~</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9900#section-6">RFC 9900 §6</see>.
    /// Hashed (SHA-256, base64url-encoded) into the <c>sd_hash</c> claim.
    /// </param>
    /// <param name="holderKey">
    /// The holder's signing key. The JWS <c>alg</c> is derived from the key's
    /// <see cref="Tag"/>; the matching public key must appear in the SD-JWT VC's
    /// <c>cnf</c> claim for the Verifier to bind the credential to this presentation.
    /// </param>
    /// <param name="verifierNonce">The Verifier-supplied <c>nonce</c> claim value.</param>
    /// <param name="verifierAud">The <c>aud</c> claim value identifying the Verifier.</param>
    /// <param name="iat">The <c>iat</c> claim value, encoded as Unix seconds.</param>
    /// <param name="base64UrlEncoder">Base64url encoder. Used both for the <c>sd_hash</c> digest and for compact JWS serialisation.</param>
    /// <param name="headerSerializer">Serialises the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serialises the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token, propagated through the registry-resolved signing delegate.</param>
    /// <returns>The compact-serialised KB-JWT (<c>header.payload.signature</c>).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "JwsMessage is disposed via the using statement before the method returns; the returned string is independent of the message.")]
    public static async ValueTask<string> IssueAsync(
        ReadOnlyMemory<byte> sdJwtCompactWithDisclosures,
        PrivateKeyMemory holderKey,
        string verifierNonce,
        string verifierAud,
        DateTimeOffset iat,
        EncodeDelegate base64UrlEncoder,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        MemoryPool<byte> memoryPool,
        IReadOnlyList<string>? transactionDataHashes = null,
        string? transactionDataHashesAlg = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(holderKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(verifierNonce);
        ArgumentException.ThrowIfNullOrWhiteSpace(verifierAud);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        string sdHash = await ComputeSdHashAsync(sdJwtCompactWithDisclosures, base64UrlEncoder, memoryPool, cancellationToken).ConfigureAwait(false);

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(holderKey.Tag);
        JwtHeader header = JwtHeaderExtensions.ForKeyBinding(algorithm);

        int capacity = 4
            + (transactionDataHashes is { Count: > 0 } ? 1 : 0)
            + (transactionDataHashesAlg is not null ? 1 : 0);

        JwtPayload payload = new(capacity)
        {
            [WellKnownJwtClaimNames.Nonce] = verifierNonce,
            [WellKnownJwtClaimNames.Aud] = verifierAud,
            [WellKnownJwtClaimNames.Iat] = iat.ToUnixTimeSeconds(),
            [SdConstants.SdHashClaim] = sdHash
        };

        if(transactionDataHashes is { Count: > 0 } hashes)
        {
            //Project to List<object> to match the payload dictionary's JSON
            //converter, which writes IList<object> arrays but not the
            //variance-incompatible IList<string>.
            List<object> wireHashes = new(hashes.Count);
            foreach(string hash in hashes)
            {
                wireHashes.Add(hash);
            }

            payload[TransactionDataClaimNames.Hashes] = wireHashes;

            if(transactionDataHashesAlg is not null)
            {
                payload[TransactionDataClaimNames.HashesAlg] = transactionDataHashesAlg;
            }
        }

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            holderKey,
            headerSerializer,
            payloadSerializer,
            base64UrlEncoder,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, base64UrlEncoder);
    }


    //Computes the SD-JWT VC sd_hash: base64url(SHA-256(issuer-jwt~d1~d2~...)).
    //Routes through CryptographicKeyEvents so this operation picks up the same
    //observability and CBOM provenance stamping as every other digest. The Span
    //input is copied into a pool-rented buffer so it can survive the async
    //boundary inside the registered ComputeDigestDelegate.
    private static async ValueTask<string> ComputeSdHashAsync(
        ReadOnlyMemory<byte> input,
        EncodeDelegate encoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, Sha256DigestLength, CryptoTags.Sha256Digest, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return encoder(digest.AsReadOnlySpan());
    }
}
