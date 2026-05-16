using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The library's default <see cref="ValidateDpopProofDelegate"/>
/// implementation. Performs the pure-validation checks RFC 9449 §4.3
/// mandates: structural parse, header validation (<c>typ</c>, <c>alg</c>,
/// <c>jwk</c>), JWS signature verification, claim checks (<c>htm</c>,
/// <c>htu</c>, <c>iat</c> skew, <c>nonce</c>, <c>ath</c>).
/// </summary>
/// <remarks>
/// <c>jti</c> replay tracking is the AS-side handler's responsibility —
/// see the remark on <see cref="ValidateDpopProofDelegate"/>.
/// </remarks>
[DebuggerDisplay("DpopProofValidator")]
public static class DpopProofValidator
{
    /// <summary>
    /// Validates a DPoP proof against the receiver's expectations.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "PublicKeyMemory created via PublicKeyFromJwk is disposed in the finally block of the verification try; the analyzer does not trace the catch-then-finally path correctly here.")]
    public static async ValueTask<DpopProofValidationResult> ValidateAsync(
        DpopProofValidationRequest request,
        VerificationDelegate verificationDelegate,
        DpopJwsPartParser parser,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        MemoryPool<byte> memoryPool,
        TimeSpan iatSkew,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentNullException.ThrowIfNull(parser);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //Structural parse first — reject obviously malformed input cheaply.
        string[] parts = request.Proof.Split('.');
        if(parts.Length != 3
            || string.IsNullOrEmpty(parts[0])
            || string.IsNullOrEmpty(parts[1])
            || string.IsNullOrEmpty(parts[2]))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.Malformed);
        }

        DpopProofHeader header;
        DpopProofClaims claims;
        try
        {
            using IMemoryOwner<byte> headerBytes = base64UrlDecoder(parts[0], memoryPool);
            using IMemoryOwner<byte> payloadBytes = base64UrlDecoder(parts[1], memoryPool);
            header = parser.ParseHeader(headerBytes.Memory);
            claims = parser.ParseClaims(payloadBytes.Memory);
        }
        catch
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.Malformed);
        }

        //Header checks.
        if(!string.Equals(header.Typ, WellKnownDpopValues.ProofTypeHeader, StringComparison.Ordinal))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidTyp);
        }
        if(string.IsNullOrEmpty(header.Alg) || !WellKnownJwaValues.IsEcdsa(header.Alg))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidAlg);
        }
        if(header.Jwk is null || header.Jwk.Count == 0)
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidJwk);
        }

        //Signature verification.
        PublicKeyMemory publicKey;
        try
        {
            publicKey = DpopJwkUtilities.PublicKeyFromJwk(
                header.Jwk, header.Alg, base64UrlDecoder, memoryPool);
        }
        catch
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.InvalidJwk);
        }

        bool signatureValid;
        try
        {
            using IMemoryOwner<byte> signatureBytes = base64UrlDecoder(parts[2], memoryPool);
            byte[] dataToVerify = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");

            signatureValid = await verificationDelegate(
                dataToVerify,
                signatureBytes.Memory,
                publicKey.AsReadOnlyMemory(),
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            publicKey.Dispose();
        }

        if(!signatureValid)
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.SignatureFailed);
        }

        //Claim checks.
        if(!string.Equals(claims.Htm, request.HttpMethod, StringComparison.OrdinalIgnoreCase))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.HtmMismatch);
        }
        if(!string.Equals(claims.Htu, request.HttpUrl, StringComparison.Ordinal))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.HtuMismatch);
        }

        DateTimeOffset now = timeProvider.GetUtcNow();
        if(claims.Iat < now - iatSkew || claims.Iat > now + iatSkew)
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.IatOutOfWindow);
        }

        //Nonce check, dispatched per receiver policy.
        if(request.NonceRequired)
        {
            if(claims.Nonce is null)
            {
                return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.NonceMissing);
            }
            if(request.ExpectedNonce is null
                || !string.Equals(claims.Nonce, request.ExpectedNonce, StringComparison.Ordinal))
            {
                return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.NonceMismatch);
            }
        }
        else if(claims.Nonce is not null
            && request.ExpectedNonce is not null
            && !string.Equals(claims.Nonce, request.ExpectedNonce, StringComparison.Ordinal))
        {
            return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.NonceMismatch);
        }

        //Access-token binding check (resource-server calls).
        if(request.AccessToken is not null)
        {
            string expectedAth = await ComputeAthAsync(request.AccessToken, base64UrlEncoder, memoryPool, cancellationToken).ConfigureAwait(false);
            if(claims.Ath is null || !string.Equals(claims.Ath, expectedAth, StringComparison.Ordinal))
            {
                return DpopProofValidationResult.Failure(DpopProofValidationFailureReason.AthMismatch);
            }
        }

        //Re-derive the thumbprint from the embedded JWK for the success result.
        //ToJwk normalises the dictionary shape; the receiver's downstream code
        //compares this against an access token's cnf.jkt binding.
        string thumbprint = ComputeThumbprintFromJwk(header.Jwk, base64UrlEncoder, memoryPool);

        return DpopProofValidationResult.Success(claims, thumbprint);
    }


    /// <summary>
    /// Computes the base64url-encoded SHA-256 of <paramref name="accessToken"/>
    /// per RFC 9449 §4.3 — the value that must appear in a resource-call
    /// proof's <c>ath</c> claim.
    /// </summary>
    /// <remarks>
    /// Routes through the registered <see cref="ComputeDigestDelegate"/> via
    /// <see cref="CryptographicKeyEvents.ComputeDigest"/> so this operation picks up
    /// the same observability and CBOM provenance stamping as every other digest
    /// in the library.
    /// </remarks>
    public static async ValueTask<string> ComputeAthAsync(
        string accessToken,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accessToken);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] accessTokenBytes = Encoding.ASCII.GetBytes(accessToken);
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            accessTokenBytes,
            outputByteLength: SHA256.HashSizeInBytes,
            tag: CryptoTags.Sha256Digest,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return base64UrlEncoder(digest.AsReadOnlySpan());
    }


    private static string ComputeThumbprintFromJwk(
        IReadOnlyDictionary<string, string> jwk,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool)
    {
        using IMemoryOwner<byte> hash = JwkThumbprintUtilities.ComputeECThumbprint(
            memoryPool,
            jwk[WellKnownJwkMemberNames.Crv],
            jwk[WellKnownJwkMemberNames.Kty],
            jwk[WellKnownJwkMemberNames.X],
            jwk[WellKnownJwkMemberNames.Y]);
        return base64UrlEncoder(hash.Memory.Span);
    }
}
