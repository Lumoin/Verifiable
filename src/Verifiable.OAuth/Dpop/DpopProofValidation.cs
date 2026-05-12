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
[DebuggerDisplay("DpopProofValidation")]
public static class DpopProofValidation
{
    /// <summary>
    /// Validates a DPoP proof against the receiver's expectations.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "PublicKeyMemory created via PublicKeyFromJwk is disposed in the finally block of the verification try; the analyzer does not trace the catch-then-finally path correctly here.")]
    public static async ValueTask<DpopValidationResult> ValidateAsync(
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
            return DpopValidationResult.Failure(DpopValidationFailureReason.Malformed);
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
            return DpopValidationResult.Failure(DpopValidationFailureReason.Malformed);
        }

        //Header checks.
        if(!string.Equals(header.Typ, WellKnownDpopValues.ProofTypeHeader, StringComparison.Ordinal))
        {
            return DpopValidationResult.Failure(DpopValidationFailureReason.InvalidTyp);
        }
        if(string.IsNullOrEmpty(header.Alg) || !WellKnownJwaValues.IsEcdsa(header.Alg))
        {
            return DpopValidationResult.Failure(DpopValidationFailureReason.InvalidAlg);
        }
        if(header.Jwk is null || header.Jwk.Count == 0)
        {
            return DpopValidationResult.Failure(DpopValidationFailureReason.InvalidJwk);
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
            return DpopValidationResult.Failure(DpopValidationFailureReason.InvalidJwk);
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
            return DpopValidationResult.Failure(DpopValidationFailureReason.SignatureFailed);
        }

        //Claim checks.
        if(!string.Equals(claims.Htm, request.HttpMethod, StringComparison.OrdinalIgnoreCase))
        {
            return DpopValidationResult.Failure(DpopValidationFailureReason.HtmMismatch);
        }
        if(!string.Equals(claims.Htu, request.HttpUrl, StringComparison.Ordinal))
        {
            return DpopValidationResult.Failure(DpopValidationFailureReason.HtuMismatch);
        }

        DateTimeOffset now = timeProvider.GetUtcNow();
        if(claims.Iat < now - iatSkew || claims.Iat > now + iatSkew)
        {
            return DpopValidationResult.Failure(DpopValidationFailureReason.IatOutOfWindow);
        }

        //Nonce check, dispatched per receiver policy.
        if(request.NonceRequired)
        {
            if(claims.Nonce is null)
            {
                return DpopValidationResult.Failure(DpopValidationFailureReason.NonceMissing);
            }
            if(request.ExpectedNonce is null
                || !string.Equals(claims.Nonce, request.ExpectedNonce, StringComparison.Ordinal))
            {
                return DpopValidationResult.Failure(DpopValidationFailureReason.NonceMismatch);
            }
        }
        else if(claims.Nonce is not null
            && request.ExpectedNonce is not null
            && !string.Equals(claims.Nonce, request.ExpectedNonce, StringComparison.Ordinal))
        {
            return DpopValidationResult.Failure(DpopValidationFailureReason.NonceMismatch);
        }

        //Access-token binding check (resource-server calls).
        if(request.AccessToken is not null)
        {
            string expectedAth = ComputeAth(request.AccessToken, base64UrlEncoder);
            if(claims.Ath is null || !string.Equals(claims.Ath, expectedAth, StringComparison.Ordinal))
            {
                return DpopValidationResult.Failure(DpopValidationFailureReason.AthMismatch);
            }
        }

        //Re-derive the thumbprint from the embedded JWK for the success result.
        //ToJwk normalises the dictionary shape; the receiver's downstream code
        //compares this against an access token's cnf.jkt binding.
        string thumbprint = ComputeThumbprintFromJwk(header.Jwk, base64UrlEncoder, memoryPool);

        return DpopValidationResult.Success(claims, thumbprint);
    }


    /// <summary>
    /// Computes the base64url-encoded SHA-256 of <paramref name="accessToken"/>
    /// per RFC 9449 §4.3 — the value that must appear in a resource-call
    /// proof's <c>ath</c> claim.
    /// </summary>
    public static string ComputeAth(string accessToken, EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(accessToken);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        if(!SHA256.TryHashData(Encoding.ASCII.GetBytes(accessToken), hash, out int written)
            || written != SHA256.HashSizeInBytes)
        {
            throw new InvalidOperationException("SHA-256 hash for ath claim failed.");
        }
        return base64UrlEncoder(hash);
    }


    private static string ComputeThumbprintFromJwk(
        IReadOnlyDictionary<string, string> jwk,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool)
    {
        using IMemoryOwner<byte> hash = JwkThumbprintUtilities.ComputeECThumbprint(
            memoryPool,
            jwk[WellKnownJwkValues.Crv],
            jwk[WellKnownJwkValues.Kty],
            jwk[WellKnownJwkValues.X],
            jwk[WellKnownJwkValues.Y]);
        return base64UrlEncoder(hash.Memory.Span);
    }
}
