using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// Verifies a Security Event Token from its compact serialization and validates
/// the SET-level claims, returning a result rather than throwing so a Receiver
/// can branch on the failure cause.
/// </summary>
/// <remarks>
/// <para>
/// The order is fail-fast and firewalled: structural parse, explicit-type check
/// (<c>typ = secevent+jwt</c>), then signature verification — and only once the
/// signature holds is the payload interpreted into a
/// <see cref="Verified{T}"/> of <see cref="JwtPayload"/> and the SET-level claims
/// validated (<c>iss</c>, <c>aud</c>, <c>iat</c>, <c>jti</c>, at least one event)
/// and the <c>jti</c> checked for replay. A firewalled Receiver reconstructs the
/// SET from wire bytes alone; nothing here trusts an in-memory object.
/// </para>
/// <para>
/// The signing key is supplied by the caller, who resolves it from the
/// Transmitter's <c>jwks_uri</c> (by the SET's <c>kid</c>) — that resolution and
/// the network fetch behind it are a receiver concern layered on top of this
/// primitive, not part of it.
/// </para>
/// </remarks>
public static class SecurityEventTokenVerification
{
    /// <summary>
    /// Verifies and validates a compact-serialized SET.
    /// </summary>
    /// <param name="compactSet">The compact SET (<c>header.payload.signature</c>).</param>
    /// <param name="signingPublicKey">The Transmitter's public key; the verification function resolves from its <see cref="Tag"/>.</param>
    /// <param name="expectedIssuer">The issuer the <c>iss</c> claim MUST equal.</param>
    /// <param name="expectedAudience">The audience the <c>aud</c> claim MUST include.</param>
    /// <param name="headerDeserializer">Deserializes the header segment's JSON bytes.</param>
    /// <param name="payloadDeserializer">Deserializes the payload segment's JSON bytes.</param>
    /// <param name="base64UrlDecoder">Base64url decoder for the compact segments.</param>
    /// <param name="isJtiSeen">Replay check consulted once the SET is otherwise valid.</param>
    /// <param name="context">Per-call exchange context, threaded to the replay check.</param>
    /// <param name="memoryPool">Memory pool for transient verification buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<SecurityEventTokenVerificationResult> VerifyAsync(
        string compactSet,
        PublicKeyMemory signingPublicKey,
        string expectedIssuer,
        string expectedAudience,
        SecurityEventTokenPartDeserializer headerDeserializer,
        SecurityEventTokenPartDeserializer payloadDeserializer,
        DecodeDelegate base64UrlDecoder,
        IsSecurityEventTokenJtiSeenDelegate isJtiSeen,
        ExchangeContext context,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(compactSet);
        ArgumentNullException.ThrowIfNull(signingPublicKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedAudience);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(payloadDeserializer);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(isJtiSeen);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(memoryPool);

        string[] parts = compactSet.Split('.');
        if(parts.Length != 3)
        {
            return SecurityEventTokenVerificationResult.Failed(SecurityEventTokenValidationError.Malformed);
        }

        Dictionary<string, object>? header;
        using(IMemoryOwner<byte> headerBytes = base64UrlDecoder(parts[0], memoryPool))
        {
            header = headerDeserializer(headerBytes.Memory.Span);
        }

        if(header is null)
        {
            return SecurityEventTokenVerificationResult.Failed(SecurityEventTokenValidationError.Malformed);
        }

        //Explicit typing is mandatory (RFC 8417 §2.3 / SSF §4.1.1): reject before
        //spending a signature verification on a token that is not a SET.
        if(!header.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typValue) || typValue is not string typ || !WellKnownMediaTypes.Jwt.IsSecEventJwt(typ))
        {
            return SecurityEventTokenVerificationResult.Failed(SecurityEventTokenValidationError.ExplicitTypeMissing);
        }

        bool signatureValid = await VerifySignatureAsync(parts, signingPublicKey, base64UrlDecoder, memoryPool, cancellationToken).ConfigureAwait(false);
        if(!signatureValid)
        {
            return SecurityEventTokenVerificationResult.Failed(SecurityEventTokenValidationError.SignatureInvalid);
        }

        //Signature holds: only now interpret the payload bytes.
        Dictionary<string, object>? payloadClaims;
        using(IMemoryOwner<byte> payloadBytes = base64UrlDecoder(parts[1], memoryPool))
        {
            payloadClaims = payloadDeserializer(payloadBytes.Memory.Span);
        }

        if(payloadClaims is null)
        {
            return SecurityEventTokenVerificationResult.Failed(SecurityEventTokenValidationError.Malformed);
        }

        SecurityEventToken token = SecurityEventTokenParsing.Parse(payloadClaims);

        SecurityEventTokenValidationError? claimError = ValidateClaims(token, expectedIssuer, expectedAudience);
        if(claimError is not null)
        {
            return SecurityEventTokenVerificationResult.Failed(claimError.Value);
        }

        bool replayed = await isJtiSeen(token.JwtId!, context, cancellationToken).ConfigureAwait(false);
        if(replayed)
        {
            return SecurityEventTokenVerificationResult.Failed(SecurityEventTokenValidationError.Replayed);
        }

        return SecurityEventTokenVerificationResult.Success(token);
    }


    //Returns the first failing check, or null when every SET-level claim check passes.
    private static SecurityEventTokenValidationError? ValidateClaims(SecurityEventToken token, string expectedIssuer, string expectedAudience)
    {
        if(string.IsNullOrEmpty(token.JwtId))
        {
            return SecurityEventTokenValidationError.MissingJwtId;
        }

        if(!string.Equals(token.Issuer, expectedIssuer, StringComparison.Ordinal))
        {
            return SecurityEventTokenValidationError.IssuerMismatch;
        }

        if(!ContainsOrdinal(token.Audiences, expectedAudience))
        {
            return SecurityEventTokenValidationError.AudienceMismatch;
        }

        if(token.IssuedAt is null)
        {
            return SecurityEventTokenValidationError.MissingIssuedAt;
        }

        if(token.Events.Count == 0)
        {
            return SecurityEventTokenValidationError.NoEvents;
        }

        return null;
    }


    private static async ValueTask<bool> VerifySignatureAsync(
        string[] parts,
        PublicKeyMemory publicKey,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        using IMemoryOwner<byte> signatureBytes = base64UrlDecoder(parts[2], memoryPool);

        //Per RFC 7515 §5.2 the signing input is the ASCII of the base64url header
        //and payload joined by a period.
        int verifyInputLength = parts[0].Length + 1 + parts[1].Length;
        using IMemoryOwner<byte> verifyInputOwner = memoryPool.Rent(verifyInputLength);
        Memory<byte> verifyInput = verifyInputOwner.Memory[..verifyInputLength];

        int written = Encoding.ASCII.GetBytes(parts[0], verifyInput.Span);
        verifyInput.Span[written] = (byte)'.';
        written += 1;
        written += Encoding.ASCII.GetBytes(parts[1], verifyInput.Span[written..]);

        Debug.Assert(written == verifyInputLength, "Verification input length must match the expected size.");

        return await verificationDelegate(
            verifyInput,
            signatureBytes.Memory,
            publicKey.AsReadOnlyMemory(),
            context: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    private static bool ContainsOrdinal(IReadOnlyList<string> values, string target)
    {
        for(int i = 0; i < values.Count; ++i)
        {
            if(string.Equals(values[i], target, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
