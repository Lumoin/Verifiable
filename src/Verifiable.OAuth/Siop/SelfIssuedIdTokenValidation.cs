using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// Validates a Self-Issued ID Token on the Relying Party side per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-11.1">SIOPv2 §11.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is a free-standing RP primitive with no <c>EndpointServer</c> coupling — a
/// verifier website, a wallet checking a peer, or an agent all validate the same way.
/// JSON field extraction uses <see cref="JwkJsonReader"/> (span-based UTF-8 scanning);
/// signature verification composes <see cref="Jws.VerifyAsync"/>; the subject key is
/// reconstructed from <c>sub_jwk</c> via
/// <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/> or resolved from
/// a DID Document via the application's <see cref="ResolveDidVerificationKeyDelegate"/>.
/// </para>
/// <para>
/// The validation sequence (§11.1):
/// </para>
/// <list type="number">
///   <item><description>Determine the token is self-issued: <c>iss</c> equals <c>sub</c>. Otherwise the token is attester-signed and processing per OpenID Connect Core §3.2.2.11 is the caller's path; this validator stops.</description></item>
///   <item><description>Identify the Subject Syntax Type from the URI of the <c>sub</c> claim (<see cref="SiopSubjectSyntaxTypes.Classify"/>).</description></item>
///   <item><description>Enforce the §8 <c>sub_jwk</c> shape: present and a bare public key for JWK Thumbprint, absent for Decentralized Identifier.</description></item>
///   <item><description>Validate the signature against the subject's key under an allowed algorithm.</description></item>
///   <item><description>Confirm the subject binding: <c>sub</c> equals the RFC 7638 thumbprint of <c>sub_jwk</c> (compared against the RFC 9278 <c>sha-256</c> Thumbprint URI form), or the DID Document key resolved from <c>sub</c> verified the signature.</description></item>
///   <item><description>Validate <c>aud</c> contains the RP's Client ID, <c>exp</c> is in the future, and <c>nonce</c> is present and matches the Authorization Request.</description></item>
/// </list>
/// <para>
/// The RFC 7638 thumbprint is computed over only the required members for the key type
/// (<c>kty</c>/<c>crv</c>/<c>x</c>/<c>y</c> for EC, <c>kty</c>/<c>n</c>/<c>e</c> for RSA,
/// <c>kty</c>/<c>crv</c>/<c>x</c> for OKP), so extra <c>sub_jwk</c> members such as
/// <c>kid</c> or <c>use</c> do not perturb the hash.
/// </para>
/// </remarks>
public static class SelfIssuedIdTokenValidation
{
    /// <summary>
    /// Validates a Self-Issued ID Token and returns the per-check outcome.
    /// </summary>
    /// <param name="idToken">The compact-JWS ID Token exactly as received in the Authorization Response.</param>
    /// <param name="expectedAudience">The Client ID the RP sent in the Authorization Request; the <c>aud</c> claim must contain it.</param>
    /// <param name="expectedNonce">The <c>nonce</c> the RP sent in the Authorization Request; the <c>nonce</c> claim must equal it.</param>
    /// <param name="allowedAlgorithms">The JWS algorithms the RP accepts, as in its <c>id_token_signing_alg_values_supported</c>. <c>none</c> is always rejected.</param>
    /// <param name="validationTime">The instant to evaluate <c>exp</c> against; callers supply their time provider's current UTC time.</param>
    /// <param name="resolveDidVerificationKey">
    /// The application's DID resolution seam, required to validate tokens of the
    /// Decentralized Identifier Subject Syntax Type. When <see langword="null"/>, such
    /// tokens fail closed (subject unconfirmed, signature unverified).
    /// </param>
    /// <param name="base64UrlDecoder">Base64url decoder.</param>
    /// <param name="base64UrlEncoder">Base64url encoder, used for the RFC 7638 thumbprint comparison.</param>
    /// <param name="memoryPool">Memory pool for transient buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="expirationLeeway">Clock-skew leeway added to <c>exp</c>; defaults to none.</param>
    /// <returns>The per-check validation outcome.</returns>
    public static async ValueTask<SelfIssuedIdTokenValidationResult> ValidateAsync(
        string idToken,
        string expectedAudience,
        string expectedNonce,
        IReadOnlyCollection<string> allowedAlgorithms,
        DateTimeOffset validationTime,
        ResolveDidVerificationKeyDelegate? resolveDidVerificationKey,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        TimeSpan? expirationLeeway = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(idToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedAudience);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedNonce);
        ArgumentNullException.ThrowIfNull(allowedAlgorithms);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        //Decode the header and payload and extract all fields synchronously
        //before any await boundaries (ReadOnlySpan cannot cross await).
        string? alg = null;
        string? kid = null;
        string? iss = null;
        string? sub = null;
        string? audString = null;
        List<string>? audArray = null;
        string? nonce = null;
        long expSeconds = 0;
        bool hasExp = false;
        long iatSeconds = 0;
        bool hasIat = false;
        Dictionary<string, object>? subJwk = null;
        bool isStructurallyValid = false;

        string[] parts = idToken.Split('.');
        if(parts.Length == 3 && parts[0].Length > 0 && parts[1].Length > 0)
        {
            try
            {
                using IMemoryOwner<byte> headerBytes = base64UrlDecoder(parts[0], memoryPool);
                ReadOnlySpan<byte> header = headerBytes.Memory.Span;
                alg = JwkJsonReader.ExtractStringValue(header, WellKnownJwkMemberNames.AlgUtf8);
                kid = JwkJsonReader.ExtractStringValue(header, WellKnownJwkMemberNames.KidUtf8);

                using IMemoryOwner<byte> payloadBytes = base64UrlDecoder(parts[1], memoryPool);
                ReadOnlySpan<byte> payload = payloadBytes.Memory.Span;
                iss = JwkJsonReader.ExtractStringValue(payload, WellKnownJwtClaimNames.IssUtf8);
                sub = JwkJsonReader.ExtractStringValue(payload, WellKnownJwtClaimNames.SubUtf8);
                audString = JwkJsonReader.ExtractStringValue(payload, WellKnownJwtClaimNames.AudUtf8);
                audArray = JwkJsonReader.ExtractStringArrayProperty(payload, WellKnownJwtClaimNames.AudUtf8);
                nonce = JwkJsonReader.ExtractStringValue(payload, WellKnownJwtClaimNames.NonceUtf8);
                hasExp = JwkJsonReader.TryExtractLongValue(payload, WellKnownJwtClaimNames.ExpUtf8, out expSeconds);
                hasIat = JwkJsonReader.TryExtractLongValue(payload, WellKnownJwtClaimNames.IatUtf8, out iatSeconds);
                subJwk = JwkJsonReader.ExtractObjectProperties(payload, WellKnownJwtClaimNames.SubJwkUtf8);

                isStructurallyValid = true;
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException)
            {
                isStructurallyValid = false;
            }
        }

        DateTimeOffset? expiresAt = hasExp ? DateTimeOffset.FromUnixTimeSeconds(expSeconds) : null;
        DateTimeOffset? issuedAt = hasIat ? DateTimeOffset.FromUnixTimeSeconds(iatSeconds) : null;

        //§11.1 step 1: the token is self-issued if and only if iss equals sub. An
        //attester-signed token is the caller's OpenID Connect Core path; stop here.
        bool isSelfIssued = isStructurallyValid
            && iss is not null
            && sub is not null
            && string.Equals(iss, sub, StringComparison.Ordinal);

        if(!isSelfIssued)
        {
            return new SelfIssuedIdTokenValidationResult
            {
                IsStructurallyValid = isStructurallyValid,
                IsSelfIssued = false,
                SubjectSyntaxType = SiopSubjectSyntaxType.Unknown,
                Issuer = iss,
                Subject = sub,
                Nonce = nonce,
                ExpiresAt = expiresAt,
                IssuedAt = issuedAt
            };
        }

        SiopSubjectSyntaxType subjectSyntaxType = SiopSubjectSyntaxTypes.Classify(sub!);

        //§11.1: the algorithm must be one of the RP's allowed algorithms. alg=none is
        //rejected unconditionally per RFC 8725 §3.1; the signature is only evaluated
        //under an allowed algorithm.
        bool isAlgorithmAllowed = alg is not null
            && !string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase)
            && ContainsOrdinal(allowedAlgorithms, alg);

        bool isSubJwkShapeValid = false;
        bool isSignatureValid = false;
        bool isSubjectConfirmed = false;

        if(subjectSyntaxType == SiopSubjectSyntaxType.JwkThumbprint)
        {
            //§8: sub_jwk MUST be included and MUST be a bare public key in JWK format.
            //A JWK missing the RFC 7638 required members for its kty is not a usable
            //bare key, so the thumbprint projection doubles as the shape check.
            Dictionary<string, string>? thumbprintMembers =
                subJwk is not null && !WellKnownJwkMemberNames.ContainsPrivateOrSymmetricMember(subJwk.Keys)
                    ? ProjectRequiredThumbprintMembers(subJwk)
                    : null;
            isSubJwkShapeValid = thumbprintMembers is not null;

            if(thumbprintMembers is not null)
            {
                //§11.1: sub MUST equal the thumbprint of the key in sub_jwk. The sub
                //claim carries the RFC 9278 JWK Thumbprint URI, so the comparison is
                //against the base64url value after the sha-256 prefix.
                using(IMemoryOwner<byte> thumbprint = JwkThumbprintUtilities.ComputeGenericThumbprint(
                    memoryPool, thumbprintMembers))
                {
                    string computed = base64UrlEncoder(thumbprint.Memory.Span);
                    isSubjectConfirmed = sub!.StartsWith(
                            SiopSubjectSyntaxTypes.JwkThumbprintSha256Prefix, StringComparison.Ordinal)
                        && string.Equals(
                            sub[SiopSubjectSyntaxTypes.JwkThumbprintSha256Prefix.Length..],
                            computed,
                            StringComparison.Ordinal);
                }

                if(isAlgorithmAllowed)
                {
                    isSignatureValid = await VerifyWithJwkAsync(
                        idToken, subJwk!, base64UrlDecoder, memoryPool, cancellationToken).ConfigureAwait(false);
                }
            }
        }
        else if(subjectSyntaxType == SiopSubjectSyntaxType.DecentralizedIdentifier)
        {
            //§8: sub_jwk MUST NOT be included for the Decentralized Identifier type.
            isSubJwkShapeValid = subJwk is null;

            if(isSubJwkShapeValid && resolveDidVerificationKey is not null)
            {
                //§11.1: the key comes from the DID Document resolved from sub, selected
                //by the header kid. Resolution by sub is what binds the document to the
                //subject, so a resolved key confirms the subject.
                PublicKeyMemory? didKey = await resolveDidVerificationKey(
                    sub!, kid, cancellationToken).ConfigureAwait(false);

                if(didKey is not null)
                {
                    using(didKey)
                    {
                        isSubjectConfirmed = true;

                        if(isAlgorithmAllowed)
                        {
                            try
                            {
                                isSignatureValid = await Jws.VerifyAsync(
                                    idToken, base64UrlDecoder, memoryPool,
                                    didKey, cancellationToken).ConfigureAwait(false);
                            }
                            catch(Exception ex) when(ex is FormatException or InvalidOperationException or ArgumentException)
                            {
                                isSignatureValid = false;
                            }
                        }
                    }
                }
            }
        }

        //§11.1: aud MUST contain the Client ID the RP sent in the Authorization Request.
        bool isAudienceValid = string.Equals(audString, expectedAudience, StringComparison.Ordinal)
            || (audArray is not null && ContainsOrdinal(audArray, expectedAudience));

        //§11.1: a nonce claim MUST be present and equal the Authorization Request value.
        bool isNonceValid = nonce is not null
            && string.Equals(nonce, expectedNonce, StringComparison.Ordinal);

        //§11.1: the current time MUST be before exp, possibly allowing small leeway.
        bool isUnexpired = expiresAt is DateTimeOffset exp
            && JwtTemporalChecks.IsBeforeExpiry(validationTime, exp, expirationLeeway ?? TimeSpan.Zero);

        return new SelfIssuedIdTokenValidationResult
        {
            IsStructurallyValid = true,
            IsSelfIssued = true,
            SubjectSyntaxType = subjectSyntaxType,
            IsSubJwkShapeValid = isSubJwkShapeValid,
            IsAlgorithmAllowed = isAlgorithmAllowed,
            IsSignatureValid = isSignatureValid,
            IsSubjectConfirmed = isSubjectConfirmed,
            IsAudienceValid = isAudienceValid,
            IsNonceValid = isNonceValid,
            IsUnexpired = isUnexpired,
            Issuer = iss,
            Subject = sub,
            Nonce = nonce,
            ExpiresAt = expiresAt,
            IssuedAt = issuedAt
        };
    }


    //Reconstructs the subject's public key from the sub_jwk members and verifies the
    //compact JWS against it — the same composition the OID4VP verifier uses for the
    //cnf.jwk holder key. Conversion failures (unsupported kty/crv, malformed
    //coordinates) mean the signature cannot be valid.
    private static async ValueTask<bool> VerifyWithJwkAsync(
        string idToken,
        Dictionary<string, object> subJwk,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        try
        {
            var (algorithm, purpose, scheme, keyBytesOwner) =
                CryptoFormatConversions.DefaultJwkToAlgorithmConverter(
                    subJwk, memoryPool, base64UrlDecoder);
            Tag subjectTag = Tag.Create(algorithm).With(purpose).With(scheme);
            using PublicKeyMemory subjectKey = new(keyBytesOwner, subjectTag);

            return await Jws.VerifyAsync(
                idToken, base64UrlDecoder, memoryPool,
                subjectKey, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception ex) when(ex is FormatException or InvalidOperationException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }


    //Projects a sub_jwk to exactly the RFC 7638 §3.2 required members for its key type
    //so extra members (kid, use — and for the RFC 7518 families, alg) do not perturb the
    //thumbprint. For an Algorithm Key Pair (ML-DSA et al.) alg IS a required member and
    //participates in the canon. Returns null when kty is absent, unrecognized, or a
    //required member is missing.
    private static Dictionary<string, string>? ProjectRequiredThumbprintMembers(
        Dictionary<string, object> jwk)
    {
        string? kty = GetStringMember(jwk, WellKnownJwkMemberNames.Kty);

        return kty switch
        {
            _ when string.Equals(kty, WellKnownKeyTypeValues.Ec, StringComparison.Ordinal) =>
                BuildMembers(jwk, kty!, WellKnownJwkMemberNames.Crv, WellKnownJwkMemberNames.X, WellKnownJwkMemberNames.Y),
            _ when string.Equals(kty, WellKnownKeyTypeValues.Rsa, StringComparison.Ordinal) =>
                BuildMembers(jwk, kty!, WellKnownJwkMemberNames.N, WellKnownJwkMemberNames.E),
            _ when string.Equals(kty, WellKnownKeyTypeValues.Okp, StringComparison.Ordinal) =>
                BuildMembers(jwk, kty!, WellKnownJwkMemberNames.Crv, WellKnownJwkMemberNames.X),
            _ when string.Equals(kty, WellKnownKeyTypeValues.Akp, StringComparison.Ordinal) =>
                BuildMembers(jwk, kty!, WellKnownJwkMemberNames.Alg, WellKnownJwkMemberNames.Pub),
            _ => null
        };
    }


    private static Dictionary<string, string>? BuildMembers(
        Dictionary<string, object> jwk,
        string kty,
        params string[] requiredMembers)
    {
        Dictionary<string, string> members = new(requiredMembers.Length + 1, StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Kty] = kty
        };

        foreach(string member in requiredMembers)
        {
            string? value = GetStringMember(jwk, member);
            if(value is null)
            {
                return null;
            }

            members[member] = value;
        }

        return members;
    }


    private static string? GetStringMember(Dictionary<string, object> jwk, string member) =>
        jwk.TryGetValue(member, out object? value) && value is string text ? text : null;


    private static bool ContainsOrdinal(IEnumerable<string> values, string candidate)
    {
        foreach(string value in values)
        {
            if(string.Equals(value, candidate, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
