using System.Buffers;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Validates an OpenID Connect Core 1.0 ID Token (OP-issued) per OIDC Core §3.1.3.7: signature,
/// <c>iss</c>, <c>aud</c>, the multi-audience/<c>azp</c> coordination, the untrusted-audience
/// rejection, the <c>nonce</c> conditional-MUST, and the <c>exp</c>/<c>iat</c>/<c>nbf</c>/<c>sub</c>
/// checks. The relying-party counterpart to the OP's ID Token issuance; distinct from
/// <see cref="Verifiable.OAuth.Siop.SelfIssuedIdTokenValidation"/> (SIOP §11.1 self-issued tokens).
/// </summary>
/// <remarks>
/// <para>
/// Shares its signature and claim validation with <see cref="JwsAccessTokenValidator"/> — both
/// delegate to the one <see cref="JwsAccessTokenValidator.ValidateSignedJwtCoreAsync"/> core —
/// passing <see cref="JwtTypeEnforcement.RejectAtJwt"/>: OIDC does not mandate a <c>typ</c> on ID
/// Tokens (they carry <c>typ</c> <c>JWT</c> or omit it), but the access-token type <c>at+jwt</c> /
/// <c>application/at+jwt</c> is refused (RFC 8725 §3.11 explicit typing) so a genuine RFC 9068
/// access token can never be validated as an ID Token. The access-token path keeps the mirror
/// requirement (<c>at+jwt</c> required), so the two token types are never interchangeable in either
/// direction.
/// </para>
/// <para>
/// The result is <see cref="Oidc10IdTokenValidationResult"/>, carrying <see cref="Oidc10IdTokenClaims"/>
/// — the ID-Token-specific view of the shared core's verified payload, mirroring how
/// <see cref="JwsAccessTokenValidator.ValidateAsync"/> maps the same core to
/// <see cref="JwsAccessTokenClaims"/>.
/// </para>
/// <para>
/// Coverage boundary — this validator performs every OIDC Core §3.1.3.7 check the shared core and its
/// own post-processing can decide without application input: the signature, <c>iss</c>/<c>aud</c>/
/// <c>azp</c>/<c>exp</c>/<c>iat</c>/<c>sub</c> checks; the untrusted-audience MUST when the caller
/// supplies a <c>trustedAudiences</c> set; and the <c>nonce</c> conditional-MUST when the caller
/// supplies an <c>expectedNonce</c>. It surfaces <see cref="Oidc10IdTokenClaims.Acr"/>,
/// <see cref="Oidc10IdTokenClaims.AuthTime"/>, and <see cref="Oidc10IdTokenClaims.Sid"/> on every
/// success but does not itself compare them against a requested <c>acr_values</c>/<c>max_age</c> or
/// an active session — the <c>acr</c>/<c>auth_time</c>/<c>max_age</c> SHOULDs remain the caller's,
/// since satisfying them requires the authentication request the validator never sees. Two
/// §3.1.3.7 items are out of scope for this asymmetric validator: an encrypted (JWE, five-segment)
/// ID Token fails the three-segment structural check as malformed, and a MAC-based (<c>HS*</c>)
/// signature has no symmetric-key path here — a relying party that negotiated encryption or a
/// symmetric signing algorithm decrypts or verifies before this call.
/// </para>
/// </remarks>
[DebuggerDisplay("Oidc10IdTokenValidator")]
public static class Oidc10IdTokenValidator
{
    /// <summary>
    /// Validates an OP-issued ID Token against the relying party's
    /// expectations per OIDC Core §3.1.3.7.
    /// </summary>
    /// <param name="idToken">The compact-serialised JWS ID Token.</param>
    /// <param name="expectedIssuer">The expected <c>iss</c> value; compared by ordinal equality.</param>
    /// <param name="expectedAudience">The expected <c>aud</c> value (the relying party's <c>client_id</c>); required to be present.</param>
    /// <param name="resolveVerificationKey">Resolves the public verification key for the header's <c>kid</c>.</param>
    /// <param name="verifySignature">The signature-verification primitive.</param>
    /// <param name="parser">JSON parser for header and payload segments.</param>
    /// <param name="base64UrlDecoder">Base64url decoder.</param>
    /// <param name="timeProvider">Time provider for <c>exp</c>/<c>nbf</c>/<c>iat</c> checks.</param>
    /// <param name="memoryPool">Memory pool for transient decoded buffers.</param>
    /// <param name="iatSkew">Tolerance for an <c>iat</c> claim slightly in the future.</param>
    /// <param name="tenantId">Tenant identifier threaded to the key resolver.</param>
    /// <param name="context">Per-request context bag threaded to the key resolver.</param>
    /// <param name="expectedAuthorizedParty">
    /// The authorized party (the relying party's own <c>client_id</c>) to validate <c>azp</c> against
    /// per OIDC Core §3.1.3.7. When <see langword="null"/>, <c>azp</c> is surfaced but not enforced;
    /// when supplied, a present <c>azp</c> must equal it and a multi-valued <c>aud</c> must carry <c>azp</c>.
    /// </param>
    /// <param name="expectedNonce">
    /// The nonce value the relying party sent in the authentication request. When non-
    /// <see langword="null"/>, the ID Token's <c>nonce</c> claim must equal it, else the token is
    /// rejected with <see cref="JwsAccessTokenValidationFailureReason.NonceMismatch"/> — OIDC Core
    /// §3.1.3.7's conditional-MUST, conditioned on the relying party having sent a nonce. When
    /// <see langword="null"/>, <c>nonce</c> is surfaced on <see cref="Oidc10IdTokenClaims.Nonce"/> but
    /// not checked.
    /// </param>
    /// <param name="trustedAudiences">
    /// The full set of audiences the relying party trusts, beyond <paramref name="expectedAudience"/>
    /// itself. When non-<see langword="null"/>, every member of the ID Token's <c>aud</c> claim must be
    /// either <paramref name="expectedAudience"/> or a member of this set, else the token is rejected
    /// with <see cref="JwsAccessTokenValidationFailureReason.UntrustedAudience"/> — OIDC Core §3.1.3.7's
    /// MUST to reject an ID Token whose <c>aud</c> contains an audience the relying party does not
    /// trust. When <see langword="null"/>, no additional-audience check runs, so a legitimately
    /// multi-audience ID Token (with <c>azp</c> coordination via <paramref name="expectedAuthorizedParty"/>)
    /// still validates. A relying party that accepts tokens from a multi-audience OP MUST therefore
    /// supply this set or <paramref name="expectedAuthorizedParty"/> (or both) to satisfy the
    /// §3.1.3.7 additional-audience MUST: with both <see langword="null"/> a multi-audience token is
    /// accepted unchecked.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<Oidc10IdTokenValidationResult> ValidateAsync(
        string idToken,
        string expectedIssuer,
        string expectedAudience,
        ServerVerificationKeyResolverDelegate resolveVerificationKey,
        VerificationDelegate verifySignature,
        JwsAccessTokenJsonParser parser,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        MemoryPool<byte> memoryPool,
        TimeSpan iatSkew,
        TenantId tenantId,
        ExchangeContext context,
        string? expectedAuthorizedParty,
        string? expectedNonce,
        IReadOnlyCollection<string>? trustedAudiences,
        CancellationToken cancellationToken)
    {
        SignedJwtValidationOutcome outcome = await JwsAccessTokenValidator.ValidateSignedJwtCoreAsync(
            idToken,
            expectedIssuer,
            expectedAudience,
            resolveVerificationKey,
            verifySignature,
            parser,
            base64UrlDecoder,
            timeProvider,
            memoryPool,
            iatSkew,
            tenantId,
            context,
            expectedAuthorizedParty,
            JwtTypeEnforcement.RejectAtJwt,
            cancellationToken).ConfigureAwait(false);

        if(!outcome.IsSuccess)
        {
            return Oidc10IdTokenValidationResult.Failure(outcome.FailureReason!.Value, outcome.FailureDescription);
        }

        JwtPayload payload = outcome.Payload!;

        //OIDC Core §3.1.3.7: "The Client MUST validate that the aud Claim contains ... an array with
        //more than one element ... only if the ID Token is issued from an Authorization Server that
        //the Client trusts." Enforced only when the caller supplies its trust set; expectedAudience is
        //always trusted since the aud-membership check in the shared core already required it present.
        if(trustedAudiences is not null && HasUntrustedAudience(outcome.Audience!, expectedAudience, trustedAudiences))
        {
            return Oidc10IdTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.UntrustedAudience,
                "ID Token aud contains a member that is neither the expected audience nor in the caller's trusted audience set (OIDC Core §3.1.3.7).");
        }

        JwsAccessTokenValidator.TryReadString(payload, WellKnownJwtClaimNames.Nonce, out string? nonce);
        if(expectedNonce is not null && !string.Equals(nonce, expectedNonce, StringComparison.Ordinal))
        {
            return Oidc10IdTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.NonceMismatch,
                "ID Token nonce is missing or does not equal the expected nonce (OIDC Core §3.1.3.7).");
        }

        DateTimeOffset? authTime = JwsAccessTokenValidator.TryReadEpochSeconds(
            payload, WellKnownJwtClaimNames.AuthTime, out DateTimeOffset authTimeValue)
            ? authTimeValue
            : null;
        JwsAccessTokenValidator.TryReadString(payload, WellKnownJwtClaimNames.Acr, out string? acr);
        IReadOnlyList<string>? amr = JwsAccessTokenValidator.TryReadStringList(
            payload, WellKnownJwtClaimNames.Amr, out IReadOnlyList<string> amrValues)
            ? amrValues
            : null;
        JwsAccessTokenValidator.TryReadString(payload, WellKnownJwtClaimNames.Sid, out string? sid);
        ConfirmationMethod? confirmation = JwsAccessTokenValidator.TryReadConfirmation(payload);

        Oidc10IdTokenClaims claims = new()
        {
            Subject = outcome.Subject!,
            Issuer = outcome.Issuer!,
            Audience = outcome.Audience!,
            IssuedAt = outcome.IssuedAt!.Value,
            Expiration = outcome.Expiration!.Value,
            NotBefore = outcome.NotBefore,
            AuthorizedParty = outcome.AuthorizedParty,
            Nonce = nonce,
            AuthTime = authTime,
            Acr = acr,
            Amr = amr,
            Sid = sid,
            Confirmation = confirmation
        };

        return Oidc10IdTokenValidationResult.Success(claims);
    }


    /// <summary>
    /// Whether <paramref name="audience"/> carries a member that is neither
    /// <paramref name="expectedAudience"/> nor a member of <paramref name="trustedAudiences"/>.
    /// </summary>
    private static bool HasUntrustedAudience(
        IReadOnlyList<string> audience,
        string expectedAudience,
        IReadOnlyCollection<string> trustedAudiences)
    {
        for(int i = 0; i < audience.Count; i++)
        {
            string candidate = audience[i];
            if(string.Equals(candidate, expectedAudience, StringComparison.Ordinal))
            {
                continue;
            }

            bool isTrusted = false;
            foreach(string trusted in trustedAudiences)
            {
                if(string.Equals(candidate, trusted, StringComparison.Ordinal))
                {
                    isTrusted = true;
                    break;
                }
            }

            if(!isTrusted)
            {
                return true;
            }
        }

        return false;
    }
}
