using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// The check of the client's own holding of an identity assertion grant that refused it, before the client presents it
/// anywhere (<see cref="IdJagGrantHolding.HoldAsync"/>).
/// </summary>
public enum IdJagGrantRefusal
{
    /// <summary>The grant is no compact JWS whose header and payload are JSON (RFC 7515 §7.1).</summary>
    Malformed,

    /// <summary>
    /// The header's <c>typ</c> is not <c>oauth-id-jag+jwt</c> (draft-ietf-oauth-identity-assertion-authz-grant-04 §3.1:
    /// "typ: REQUIRED. The ID-JAG MUST contain a typ header with the value oauth-id-jag+jwt.").
    /// </summary>
    TypeNotIdJag,

    /// <summary>The <c>iss</c> is not the issuer the client expects of the identity provider that minted it.</summary>
    IssuerNotExpected,

    /// <summary>
    /// No key of the provider's published set verifies the grant under the header's algorithm: the header names no <c>kid</c>
    /// or no <c>alg</c>, or the resolver answers no key (RFC 8725 §3.1).
    /// </summary>
    KeyUnresolved,

    /// <summary>The signature does not verify under the key resolved (RFC 7515 §5.2).</summary>
    SignatureUnverified,

    /// <summary>
    /// A claim rule of draft-04 §4.4.1 refused the grant (<see cref="IdJagAssertionValidation.Validate"/>); the rule is
    /// <see cref="IdJagGrantHoldingResult.ClaimsFailure"/>.
    /// </summary>
    ClaimsRefused,

    /// <summary>
    /// The grant names a <c>resource</c> and not the one the exchange asked for (the Enterprise-Managed Authorization
    /// extension's section 4: "resource ... if set, MUST be the Resource Identifier of the MCP Server").
    /// </summary>
    ResourceNotAsked
}


/// <summary>
/// What a client expects of an identity assertion grant it obtained from an identity provider, before it presents it at the
/// Resource Authorization Server (draft-ietf-oauth-identity-assertion-authz-grant-04 §4.4.1, as the client holds it).
/// </summary>
[DebuggerDisplay("IdJagGrantExpectations Issuer={Issuer} ResourceAuthorizationServer={ResourceAuthorizationServer}")]
public sealed record IdJagGrantExpectations
{
    /// <summary>The <c>iss</c> the identity provider's grants carry, compared code point for code point.</summary>
    public required string Issuer { get; init; }

    /// <summary>The Resource Authorization Server's issuer identifier, the grant's one <c>aud</c> (draft-04 §4.4.1).</summary>
    public required string ResourceAuthorizationServer { get; init; }

    /// <summary>
    /// The client identifier the client authenticates at the Resource Authorization Server with, the grant's <c>client_id</c>
    /// (draft-04 §4.4.1: "The client_id claim MUST identify the same client as the client authentication in the request").
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>The resource the exchange asked the grant for, which a grant naming any <c>resource</c> must name.</summary>
    public required string Resource { get; init; }
}


/// <summary>
/// What holding an identity assertion grant found: the identifiers it carries as read once before verification
/// (<see cref="Facts"/>) and, where a check refused it, which (<see cref="Refusal"/>, and the claim rule under
/// <see cref="ClaimsFailure"/>).
/// </summary>
[DebuggerDisplay("IdJagGrantHoldingResult Refusal={Refusal} ClaimsFailure={ClaimsFailure}")]
public sealed record IdJagGrantHoldingResult
{
    /// <summary>The grant's identifiers, read unverified: text its issuer chose, even where every check held.</summary>
    public required UnverifiedJwsFacts Facts { get; init; }

    /// <summary>The check that refused the grant, or <see langword="null"/> where every check held.</summary>
    public IdJagGrantRefusal? Refusal { get; init; }

    /// <summary>The claim rule that refused it, for <see cref="IdJagGrantRefusal.ClaimsRefused"/>; otherwise <see langword="null"/>.</summary>
    public IdJagValidationFailureReason? ClaimsFailure { get; init; }

    /// <summary>Whether every check held, so the client may present the grant.</summary>
    public bool IsHeld => Refusal is null;
}


/// <summary>
/// The client's own holding of an identity assertion grant an identity provider minted for it
/// (draft-ietf-oauth-identity-assertion-authz-grant-04 §4.3 and §4.4.1), before the client presents it at the Resource
/// Authorization Server: a client acting for a person presents nothing it cannot verify, so the grant is held to the
/// checks the Resource Authorization Server makes of it, through the library's one judgement of its claims
/// (<see cref="IdJagAssertionValidation.Validate"/>), configured with the client's expectations.
/// </summary>
public static class IdJagGrantHolding
{
    /// <summary>
    /// Holds a grant: its <c>typ</c> (draft-04 §3.1), its <c>iss</c> the provider's, the key its header's <c>kid</c> names
    /// resolved under the header's <c>alg</c> alone (RFC 8725 §3.1), its signature verified under that key (RFC 7515 §5.2),
    /// every claim rule of §4.4.1 with the Resource Authorization Server as its one audience and the client the server
    /// authenticates as its <c>client_id</c>, and a <c>resource</c> it names the one asked for. The checks run in that order
    /// and the first that refuses ends the holding; the grant's identifiers are read once whatever is found.
    /// </summary>
    /// <param name="assertion">The compact grant the provider answered.</param>
    /// <param name="expectations">What the client expects of it.</param>
    /// <param name="resolveKey">Resolves the provider's published key by the header's <c>kid</c> and <c>alg</c>.</param>
    /// <param name="base64UrlDecoder">The base64url decoder.</param>
    /// <param name="partDecoder">The decoder of the verified header and payload.</param>
    /// <param name="pool">The pool decoded parts are rented from.</param>
    /// <param name="timeProvider">The clock the temporal claims are judged by.</param>
    /// <param name="clockSkew">The tolerance the temporal claims are judged with.</param>
    /// <param name="cancellationToken">Cancels the key's resolution and the verification.</param>
    /// <returns>What the holding found.</returns>
    public static async ValueTask<IdJagGrantHoldingResult> HoldAsync(
        string assertion,
        IdJagGrantExpectations expectations,
        ResolveJwsVerificationKeyDelegate resolveKey,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        BaseMemoryPool pool,
        TimeProvider timeProvider,
        TimeSpan clockSkew,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(expectations);
        ArgumentNullException.ThrowIfNull(resolveKey);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(partDecoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(timeProvider);

        if(UnverifiedJwsFacts.Read(assertion, base64UrlDecoder, pool) is not { } facts)
        {
            return Refused(UnverifiedJwsFacts.None, IdJagGrantRefusal.Malformed);
        }

        if(facts.Type is not { } type || !WellKnownMediaTypes.Jwt.IsOauthIdJagJwt(type))
        {
            return Refused(facts, IdJagGrantRefusal.TypeNotIdJag);
        }

        if(!string.Equals(facts.Issuer, expectations.Issuer, StringComparison.Ordinal))
        {
            return Refused(facts, IdJagGrantRefusal.IssuerNotExpected);
        }

        if(facts.KeyId is not { Length: > 0 } keyId || facts.Algorithm is not { Length: > 0 } algorithm)
        {
            return Refused(facts, IdJagGrantRefusal.KeyUnresolved);
        }

        using var key = await resolveKey(keyId, algorithm, cancellationToken).ConfigureAwait(false);

        if(key is null)
        {
            return Refused(facts, IdJagGrantRefusal.KeyUnresolved);
        }

        JwsVerificationResult verification;

        try
        {
            verification = await Jws.VerifyAndDecodeAsync(assertion, base64UrlDecoder, partDecoder, pool, key, cancellationToken)
                .ConfigureAwait(false);
        }
        catch(Exception unreadable) when(unreadable is FormatException or InvalidOperationException or ArgumentException)
        {
            return Refused(facts, IdJagGrantRefusal.SignatureUnverified);
        }

        if(!verification.IsValid)
        {
            return Refused(facts, IdJagGrantRefusal.SignatureUnverified);
        }

        var validated = IdJagAssertionValidation.Validate(
            verification.Header,
            verification.Payload,
            expectations.ResourceAuthorizationServer,
            expectations.ClientId,
            timeProvider.GetUtcNow(),
            clockSkew);

        if(!validated.IsValid)
        {
            return new IdJagGrantHoldingResult
            {
                Facts = facts,
                Refusal = IdJagGrantRefusal.ClaimsRefused,
                ClaimsFailure = validated.FailureReason
            };
        }

        if(validated.Resource.Count > 0 && !validated.Resource.Contains(expectations.Resource, StringComparer.Ordinal))
        {
            return Refused(facts, IdJagGrantRefusal.ResourceNotAsked);
        }

        return new IdJagGrantHoldingResult { Facts = facts };
    }


    /// <summary>A holding refused by one check.</summary>
    /// <param name="facts">The grant's identifiers.</param>
    /// <param name="refusal">The check.</param>
    /// <returns>The result.</returns>
    private static IdJagGrantHoldingResult Refused(UnverifiedJwsFacts facts, IdJagGrantRefusal refusal) =>
        new() { Facts = facts, Refusal = refusal };
}
