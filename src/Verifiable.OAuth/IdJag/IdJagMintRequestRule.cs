using System.Collections.Frozen;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.TokenExchange;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// Builds a <see cref="ValidateTokenExchangeRequestDelegate"/> that holds a Token Exchange request for an
/// Identity Assertion JWT Authorization Grant (ID-JAG) to the <c>requested_token_type</c> of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.3</see>:
/// "requested_token_type: REQUIRED - The value urn:ietf:params:oauth:token-type:id-jag indicates that an Identity
/// Assertion JWT Authorization Grant is being requested." and "audience: REQUIRED - The identifier of the
/// Resource Authorization Server in another trust domain as the intended audience for the ID-JAG."
/// </summary>
/// <remarks>
/// <para>
/// Token Exchange itself leaves the parameter optional
/// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 Section 2.1</see>), so the token
/// endpoint cannot tell an ID-JAG request that omits it from a plain exchange. The rule tells them apart by the
/// request's shape and an explicit set of <c>audience</c> values: a request whose <c>subject_token_type</c> is
/// one of the three Section 4.3 names (<c>urn:ietf:params:oauth:token-type:id_token</c>,
/// <c>urn:ietf:params:oauth:token-type:saml2</c>, <c>urn:ietf:params:oauth:token-type:refresh_token</c>) and
/// whose one <c>audience</c> is in the set is an ID-JAG request, and one whose <c>requested_token_type</c> is
/// absent or names another type is refused, naming <see cref="OAuthRequestParameterNames.RequestedTokenType"/>
/// with the description "requested_token_type must be urn:ietf:params:oauth:token-type:id-jag.". The token
/// endpoint answers that refusal 400 <c>invalid_request</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see>). A request
/// the rule cannot classify (no <c>audience</c>, several, one outside the set, or another
/// <c>subject_token_type</c>) passes untouched.
/// </para>
/// <para>
/// The set is explicit, with no mode that covers every audience: a server mints ID-JAGs for the Resource
/// Authorization Servers it knows, and only a request naming one of them is read as an ID-JAG request.
/// </para>
/// <para>
/// The rule is opt-in. An application wires the delegate as
/// <see cref="AuthorizationServerIntegration.ValidateTokenExchangeRequestAsync"/>, alone or composed with its
/// own: its delegate calls the rule's delegate first, returns a refusal the rule answers, and otherwise runs its
/// own checks. Every policy beyond the shape (which client may mint for which audience, which subjects, which
/// scopes) stays the application's, in its own request seam and in
/// <see cref="AuthorizationServerIntegration.AuthorizeTokenExchangeAsync"/>.
/// </para>
/// </remarks>
public static class IdJagMintRequestRule
{
    /// <summary>
    /// The description of the refusal, naming the one <c>requested_token_type</c> value an ID-JAG request
    /// carries
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.3</see>).
    /// </summary>
    private static string RequestedTokenTypeDescription { get; } =
        "requested_token_type must be urn:ietf:params:oauth:token-type:id-jag.";


    /// <summary>
    /// Builds the request seam over an explicit set of <c>audience</c> values.
    /// </summary>
    /// <remarks>
    /// A member that is <see langword="null"/>, empty or white space only names no audience: the token endpoint drops an
    /// empty <c>audience</c> and refuses one of white space only before the seam runs, so such a member could match no
    /// request and a rule built over it would refuse nothing. It is the caller's own bad argument and throws.
    /// </remarks>
    /// <param name="audiences">
    /// The <c>audience</c> values of the Resource Authorization Servers this server mints ID-JAGs for, compared
    /// ordinally; the set is copied when the seam is built.
    /// </param>
    /// <returns>The request seam to wire as <see cref="AuthorizationServerIntegration.ValidateTokenExchangeRequestAsync"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="audiences"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="audiences"/> is empty, or one of its members is <see langword="null"/>, empty or white space only.
    /// </exception>
    public static ValidateTokenExchangeRequestDelegate Build(IEnumerable<string> audiences)
    {
        ArgumentNullException.ThrowIfNull(audiences);

        FrozenSet<string> audienceSet = audiences.ToFrozenSet(StringComparer.Ordinal);
        if(audienceSet.Count == 0)
        {
            throw new ArgumentException("The set of audience values must name at least one value.", nameof(audiences));
        }

        if(audienceSet.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException(
                "The set of audience values must not hold a value that is null, empty or white space only.", nameof(audiences));
        }

        return (request, registration, context, cancellationToken) =>
            ValueTask.FromResult<TokenExchangeRequestRefusal?>(IsIdJagRequestWithoutTheIdJagType(request, audienceSet)
                ? new TokenExchangeRequestRefusal
                {
                    Parameter = OAuthRequestParameterNames.RequestedTokenType,
                    Description = RequestedTokenTypeDescription
                }
                : null);
    }


    /// <summary>
    /// Whether <paramref name="request"/> is an ID-JAG request by its shape (a <c>subject_token_type</c> of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.3</see>
    /// and one <c>audience</c> in <paramref name="audienceSet"/>) whose <c>requested_token_type</c> is absent or is
    /// not the id-jag type. The classification is a rule of this library.
    /// </summary>
    /// <param name="request">The Token Exchange request after the library's parameter checks.</param>
    /// <param name="audienceSet">The audience values the rule was built over.</param>
    /// <returns><see langword="true"/> when the request is refused.</returns>
    private static bool IsIdJagRequestWithoutTheIdJagType(TokenExchangeRequest request, FrozenSet<string> audienceSet)
    {
        bool isIdJagSubjectTokenType = request.SubjectTokenType == TokenType.IdToken
            || request.SubjectTokenType == TokenType.Saml2
            || request.SubjectTokenType == TokenType.RefreshToken;
        bool isOneKnownAudience = request.Audience is [string audience] && audienceSet.Contains(audience);

        return isIdJagSubjectTokenType && isOneKnownAudience && request.RequestedTokenType != TokenType.IdJag;
    }
}
