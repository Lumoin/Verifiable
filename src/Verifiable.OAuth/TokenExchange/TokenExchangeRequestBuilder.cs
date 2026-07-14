using System.Diagnostics;
using Verifiable.Core;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.IdJag;
using Verifiable.OAuth.WellKnown;

namespace Verifiable.OAuth.TokenExchange;

/// <summary>
/// The acting-party token and its type, presented together on an
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 §2.1</see> token-exchange
/// request when the exchange is a DELEGATION (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-1.1">§1.1</see>)
/// rather than an impersonation.
/// </summary>
/// <remarks>
/// RFC 8693 §2.1 makes <c>actor_token_type</c> REQUIRED whenever <c>actor_token</c> is present and
/// says it "MUST NOT be included otherwise" — a paired-presence rule two independently-nullable
/// fields can only enforce at runtime. Placing both members as <see langword="required"/> on this one
/// carrier instead makes the invalid state (a token with no type, or a type with no token)
/// unconstructible: there is no way to build a <see cref="TokenExchangeBuilderOptions"/> that carries
/// one without the other.
/// </remarks>
[DebuggerDisplay("TokenExchangeActor TokenType={TokenType}")]
public sealed record TokenExchangeActor
{
    /// <summary>The security token that represents the identity of the acting party (RFC 8693 §2.1 <c>actor_token</c>). Confidential.</summary>
    public required string Token { get; init; }

    /// <summary>The type of <see cref="Token"/> (RFC 8693 §2.1 <c>actor_token_type</c>).</summary>
    public required TokenType TokenType { get; init; }
}


/// <summary>
/// Per-call inputs for <see cref="TokenExchangeRequestBuilder.Build(TokenExchangeBuilderOptions)"/> —
/// the client side of an <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 §2.1</see>
/// token-exchange request. Field shape mirrors the client-side precedent
/// <see cref="Verifiable.OAuth.IdJag.IdJagMintOptions"/>: <see langword="required"/> for §2.1 REQUIRED parameters,
/// nullable or empty-defaulted for OPTIONAL ones.
/// </summary>
[DebuggerDisplay("TokenExchangeBuilderOptions SubjectTokenType={SubjectTokenType}, Delegation={Actor != null}")]
public sealed record TokenExchangeBuilderOptions
{
    /// <summary>The security token identifying the party the request is made on behalf of (RFC 8693 §2.1 <c>subject_token</c>, REQUIRED). Confidential.</summary>
    public required string SubjectToken { get; init; }

    /// <summary>The type of <see cref="SubjectToken"/> (RFC 8693 §2.1 <c>subject_token_type</c>, REQUIRED).</summary>
    public required TokenType SubjectTokenType { get; init; }

    /// <summary>
    /// The acting-party token and its type (RFC 8693 §2.1 <c>actor_token</c> / <c>actor_token_type</c>),
    /// or <see langword="null"/> for an IMPERSONATION exchange with no acting party. Presence selects
    /// DELEGATION (RFC 8693 §1.1); see <see cref="TokenExchangeActor"/> for why the pairing is one
    /// carrier rather than two independently-nullable fields.
    /// </summary>
    public TokenExchangeActor? Actor { get; init; }

    /// <summary>The type of token requested (RFC 8693 §2.1 <c>requested_token_type</c>, OPTIONAL). <see langword="null"/> leaves the issued type to the authorization server's discretion.</summary>
    public TokenType? RequestedTokenType { get; init; }

    /// <summary>
    /// The target-resource URIs (RFC 8693 §2.1 / <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>
    /// <c>resource</c>, OPTIONAL, REPEATABLE). Each entry MUST be an absolute URI with no fragment
    /// component; <see cref="TokenExchangeRequestBuilder.Build(TokenExchangeBuilderOptions)"/> enforces
    /// this build-time and rejects the whole request with <see cref="InvalidResourceParameter"/> when
    /// it is not. MAY be empty.
    /// </summary>
    public IReadOnlyList<string> Resource { get; init; } = [];

    /// <summary>
    /// The logical name of the target service (RFC 8693 §2.1 <c>audience</c>, OPTIONAL). A single
    /// value — unlike <see cref="Resource"/>, RFC 8693 does not make <c>audience</c> a client-side
    /// repeatable-carrier concern for this builder, and the value MAY itself contain spaces (it is an
    /// opaque logical name, not a URI).
    /// </summary>
    public string? Audience { get; init; }

    /// <summary>The requested scope of the issued token (RFC 8693 §2.1 / RFC 6749 §3.3 <c>scope</c>, OPTIONAL).</summary>
    public string? Scope { get; init; }
}


/// <summary>
/// Builds the body of an <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 §2.1</see>
/// token-exchange request as an <see cref="OutgoingFormFields"/>.
/// </summary>
/// <remarks>
/// Static and allocation-light: no I/O, and no client authentication — those are separate, composable
/// steps (RFC 6749 §2.3: "the client MUST NOT use more than one authentication method in each
/// request") via <see cref="OutgoingFormFieldsClientAuthExtensions.WithClientSecretPost"/>,
/// <see cref="OutgoingHeadersClientAuthExtensions.WithClientSecretBasic"/>, or
/// <see cref="ClientAssertionSigning"/>. The caller hands the resulting <see cref="OutgoingFormFields"/>
/// to <see cref="OAuthClientInfrastructure.SendFormPostAsync"/>; no percent-encoding happens here (the
/// transport delegate owns <c>application/x-www-form-urlencoded</c> wire encoding).
/// </remarks>
public static class TokenExchangeRequestBuilder
{
    /// <summary>
    /// The exact rejection reason reported on <see cref="InvalidResourceParameter"/> — the same message
    /// the shipped authorization-server-side resource parser uses, so both sides of the wire describe
    /// the identical rule.
    /// </summary>
    public const string InvalidResourceReason =
        "The resource parameter must be an absolute https, http, or urn URI without a fragment.";


    /// <summary>
    /// Composes <paramref name="options"/> into the RFC 8693 §2.1 request body, or a
    /// <see cref="TokenRequestBuilderError"/> when <see cref="TokenExchangeBuilderOptions.Resource"/>
    /// contains a value that is not an absolute URI without a fragment (RFC 8693 §2.1 /
    /// RFC 8707 §2). The authorization server's own <c>invalid_target</c> policy decision (RFC 8693
    /// §2.2.2) is a separate, later step this check does not perform or preempt.
    /// </summary>
    /// <param name="options">The per-call token-exchange inputs.</param>
    public static Result<OutgoingFormFields, TokenRequestBuilderError> Build(TokenExchangeBuilderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        foreach(string resource in options.Resource)
        {
            if(!IsValidResource(resource))
            {
                return Result.Failure<OutgoingFormFields, TokenRequestBuilderError>(
                    new InvalidResourceParameter(resource, InvalidResourceReason));
            }
        }

        OutgoingFormFields form = new(capacity: 8)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.SubjectToken] = options.SubjectToken,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(options.SubjectTokenType)
        };

        if(options.Actor is TokenExchangeActor actor)
        {
            form[OAuthRequestParameterNames.ActorToken] = actor.Token;
            form[OAuthRequestParameterNames.ActorTokenType] = TokenTypeNames.GetName(actor.TokenType);
        }

        if(options.RequestedTokenType is TokenType requestedTokenType)
        {
            form[OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(requestedTokenType);
        }

        //RFC 8693 §2.1.1 / RFC 8707 §2: multiple resource values indicate the issued token is intended
        //for all of them. OutgoingFormFields is a single-value-per-key dictionary, so repetition is
        //represented the same way the shipped ID-JAG mint path represents it
        //(IdJagFlowHandlers.MintAsync) — collapsed to one space-delimited field the authorization
        //server's skin re-splits.
        if(options.Resource.Count > 0)
        {
            form[OAuthRequestParameterNames.Resource] = string.Join(' ', options.Resource);
        }

        if(!string.IsNullOrEmpty(options.Audience))
        {
            form[OAuthRequestParameterNames.Audience] = options.Audience;
        }

        if(!string.IsNullOrEmpty(options.Scope))
        {
            form[OAuthRequestParameterNames.Scope] = options.Scope;
        }

        return Result.Success<OutgoingFormFields, TokenRequestBuilderError>(form);
    }


    /// <summary>
    /// RFC 8707 §2 / RFC 8693 §2.1: a <c>resource</c> value MUST be an absolute URI
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.3">RFC 3986 §4.3</see>) and MUST
    /// NOT include a fragment component. Restricted to https/http/urn schemes — the same
    /// cross-platform <see cref="Uri.TryCreate(string, UriKind, out Uri)"/> guard the shipped
    /// authorization-server-side resource parser uses, since a leading-slash value like
    /// <c>/relative</c> parses as an absolute <c>file:</c> URI on Unix but not on Windows, so scheme
    /// restriction (not <see cref="UriKind.Absolute"/> alone) is what keeps the check
    /// platform-independent.
    /// </summary>
    private static bool IsValidResource(string resource) =>
        Uri.TryCreate(resource, UriKind.Absolute, out Uri? parsed)
        && (string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            || string.Equals(parsed.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
            || string.Equals(parsed.Scheme, "urn", StringComparison.Ordinal))
        && string.IsNullOrEmpty(parsed.Fragment);
}
