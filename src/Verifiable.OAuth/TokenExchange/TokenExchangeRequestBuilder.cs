using System.Diagnostics;
using Verifiable.Core;
using Verifiable.OAuth.Client;

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
    /// component. <see cref="TokenExchangeRequestBuilder.Build(TokenExchangeBuilderOptions)"/> reads each
    /// entry by <see cref="ResourceIndicatorSyntax.IsAbsoluteResourceIndicator(ReadOnlySpan{char})"/>, the
    /// rule the token endpoint reads a <c>resource</c> value by: an absolute URI of any scheme, in
    /// ASCII, with well-formed percent triplets and no fragment; for <c>http</c> and <c>https</c>, an
    /// authority with a non-empty host and no userinfo. The rule admits the userinfo of any other
    /// scheme and sends it as written:
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.1">RFC 3986 Section 3.2.1</see>
    /// says "The userinfo subcomponent may consist of a user name and, optionally, scheme-specific
    /// information about how to gain authorization to access the resource." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-7.6">Section 7.6</see> that it "can
    /// be used to construct a URI intended to mislead a human user", and the entry on resource
    /// indicators in the authorization server design document states the same deviation. An
    /// entry the rule refuses rejects the whole request with <see cref="InvalidResourceParameter"/>.
    /// Every other entry is sent as its own <c>resource</c> occurrence, unfolded. MAY be empty.
    /// </summary>
    public IReadOnlyList<string> Resource { get; init; } = [];

    /// <summary>
    /// The logical name of the target service (RFC 8693 §2.1 <c>audience</c>, OPTIONAL). A single
    /// value — unlike <see cref="Resource"/>, RFC 8693 does not make <c>audience</c> a client-side
    /// repeatable-carrier concern for this builder, and the value MAY itself contain spaces (it is an
    /// opaque logical name, not a URI).
    /// </summary>
    public string? Audience { get; init; }

    /// <summary>
    /// The requested scope of the issued token (RFC 8693 section 2.1 / RFC 6749 section 3.3 <c>scope</c>, OPTIONAL).
    /// A value of white space only, white space being every character
    /// <see cref="char.IsWhiteSpace(char)"/> reads as white space, holds no <c>scope-token</c> and is
    /// no scope: the request carries no <c>scope</c> parameter
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 section 3.3</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">section 3.2</see>). Any other
    /// value is sent as given, its <c>scope-token</c> syntax being the caller's.
    /// </summary>
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
    /// The rejection reason reported on <see cref="InvalidResourceParameter"/>: the text the token
    /// endpoint answers as the <c>error_description</c> of its <c>invalid_target</c> refusal of a
    /// <c>resource</c> value, so both sides of the wire describe the identical rule.
    /// </summary>
    public static string InvalidResourceReason { get; } =
        "The resource parameter must be an absolute URI (RFC 3986 section 4.3) without a fragment.";


    /// <summary>
    /// Composes <paramref name="options"/> into the RFC 8693 §2.1 request body, or a
    /// <see cref="TokenRequestBuilderError"/> when an entry of <see cref="TokenExchangeBuilderOptions.Resource"/>
    /// is refused by <see cref="ResourceIndicatorSyntax.IsAbsoluteResourceIndicator(ReadOnlySpan{char})"/>,
    /// the rule the token endpoint reads a <c>resource</c> value by (RFC 8693 section 2.1 / RFC 8707 section 2):
    /// an absolute URI of any scheme, in ASCII, with well-formed percent triplets and no fragment; for
    /// <c>http</c> and <c>https</c>, an authority with a non-empty host and no userinfo. The rule
    /// admits the userinfo of any other scheme, which is sent as written
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.1">RFC 3986 Section 3.2.1</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-7.6">Section 7.6</see>), as the
    /// entry on resource indicators in the authorization server design document states. Every
    /// other entry is sent as its own <c>resource</c> occurrence, unfolded. A
    /// <see cref="TokenExchangeBuilderOptions.Scope"/> of white space only holds no <c>scope-token</c>
    /// and is no scope, so the request carries no <c>scope</c> parameter
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 section 3.3</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">section 3.2</see>). The
    /// authorization server's own <c>invalid_target</c> policy decision (RFC 8693 section 2.2.2) is a separate,
    /// later step this check does not perform or preempt.
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
        //for all of them. Each entry becomes its OWN repeated resource occurrence on the wire
        //(OutgoingFormFields.Add) — the genuine RFC 8707 §2 multi-resource wire form the
        //authorization server's own ReadResource/RequestFields.GetValues read expects, never one
        //occurrence carrying several space-joined URIs.
        foreach(string resource in options.Resource)
        {
            form.Add(OAuthRequestParameterNames.Resource, resource);
        }

        if(!string.IsNullOrEmpty(options.Audience))
        {
            form[OAuthRequestParameterNames.Audience] = options.Audience;
        }

        if(!string.IsNullOrWhiteSpace(options.Scope))
        {
            form[OAuthRequestParameterNames.Scope] = options.Scope;
        }

        return Result.Success<OutgoingFormFields, TokenRequestBuilderError>(form);
    }


    /// <summary>
    /// RFC 8707 §2 / RFC 8693 §2.1: a <c>resource</c> value MUST be an absolute URI
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.3">RFC 3986 section 4.3</see>) and
    /// MUST NOT include a fragment component. The value is read by
    /// <see cref="ResourceIndicatorSyntax.IsAbsoluteResourceIndicator(ReadOnlySpan{char})"/>, the rule
    /// the token endpoint reads a <c>resource</c> value by, so the builder refuses every value the
    /// token endpoint refuses. An empty entry, which the endpoint reads as omitted
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 Section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."),
    /// is refused here.
    /// </summary>
    /// <param name="resource">The <c>resource</c> value.</param>
    private static bool IsValidResource(string resource) =>
        ResourceIndicatorSyntax.IsAbsoluteResourceIndicator(resource);
}
