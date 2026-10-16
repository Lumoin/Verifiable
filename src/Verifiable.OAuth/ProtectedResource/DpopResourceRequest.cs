using System.Diagnostics;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// One presentation of an access token at an application's protected resource, the input of
/// <see cref="DpopResourceAccess.DecideAsync"/>: the token as presented, the scheme it was presented under, the binding the
/// caller's own validation read from it, the request's method, target URI and <c>DPoP</c> field lines, and the
/// parameters of the <c>DPoP</c> challenges the resource answers with.
/// </summary>
/// <remarks>
/// <para>
/// The caller validates the access token first, its signature, issuer, audience and lifetime, and passes only what
/// that validation read of its binding: <see cref="IsSenderConstrained"/> whether it carries a <c>cnf</c> claim and
/// <see cref="BoundThumbprint"/> its <c>cnf.jkt</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 Section 6.1</see>). The library's
/// <see cref="JwsAccessTokenValidator.ValidateAsync"/> refuses a token whose <c>cnf</c> carries no <c>jkt</c> it reads,
/// so a token it validated is either unbound (<see cref="JwsAccessTokenClaims.Confirmation"/> <see langword="null"/>)
/// or bound by its <c>cnf.jkt</c>. A caller validating with its own validator, which reads another confirmation method,
/// passes such a token as <see cref="IsSenderConstrained"/> without a <see cref="BoundThumbprint"/>, and it is refused
/// rather than served as a bearer token.
/// </para>
/// <para>
/// A resource requiring DPoP-bound access tokens (<see cref="IsDpopBoundAccessTokenRequired"/>) answers a request
/// without credentials and any <c>Bearer</c> presentation with the <c>DPoP</c> challenge alone and no <c>error</c>,
/// before validating the token, as the library's resources do
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "Upon receipt of a
/// request to a protected resource within the protection space requiring DPoP authentication, the server can respond
/// with a challenge to the client to provide DPoP authentication information if the request does not include valid
/// credentials or does not contain an access token sufficient for access."; RFC 6750 Section 3.1). A request that
/// reaches no validated token, one without credentials, with a malformed <c>Authorization</c> field or with a
/// <c>Bearer</c> presentation the caller refuses before validating its token, is the caller's to answer so; a
/// <c>Bearer</c> presentation of a validated token is answered so by <see cref="DpopResourceAccess.DecideAsync"/>. An
/// <c>Authorization</c> field sent on two or more lines is the caller's to answer 400 <c>invalid_request</c> before any
/// token is validated, as the library's resources answer it
/// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request The
/// request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same
/// parameter, uses more than one method for including an access token, or is otherwise malformed. The resource server
/// SHOULD respond with the HTTP 400 (Bad Request) status code."): under the requirement with the <c>DPoP</c> challenge
/// alone carrying that error, otherwise with the challenge of the mechanism the lines attempt, the <c>DPoP</c>
/// challenge alone where every line names <c>DPoP</c>, the <c>Bearer</c> challenge alone where every line names
/// <c>Bearer</c>, both in one field line where the lines name two schemes
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used to
/// attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
/// deliver error information (Figure 18)." and "Otherwise, both Bearer and DPoP challenges MAY be used to deliver error
/// information (Figure 19).").
/// </para>
/// <para>
/// The realm, the scope, the metadata URL and the requirement are the application's own knowledge of its protection
/// space and enter as values it passes; the library derives none of them.
/// </para>
/// </remarks>
[DebuggerDisplay("DpopResourceRequest {HttpMethod} IsDpopPresentation={IsDpopPresentation}")]
public sealed record DpopResourceRequest
{
    /// <summary>The access token exactly as presented, the value a DPoP proof's <c>ath</c> claim hashes.</summary>
    public required string AccessToken { get; init; }

    /// <summary>
    /// Whether the token was presented under the <c>DPoP</c> scheme
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "A DPoP-bound
    /// access token is sent using the Authorization request header field per Section 11.6.2 of [RFC9110] with an
    /// authentication scheme of DPoP."), or under the <c>Bearer</c> scheme otherwise.
    /// </summary>
    public required bool IsDpopPresentation { get; init; }

    /// <summary>Whether the validated token carries a <c>cnf</c> claim, a confirmation of any method.</summary>
    public bool IsSenderConstrained { get; init; }

    /// <summary>
    /// The token's <c>cnf.jkt</c>, the JWK SHA-256 Thumbprint of the public key it is bound to, or
    /// <see langword="null"/> when the token carries none.
    /// </summary>
    public string? BoundThumbprint { get; init; }

    /// <summary>The HTTP method of the request, the value a DPoP proof's <c>htm</c> claim names.</summary>
    public required string HttpMethod { get; init; }

    /// <summary>
    /// The target URI of the request as the resource's own configuration names it, its scheme, authority and path with
    /// no userinfo, query or fragment, never read from the request's <c>Host</c> field: the value a DPoP proof's
    /// <c>htu</c> claim names (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section
    /// 4.2</see>: "htu: The HTTP target URI (Section 7.1 of [RFC9110]) of the request to which the JWT is attached,
    /// without query and fragment parts."; <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section
    /// 4.3</see>: "The htu claim matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring
    /// any query and fragment parts."), and the endpoint the resource's nonces are issued for and accepted at. It is the
    /// configured origin followed by the route's path, never the request path resolved as a relative reference, and a
    /// request whose path would put a query or fragment into it is the application's to refuse before calling
    /// <see cref="DpopResourceAccess.DecideAsync"/>. A proof's <c>jti</c> is recorded through the integration's
    /// <c>jti</c> slots, which carry no target URI, so it is keyed as the application keys it. A value that is not an
    /// absolute http or https URI, or that carries userinfo
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">RFC 9110 Section 4.2.4</see>: "A sender MUST NOT
    /// generate the userinfo subcomponent (and its "@" delimiter) when an "http" or "https" URI reference is generated
    /// within a message as a target URI or field value."), a query or a fragment, is the caller's argument and
    /// <see cref="DpopResourceAccess.DecideAsync"/> throws <see cref="ArgumentException"/> for it.
    /// </summary>
    public required Uri TargetUri { get; init; }

    /// <summary>
    /// Every <c>DPoP</c> field line of the request in received order: none when no proof was presented, two or more
    /// when the field was repeated (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section
    /// 4.3</see>: "There is not more than one DPoP HTTP request header field.").
    /// </summary>
    public required IReadOnlyList<string> DpopFieldLines { get; init; }

    /// <summary>
    /// Whether the resource always requires DPoP-bound access tokens, so a presentation under the <c>Bearer</c> scheme
    /// is refused with the <c>DPoP</c> challenge alone
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>,
    /// <c>dpop_bound_access_tokens_required</c>).
    /// </summary>
    public bool IsDpopBoundAccessTokenRequired { get; init; }

    /// <summary>
    /// The <c>realm</c> every challenge of the resource carries, or <see langword="null"/> for none
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "The authentication
    /// parameter realm MAY be included to indicate the scope of protection in the manner described in [RFC9110],
    /// Section 11.5.").
    /// </summary>
    public string? Realm { get; init; }

    /// <summary>
    /// The <c>scope</c> every <c>DPoP</c> challenge of the resource carries, or <see langword="null"/> for none
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "A scope
    /// authentication parameter MAY be included as defined in [RFC6750], Section 3.").
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// The URL of the resource's protected resource metadata, written as the <c>resource_metadata</c> parameter of every
    /// challenge, or <see langword="null"/> for none
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see>: "This parameter MAY
    /// also be used in WWW-Authenticate responses using authorization schemes other than "Bearer" [RFC6750], such as the
    /// DPoP scheme defined by [RFC9449].").
    /// </summary>
    public Uri? ResourceMetadata { get; init; }
}
