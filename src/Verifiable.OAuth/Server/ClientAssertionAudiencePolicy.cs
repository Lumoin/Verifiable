using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The rule an authorization server applies to a <c>private_key_jwt</c> client assertion's
/// <c>aud</c> claim when validating it, chosen once per
/// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
/// call and applied to every assertion that validator accepts.
/// </summary>
/// <remarks>
/// <para>
/// A closed set of two values: the constructor is private and no application-defined value can be
/// registered, following the shape of the project's closed value types (a private constructor and
/// get-only static instances, as in <see cref="Verifiable.Cryptography.ResolutionSource"/> and
/// <see cref="Verifiable.OAuth.Client.ClientAssertionAudience"/>).
/// </para>
/// <para>
/// <see cref="AuthorizationServerIdentities"/> is the library default:
/// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 Section 2</see> states that
/// "the authorization server MUST accept its issuer identifier, token endpoint URL, or pushed
/// authorization request endpoint URL as values that identify it as an intended audience." A
/// server therefore takes any one of the three by default. <see cref="IssuerIdentifierOnly"/> is an
/// opt-in: the Internet-Draft
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">rfc7523bis-11
/// Section 4</see> item b narrows client authentication so the <c>aud</c> claim value "MUST indicate
/// only the issuer identifier of the intended authorization server as the audience of the JWT; this
/// includes that the token endpoint URL of the authorization server MUST NOT be used as an audience
/// value." It also states that the authorization server "MUST reject any JWT that does not contain
/// its issuer identifier as its sole audience value." For a pushed authorization request,
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-5">Section
/// 5</see> states that "the issuer identifier URL of the authorization server according to [RFC8414]
/// MUST be used as the sole value of the audience." A server does not take this
/// rule by default while the draft is not an RFC: as
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-6">Section
/// 6</see> states, "the resulting compatibility is not entirely symmetric" - a server enforcing the
/// draft's narrower rule refuses a client that follows
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3 item 3</see> (which
/// allows the token endpoint URL) or
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">OpenID
/// Connect Core 1.0 Section 9</see> (which prefers it).
/// </para>
/// </remarks>
[DebuggerDisplay("ClientAssertionAudiencePolicy Code={Code}")]
public sealed record ClientAssertionAudiencePolicy
{
    /// <summary>Gets the numeric code identifying this policy choice.</summary>
    public int Code { get; }

    /// <summary>
    /// Creates the policy identified by <paramref name="code"/>. Private because the set of valid
    /// choices is closed to <see cref="AuthorizationServerIdentities"/> and
    /// <see cref="IssuerIdentifierOnly"/>.
    /// </summary>
    /// <param name="code">The numeric code identifying the policy choice.</param>
    private ClientAssertionAudiencePolicy(int code)
    {
        Code = code;
    }


    /// <summary>
    /// Accepts the resolved issuer identifier together with every endpoint URL the request's
    /// <c>EndpointChain</c> carries (the token endpoint and, for a pushed request, the pushed
    /// authorization request endpoint), the library default.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 Section 2</see> states
    /// that the authorization server "MUST accept its issuer identifier, token endpoint URL, or
    /// pushed authorization request endpoint URL as values that identify it as an intended audience."
    /// </summary>
    public static ClientAssertionAudiencePolicy AuthorizationServerIdentities { get; } = new(0);

    /// <summary>
    /// Accepts only the resolved issuer identifier, written as the sole <c>aud</c> value - a string,
    /// or an array holding exactly that one string. rfc7523bis-11
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">Section
    /// 4</see> item b: the <c>aud</c> claim value "MUST indicate only the issuer identifier of the
    /// intended authorization server as the audience of the JWT; this includes that the token endpoint
    /// URL of the authorization server MUST NOT be used as an audience value." For a pushed
    /// authorization request,
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-5">Section
    /// 5</see> states that the authorization server "MUST reject any such JWT that does not contain its
    /// own issuer identifier as the sole audience value." So the token endpoint URL, the pushed
    /// authorization request endpoint URL, a second array element of any value, and a duplicated
    /// issuer are all refused. An opt-in: see this type's remarks for why it is not the default.
    /// </summary>
    public static ClientAssertionAudiencePolicy IssuerIdentifierOnly { get; } = new(1);
}
