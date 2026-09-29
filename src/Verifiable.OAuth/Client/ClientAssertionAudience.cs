using System.Diagnostics;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The value a <c>private_key_jwt</c> client assertion's <c>aud</c> claim names, chosen once per
/// <see cref="ClientRegistration.ClientAssertionAudience"/> and applied at every endpoint the
/// registration authenticates at.
/// </summary>
/// <remarks>
/// <para>
/// A closed set of two values, never a third combining them: the Internet-Draft
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">rfc7523bis-11
/// Section 4</see> requires that for client authentication the <c>aud</c> claim value "MUST indicate only
/// the issuer identifier of the intended authorization server as the audience of the JWT", so a
/// registration names one of these two, not both. The constructor is private and no application-defined
/// value can be registered: a <c>private_key_jwt</c> assertion carries exactly one <c>aud</c> and this
/// type is the closed catalog of what that one value may be, following the shape of the project's closed
/// value types (a private constructor and get-only static instances, as in
/// <see cref="Verifiable.Cryptography.ResolutionSource"/>).
/// </para>
/// <para>
/// The chosen value is written into the assertion payload as a single JSON string per
/// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 Section 4.1.3</see>, which
/// states that "the &quot;aud&quot; value MAY be a single case-sensitive string containing a
/// StringOrURI value" for one audience.
/// </para>
/// </remarks>
[DebuggerDisplay("ClientAssertionAudience Code={Code}")]
public sealed record ClientAssertionAudience
{
    /// <summary>Gets the numeric code identifying this audience choice.</summary>
    public int Code { get; }

    /// <summary>
    /// Creates the audience choice identified by <paramref name="code"/>. Private because the set of
    /// valid choices is closed to <see cref="IssuerIdentifier"/> and <see cref="TokenEndpoint"/>.
    /// </summary>
    /// <param name="code">The numeric code identifying the audience choice.</param>
    private ClientAssertionAudience(int code)
    {
        Code = code;
    }


    /// <summary>
    /// The authorization server's issuer identifier, the library default. rfc7523bis-11 Section 4
    /// requires that the <c>aud</c> claim value "MUST indicate only the issuer identifier of the intended
    /// authorization server as the audience of the JWT". For a pushed authorization request
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-5">rfc7523bis-11
    /// Section 5</see> replaces the last paragraph of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 Section 2</see>, which
    /// states that "the issuer identifier URL of the authorization server ... SHOULD be used as the value
    /// of the audience", with the text "the issuer identifier URL of the authorization server according to
    /// [RFC8414] MUST be used as the sole value of the audience."
    /// </summary>
    public static ClientAssertionAudience IssuerIdentifier { get; } = new(0);

    /// <summary>
    /// The resolved token endpoint URL the assertion accompanies. Choosing it is a deviation from
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">rfc7523bis-11
    /// Section 4</see>, which states that for client authentication "the token endpoint URL of the
    /// authorization server MUST NOT be used as an audience value"; it is offered only for an
    /// authorization server that refuses its issuer identifier as the audience.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3 item 3</see>
    /// permits (MAY) it, "The token endpoint URL of the authorization server MAY be used as a value
    /// for an &quot;aud&quot; element", and
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">OpenID
    /// Connect Core 1.0 Section 9</see> recommends (SHOULD) it: "The Audience SHOULD be the URL of
    /// the Authorization Server's Token Endpoint." An <c>aud</c> naming this endpoint but presented
    /// at a different one is the audience-injection attack
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-1">rfc7523bis-11's
    /// Introduction</see> describes: "Other endpoint values of the metadata cannot be directly
    /// validated and, if used as audience when sent to a different endpoint, can open an attack
    /// vector."
    /// </summary>
    public static ClientAssertionAudience TokenEndpoint { get; } = new(1);
}
