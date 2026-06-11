using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// A typed Authorization Request Object (JAR payload) for the OAuth 2.0
/// Authorization Code flow per
/// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see>.
/// </summary>
/// <remarks>
/// <para>
/// Represents the protocol-shaped projection of a verified JAR's claims into
/// the Authorization Code-relevant fields. <see cref="AuthCodeRequestObjectExtensions.ProjectAuthCode"/>
/// builds this from a <see cref="Verifiable.OAuth.Jar.JarVerified"/> result;
/// the matcher then performs RFC 9101 §10.2 / RFC 9700 §4 protocol checks
/// against the typed fields rather than poking at the raw claim dictionary.
/// </para>
/// <para>
/// Property names <see cref="Iat"/>, <see cref="Nbf"/>, <see cref="Exp"/> match the
/// JWT claim abbreviations defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc7519">RFC 7519 §4.1.4–§4.1.6</see>.
/// All three are required because the JAR verification primitive parses and
/// validates them; the projection passes the parsed values through rather
/// than re-reading from the claim dictionary.
/// </para>
/// <para>
/// <see cref="Iss"/>, <see cref="Aud"/>, and <see cref="Jti"/> are optional
/// in this projection because RFC 9101 leaves them as protocol-shaped checks
/// the matcher performs. The matcher rejects a JAR with absent <c>iss</c>
/// or <c>aud</c> at the call site; the projection itself does not.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthCodeRequestObject ClientId={ClientId} ResponseType={ResponseType}")]
public sealed class AuthCodeRequestObject: IEquatable<AuthCodeRequestObject>
{
    /// <summary>
    /// The OAuth client identifier. REQUIRED per RFC 9101 §4.
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The OAuth response type. REQUIRED per RFC 9101 §4. Always <c>code</c>
    /// for the Authorization Code flow.
    /// </summary>
    public required string ResponseType { get; init; }

    /// <summary>
    /// The redirect URI. REQUIRED per RFC 9101 §4 and RFC 6749 §4.1.1.
    /// Exact-match validation against the registration's allowed redirect URIs
    /// is enforced at the matcher per RFC 9700 §4.1.
    /// </summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>
    /// The requested scope. REQUIRED per RFC 9101 §4 (carried-through from the
    /// would-be authorization request per RFC 6749 §4.1.1).
    /// </summary>
    public required string Scope { get; init; }

    /// <summary>
    /// The opaque CSRF binding value. REQUIRED per RFC 9101 §4 and
    /// RFC 9700 §4.7.
    /// </summary>
    public required string State { get; init; }

    /// <summary>
    /// The fresh nonce for replay protection and ID Token binding. REQUIRED
    /// per OIDC Core 1.0 §3.1.2.1 and carried through the JAR per RFC 9101 §4.
    /// </summary>
    public required string Nonce { get; init; }

    /// <summary>
    /// The PKCE code challenge per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>.
    /// REQUIRED.
    /// </summary>
    public required string CodeChallenge { get; init; }

    /// <summary>
    /// The PKCE code challenge method per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>.
    /// REQUIRED. Must be <c>S256</c> per FAPI 2.0 §5.2.2 and HAIP 1.0 §3 — the
    /// matcher enforces this.
    /// </summary>
    public required string CodeChallengeMethod { get; init; }

    /// <summary>
    /// The instant the JAR was issued. REQUIRED — the JAR verification
    /// primitive parses and validates the <c>iat</c> claim before the
    /// projection is built.
    /// </summary>
    public required DateTimeOffset Iat { get; init; }

    /// <summary>
    /// The earliest instant the JAR is valid. REQUIRED.
    /// </summary>
    public required DateTimeOffset Nbf { get; init; }

    /// <summary>
    /// The instant after which the JAR MUST NOT be accepted. REQUIRED per
    /// FAPI 2.0 §5.2.2 Clause 13.
    /// </summary>
    public required DateTimeOffset Exp { get; init; }

    /// <summary>
    /// The issuer of the JAR. OPTIONAL in the projection — the matcher
    /// rejects with <c>invalid_request_object</c> when absent or not equal
    /// to <see cref="ClientId"/> per RFC 9101 §10.2.
    /// </summary>
    public string? Iss { get; init; }

    /// <summary>
    /// The intended audience of the JAR. OPTIONAL in the projection — the
    /// matcher rejects with <c>invalid_request_object</c> when absent or not
    /// equal to the AS issuer URL per RFC 9101 §10.2 and RFC 9700 §4.2.
    /// </summary>
    public string? Aud { get; init; }

    /// <summary>
    /// The JWT identifier. OPTIONAL. <c>jti</c>-based replay defense is
    /// deferred to a future round; this property is exposed for the matcher
    /// to log or pass to the future replay store.
    /// </summary>
    public string? Jti { get; init; }

    /// <summary>
    /// The requested <c>acr_values</c> (space-separated, preference-ordered), or
    /// <see langword="null"/> when absent. OPTIONAL per OIDC Core §3.1.2.1; carried through
    /// for RFC 9470 §5 step-up evaluation at the authorization endpoint.
    /// </summary>
    public string? AcrValues { get; init; }

    /// <summary>
    /// The requested <c>max_age</c> (maximum authentication age in seconds), or
    /// <see langword="null"/> when absent. OPTIONAL per OIDC Core §3.1.2.1; carried through
    /// for authentication-recency enforcement at the authorization endpoint.
    /// </summary>
    public int? MaxAge { get; init; }

    /// <summary>
    /// The RFC 9396 <c>authorization_details</c> of the Request Object as its verbatim JSON
    /// array text, or <see langword="null"/> when absent. RFC 9396 §3 carries the value as a
    /// native JSON array inside a JWT, so the matcher re-slices the exact signed text from the
    /// verified payload rather than reserialising the parsed claims.
    /// </summary>
    public string? AuthorizationDetails { get; init; }

    /// <summary>
    /// The <c>response_mode</c> the Request Object asks for, or <see langword="null"/> when
    /// absent. A JARM value (<see cref="Jarm.JarmResponseModes"/>) requests a JWT-secured
    /// authorization response; the matcher gates it for servability at receipt.
    /// </summary>
    public string? ResponseMode { get; init; }

    /// <summary>
    /// The OID4VCI 1.0 §5.1.3 <c>issuer_state</c> claim of the Request Object, or
    /// <see langword="null"/> when absent. Carried through verbatim and surfaced as UNTRUSTED
    /// input to the authorization-decision seam — §5.1.3 requires the issuer to treat it as
    /// possibly attacker-injected, so the matcher validates nothing about it.
    /// </summary>
    public string? IssuerState { get; init; }

    /// <summary>
    /// The RFC 8707 <c>resource</c> indicator(s) of the Request Object (space-delimited when
    /// multiple), or <see langword="null"/> when absent. OID4VCI 1.0 §5.1.2 RECOMMENDS its use to
    /// let the Authorization Server differentiate Credential Issuers; carried through and surfaced
    /// to the authorization-decision seam.
    /// </summary>
    public string? Resource { get; init; }


    /// <inheritdoc/>
    public bool Equals(AuthCodeRequestObject? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(ClientId, other.ClientId, StringComparison.Ordinal)
            && string.Equals(ResponseType, other.ResponseType, StringComparison.Ordinal)
            && RedirectUri == other.RedirectUri
            && string.Equals(Scope, other.Scope, StringComparison.Ordinal)
            && string.Equals(State, other.State, StringComparison.Ordinal)
            && string.Equals(Nonce, other.Nonce, StringComparison.Ordinal)
            && string.Equals(CodeChallenge, other.CodeChallenge, StringComparison.Ordinal)
            && string.Equals(CodeChallengeMethod, other.CodeChallengeMethod, StringComparison.Ordinal)
            && Iat == other.Iat
            && Nbf == other.Nbf
            && Exp == other.Exp
            && string.Equals(Iss, other.Iss, StringComparison.Ordinal)
            && string.Equals(Aud, other.Aud, StringComparison.Ordinal)
            && string.Equals(Jti, other.Jti, StringComparison.Ordinal)
            && string.Equals(AcrValues, other.AcrValues, StringComparison.Ordinal)
            && MaxAge == other.MaxAge
            && string.Equals(AuthorizationDetails, other.AuthorizationDetails, StringComparison.Ordinal)
            && string.Equals(ResponseMode, other.ResponseMode, StringComparison.Ordinal)
            && string.Equals(IssuerState, other.IssuerState, StringComparison.Ordinal)
            && string.Equals(Resource, other.Resource, StringComparison.Ordinal);
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is AuthCodeRequestObject other && Equals(other);


    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(ClientId, ResponseType, RedirectUri, Scope, State, Nonce, CodeChallenge, Exp);


    /// <summary>Determines whether two instances are equal.</summary>
    public static bool operator ==(
        AuthCodeRequestObject? left,
        AuthCodeRequestObject? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>Determines whether two instances differ.</summary>
    public static bool operator !=(
        AuthCodeRequestObject? left,
        AuthCodeRequestObject? right) =>
        !(left == right);
}
