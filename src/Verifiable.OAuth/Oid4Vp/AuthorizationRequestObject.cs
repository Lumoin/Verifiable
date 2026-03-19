using System.Diagnostics;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// A typed Authorization Request Object (JAR payload) for the OID4VP cross-device
/// flow, as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5">OID4VP 1.0 §5</see>
/// and
/// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see>.
/// </summary>
/// <remarks>
/// <para>
/// Represents the claims set of the signed JWT served at the <c>request_uri</c>
/// endpoint with media type <c>application/oauth-authz-req+jwt</c>
/// (<see cref="Verifiable.JCose.WellKnownMediaTypes.Application.OauthAuthzReqJwt"/>).
/// The Wallet fetches and parses this object to determine what credentials to
/// present and where to POST the Authorization Response.
/// </para>
/// <para>
/// Authorization Request parameter name constants are in
/// <see cref="AuthorizationRequestParameters"/>. Profile-specific factory methods
/// are in <see cref="HaipProfile"/>. Serialization lives in <c>Verifiable.Json</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationRequestObject ClientId={ClientId} ResponseMode={ResponseMode}")]
public sealed class AuthorizationRequestObject: IEquatable<AuthorizationRequestObject>
{
    /// <summary>
    /// The verifier's client identifier. REQUIRED.
    /// Identifies the Verifier per OID4VP 1.0 §5.9.
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The client identifier scheme. OPTIONAL.
    /// Indicates how the Wallet interprets <see cref="ClientId"/> per OID4VP 1.0 §5.9.1.
    /// </summary>
    public string? ClientIdScheme { get; init; }

    /// <summary>
    /// The response type. REQUIRED. Always
    /// <see cref="AuthorizationRequestParameters.ResponseTypeVpToken"/> for OID4VP.
    /// </summary>
    public required string ResponseType { get; init; }

    /// <summary>
    /// The response mode. REQUIRED for cross-device flow.
    /// <see cref="WellKnownResponseModes.DirectPostJwt"/> for HAIP 1.0 encrypted responses.
    /// </summary>
    public required string ResponseMode { get; init; }

    /// <summary>
    /// The URI to which the Wallet POSTs the Authorization Response. REQUIRED
    /// when <see cref="ResponseMode"/> is <c>direct_post</c> or <c>direct_post.jwt</c>
    /// per OID4VP 1.0 §8.2.
    /// </summary>
    public required Uri ResponseUri { get; init; }

    /// <summary>
    /// A fresh nonce for replay protection and Key Binding JWT binding.
    /// REQUIRED per OID4VP 1.0 §5.2.
    /// </summary>
    public required string Nonce { get; init; }

    /// <summary>
    /// An opaque state value for CSRF protection, returned unchanged in the
    /// Authorization Response per RFC 6749 §4.1.1 and RFC 9700 §4.7. OPTIONAL.
    /// </summary>
    public string? State { get; init; }

    /// <summary>
    /// The DCQL query specifying the requested credentials. REQUIRED when neither
    /// <c>presentation_definition</c> nor a scope representing a query is present
    /// per OID4VP 1.0 §5.1.
    /// </summary>
    public DcqlQuery? DcqlQuery { get; init; }

    /// <summary>
    /// Inline Verifier metadata. OPTIONAL. Contains the JWKS for response
    /// encryption and supported formats per OID4VP 1.0 §5.1 and §11.
    /// </summary>
    public VerifierClientMetadata? ClientMetadata { get; init; }

    /// <summary>
    /// The issuer identifier of the Verifier. OPTIONAL per RFC 9101.
    /// When present the Wallet MUST ignore it to avoid breaking JAR
    /// implementations per OID4VP 1.0 §5.8.
    /// </summary>
    public string? Iss { get; init; }

    /// <summary>
    /// The intended audience. REQUIRED in signed Request Objects per OID4VP 1.0 §5.8.
    /// Set to the authorization server issuer identifier when Dynamic Discovery is
    /// used, or to <c>https://self-issued.me/v2</c> when Static Discovery is used.
    /// </summary>
    public string? Aud { get; init; }


    /// <inheritdoc/>
    public bool Equals(AuthorizationRequestObject? other)
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
            && string.Equals(ClientIdScheme, other.ClientIdScheme, StringComparison.Ordinal)
            && string.Equals(ResponseType, other.ResponseType, StringComparison.Ordinal)
            && string.Equals(ResponseMode, other.ResponseMode, StringComparison.Ordinal)
            && ResponseUri == other.ResponseUri
            && string.Equals(Nonce, other.Nonce, StringComparison.Ordinal)
            && string.Equals(State, other.State, StringComparison.Ordinal)
            && string.Equals(Iss, other.Iss, StringComparison.Ordinal)
            && string.Equals(Aud, other.Aud, StringComparison.Ordinal)
            && Equals(ClientMetadata, other.ClientMetadata);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is AuthorizationRequestObject other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(ClientId, ResponseType, ResponseMode, ResponseUri, Nonce);

    /// <summary>Determines whether two instances are equal.</summary>
    public static bool operator ==(
        AuthorizationRequestObject? left,
        AuthorizationRequestObject? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two instances differ.</summary>
    public static bool operator !=(
        AuthorizationRequestObject? left,
        AuthorizationRequestObject? right) =>
        !(left == right);
}
