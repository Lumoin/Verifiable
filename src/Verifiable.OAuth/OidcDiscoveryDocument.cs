using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth;

/// <summary>
/// The OpenID Connect Discovery document served at
/// <c>/.well-known/openid-configuration</c> per
/// <see href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</see>
/// and <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414</see>.
/// </summary>
/// <remarks>
/// <para>
/// Used in both directions: a server populates and serializes this type at the
/// discovery endpoint; a client deserializes it after fetching the document at
/// the URI computed by <see cref="WellKnownPaths.OpenIdConfiguration"/>.
/// </para>
/// <para>
/// Serialization is handled in <c>Verifiable.Json</c> where the naming policy and
/// source-generated type information are configured.
/// </para>
/// </remarks>
[DebuggerDisplay("OidcDiscoveryDocument Issuer={Issuer}")]
public sealed class OidcDiscoveryDocument: IEquatable<OidcDiscoveryDocument>
{
    /// <summary>The authorization server's issuer identifier URI.</summary>
    public string Issuer { get; init; } = string.Empty;

    /// <summary>URL of the authorization endpoint.</summary>
    public Uri? AuthorizationEndpoint { get; init; }

    /// <summary>URL of the token endpoint.</summary>
    public Uri? TokenEndpoint { get; init; }

    /// <summary>
    /// URL of the Pushed Authorization Request endpoint per RFC 9126.
    /// <see langword="null"/> when the server does not support PAR.
    /// </summary>
    public Uri? PushedAuthorizationRequestEndpoint { get; init; }

    /// <summary>URL of the JWKS document endpoint.</summary>
    public Uri? JwksUri { get; init; }

    /// <summary>Supported response type values, e.g. <c>["code"]</c>.</summary>
    public string[] ResponseTypesSupported { get; init; } = [];

    /// <summary>Supported subject identifier types, e.g. <c>["public"]</c>.</summary>
    public string[] SubjectTypesSupported { get; init; } = [];

    /// <summary>Supported ID token signing algorithm values.</summary>
    public string[] IdTokenSigningAlgValuesSupported { get; init; } = [];

    /// <summary>
    /// Supported PKCE code challenge methods.
    /// HAIP 1.0 and RFC 9700 require <c>S256</c>.
    /// </summary>
    public string[] CodeChallengeMethodsSupported { get; init; } = [];

    /// <summary>Whether PAR is required for all authorization requests per RFC 9126 §4.</summary>
    public bool RequirePushedAuthorizationRequests { get; init; }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(OidcDiscoveryDocument? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Issuer == other.Issuer
            && AuthorizationEndpoint == other.AuthorizationEndpoint
            && TokenEndpoint == other.TokenEndpoint
            && PushedAuthorizationRequestEndpoint == other.PushedAuthorizationRequestEndpoint
            && JwksUri == other.JwksUri
            && RequirePushedAuthorizationRequests == other.RequirePushedAuthorizationRequests
            && ResponseTypesSupported.SequenceEqual(other.ResponseTypesSupported)
            && SubjectTypesSupported.SequenceEqual(other.SubjectTypesSupported)
            && IdTokenSigningAlgValuesSupported.SequenceEqual(other.IdTokenSigningAlgValuesSupported)
            && CodeChallengeMethodsSupported.SequenceEqual(other.CodeChallengeMethodsSupported);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is OidcDiscoveryDocument other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Issuer);
        hash.Add(AuthorizationEndpoint);
        hash.Add(TokenEndpoint);
        hash.Add(PushedAuthorizationRequestEndpoint);
        hash.Add(JwksUri);
        hash.Add(RequirePushedAuthorizationRequests);
        foreach(string s in ResponseTypesSupported) { hash.Add(s); }
        foreach(string s in SubjectTypesSupported) { hash.Add(s); }
        foreach(string s in IdTokenSigningAlgValuesSupported) { hash.Add(s); }
        foreach(string s in CodeChallengeMethodsSupported) { hash.Add(s); }
        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(OidcDiscoveryDocument? left, OidcDiscoveryDocument? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(OidcDiscoveryDocument? left, OidcDiscoveryDocument? right) =>
        !(left == right);
}
