using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Wallet metadata (Authorization Server metadata) as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-10">OID4VP 1.0 §10</see>.
/// </summary>
/// <remarks>
/// <para>
/// Published at the Wallet's well-known endpoint so that Verifiers can discover
/// the Wallet's capabilities before constructing an Authorization Request. The
/// Wallet's metadata takes precedence over values in <c>client_metadata</c>
/// when both are present.
/// </para>
/// <para>
/// The well-known URI is computed via <see cref="Verifiable.OAuth.WellKnownPaths"/>
/// and is not hardwired here. Fetching and caching are the application's
/// responsibility.
/// </para>
/// </remarks>
[DebuggerDisplay("WalletMetadata AuthorizationEndpoint={AuthorizationEndpoint}")]
public sealed class WalletMetadata: IEquatable<WalletMetadata>
{
    /// <summary>
    /// The authorization endpoint URI used to invoke the Wallet. May be a custom
    /// URI scheme (e.g. <c>openid4vp://</c>) or a Universal Link.
    /// Per OID4VP 1.0 §13.1.
    /// </summary>
    public Uri? AuthorizationEndpoint { get; init; }

    /// <summary>
    /// The credential formats and algorithms supported by the Wallet. REQUIRED.
    /// Per OID4VP 1.0 §10.1. Decision logic is available via
    /// <see cref="VpFormatsExtensions"/>.
    /// </summary>
    public required VpFormatsSupported VpFormatsSupported { get; init; }

    /// <summary>
    /// Whether the Wallet supports passing <c>presentation_definition</c> by
    /// reference. OPTIONAL. Defaults to <see langword="true"/> when absent.
    /// Per OID4VP 1.0 §10.1.
    /// </summary>
    public bool? PresentationDefinitionUriSupported { get; init; }

    /// <summary>
    /// Additional metadata parameters. Profiles of OID4VP may define additional
    /// parameters per OID4VP 1.0 §10.1.
    /// </summary>
    public IReadOnlyDictionary<string, object>? AdditionalParameters { get; init; }


    /// <inheritdoc/>
    public bool Equals(WalletMetadata? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return AuthorizationEndpoint == other.AuthorizationEndpoint
            && PresentationDefinitionUriSupported == other.PresentationDefinitionUriSupported
            && ReferenceEquals(VpFormatsSupported, other.VpFormatsSupported);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is WalletMetadata other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(AuthorizationEndpoint, PresentationDefinitionUriSupported);

    /// <summary>Determines whether two instances are equal.</summary>
    public static bool operator ==(WalletMetadata? left, WalletMetadata? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two instances differ.</summary>
    public static bool operator !=(WalletMetadata? left, WalletMetadata? right) =>
        !(left == right);
}
