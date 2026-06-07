using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The client identifier a relying party is known by at an authorization
/// server. A typed wrapper around the wire-format string that disallows
/// empty and whitespace-only values.
/// </summary>
/// <remarks>
/// <para>
/// Unlike <see cref="GrantType"/>, <see cref="ResponseType"/>, or
/// <see cref="ClientAuthenticationMethod"/>, <see cref="ClientId"/> is not a
/// closed canonical set — every value is application-specific or
/// AS-assigned. The wrapper exists for two reasons: to keep method
/// signatures self-describing (a parameter named
/// <c>ClientId clientId</c> reads better than <c>string clientId</c>), and
/// to centralize the non-empty invariant.
/// </para>
/// <para>
/// The library does not interpret the shape of the value at construction
/// time. Different lifecycle models produce differently-shaped client IDs:
/// </para>
/// <list type="bullet">
///   <item><description>
///     Pre-registered (legacy) and RFC 7591 dynamic registration: opaque
///     AS-assigned strings.
///   </description></item>
///   <item><description>
///     <see href="https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/">CIMD</see>:
///     an absolute URL pointing at the client's metadata document. The
///     authorization server fetches the document on demand.
///   </description></item>
///   <item><description>
///     <see href="https://openid.net/specs/openid-federation-1_1-final.html">OpenID Federation 1.1</see>:
///     the federation entity URL of the relying party. The authorization
///     server resolves the trust chain from this entity identifier.
///   </description></item>
///   <item><description>
///     DID-based identification (decentralised-identifier deployments):
///     a DID URI per W3C DID Core.
///   </description></item>
/// </list>
/// <para>
/// Library call sites that need to dispatch on shape (CIMD-fetch versus
/// federation-resolve versus opaque-lookup) inspect the value with the
/// helpers on this type rather than re-parsing the string in multiple
/// places.
/// </para>
/// </remarks>
[DebuggerDisplay("ClientId Value={Value}")]
public readonly struct ClientId: IEquatable<ClientId>
{
    /// <summary>Gets the underlying wire-format string value.</summary>
    public string Value { get; }


    /// <summary>
    /// Constructs a <see cref="ClientId"/> from a non-empty, non-whitespace
    /// string.
    /// </summary>
    /// <param name="value">The wire-format client identifier.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="value"/> is <see langword="null"/>, empty,
    /// or whitespace-only.
    /// </exception>
    public ClientId(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }


    /// <summary>
    /// Returns <see langword="true"/> when the value is an absolute URL
    /// (HTTP or HTTPS). Used to detect the CIMD lifecycle model and the
    /// OpenID Federation entity-identifier shape; the federation
    /// trust-chain resolution further distinguishes those two by inspecting
    /// the document the URL serves.
    /// </summary>
    public bool IsAbsoluteUrl =>
        Uri.TryCreate(Value, UriKind.Absolute, out Uri? uri)
        && (string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
            || string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal));


    /// <summary>
    /// Returns <see langword="true"/> when the value is a DID URI
    /// (scheme <c>did:</c>) per W3C DID Core. Used to dispatch to DID
    /// resolver lookup for client metadata.
    /// </summary>
    public bool IsDid =>
        Value.StartsWith("did:", StringComparison.Ordinal);


    /// <inheritdoc/>
    public override string ToString() => Value;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(ClientId other) => string.Equals(Value, other.Value, StringComparison.Ordinal);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is ClientId other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() =>
        Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(ClientId left, ClientId right) => left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(ClientId left, ClientId right) => !left.Equals(right);
}
