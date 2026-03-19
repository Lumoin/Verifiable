using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth;

/// <summary>
/// The success response body from a Pushed Authorization Request endpoint per
/// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// A server populates and serializes this type as the HTTP 201 response body when it
/// accepts a pushed authorization request. The client parses the wire bytes into the
/// client-side <c>ParResponse</c> type using <see cref="OAuthResponseParsers.ParseParResponse"/>.
/// </para>
/// <para>
/// Serialization is handled in <c>Verifiable.Json</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("ParServerResponse RequestUri={RequestUri} ExpiresIn={ExpiresIn}")]
public sealed class ParServerResponse: IEquatable<ParServerResponse>
{
    /// <summary>
    /// The <c>request_uri</c> assigned by the server per RFC 9126 §2.2.
    /// Follows the <c>urn:ietf:params:oauth:request_uri:</c> scheme.
    /// </summary>
    public Uri? RequestUri { get; init; }

    /// <summary>The lifetime in seconds of the request URI per RFC 9126 §2.2.</summary>
    public int ExpiresIn { get; init; }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(ParServerResponse? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return RequestUri == other.RequestUri
            && ExpiresIn == other.ExpiresIn;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is ParServerResponse other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() =>
        HashCode.Combine(RequestUri, ExpiresIn);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(ParServerResponse? left, ParServerResponse? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(ParServerResponse? left, ParServerResponse? right) =>
        !(left == right);
}
