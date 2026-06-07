using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A JSON Web Key Set document served at the JWKS URI per
/// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5">RFC 7517 §5</see>.
/// </summary>
/// <remarks>
/// Used in both directions: a server serializes this at the JWKS endpoint, and a
/// client deserializes it to obtain public keys for token signature verification.
/// Serialization is handled in <c>Verifiable.Json</c>.
/// </remarks>
[DebuggerDisplay("JwksDocument Keys={Keys.Length}")]
public sealed class JwksDocument: IEquatable<JwksDocument>
{
    /// <summary>The array of JSON Web Keys in this set.</summary>
    public JsonWebKey[] Keys { get; init; } = [];


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(JwksDocument? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Keys.SequenceEqual(other.Keys);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is JwksDocument other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach(JsonWebKey key in Keys) { hash.Add(key); }
        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(JwksDocument? left, JwksDocument? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(JwksDocument? left, JwksDocument? right) =>
        !(left == right);
}
