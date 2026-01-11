using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A single JWS signature with its protected and unprotected headers.
/// </summary>
/// <remarks>
/// <para>
/// In Compact serialization, only the protected header is used.
/// In JSON serializations (Flattened and General), both protected and
/// unprotected headers may be present.
/// </para>
/// <para>
/// This type is immutable and thread-safe.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class JwsSignatureComponent: IEquatable<JwsSignatureComponent>
{
    /// <summary>
    /// The Base64Url-encoded protected header.
    /// </summary>
    public string Protected { get; }

    /// <summary>
    /// The decoded protected header parameters.
    /// </summary>
    public IReadOnlyDictionary<string, object> ProtectedHeader { get; }

    /// <summary>
    /// The unprotected header parameters (not integrity-protected).
    /// </summary>
    /// <remarks>
    /// Only used in JSON serializations. Null for Compact serialization.
    /// </remarks>
    public IReadOnlyDictionary<string, object>? UnprotectedHeader { get; }

    /// <summary>
    /// The signature bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Signature { get; }


    /// <summary>
    /// Creates a new JWS signature component.
    /// </summary>
    /// <param name="protectedEncoded">The Base64Url-encoded protected header.</param>
    /// <param name="protectedHeader">The decoded protected header parameters.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <param name="unprotectedHeader">Optional unprotected header parameters.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="protectedEncoded"/> or <paramref name="protectedHeader"/> is null.
    /// </exception>
    public JwsSignatureComponent(
        string protectedEncoded,
        IReadOnlyDictionary<string, object> protectedHeader,
        ReadOnlyMemory<byte> signature,
        IReadOnlyDictionary<string, object>? unprotectedHeader = null)
    {
        ArgumentNullException.ThrowIfNull(protectedEncoded);
        ArgumentNullException.ThrowIfNull(protectedHeader);

        Protected = protectedEncoded;
        ProtectedHeader = protectedHeader;
        Signature = signature;
        UnprotectedHeader = unprotectedHeader;
    }


    private string DebuggerDisplay
    {
        get
        {
            string alg = ProtectedHeader.TryGetValue("alg", out object? algValue)
                ? algValue?.ToString() ?? "?"
                : "?";
            return $"JwsSignature[alg={alg}, {Signature.Length} bytes]";
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(JwsSignatureComponent? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Protected == other.Protected
            && Signature.Span.SequenceEqual(other.Signature.Span)
            && HeadersEqual(ProtectedHeader, other.ProtectedHeader)
            && HeadersEqual(UnprotectedHeader, other.UnprotectedHeader);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is JwsSignatureComponent other && Equals(other);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Protected);
        hash.AddBytes(Signature.Span);
        return hash.ToHashCode();
    }


    /// <summary>
    /// Determines whether two signature components are equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(JwsSignatureComponent? left, JwsSignatureComponent? right)
    {
        return left is null ? right is null : left.Equals(right);
    }


    /// <summary>
    /// Determines whether two signature components are not equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(JwsSignatureComponent? left, JwsSignatureComponent? right)
    {
        return !(left == right);
    }


    /// <inheritdoc/>
    public override string ToString()
    {
        string alg = ProtectedHeader.TryGetValue("alg", out object? algValue)
            ? algValue?.ToString() ?? "unknown"
            : "unknown";
        return $"JwsSignature[alg={alg}, {Signature.Length} bytes]";
    }


    private static bool HeadersEqual(
        IReadOnlyDictionary<string, object>? a,
        IReadOnlyDictionary<string, object>? b)
    {
        if(a is null && b is null)
        {
            return true;
        }

        if(a is null || b is null)
        {
            return false;
        }

        if(a.Count != b.Count)
        {
            return false;
        }

        foreach(var kvp in a)
        {
            if(!b.TryGetValue(kvp.Key, out object? bValue))
            {
                return false;
            }

            if(!Equals(kvp.Value, bValue))
            {
                return false;
            }
        }

        return true;
    }
}