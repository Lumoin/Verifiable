using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// A single JWS signature with its protected and unprotected headers.
/// Owns the signature memory and must be disposed to return memory to the pool.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class JwsSignatureComponent: IEquatable<JwsSignatureComponent>, IDisposable
{
    private bool disposed;

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
    public IReadOnlyDictionary<string, object>? UnprotectedHeader { get; }

    /// <summary>
    /// The cryptographic signature. Owned by this component.
    /// </summary>
    public Signature Signature { get; }

    /// <summary>
    /// Gets the signature bytes.
    /// </summary>
    public ReadOnlyMemory<byte> SignatureBytes => Signature.AsReadOnlyMemory();


    /// <summary>
    /// Creates a new JWS signature component.
    /// </summary>
    /// <param name="protectedEncoded">The Base64Url-encoded protected header.</param>
    /// <param name="protectedHeader">The decoded protected header parameters.</param>
    /// <param name="signature">The signature. Ownership is transferred to this component.</param>
    /// <param name="unprotectedHeader">Optional unprotected header parameters.</param>
    public JwsSignatureComponent(
        string protectedEncoded,
        IReadOnlyDictionary<string, object> protectedHeader,
        Signature signature,
        IReadOnlyDictionary<string, object>? unprotectedHeader = null)
    {
        ArgumentNullException.ThrowIfNull(protectedEncoded);
        ArgumentNullException.ThrowIfNull(protectedHeader);
        ArgumentNullException.ThrowIfNull(signature);

        Protected = protectedEncoded;
        ProtectedHeader = protectedHeader;
        Signature = signature;
        UnprotectedHeader = unprotectedHeader;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Signature.Dispose();
            disposed = true;
        }
    }


    private string DebuggerDisplay
    {
        get
        {
            string alg = ProtectedHeader.TryGetValue("alg", out object? algValue)
                ? algValue?.ToString() ?? "?"
                : "?";
            return $"JwsSignature[alg={alg}, {Signature.AsReadOnlySpan().Length} bytes]";
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
            && Signature.AsReadOnlySpan().SequenceEqual(other.Signature.AsReadOnlySpan())
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
        hash.AddBytes(Signature.AsReadOnlySpan());
        return hash.ToHashCode();
    }


    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(JwsSignatureComponent? left, JwsSignatureComponent? right)
    {
        return left is null ? right is null : left.Equals(right);
    }


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
        return $"JwsSignature[alg={alg}, {Signature.AsReadOnlySpan().Length} bytes]";
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