using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A complete JWS (JSON Web Signature) message that can be serialized to any JOSE format.
/// Owns the signature components and must be disposed to return memory to the pool.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class JwsMessage: IEquatable<JwsMessage>, IDisposable
{
    private bool disposed;

    /// <summary>
    /// The payload bytes (before Base64Url encoding).
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>
    /// The signatures. Compact and Flattened serializations require exactly one.
    /// General JSON serialization supports multiple signatures.
    /// </summary>
    public IReadOnlyList<JwsSignatureComponent> Signatures { get; }

    /// <summary>
    /// Whether this is a detached payload JWS (payload not included in serialization).
    /// </summary>
    public bool IsDetachedPayload { get; }


    /// <summary>
    /// Creates a new JWS message with a single signature.
    /// </summary>
    /// <param name="payload">The payload bytes.</param>
    /// <param name="signature">The signature component. Ownership is transferred.</param>
    /// <param name="isDetachedPayload">Whether the payload is detached.</param>
    public JwsMessage(
        ReadOnlyMemory<byte> payload,
        JwsSignatureComponent signature,
        bool isDetachedPayload = false)
    {
        ArgumentNullException.ThrowIfNull(signature);

        Payload = payload;
        Signatures = [signature];
        IsDetachedPayload = isDetachedPayload;
    }


    /// <summary>
    /// Creates a new JWS message with multiple signatures.
    /// </summary>
    /// <param name="payload">The payload bytes.</param>
    /// <param name="signatures">The signature components. Ownership is transferred.</param>
    /// <param name="isDetachedPayload">Whether the payload is detached.</param>
    public JwsMessage(
        ReadOnlyMemory<byte> payload,
        IReadOnlyList<JwsSignatureComponent> signatures,
        bool isDetachedPayload = false)
    {
        ArgumentNullException.ThrowIfNull(signatures);

        if(signatures.Count == 0)
        {
            throw new ArgumentException("At least one signature is required.", nameof(signatures));
        }

        Payload = payload;
        Signatures = signatures;
        IsDetachedPayload = isDetachedPayload;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            foreach(var signature in Signatures)
            {
                signature.Dispose();
            }
            disposed = true;
        }
    }


    private string DebuggerDisplay
    {
        get
        {
            string detached = IsDetachedPayload ? ", detached" : "";
            string sigCount = Signatures.Count == 1 ? "1 sig" : $"{Signatures.Count} sigs";
            return $"JwsMessage[{sigCount}, {Payload.Length} bytes{detached}]";
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(JwsMessage? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(IsDetachedPayload != other.IsDetachedPayload)
        {
            return false;
        }

        if(!Payload.Span.SequenceEqual(other.Payload.Span))
        {
            return false;
        }

        if(Signatures.Count != other.Signatures.Count)
        {
            return false;
        }

        for(int i = 0; i < Signatures.Count; i++)
        {
            if(!Signatures[i].Equals(other.Signatures[i]))
            {
                return false;
            }
        }

        return true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is JwsMessage other && Equals(other);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Payload.Span);
        hash.Add(Signatures.Count);
        hash.Add(IsDetachedPayload);
        return hash.ToHashCode();
    }


    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(JwsMessage? left, JwsMessage? right)
    {
        return left is null ? right is null : left.Equals(right);
    }


    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(JwsMessage? left, JwsMessage? right)
    {
        return !(left == right);
    }


    /// <inheritdoc/>
    public override string ToString()
    {
        string detached = IsDetachedPayload ? ", detached" : "";
        return $"JwsMessage[{Signatures.Count} signature(s), {Payload.Length} bytes{detached}]";
    }
}