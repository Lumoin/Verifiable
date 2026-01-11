using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A complete JWS (JSON Web Signature) message that can be serialized to any JOSE format.
/// </summary>
/// <remarks>
/// <para>
/// This POCO holds the logical structure of a JWS. Use <see cref="JwsSerialization"/>
/// to convert to Compact, Flattened JSON, or General JSON format.
/// </para>
/// <para>
/// For Compact serialization, exactly one signature must be present and
/// the payload must not be detached.
/// </para>
/// <para>
/// This type is immutable and thread-safe.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class JwsMessage: IEquatable<JwsMessage>
{
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
    /// <remarks>
    /// When true, the payload is not included in the serialized form. The recipient
    /// must obtain the payload through other means and verify it against this signature.
    /// </remarks>
    public bool IsDetachedPayload { get; }


    /// <summary>
    /// Creates a new JWS message with a single signature.
    /// </summary>
    /// <param name="payload">The payload bytes.</param>
    /// <param name="signature">The signature component.</param>
    /// <param name="isDetachedPayload">Whether the payload is detached.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="signature"/> is null.
    /// </exception>
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
    /// <param name="signatures">The signature components.</param>
    /// <param name="isDetachedPayload">Whether the payload is detached.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="signatures"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="signatures"/> is empty.
    /// </exception>
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


    /// <summary>
    /// Determines whether two JWS messages are equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(JwsMessage? left, JwsMessage? right)
    {
        return left is null ? right is null : left.Equals(right);
    }


    /// <summary>
    /// Determines whether two JWS messages are not equal.
    /// </summary>
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