using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A JWS message parsed from untrusted input. Must be verified before the payload
/// or claims can be trusted.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class UnverifiedJwsMessage: IDisposable, IEquatable<UnverifiedJwsMessage>
{
    private bool disposed;

    /// <summary>
    /// Owned payload memory (when parsed). Null if payload comes from external source.
    /// </summary>
    private IMemoryOwner<byte>? OwnedPayload { get; }

    /// <summary>
    /// The payload bytes. UNTRUSTED until signature is verified.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>
    /// The signatures. UNTRUSTED until verified.
    /// </summary>
    public IReadOnlyList<UnverifiedJwsSignature> Signatures { get; }

    /// <summary>
    /// Whether this is a detached payload JWS.
    /// </summary>
    public bool IsDetachedPayload { get; }


    /// <summary>
    /// Initializes a new instance carrying a single unverified signature.
    /// </summary>
    /// <param name="payloadOwner">The owner of <paramref name="payload"/>'s backing memory, disposed together with this instance; <see langword="null"/> when the payload comes from an external, caller-owned source.</param>
    /// <param name="payload">The untrusted payload bytes carried alongside <paramref name="signature"/> until verification.</param>
    /// <param name="signature">The single unverified signature this message carries.</param>
    /// <param name="isDetachedPayload">Whether the JWS payload is detached from the compact/JSON serialization and supplied out of band.</param>
    public UnverifiedJwsMessage(
        IMemoryOwner<byte>? payloadOwner,
        ReadOnlyMemory<byte> payload,
        UnverifiedJwsSignature signature,
        bool isDetachedPayload = false)
    {
        ArgumentNullException.ThrowIfNull(signature);

        OwnedPayload = payloadOwner;
        Payload = payload;
        Signatures = [signature];
        IsDetachedPayload = isDetachedPayload;
    }


    /// <summary>
    /// Initializes a new instance carrying one or more unverified signatures (JWS JSON serialization).
    /// </summary>
    /// <param name="payloadOwner">The owner of <paramref name="payload"/>'s backing memory, disposed together with this instance; <see langword="null"/> when the payload comes from an external, caller-owned source.</param>
    /// <param name="payload">The untrusted payload bytes carried alongside <paramref name="signatures"/> until verification.</param>
    /// <param name="signatures">The non-empty list of unverified signatures this message carries.</param>
    /// <param name="isDetachedPayload">Whether the JWS payload is detached from the compact/JSON serialization and supplied out of band.</param>
    public UnverifiedJwsMessage(
        IMemoryOwner<byte>? payloadOwner,
        ReadOnlyMemory<byte> payload,
        IReadOnlyList<UnverifiedJwsSignature> signatures,
        bool isDetachedPayload = false)
    {
        ArgumentNullException.ThrowIfNull(signatures);
        if(signatures.Count == 0)
        {
            throw new ArgumentException("At least one signature is required.", nameof(signatures));
        }

        OwnedPayload = payloadOwner;
        Payload = payload;
        Signatures = signatures;
        IsDetachedPayload = isDetachedPayload;
    }


    /// <summary>
    /// Releases the owned payload memory, when present, and disposes every signature in <see cref="Signatures"/>.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            OwnedPayload?.Dispose();
            foreach(var sig in Signatures)
            {
                sig.Dispose();
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
            return $"UnverifiedJwsMessage[{sigCount}, {Payload.Length} bytes{detached}]";
        }
    }


    /// <summary>
    /// Determines whether <paramref name="other"/> carries the same detachment flag, the same payload bytes and the same signature count as this instance.
    /// </summary>
    /// <param name="other">The instance to compare against.</param>
    /// <returns><see langword="true"/> when the untrusted payload and signature shape match; otherwise <see langword="false"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(UnverifiedJwsMessage? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return IsDetachedPayload == other.IsDetachedPayload
            && Payload.Span.SequenceEqual(other.Payload.Span)
            && Signatures.Count == other.Signatures.Count;
    }


    /// <summary>
    /// Determines whether <paramref name="obj"/> is an <see cref="UnverifiedJwsMessage"/> equal to this instance.
    /// </summary>
    /// <param name="obj">The object to compare against.</param>
    /// <returns><see langword="true"/> when <paramref name="obj"/> is an <see cref="UnverifiedJwsMessage"/> and <see cref="Equals(UnverifiedJwsMessage?)"/> returns <see langword="true"/> for it; otherwise <see langword="false"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is UnverifiedJwsMessage other && Equals(other);


    /// <summary>
    /// Computes a hash code from the payload bytes, the signature count and the detachment flag, matching the fields <see cref="Equals(UnverifiedJwsMessage?)"/> compares.
    /// </summary>
    /// <returns>The computed hash code.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Payload.Span);
        hash.Add(Signatures.Count);
        hash.Add(IsDetachedPayload);
        return hash.ToHashCode();
    }
}
