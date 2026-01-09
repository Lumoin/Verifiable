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
public sealed class UnverifiedJwsMessage : IDisposable, IEquatable<UnverifiedJwsMessage>
{
    private bool disposed;

    /// <summary>
    /// Owned payload memory (when parsed). Null if payload comes from external source.
    /// </summary>
    private readonly IMemoryOwner<byte>? ownedPayload;

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


    public UnverifiedJwsMessage(
        IMemoryOwner<byte>? payloadOwner,
        ReadOnlyMemory<byte> payload,
        UnverifiedJwsSignature signature,
        bool isDetachedPayload = false)
    {
        ArgumentNullException.ThrowIfNull(signature);

        ownedPayload = payloadOwner;
        Payload = payload;
        Signatures = [signature];
        IsDetachedPayload = isDetachedPayload;
    }


    public UnverifiedJwsMessage(
        IMemoryOwner<byte>? payloadOwner,
        ReadOnlyMemory<byte> payload,
        IReadOnlyList<UnverifiedJwsSignature> signatures,
        bool isDetachedPayload = false)
    {
        ArgumentNullException.ThrowIfNull(signatures);
        if(signatures.Count == 0)
            throw new ArgumentException("At least one signature is required.", nameof(signatures));

        ownedPayload = payloadOwner;
        Payload = payload;
        Signatures = signatures;
        IsDetachedPayload = isDetachedPayload;
    }


    public void Dispose()
    {
        if(!disposed)
        {
            ownedPayload?.Dispose();
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


    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(UnverifiedJwsMessage? other)
    {
        if(other is null) return false;
        if(ReferenceEquals(this, other)) return true;

        return IsDetachedPayload == other.IsDetachedPayload
            && Payload.Span.SequenceEqual(other.Payload.Span)
            && Signatures.Count == other.Signatures.Count;
    }


    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is UnverifiedJwsMessage other && Equals(other);


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