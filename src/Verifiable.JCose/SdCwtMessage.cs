using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.JCose.Sd;

namespace Verifiable.JCose;

/// <summary>
/// A complete SD-CWT (Selective Disclosure CBOR Web Token) message.
/// </summary>
/// <remarks>
/// <para>
/// SD-CWT uses COSE_Sign1 structure with disclosures in the unprotected header,
/// as specified by IETF SPICE draft-ietf-spice-sd-cwt.
/// </para>
/// <para>
/// This type is immutable and thread-safe.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SdCwtMessage: IEquatable<SdCwtMessage>
{
    /// <summary>
    /// The CWT payload bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>
    /// The protected header bytes (CBOR-encoded).
    /// </summary>
    public ReadOnlyMemory<byte> ProtectedHeader { get; }

    /// <summary>
    /// The signature bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>
    /// The selective disclosures included in the unprotected header.
    /// </summary>
    public IReadOnlyList<SdDisclosure> Disclosures { get; }


    /// <summary>
    /// Creates a new SD-CWT message.
    /// </summary>
    /// <param name="payload">The CWT payload bytes.</param>
    /// <param name="protectedHeader">The protected header bytes.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <param name="disclosures">The selective disclosures.</param>
    public SdCwtMessage(
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> protectedHeader,
        ReadOnlyMemory<byte> signature,
        IReadOnlyList<SdDisclosure> disclosures)
    {
        ArgumentNullException.ThrowIfNull(disclosures);

        Payload = payload;
        ProtectedHeader = protectedHeader;
        Signature = signature;
        Disclosures = disclosures;
    }


    private string DebuggerDisplay
    {
        get
        {
            string disclosureInfo = Disclosures.Count == 1 ? "1 disclosure" : $"{Disclosures.Count} disclosures";
            return $"SdCwtMessage[{Payload.Length} bytes, {disclosureInfo}]";
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(SdCwtMessage? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(!Payload.Span.SequenceEqual(other.Payload.Span))
        {
            return false;
        }

        if(!ProtectedHeader.Span.SequenceEqual(other.ProtectedHeader.Span))
        {
            return false;
        }

        if(!Signature.Span.SequenceEqual(other.Signature.Span))
        {
            return false;
        }

        if(Disclosures.Count != other.Disclosures.Count)
        {
            return false;
        }

        return true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is SdCwtMessage other && Equals(other);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Payload.Span);
        hash.AddBytes(ProtectedHeader.Span);
        hash.Add(Disclosures.Count);
        return hash.ToHashCode();
    }


    /// <summary>
    /// Determines whether two SD-CWT messages are equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(SdCwtMessage? left, SdCwtMessage? right)
    {
        return left is null ? right is null : left.Equals(right);
    }


    /// <summary>
    /// Determines whether two SD-CWT messages are not equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(SdCwtMessage? left, SdCwtMessage? right)
    {
        return !(left == right);
    }


    /// <inheritdoc/>
    public override string ToString()
    {
        return $"SdCwtMessage[{Payload.Length} bytes, {Disclosures.Count} disclosure(s)]";
    }
}