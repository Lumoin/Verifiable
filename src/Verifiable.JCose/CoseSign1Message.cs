using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// Represents a COSE_Sign1 message structure.
/// </summary>
/// <remarks>
/// <para>
/// This is a format-agnostic POCO analogous to <see cref="JwsMessage"/>.
/// It holds the components of a COSE_Sign1 structure without any serialization logic.
/// </para>
/// <para>
/// COSE_Sign1 structure per RFC 9052:
/// </para>
/// <code>
/// COSE_Sign1 = [
///     protected : bstr,        ; Serialized protected header
///     unprotected : header_map ; Unprotected header (integer-keyed map)
///     payload : bstr / nil,    ; Payload bytes
///     signature : bstr         ; Signature bytes
/// ]
/// </code>
/// <para>
/// Use <c>CoseSerialization</c> in <c>Verifiable.Cbor</c> to serialize/deserialize.
/// </para>
/// </remarks>
[DebuggerDisplay("CoseSign1Message: Payload={Payload.Length} bytes, Signature={Signature.Length} bytes")]
public sealed class CoseSign1Message: IEquatable<CoseSign1Message>
{
    /// <summary>
    /// Gets the serialized protected header bytes.
    /// </summary>
    /// <remarks>
    /// The protected header is serialized as a CBOR map, then wrapped as a bstr.
    /// Contains cryptographically protected parameters like algorithm (alg).
    /// </remarks>
    public ReadOnlyMemory<byte> ProtectedHeaderBytes { get; }

    /// <summary>
    /// Gets the unprotected header as an integer-keyed dictionary.
    /// </summary>
    /// <remarks>
    /// Contains parameters that are not cryptographically protected.
    /// For SD-CWT, this includes the <c>sd_claims</c> (disclosures) array.
    /// </remarks>
    public IReadOnlyDictionary<int, object>? UnprotectedHeader { get; }

    /// <summary>
    /// Gets the payload bytes.
    /// </summary>
    /// <remarks>
    /// For credentials, this is typically a CWT claims set or JSON-encoded credential.
    /// May be empty for detached payloads.
    /// </remarks>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>
    /// Gets the signature bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>
    /// Gets a value indicating whether this message has a detached payload.
    /// </summary>
    public bool IsDetachedPayload => Payload.IsEmpty;


    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSign1Message"/> class.
    /// </summary>
    /// <param name="protectedHeaderBytes">The serialized protected header.</param>
    /// <param name="unprotectedHeader">The unprotected header map.</param>
    /// <param name="payload">The payload bytes.</param>
    /// <param name="signature">The signature bytes.</param>
    public CoseSign1Message(
        ReadOnlyMemory<byte> protectedHeaderBytes,
        IReadOnlyDictionary<int, object>? unprotectedHeader,
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> signature)
    {
        ProtectedHeaderBytes = protectedHeaderBytes;
        UnprotectedHeader = unprotectedHeader;
        Payload = payload;
        Signature = signature;
    }


    /// <summary>
    /// Initializes a new instance with no unprotected header.
    /// </summary>
    /// <param name="protectedHeaderBytes">The serialized protected header.</param>
    /// <param name="payload">The payload bytes.</param>
    /// <param name="signature">The signature bytes.</param>
    public CoseSign1Message(
        ReadOnlyMemory<byte> protectedHeaderBytes,
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> signature): this(protectedHeaderBytes, null, payload, signature)
    {
    }


    /// <inheritdoc/>
    public bool Equals(CoseSign1Message? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return ProtectedHeaderBytes.Span.SequenceEqual(other.ProtectedHeaderBytes.Span)
            && Payload.Span.SequenceEqual(other.Payload.Span)
            && Signature.Span.SequenceEqual(other.Signature.Span);
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CoseSign1Message);


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();

        foreach(byte b in ProtectedHeaderBytes.Span)
        {
            hash.Add(b);
        }

        foreach(byte b in Payload.Span.Slice(0, Math.Min(16, Payload.Length)))
        {
            hash.Add(b);
        }

        return hash.ToHashCode();
    }


    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(CoseSign1Message? left, CoseSign1Message? right) => left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(CoseSign1Message? left, CoseSign1Message? right) => !(left == right);
}