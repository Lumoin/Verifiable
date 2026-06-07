using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Represents a COSE_Sign1 message structure per
/// <see href="https://www.rfc-editor.org/rfc/rfc9052">RFC 9052</see>.
/// </summary>
/// <remarks>
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
/// <strong>Ownership:</strong> the message owns its
/// <see cref="ProtectedHeader"/> (an <see cref="EncodedCoseProtectedHeader"/>
/// pool-rented carrier) and its <see cref="Signature"/> (a
/// <see cref="Verifiable.Cryptography.Signature"/> pool-rented carrier).
/// Disposing the message disposes both. <see cref="Payload"/> is a
/// borrowed reference — the caller (signing path) or the wire-bytes
/// source (parse path) owns the underlying memory; the message just
/// holds a view.
/// </para>
/// <para>
/// Use <c>CoseSerialization</c> in <c>Verifiable.Cbor</c> to
/// serialize/deserialize.
/// </para>
/// </remarks>
[DebuggerDisplay("CoseSign1Message: Payload={Payload.Length} bytes, Signature={Signature.AsReadOnlySpan().Length} bytes")]
public sealed class CoseSign1Message: IEquatable<CoseSign1Message>, IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSign1Message"/> class.
    /// Ownership of <paramref name="protectedHeader"/> and
    /// <paramref name="signature"/> transfers to the message; disposing the
    /// message disposes both.
    /// </summary>
    /// <param name="protectedHeader">The serialized protected header carrier.</param>
    /// <param name="unprotectedHeader">The unprotected header map.</param>
    /// <param name="payload">The payload bytes (borrowed from caller).</param>
    /// <param name="signature">The signature carrier.</param>
    public CoseSign1Message(
        EncodedCoseProtectedHeader protectedHeader,
        IReadOnlyDictionary<int, object>? unprotectedHeader,
        ReadOnlyMemory<byte> payload,
        Signature signature)
    {
        ArgumentNullException.ThrowIfNull(protectedHeader);
        ArgumentNullException.ThrowIfNull(signature);

        ProtectedHeader = protectedHeader;
        UnprotectedHeader = unprotectedHeader;
        Payload = payload;
        Signature = signature;
    }


    /// <summary>
    /// Initializes a new instance with no unprotected header.
    /// </summary>
    /// <param name="protectedHeader">The serialized protected header carrier.</param>
    /// <param name="payload">The payload bytes (borrowed from caller).</param>
    /// <param name="signature">The signature carrier.</param>
    public CoseSign1Message(
        EncodedCoseProtectedHeader protectedHeader,
        ReadOnlyMemory<byte> payload,
        Signature signature)
        : this(protectedHeader, null, payload, signature)
    {
    }


    /// <summary>
    /// Gets the serialized protected header carrier. Owned by this message;
    /// disposed via <see cref="Dispose"/>.
    /// </summary>
    /// <remarks>
    /// The protected header is serialized as a CBOR map then wrapped as a
    /// bstr in the outer COSE_Sign1 array. Contains cryptographically
    /// protected parameters like algorithm (<c>alg</c>).
    /// </remarks>
    public EncodedCoseProtectedHeader ProtectedHeader { get; }

    /// <summary>
    /// Gets the unprotected header as an integer-keyed dictionary.
    /// </summary>
    /// <remarks>
    /// Contains parameters that are not cryptographically protected.
    /// For SD-CWT this includes the <c>sd_claims</c> (disclosures) array;
    /// for mdoc this carries the <c>x5chain</c>.
    /// </remarks>
    public IReadOnlyDictionary<int, object>? UnprotectedHeader { get; }

    /// <summary>
    /// Gets the payload bytes. <strong>Borrowed</strong> reference — the
    /// caller (sign path) or the wire-bytes source (parse path) owns the
    /// underlying memory.
    /// </summary>
    /// <remarks>
    /// For credentials this is typically a CWT claims set or a CBOR-encoded
    /// MSO. May be empty for detached payloads (ISO/IEC 18013-5 §9.1.3.4
    /// device signatures use the detached form).
    /// </remarks>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>
    /// Gets the signature carrier. Owned by this message; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public Signature Signature { get; }

    /// <summary>
    /// Gets a value indicating whether this message has a detached payload.
    /// </summary>
    public bool IsDetachedPayload => Payload.IsEmpty;


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        ProtectedHeader.Dispose();
        Signature.Dispose();
        disposed = true;
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

        return ProtectedHeader.AsReadOnlySpan().SequenceEqual(other.ProtectedHeader.AsReadOnlySpan())
            && Payload.Span.SequenceEqual(other.Payload.Span)
            && Signature.AsReadOnlySpan().SequenceEqual(other.Signature.AsReadOnlySpan());
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CoseSign1Message);


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();

        foreach(byte b in ProtectedHeader.AsReadOnlySpan())
        {
            hash.Add(b);
        }

        foreach(byte b in Payload.Span.Slice(0, Math.Min(16, Payload.Length)))
        {
            hash.Add(b);
        }

        return hash.ToHashCode();
    }


    /// <summary>Equality operator.</summary>
    public static bool operator ==(CoseSign1Message? left, CoseSign1Message? right) => left is null ? right is null : left.Equals(right);


    /// <summary>Inequality operator.</summary>
    public static bool operator !=(CoseSign1Message? left, CoseSign1Message? right) => !(left == right);
}
