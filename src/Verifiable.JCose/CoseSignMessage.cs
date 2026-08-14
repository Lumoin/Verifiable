using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// Represents a COSE_Sign message structure — one or more signatures applied to the same
/// payload — per
/// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.1">RFC 9052 §4.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// COSE_Sign structure per RFC 9052:
/// </para>
/// <code>
/// COSE_Sign = [
///     protected : bstr,          ; Serialized body-layer protected header
///     unprotected : header_map,  ; Body-layer unprotected header
///     payload : bstr / nil,      ; Payload bytes
///     signatures : [+COSE_Signature]
/// ]
/// </code>
/// <para>
/// <strong>Ownership:</strong> the message owns its body-layer <see cref="ProtectedHeader"/>
/// (an <see cref="EncodedCoseProtectedHeader"/> pool-rented carrier) and every entry of
/// <see cref="Signatures"/> (each a <see cref="CoseSignatureComponent"/>, itself owning its
/// own signer-layer carriers). Disposing the message disposes all of them.
/// <see cref="Payload"/> is a borrowed reference, mirroring
/// <see cref="CoseSign1Message.Payload"/> — the caller (signing path) or the wire-bytes
/// source (parse path) owns the underlying memory.
/// </para>
/// <para>
/// Shape precedent: <see cref="JwsMessage"/>/<see cref="JwsSignatureComponent"/> model the
/// same one-payload/many-signers relationship for the JOSE General JSON serialization —
/// this type is the COSE-side, CBOR-wire-typed counterpart, with per-layer protected
/// headers carried as raw <see cref="EncodedCoseProtectedHeader"/> bytes (never a decoded
/// dictionary) rather than JWS's Base64Url string, matching <see cref="CoseSign1Message"/>'s
/// own convention.
/// </para>
/// <para>
/// Use <c>CoseSerialization</c> in <c>Verifiable.Cbor</c> to serialize/deserialize, and
/// <see cref="CoseSign"/> to sign/verify.
/// </para>
/// </remarks>
[DebuggerDisplay("CoseSignMessage: Payload={Payload.Length} bytes, Signatures={Signatures.Count}")]
public sealed class CoseSignMessage: IEquatable<CoseSignMessage>, IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSignMessage"/> class. Ownership of
    /// <paramref name="protectedHeader"/> and every entry of <paramref name="signatures"/>
    /// transfers to the message; disposing the message disposes all of them.
    /// </summary>
    /// <param name="protectedHeader">The body-layer serialized protected header carrier.</param>
    /// <param name="unprotectedHeader">The body-layer unprotected header map.</param>
    /// <param name="payload">The payload bytes (borrowed from caller).</param>
    /// <param name="signatures">
    /// The per-signer <see cref="CoseSignatureComponent"/> entries, in wire order. At least
    /// one is required — RFC 9052 §4.1's CDDL types <c>signatures</c> as
    /// <c>[+ COSE_Signature]</c>, a non-empty array.
    /// </param>
    public CoseSignMessage(
        EncodedCoseProtectedHeader protectedHeader,
        IReadOnlyDictionary<int, object>? unprotectedHeader,
        ReadOnlyMemory<byte> payload,
        IReadOnlyList<CoseSignatureComponent> signatures)
    {
        ArgumentNullException.ThrowIfNull(protectedHeader);
        ArgumentNullException.ThrowIfNull(signatures);

        if(signatures.Count == 0)
        {
            throw new ArgumentException("COSE_Sign requires at least one COSE_Signature entry.", nameof(signatures));
        }

        ProtectedHeader = protectedHeader;
        UnprotectedHeader = unprotectedHeader;
        Payload = payload;
        Signatures = signatures;
    }


    /// <summary>
    /// Gets the body-layer serialized protected header carrier. Owned by this message;
    /// disposed via <see cref="Dispose"/>.
    /// </summary>
    /// <remarks>
    /// The protected header is serialized as a CBOR map then wrapped as a bstr in the outer
    /// COSE_Sign array. RFC 9052 §4.4's <c>body_protected</c> Sig_structure field is built
    /// from these exact bytes for every signer.
    /// </remarks>
    public EncodedCoseProtectedHeader ProtectedHeader { get; }

    /// <summary>
    /// Gets the body-layer unprotected header as an integer-keyed dictionary.
    /// </summary>
    public IReadOnlyDictionary<int, object>? UnprotectedHeader { get; }

    /// <summary>
    /// Gets the payload bytes. <strong>Borrowed</strong> reference — the caller (sign path)
    /// or the wire-bytes source (parse path) owns the underlying memory.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>
    /// Gets the per-signer <see cref="CoseSignatureComponent"/> entries, in wire order.
    /// Owned by this message; disposed via <see cref="Dispose"/>.
    /// </summary>
    public IReadOnlyList<CoseSignatureComponent> Signatures { get; }

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
        foreach(CoseSignatureComponent signature in Signatures)
        {
            signature.Dispose();
        }
        disposed = true;
    }


    /// <inheritdoc/>
    public bool Equals(CoseSignMessage? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(!ProtectedHeader.AsReadOnlySpan().SequenceEqual(other.ProtectedHeader.AsReadOnlySpan())
            || !Payload.Span.SequenceEqual(other.Payload.Span)
            || Signatures.Count != other.Signatures.Count)
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
    public override bool Equals(object? obj) => Equals(obj as CoseSignMessage);


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

        hash.Add(Signatures.Count);

        return hash.ToHashCode();
    }


    /// <summary>Equality operator.</summary>
    public static bool operator ==(CoseSignMessage? left, CoseSignMessage? right) => left is null ? right is null : left.Equals(right);


    /// <summary>Inequality operator.</summary>
    public static bool operator !=(CoseSignMessage? left, CoseSignMessage? right) => !(left == right);
}
