using System;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// The COSE <c>kid</c> header parameter (label 4) — an opaque key-identifier hint,
/// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see> a byte string with no
/// structure COSE itself assigns; ETSI TS 119 152-1 V1.1.1 clause 5.1.4 (CB-5.1.4) states a CB-AdES <c>kid</c>
/// SHOULD carry a DER-encoded <c>IssuerSerial</c> (IETF RFC 5035), carried here uninterpreted. A named carrier
/// rather than a bare <see cref="ReadOnlyMemory{Byte}"/> so the value reads as a key-identifier hint at every
/// use site and has one home for the hex-label projection and the latent <c>IssuerSerial</c> parse.
/// </summary>
/// <remarks>
/// <para><strong>Borrowed view.</strong> This wraps memory the caller (creation path) or the wire-bytes source
/// (parse path) owns; it copies nothing and owns nothing, so it is never disposed.</para>
/// <para><strong>A class with explicit content equality, not a record.</strong> A record's synthesized
/// equality over a <see cref="ReadOnlyMemory{Byte}"/> member compares the underlying buffer by reference and
/// range, not by content — two byte-identical <c>kid</c> hints backed by different buffers would compare
/// unequal. This carrier instead compares the bytes themselves, so equality means "the same key-identifier
/// value", matching the "same value" equality the COSE label union (<see cref="CoseHeaderLabel"/>) documents.</para>
/// </remarks>
[DebuggerDisplay("CoseKeyIdentifier: {Value.Length} bytes")]
public sealed class CoseKeyIdentifier: IEquatable<CoseKeyIdentifier>
{
    /// <summary>Initializes a borrowed-view carrier over <paramref name="value"/>'s bytes.</summary>
    /// <param name="value">The opaque <c>kid</c> octets; borrowed, never copied.</param>
    public CoseKeyIdentifier(ReadOnlyMemory<byte> value)
    {
        Value = value;
    }

    /// <summary>Gets the opaque <c>kid</c> octets — a borrowed view; see the type remarks.</summary>
    public ReadOnlyMemory<byte> Value { get; }

    /// <summary>
    /// Projects the opaque bytes to the shared <see cref="KeyId"/> label vocabulary as their lower-case
    /// hexadecimal rendering — the SAME hex vocabulary the certificate-digest binding path uses, so an asserted
    /// (kid-hex) and a bound (digest-hex) label share one family.
    /// </summary>
    public KeyId ToKeyId()
    {
        return new KeyId(Convert.ToHexStringLower(Value.Span));
    }

    /// <inheritdoc/>
    public bool Equals(CoseKeyIdentifier? other)
    {
        return other is not null && Value.Span.SequenceEqual(other.Value.Span);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as CoseKeyIdentifier);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Value.Span);

        return hash.ToHashCode();
    }

    /// <summary>Reports whether two carriers hold the same key-identifier value (byte content).</summary>
    public static bool operator ==(CoseKeyIdentifier? left, CoseKeyIdentifier? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two carriers hold different key-identifier values.</summary>
    public static bool operator !=(CoseKeyIdentifier? left, CoseKeyIdentifier? right)
    {
        return !(left == right);
    }
}
