using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Verifiable.Cryptography;

/// <summary>
/// Converts an ECDSA signature value between the fixed-width IEEE P1363 <c>r ‖ s</c> encoding this
/// library's registered signing and verification seam (<see cref="SigningDelegate"/>,
/// <see cref="VerificationDelegate"/>) produces and expects internally, and the ASN.1 DER
/// <c>Ecdsa-Sig-Value</c> encoding several wire formats require for the same signature value.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3">RFC 3279 section 2.2.3,
/// Elliptic Curve Digital Signature Algorithm (ECDSA)</see> defines
/// <c>Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }</c> — the encoding
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types">W3C Web Authentication
/// Level 3 section 6.5.5, Signature Formats for Packed Attestation, FIDO U2F Attestation, and
/// Assertion Signatures</see> requires for an ECDSA <c>sig</c> value (<c>COSEAlgorithmIdentifier</c>
/// -7/-35/-36, ES256/ES384/ES512), and that X.509, TLS, and CMS also use for the same signature value.
/// </para>
/// <para>
/// Both directions are needed because the two encodings serve different boundaries in this library: the
/// registered seam always produces/consumes P1363, so a DER-encoded wire value must be converted to
/// P1363 before reaching it, and a P1363 signature the seam produced must be converted to DER before it
/// reaches a DER-only wire consumer.
/// </para>
/// </remarks>
public static class EcdsaSignatureEncoding
{
    /// <summary>The DER two's-complement sign-extension octet an INTEGER's magnitude carries when its
    /// high bit would otherwise read as negative.</summary>
    private const byte SignExtensionOctet = 0x00;


    /// <summary>
    /// Converts a fixed-width IEEE P1363 <c>r ‖ s</c> signature — each component zero-padded to half of
    /// <paramref name="p1363Signature"/>'s length — to its ASN.1 DER
    /// <c>Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }</c> form.
    /// </summary>
    /// <param name="p1363Signature">The fixed-width <c>r ‖ s</c> signature; its length must be even.</param>
    /// <param name="pool">The memory pool the returned buffer is rented from.</param>
    /// <param name="length">The exact number of meaningful bytes written to the returned owner's memory.</param>
    /// <returns>A pooled buffer holding the DER encoding. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="p1363Signature"/>'s length is zero or odd.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the caller, which disposes it via a using declaration.")]
    public static IMemoryOwner<byte> ConvertP1363ToDer(ReadOnlySpan<byte> p1363Signature, MemoryPool<byte> pool, out int length)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(p1363Signature.Length == 0 || p1363Signature.Length % 2 != 0)
        {
            throw new ArgumentException("A fixed-width IEEE P1363 signature must have a non-zero, even length.", nameof(p1363Signature));
        }

        int fieldWidth = p1363Signature.Length / 2;
        ReadOnlySpan<byte> r = TrimToMinimalUnsigned(p1363Signature[..fieldWidth]);
        ReadOnlySpan<byte> s = TrimToMinimalUnsigned(p1363Signature[fieldWidth..]);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(r);
            writer.WriteIntegerUnsigned(s);
        }

        //The DER encoding is small and fixed-shape (at most a few hundred bytes even for P-521); write it
        //straight into the caller's pooled carrier via the writer's exact encoded length, so no
        //intermediate heap array is allocated.
        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out length);

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Converts an ASN.1 DER <c>Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }</c> to the
    /// fixed-width IEEE P1363 <c>r ‖ s</c> form, left-padding each coordinate to <paramref name="fieldWidth"/>.
    /// </summary>
    /// <param name="derSignature">The DER-encoded <c>Ecdsa-Sig-Value</c>.</param>
    /// <param name="fieldWidth">The curve's field width in bytes (32 for P-256, 48 for P-384, 66 for P-521).</param>
    /// <param name="pool">The memory pool the returned buffer is rented from.</param>
    /// <param name="length">
    /// The exact number of meaningful bytes written to the returned owner's memory; always
    /// <c>fieldWidth * 2</c>.
    /// </param>
    /// <returns>A pooled buffer holding the fixed-width <c>r ‖ s</c> encoding. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">A decoded coordinate exceeds <paramref name="fieldWidth"/>.</exception>
    /// <exception cref="AsnContentException"><paramref name="derSignature"/> is not a well-formed DER <c>Ecdsa-Sig-Value</c>.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the caller, which disposes it via a using declaration.")]
    public static IMemoryOwner<byte> ConvertDerToP1363(ReadOnlySpan<byte> derSignature, int fieldWidth, MemoryPool<byte> pool, out int length)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //AsnReader requires ReadOnlyMemory<byte>; copy the small signature into a pooled buffer (released
        //when this method returns) rather than a heap array. The decoded r/s spans alias this buffer and
        //are copied out into the result below before it is released.
        using IMemoryOwner<byte> inputOwner = pool.Rent(derSignature.Length);
        derSignature.CopyTo(inputOwner.Memory.Span);
        var reader = new AsnReader(inputOwner.Memory[..derSignature.Length], AsnEncodingRules.DER);
        AsnReader sequence = reader.ReadSequence();
        ReadOnlySpan<byte> r = StripLeadingZero(sequence.ReadIntegerBytes().Span);
        ReadOnlySpan<byte> s = StripLeadingZero(sequence.ReadIntegerBytes().Span);

        if(r.Length > fieldWidth || s.Length > fieldWidth)
        {
            throw new CryptographicException("The DER ECDSA signature coordinates exceed the curve field width.");
        }

        length = fieldWidth * 2;
        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            Span<byte> span = owner.Memory.Span[..length];
            span.Clear();
            r.CopyTo(span[(fieldWidth - r.Length)..fieldWidth]);
            s.CopyTo(span[(length - s.Length)..]);

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Strips a single leading <c>0x00</c> sign octet from a DER INTEGER's two's-complement encoding.
    /// </summary>
    private static ReadOnlySpan<byte> StripLeadingZero(ReadOnlySpan<byte> integer) =>
        integer.Length > 1 && integer[0] == SignExtensionOctet ? integer[1..] : integer;


    /// <summary>
    /// Trims every redundant leading <c>0x00</c> byte from a zero-padded unsigned big-endian coordinate
    /// (a P1363 <c>r</c> or <c>s</c> component), leaving at least one byte. <see cref="AsnWriter.WriteIntegerUnsigned"/>
    /// requires this minimal form — it adds its own single DER sign-extension byte when the remaining
    /// leading byte's high bit is set — and rejects an already over-padded value.
    /// </summary>
    private static ReadOnlySpan<byte> TrimToMinimalUnsigned(ReadOnlySpan<byte> value)
    {
        int index = 0;
        while(index < value.Length - 1 && value[index] == SignExtensionOctet)
        {
            index++;
        }

        return value[index..];
    }
}
