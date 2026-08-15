using System;
using System.Buffers;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Computes a Signature VRI dictionary's own key — the base-16-encoded (uppercase) SHA-1 digest naming, per
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see> clause 5.4.2.2's own table (PA-5.4.2.2-T2), "the signature to which it applies".
/// Which bytes are hashed depends on what kind of signature that is; the two methods here cover the two shapes
/// PA-5.4.2.2-09/-10 (letters a) and b)) state.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why SHA-1, and why not through <see cref="PkiDigestAlgorithm"/>.</strong> The VRI key is an object
/// identifier this specification mandates SHA-1 for, not a cryptographic strength claim about anything the
/// signature itself relies on — <see cref="CryptoTags.Sha1Digest"/>'s own remarks state exactly this boundary,
/// and <see cref="PkiDigestAlgorithm"/>'s own remarks explain why SHA-1 must stay absent from the
/// signature-relevant digest-resolution surface. This type calls the registered digest seam directly with
/// <see cref="CryptoTags.Sha1Digest"/>, never through <see cref="PkiDigestAlgorithm"/>.
/// </para>
/// <para>
/// <strong>Letter c) — XAdES-XFA — is not implemented.</strong> PA-5.4.2.2-11 states a third computation, over an
/// exclusively-canonicalized <c>ds:Signature</c> element embedded in dynamic XFA form data. This library carries
/// no XML canonicalization substrate, so the XAdES/XML leg is out of scope; no
/// method here computes it, and a caller reaching for it fails at compile time rather than through a runtime
/// <see cref="NotSupportedException"/>.
/// </para>
/// </remarks>
public static class PdfVriKey
{
    /// <summary>The digest's own rendered length: 20 SHA-1 octets, base-16 encoded.</summary>
    private const int RenderedKeyLength = 40;


    /// <summary>
    /// Computes the VRI key for a document signature or a document time-stamp signature (PA-5.4.2.2-09, letter
    /// a)): the SHA-1 digest of "the complete hexadecimal string in the entry with the key Contents", read
    /// DIRECTLY off the document's own bytes — never a hexadecimal string re-rendered from the decoded binary
    /// object those digits represent. Re-rendering is not merely a style choice: <see cref="PdfIncrementalUpdateWriter.CompleteSignature"/>
    /// pads <c>Contents</c>' own reserved capacity with trailing zero hexadecimal digits past the real signature
    /// value's own end (ISO 32000-1 clause 7.3.4), so the LITERAL printed string is longer than the decoded DER
    /// object's own re-rendered hex would be — hashing a re-rendering silently omits that padding and computes a
    /// digest PA-5.4.2.2-09 does not name.
    /// </summary>
    /// <param name="signature">The located Signature Dictionary (an ordinary signature or a document time-stamp candidate) whose own literal <c>Contents</c> hexadecimal string is hashed.</param>
    /// <param name="pool">The memory pool the digest computation rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 40-character uppercase hexadecimal VRI key.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signature"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">When no <see cref="ComputeDigestDelegate"/> has been registered.</exception>
    public static async ValueTask<string> ForSignatureContentsAsync(
        PdfSignatureDictionary signature, BaseMemoryPool pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(pool);

        //The literal hexadecimal digit octets as printed in the document, [GapStart + 1, SecondOffset - 1) --
        //the ByteRange gap excludes the whole Contents string value, its '<'/'>' delimiters included (the same
        //convention PdfByteSurfaceReader/PdfIncrementalUpdateWriter both apply), so this is exactly the digit
        //span between those delimiters, padding included, never re-derived from the decoded value.
        ReadOnlyMemory<byte> hexStringAscii = signature.Document[(signature.ByteRange.GapStart + 1)..(signature.ByteRange.SecondOffset - 1)];

        return await HashToKeyAsync(hexStringAscii, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Computes the VRI key for the signature of a CRL or an OCSP response (PA-5.4.2.2-10, letter b)): the SHA-1
    /// digest of the response object represented as a BER-encoded <c>OCTET STRING</c> with primitive encoding —
    /// the DER-encoded object wrapped in one primitive octet-string TLV, then hashed whole (tag and length octets
    /// included).
    /// </summary>
    /// <param name="responseDer">The DER-encoded CRL (<c>CertificateList</c>) or OCSP response object.</param>
    /// <param name="pool">The memory pool the digest computation rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 40-character uppercase hexadecimal VRI key.</returns>
    /// <exception cref="InvalidOperationException">When no <see cref="ComputeDigestDelegate"/> has been registered.</exception>
    public static async ValueTask<string> ForCrlOrOcspResponseAsync(
        ReadOnlyMemory<byte> responseDer, BaseMemoryPool pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new AsnWriter(AsnEncodingRules.BER);
        writer.WriteOctetString(responseDer.Span);
        byte[] encoded = writer.Encode();

        return await HashToKeyAsync(encoded, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Reports whether a string is shaped like a VRI key this type produces: exactly 40 uppercase hexadecimal characters.</summary>
    /// <param name="candidate">The string to check.</param>
    /// <returns><see langword="true"/> when <paramref name="candidate"/> is a well-formed VRI key.</returns>
    public static bool IsWellFormed(string candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        if(candidate.Length != RenderedKeyLength)
        {
            return false;
        }

        for(int i = 0; i < candidate.Length; ++i)
        {
            char c = candidate[i];
            bool isUpperHex = c is (>= '0' and <= '9') or (>= 'A' and <= 'F');
            if(!isUpperHex)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>Computes the SHA-1 digest of <paramref name="data"/> and renders it as an uppercase hexadecimal VRI key.</summary>
    private static async ValueTask<string> HashToKeyAsync(ReadOnlyMemory<byte> data, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            data, WellKnownHashAlgorithms.Sha1SizeBytes, CryptoTags.Sha1Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return Convert.ToHexString(digest.AsReadOnlySpan());
    }
}
