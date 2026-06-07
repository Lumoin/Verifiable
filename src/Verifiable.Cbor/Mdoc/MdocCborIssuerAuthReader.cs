using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// CBOR reader for the <c>issuerAuth</c> slot inside
/// <see cref="MdocIssuerSigned"/> — composes the existing COSE_Sign1
/// parser (<see cref="CoseSerialization.ParseCoseSign1"/>) with the
/// MSO reader to produce a fully-populated <see cref="MdocIssuerAuth"/>
/// carrier.
/// </summary>
/// <remarks>
/// <para>
/// On the wire <c>issuerAuth</c> is a COSE_Sign1 (CBOR Tag 18 per RFC 9052)
/// whose payload is the MSO wrapped in CBOR Tag 24 per ISO/IEC 18013-5
/// §9.1.2.4. This reader walks both layers — Tag 18 → COSE_Sign1 array →
/// payload bstr → Tag 24 wrapper → MSO map — and returns the parsed MSO
/// alongside the original COSE_Sign1 wire bytes (in a pool-routed
/// <see cref="EncodedCoseSign1"/> carrier) for downstream signature
/// verification and digest binding.
/// </para>
/// <para>
/// The signature itself is NOT verified here. This reader only validates
/// the wire shape and routes bytes into pool memory so the carrier
/// outlives the input span.
/// </para>
/// </remarks>
public static class MdocCborIssuerAuthReader
{
    /// <summary>
    /// Reads an <c>issuerAuth</c> COSE_Sign1 from the supplied CBOR bytes.
    /// </summary>
    /// <param name="encodedCoseSign1">The CBOR-encoded COSE_Sign1 bytes (Tag 18 included).</param>
    /// <param name="pool">Memory pool the wire-bytes carrier rents from.</param>
    /// <returns>
    /// The <see cref="MdocIssuerAuth"/> carrier holding the parsed MSO plus
    /// the original COSE_Sign1 wire bytes (pool-routed). Caller owns the
    /// returned carrier and must dispose it.
    /// </returns>
    /// <exception cref="CborContentException">
    /// Thrown when the bytes are not a valid COSE_Sign1, the payload is
    /// missing, or the inner MSO does not satisfy ISO/IEC 18013-5 §9.1.2.4.
    /// </exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of wireOwner and parsedCose transfers to the returned MdocIssuerAuth; caller disposes the issuerAuth.")]
    public static MdocIssuerAuth Read(ReadOnlySpan<byte> encodedCoseSign1, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //Pool-route the wire bytes copy so the carrier carries CBOM
        //provenance and OTel observes the allocation.
        IMemoryOwner<byte> wireOwner = pool.Rent(encodedCoseSign1.Length);
        encodedCoseSign1.CopyTo(wireOwner.Memory.Span);
        EncodedCoseSign1 wireCarrier = new(wireOwner, CryptoTags.CoseEncodedSign1);

        //Parse for payload inspection — this materializes pool-routed
        //EncodedCoseProtectedHeader + Signature carriers we don't keep,
        //so dispose after extracting the MSO from the payload.
        using CoseSign1Message parsedCose = CoseSerialization.ParseCoseSign1(wireCarrier.AsReadOnlyMemory(), pool);

        if(parsedCose.Payload.IsEmpty)
        {
            wireCarrier.Dispose();
            throw new CborContentException(
                "COSE_Sign1 for issuerAuth must carry the MSO as its payload; got an empty/detached payload.");
        }

        //The payload is a Tag 24 wrapper around the MSO bytes per
        //ISO/IEC 18013-5 §9.1.2.4. Unwrap once to get the inner MSO map.
        EncodedCborItem wrapper = EncodedCborItem.Read(new CborReader(parsedCose.Payload.ToArray(), CborConformanceMode.Lax));
        MdocMobileSecurityObject mso = MdocCborMsoReader.Read(wrapper.InnerBytes.Span);

        return new MdocIssuerAuth(mso, wireCarrier);
    }
}
