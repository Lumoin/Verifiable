using System.Formats.Cbor;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// The shipped default for <see cref="EncodePackedSelfAttestationStatementDelegate"/> and
/// <see cref="EncodePackedCertifiedAttestationStatementDelegate"/>: encodes a self-attestation or
/// certified <c>packed</c> attestation statement into its CTAP2-canonical CBOR bytes — the production
/// counterpart to <see cref="PackedAttestationStatementCborReader"/>'s two acceptance paths.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3,
/// section 8.2: Packed Attestation Statement Format</see>'s CDDL defines two alternatives for
/// <c>packedStmtFormat</c>. <see cref="Write"/> emits the self-attestation alternative — a map with
/// exactly the two required members <c>alg</c> and <c>sig</c>, with the <c>x5c</c> member OMITTED
/// ENTIRELY (never an empty array). <see cref="PackedAttestationStatementCborReader.Parse"/> treats any
/// <c>x5c</c> presence — including an empty array — as the certified-attestation branch discriminant,
/// which then rejects an empty chain outright, so an empty-array <c>x5c</c> would not round-trip to the
/// self attestation <see cref="Write"/> produces. <see cref="WriteCertified"/> emits the certified
/// alternative — a 3-member map with <c>x5c</c> present, keys in ascending text-key order <c>alg</c> &lt;
/// <c>sig</c> &lt; <c>x5c</c> (3-character tie, bytewise: <c>'a'</c> &lt; <c>'s'</c> &lt; <c>'x'</c>,
/// waveep R7 trap 14). Both written with <see cref="CborConformanceMode.Ctap2Canonical"/> per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-conforming-all-classes">section 2.4: All Conformance
/// Classes</see>.
/// </para>
/// </remarks>
public static class PackedAttestationStatementCborWriter
{
    /// <summary>The CBOR map key for the COSE algorithm identifier.</summary>
    private const string AlgKey = "alg";

    /// <summary>The CBOR map key for the attestation signature.</summary>
    private const string SigKey = "sig";

    /// <summary>The CBOR map key for the certificate chain.</summary>
    private const string X5cKey = "x5c";


    /// <summary>
    /// Encodes a self-attestation <c>packed</c> attestation statement from its algorithm and signature.
    /// Method-group-compatible with <see cref="EncodePackedSelfAttestationStatementDelegate"/>.
    /// </summary>
    /// <param name="alg">The credential private key's COSE algorithm identifier.</param>
    /// <param name="signature">The self-attestation signature bytes.</param>
    /// <returns>The encoded, text-keyed <c>attStmt</c> bytes, tagged <see cref="Fido2BufferTags.PackedAttestationStatementPayload"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="signature"/> is empty.</exception>
    public static TaggedMemory<byte> Write(int alg, ReadOnlySpan<byte> signature)
    {
        if(signature.IsEmpty)
        {
            throw new ArgumentException("The self-attestation signature must not be empty.", nameof(signature));
        }

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);

        writer.WriteTextString(AlgKey);
        writer.WriteInt32(alg);

        writer.WriteTextString(SigKey);
        writer.WriteByteString(signature);

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.PackedAttestationStatementPayload);
    }


    /// <summary>
    /// Encodes a certified (enterprise) <c>packed</c> attestation statement from its algorithm,
    /// signature, and seeded certificate chain. Method-group-compatible with
    /// <see cref="EncodePackedCertifiedAttestationStatementDelegate"/>.
    /// </summary>
    /// <param name="alg">The seeded enterprise attestation private key's COSE algorithm identifier.</param>
    /// <param name="signature">The certified attestation signature bytes.</param>
    /// <param name="x5c">The seeded attestation certificate chain, leaf-first — carried onto the wire verbatim, never parsed.</param>
    /// <returns>The encoded, text-keyed <c>attStmt</c> bytes, tagged <see cref="Fido2BufferTags.PackedAttestationStatementPayload"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="signature"/> or <paramref name="x5c"/> is empty.</exception>
    public static TaggedMemory<byte> WriteCertified(int alg, ReadOnlySpan<byte> signature, IReadOnlyList<PkiCertificateMemory> x5c)
    {
        if(signature.IsEmpty)
        {
            throw new ArgumentException("The certified attestation signature must not be empty.", nameof(signature));
        }

        ArgumentNullException.ThrowIfNull(x5c);
        if(x5c.Count == 0)
        {
            throw new ArgumentException("The certified attestation statement's x5c chain must not be empty.", nameof(x5c));
        }

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);

        writer.WriteTextString(AlgKey);
        writer.WriteInt32(alg);

        writer.WriteTextString(SigKey);
        writer.WriteByteString(signature);

        writer.WriteTextString(X5cKey);
        writer.WriteStartArray(x5c.Count);
        foreach(PkiCertificateMemory certificate in x5c)
        {
            writer.WriteByteString(certificate.AsReadOnlySpan());
        }
        writer.WriteEndArray();

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.PackedAttestationStatementPayload);
    }
}
