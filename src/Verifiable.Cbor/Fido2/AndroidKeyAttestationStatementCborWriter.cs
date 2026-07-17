using System.Formats.Cbor;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// Encodes an <c>android-key</c> attestation statement into its CTAP2-canonical CBOR bytes — the
/// production counterpart to <see cref="AndroidKeyAttestationStatementCborReader"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web Authentication
/// Level 3, section 8.4: Android Key Attestation Statement Format</see>'s CDDL defines
/// <c>androidKeyStmtFormat</c> as a 3-member map with all of <c>alg</c>, <c>sig</c>, and <c>x5c</c>
/// REQUIRED — the format has no self-attestation branch, so <c>x5c</c> is always present on the wire,
/// unlike <c>packed</c>'s optional <c>x5c</c>. <see cref="Write"/> emits the three members in ascending
/// canonical key order (equal-length text-string keys sort bytewise: <c>'a'</c> &lt; <c>'s'</c> &lt;
/// <c>'x'</c>), with <see cref="CborConformanceMode.Ctap2Canonical"/> per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-conforming-all-classes">section 2.4: All Conformance
/// Classes</see>. <paramref name="x5c"/> is written verbatim regardless of element count — the CDDL's
/// <c>≥1</c>-element shape is <see cref="AndroidKeyAttestation"/>'s verification-procedure concern, not
/// this codec's, mirroring <see cref="AndroidKeyAttestationStatementCborReader.Parse"/>'s own leniency.
/// </para>
/// </remarks>
public static class AndroidKeyAttestationStatementCborWriter
{
    /// <summary>The CBOR map key for the COSE algorithm identifier.</summary>
    private const string AlgKey = "alg";

    /// <summary>The CBOR map key for the attestation signature.</summary>
    private const string SigKey = "sig";

    /// <summary>The CBOR map key for the mandatory certificate chain.</summary>
    private const string X5cKey = "x5c";


    /// <summary>
    /// Encodes an <c>android-key</c> attestation statement from its algorithm, signature, and
    /// credCert-first certificate chain.
    /// </summary>
    /// <param name="alg">The credential private key's COSE algorithm identifier.</param>
    /// <param name="signature">The attestation signature bytes.</param>
    /// <param name="x5c">The credCert followed by its certificate chain, credCert first, carried onto the wire verbatim, never parsed.</param>
    /// <returns>The encoded, text-keyed <c>attStmt</c> bytes, tagged <see cref="Fido2BufferTags.AndroidKeyAttestationStatementPayload"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="signature"/> is empty.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="x5c"/> is <see langword="null"/>.</exception>
    public static TaggedMemory<byte> Write(int alg, ReadOnlySpan<byte> signature, IReadOnlyList<PkiCertificateMemory> x5c)
    {
        if(signature.IsEmpty)
        {
            throw new ArgumentException("The android-key attestation signature must not be empty.", nameof(signature));
        }

        ArgumentNullException.ThrowIfNull(x5c);

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

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.AndroidKeyAttestationStatementPayload);
    }
}
