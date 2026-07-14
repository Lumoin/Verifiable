using System.Formats.Cbor;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// Encodes a <c>fido-u2f</c> attestation statement into its CTAP2-canonical CBOR bytes — the production
/// counterpart to <see cref="FidoU2fAttestationStatementCborReader"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">W3C Web Authentication Level
/// 3, section 8.6: FIDO U2F Attestation Statement Format</see>'s CDDL defines <c>fidoU2fStmtFormat</c> as
/// a 2-member map with both members REQUIRED: <c>sig</c> and a single-element <c>x5c</c>
/// (<c>x5c: [ attestnCert: bytes ]</c>) — unlike <c>packed</c>, there is no <c>alg</c> member and no
/// self-attestation branch. <see cref="Write"/> emits the two members in ascending canonical key order
/// (equal-length text-string keys sort bytewise: <c>'s'</c> &lt; <c>'x'</c>, so <c>sig</c> precedes
/// <c>x5c</c>), with <see cref="CborConformanceMode.Ctap2Canonical"/> per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-conforming-all-classes">section 2.4: All Conformance
/// Classes</see>. <paramref name="x5c"/> is REQUIRED to carry exactly one certificate, mirroring
/// <see cref="FidoU2fAttestationStatementCborReader.Parse"/>'s own section 8.6 verification procedure
/// step 2 enforcement ("Check that x5c has exactly one element").
/// </para>
/// </remarks>
public static class FidoU2fAttestationStatementCborWriter
{
    /// <summary>The CBOR map key for the attestation signature.</summary>
    private const string SigKey = "sig";

    /// <summary>The CBOR map key for the mandatory single-element certificate array.</summary>
    private const string X5cKey = "x5c";

    /// <summary>The exact element count section 8.6 verification procedure step 2 requires of <c>x5c</c>.</summary>
    private const int RequiredX5cElementCount = 1;


    /// <summary>
    /// Encodes a <c>fido-u2f</c> attestation statement from its signature and single-element attestation
    /// certificate array.
    /// </summary>
    /// <param name="signature">The attestation signature bytes.</param>
    /// <param name="x5c">
    /// The single-element attestation certificate array, carried onto the wire verbatim, never parsed.
    /// </param>
    /// <returns>The encoded, text-keyed <c>attStmt</c> bytes, tagged <see cref="Fido2BufferTags.FidoU2fAttestationStatementPayload"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="signature"/> is empty, or <paramref name="x5c"/> does not carry exactly one element.</exception>
    public static TaggedMemory<byte> Write(ReadOnlySpan<byte> signature, IReadOnlyList<PkiCertificateMemory> x5c)
    {
        if(signature.IsEmpty)
        {
            throw new ArgumentException("The fido-u2f attestation signature must not be empty.", nameof(signature));
        }

        ArgumentNullException.ThrowIfNull(x5c);
        if(x5c.Count != RequiredX5cElementCount)
        {
            throw new ArgumentException($"The fido-u2f attestation statement's x5c must contain exactly one element, but {x5c.Count} were given.", nameof(x5c));
        }

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);

        writer.WriteTextString(SigKey);
        writer.WriteByteString(signature);

        writer.WriteTextString(X5cKey);
        writer.WriteStartArray(x5c.Count);
        writer.WriteByteString(x5c[0].AsReadOnlySpan());
        writer.WriteEndArray();

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.FidoU2fAttestationStatementPayload);
    }
}
