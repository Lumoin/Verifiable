using System.Formats.Cbor;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Shared test-vector builders for the <c>fido-u2f</c> attestation-verification tests: the section 8.6
/// <c>verificationData</c> transcript construction that no shared helper builds (every other WebAuthn
/// L3 format signs <c>authData || clientDataHash</c> directly; <c>fido-u2f</c> signs its own distinct
/// U2F-message-formats-derived layout), plus a hand-built out-of-range-coordinate COSE_Key for the
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">section 8.6</see> coordinate
/// length negative fixtures. Reuses <see cref="Fido2AttestationTestVectors"/> and <see cref="Fido2TestVectors"/>
/// for every certificate, authenticator data, and signing concern the two formats share.
/// </summary>
internal static class FidoU2fAttestationTestVectors
{
    /// <summary>
    /// The leading version byte <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">section
    /// 8.6</see> verification procedure step 5 uses to build <c>verificationData</c>.
    /// </summary>
    private const byte VerificationDataVersionPrefix = 0x00;

    /// <summary>
    /// The uncompressed elliptic-curve point format prefix byte section 8.6 verification procedure
    /// step 4 uses to build <c>publicKeyU2F</c> (<c>0x04 || x || y</c>).
    /// </summary>
    private const byte UncompressedEcPointPrefix = 0x04;


    /// <summary>
    /// Builds the section 8.6 verification procedure's <c>verificationData</c> transcript —
    /// <c>0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F</c>, where
    /// <c>publicKeyU2F</c> is <c>0x04 || x || y</c> — the bytes a <c>fido-u2f</c> attestation
    /// signature covers. Each component is supplied independently so a test can build a
    /// deliberately mismatched transcript (a wrong <paramref name="rpIdHash"/>,
    /// <paramref name="clientDataHash"/>, or <paramref name="credentialId"/> relative to what a
    /// request's other members carry) for the transcript-binding negative fixtures.
    /// </summary>
    /// <param name="rpIdHash">The relying party ID hash bytes to embed.</param>
    /// <param name="clientDataHash">The client data hash to embed.</param>
    /// <param name="credentialId">The credential identifier bytes to embed.</param>
    /// <param name="x">The credential public key's <c>x</c> coordinate, exactly 32 bytes for a well-formed vector.</param>
    /// <param name="y">The credential public key's <c>y</c> coordinate, exactly 32 bytes for a well-formed vector.</param>
    /// <returns>The assembled <c>verificationData</c> bytes.</returns>
    internal static byte[] BuildVerificationData(
        ReadOnlySpan<byte> rpIdHash,
        DigestValue clientDataHash,
        ReadOnlySpan<byte> credentialId,
        ReadOnlySpan<byte> x,
        ReadOnlySpan<byte> y)
    {
        ArgumentNullException.ThrowIfNull(clientDataHash);

        byte[] result = new byte[1 + rpIdHash.Length + clientDataHash.Length + credentialId.Length + 1 + x.Length + y.Length];
        Span<byte> destination = result;

        int offset = 0;
        destination[offset] = VerificationDataVersionPrefix;
        offset += 1;

        rpIdHash.CopyTo(destination[offset..]);
        offset += rpIdHash.Length;

        clientDataHash.AsReadOnlySpan().CopyTo(destination[offset..]);
        offset += clientDataHash.Length;

        credentialId.CopyTo(destination[offset..]);
        offset += credentialId.Length;

        destination[offset] = UncompressedEcPointPrefix;
        offset += 1;

        x.CopyTo(destination[offset..]);
        offset += x.Length;

        y.CopyTo(destination[offset..]);

        return result;
    }


    /// <summary>
    /// Builds a hand-crafted EC2 <see cref="CoseKey"/> whose <c>x</c>/<c>y</c> coordinates are
    /// exactly <paramref name="xLength"/>/<paramref name="yLength"/> bytes — the section 8.6
    /// coordinate-length negative fixture (the CR requires exactly 32 bytes for each). The
    /// coordinate content is immaterial to the check under test, only its length.
    /// </summary>
    /// <param name="xLength">The byte length to give the <c>x</c> coordinate.</param>
    /// <param name="yLength">The byte length to give the <c>y</c> coordinate.</param>
    /// <returns>The hand-crafted <see cref="CoseKey"/>.</returns>
    internal static CoseKey CreateP256CoseKeyWithCoordinateLengths(int xLength, int yLength)
    {
        return new CoseKey(kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256, x: new byte[xLength], y: new byte[yLength]);
    }


    /// <summary>
    /// A <see cref="ParseFidoU2fAttestationStatementDelegate"/> stub that ignores the raw CBOR input and
    /// returns a pre-built <see cref="FidoU2fAttestationStatement"/> — mirrors
    /// <see cref="Fido2AttestationTestVectors.CreateStatementParser"/> for this format's own statement
    /// type, since the CBOR codec is edge-wired separately for the direct-verifier-level tests.
    /// </summary>
    /// <param name="statement">The statement to return regardless of the supplied bytes.</param>
    /// <returns>A delegate that always returns <paramref name="statement"/>.</returns>
    internal static ParseFidoU2fAttestationStatementDelegate CreateStatementParser(FidoU2fAttestationStatement statement) =>
        (_, _) => statement;


    /// <summary>
    /// A <see cref="ParseFidoU2fAttestationStatementDelegate"/> stub that always throws
    /// <see cref="Fido2FormatException"/> — simulates a malformed <c>attStmt</c> CBOR payload so the
    /// caller's catch-and-map-to-<c>MalformedStatement</c> behavior can be exercised without a real codec.
    /// </summary>
    /// <param name="message">The exception message.</param>
    /// <returns>A delegate that always throws.</returns>
    internal static ParseFidoU2fAttestationStatementDelegate CreateThrowingParser(string message) =>
        (_, _) => throw new Fido2FormatException(message);


    /// <summary>
    /// Encodes a <c>fido-u2f</c> <c>attStmt</c> CBOR map (<c>sig</c>/<c>x5c</c>) in the CTAP2 canonical CBOR
    /// encoding form, with <paramref name="x5cEntries"/>'s element count left under the caller's control —
    /// the building block for the <c>x5c</c>-element-count and trailing-bytes negative fixtures, deliberately
    /// independent of <see cref="Verifiable.Cbor.Fido2.FidoU2fAttestationStatementCborWriter"/>.
    /// </summary>
    /// <param name="sig">The attestation signature bytes.</param>
    /// <param name="x5cEntries">The certificate chain DER entries to embed in <c>x5c</c>, under the caller's count control.</param>
    /// <returns>The encoded <c>attStmt</c> bytes.</returns>
    internal static byte[] EncodeFidoU2fAttStmtRaw(byte[] sig, params byte[][] x5cEntries)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteTextString("sig");
        writer.WriteByteString(sig);
        writer.WriteTextString("x5c");
        writer.WriteStartArray(x5cEntries.Length);
        foreach(byte[] certificate in x5cEntries)
        {
            writer.WriteByteString(certificate);
        }

        writer.WriteEndArray();
        writer.WriteEndMap();

        return writer.Encode();
    }
}
