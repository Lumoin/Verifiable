using System.Formats.Cbor;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Reader-level tests for <see cref="AndroidKeyAttestationStatementCborReader"/> — the shipped default
/// for <see cref="ParseAndroidKeyAttestationStatementDelegate"/>, decoding the <c>android-key</c>
/// <c>attStmt</c> CBOR map per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">WebAuthn L3 section 8.4</see>.
/// </summary>
/// <remarks>
/// Before this file, this reader was exercised only through the full <see cref="AndroidKeyAttestation"/>
/// verifier composition in <c>AndroidKeyAttestationTests.cs</c>, always with well-formed statements — the
/// only per-format statement reader in the suite with zero direct unit tests. These tests port the
/// reader-level battery <c>FidoU2fAttestationTests.cs</c> already runs against
/// <see cref="FidoU2fAttestationStatementCborReader"/> onto this reader, plus one case
/// <c>fido-u2f</c> has no equivalent of: an empty <c>x5c</c> array decodes successfully here (android-key
/// has no minimum-element-count rule, unlike <c>fido-u2f</c>'s exactly-one-element requirement) — the
/// codec-level half of the type's own doc remark, which <see cref="AndroidKeyAttestation"/>'s
/// verification procedure, not this codec, rejects.
/// </remarks>
[TestClass]
internal sealed class AndroidKeyAttestationStatementCborReaderTests
{
    /// <summary>A statement missing the required <c>alg</c> member is rejected by the shipped default reader.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAMissingAlgMember()
    {
        byte[] cbor = EncodeAndroidKeyAttStmtRaw(alg: null, sig: [1, 2, 3], x5cEntries: [[9, 9, 9]]);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => AndroidKeyAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("alg", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A statement missing the required <c>sig</c> member is rejected by the shipped default reader.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAMissingSigMember()
    {
        byte[] cbor = EncodeAndroidKeyAttStmtRaw(alg: -7, sig: null, x5cEntries: [[9, 9, 9]]);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => AndroidKeyAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("sig", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A statement missing the required <c>x5c</c> member is rejected by the shipped default reader —
    /// the clause that makes <c>android-key</c> structurally different from <c>packed</c>'s
    /// self-attestation branch (section 8.4: android-key has no self-attestation branch, so <c>x5c</c>
    /// is always required on the wire).
    /// </summary>
    [TestMethod]
    public void StatementDefaultRejectsAMissingX5cMember()
    {
        byte[] cbor = EncodeAndroidKeyAttStmtRaw(alg: -7, sig: [1, 2, 3], x5cEntries: null);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => AndroidKeyAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("x5c", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// An <c>x5c</c> array with zero elements decodes successfully — unlike <c>fido-u2f</c>'s
    /// exactly-one-element rule, the android-key codec itself imposes no minimum element count (the
    /// type's own doc remark); a non-empty <c>x5c</c> is <see cref="AndroidKeyAttestation"/>'s
    /// verification-procedure concern, not this codec's.
    /// </summary>
    [TestMethod]
    public void StatementDefaultAcceptsAnEmptyX5cArray()
    {
        byte[] signature = [1, 2, 3];
        byte[] cbor = EncodeAndroidKeyAttStmtRaw(alg: -7, sig: signature, x5cEntries: []);

        AndroidKeyAttestationStatement statement = AndroidKeyAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared);

        Assert.AreEqual(-7, statement.Alg);
        Assert.IsTrue(statement.Signature.Span.SequenceEqual(signature));
        Assert.HasCount(0, statement.X5c);
    }


    /// <summary>A statement carrying an unrecognised member is rejected by the shipped default reader.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAnUnrecognisedMember()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(4);
        writer.WriteTextString("alg");
        writer.WriteInt32(-7);
        writer.WriteTextString("foo");
        writer.WriteBoolean(true);
        writer.WriteTextString("sig");
        writer.WriteByteString([1, 2, 3]);
        writer.WriteTextString("x5c");
        writer.WriteStartArray(1);
        writer.WriteByteString([9, 9, 9]);
        writer.WriteEndArray();
        writer.WriteEndMap();
        byte[] cbor = writer.Encode();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => AndroidKeyAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("foo", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A byte trailing an otherwise-valid statement map is rejected by the shipped default reader.</summary>
    [TestMethod]
    public void StatementDefaultRejectsTrailingBytes()
    {
        byte[] valid = EncodeAndroidKeyAttStmtRaw(alg: -7, sig: [1, 2, 3], x5cEntries: [[9, 9, 9]]);
        byte[] withTrailingByte = [.. valid, 0xFF];

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => AndroidKeyAttestationStatementCborReader.Parse(withTrailingByte, BaseMemoryPool.Shared));

        Assert.Contains("trailing", exception.Message, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>The shipped default reader parses a minted, conformant statement — the positive control for the reader alone.</summary>
    [TestMethod]
    public void StatementDefaultParsesAMintedStatement()
    {
        byte[] signature = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[] certificateBytes = [9, 8, 7, 6, 5];
        byte[] cbor = EncodeAndroidKeyAttStmtRaw(alg: -7, sig: signature, x5cEntries: [certificateBytes]);

        AndroidKeyAttestationStatement statement = AndroidKeyAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared);
        try
        {
            Assert.AreEqual(-7, statement.Alg);
            Assert.IsTrue(statement.Signature.Span.SequenceEqual(signature));
            Assert.HasCount(1, statement.X5c);
            Assert.IsTrue(statement.X5c[0].IsX509Certificate);
            Assert.IsTrue(statement.X5c[0].AsReadOnlySpan().SequenceEqual(certificateBytes));
        }
        finally
        {
            foreach(PkiCertificateMemory certificate in statement.X5c)
            {
                certificate.Dispose();
            }
        }
    }


    /// <summary>
    /// Encodes an android-key <c>attStmt</c> CBOR map (<c>alg</c>/<c>sig</c>/<c>x5c</c>) in the CTAP2
    /// canonical CBOR encoding form, omitting any member whose argument is <see langword="null"/> —
    /// the building block for both the positive vectors and the missing-member negative fixtures.
    /// Member insertion order (<c>alg</c>, <c>sig</c>, <c>x5c</c>) is already the CTAP2 canonical
    /// ordering for these three equal-length keys, so any subset remains canonically ordered.
    /// </summary>
    /// <param name="alg">The <c>alg</c> value, or <see langword="null"/> to omit the member.</param>
    /// <param name="sig">The <c>sig</c> value, or <see langword="null"/> to omit the member.</param>
    /// <param name="x5cEntries">The <c>x5c</c> array's DER entries, or <see langword="null"/> to omit the member (an empty array is a present, zero-element member).</param>
    /// <returns>The encoded CBOR bytes.</returns>
    private static byte[] EncodeAndroidKeyAttStmtRaw(int? alg, byte[]? sig, byte[][]? x5cEntries)
    {
        int memberCount = (alg is not null ? 1 : 0) + (sig is not null ? 1 : 0) + (x5cEntries is not null ? 1 : 0);
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(memberCount);

        if(alg is not null)
        {
            writer.WriteTextString("alg");
            writer.WriteInt32(alg.Value);
        }

        if(sig is not null)
        {
            writer.WriteTextString("sig");
            writer.WriteByteString(sig);
        }

        if(x5cEntries is not null)
        {
            writer.WriteTextString("x5c");
            writer.WriteStartArray(x5cEntries.Length);
            foreach(byte[] certificate in x5cEntries)
            {
                writer.WriteByteString(certificate);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndMap();

        return writer.Encode();
    }
}
