using System.Formats.Cbor;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Reader-level tests for <see cref="TpmAttestationStatementCborReader"/> — the shipped default for
/// <see cref="ParseTpmAttestationStatementDelegate"/>, decoding the <c>tpm</c> <c>attStmt</c> CBOR
/// map per <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">WebAuthn L3 section
/// 8.3</see>.
/// </summary>
/// <remarks>
/// Mirrors the reader-level battery <c>AndroidKeyAttestationStatementCborReaderTests.cs</c> runs
/// against <see cref="AndroidKeyAttestationStatementCborReader"/>, plus the two acceptance rules
/// unique to <c>tpm</c>'s CDDL: the literal <c>ver == "2.0"</c> requirement, and the two additional
/// mandatory byte-string members <c>certInfo</c>/<c>pubArea</c>.
/// </remarks>
[TestClass]
internal sealed class TpmAttestationStatementCborReaderTests
{
    /// <summary>A statement missing the required <c>ver</c> member is rejected.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAMissingVerMember()
    {
        byte[] cbor = EncodeTpmAttStmtRaw(ver: null, alg: -7, sig: [1], certInfo: [2], pubArea: [3], x5cEntries: [[9]]);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => TpmAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("ver", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A statement whose <c>ver</c> is not the literal <c>"2.0"</c> is rejected.</summary>
    [TestMethod]
    public void StatementDefaultRejectsANonTwoPointZeroVersion()
    {
        byte[] cbor = EncodeTpmAttStmtRaw(ver: "1.0", alg: -7, sig: [1], certInfo: [2], pubArea: [3], x5cEntries: [[9]]);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => TpmAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("'2.0'", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A statement missing the required <c>alg</c> member is rejected.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAMissingAlgMember()
    {
        byte[] cbor = EncodeTpmAttStmtRaw(ver: "2.0", alg: null, sig: [1], certInfo: [2], pubArea: [3], x5cEntries: [[9]]);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => TpmAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("alg", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A statement missing the required <c>sig</c> member is rejected.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAMissingSigMember()
    {
        byte[] cbor = EncodeTpmAttStmtRaw(ver: "2.0", alg: -7, sig: null, certInfo: [2], pubArea: [3], x5cEntries: [[9]]);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => TpmAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("sig", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A statement missing the required <c>certInfo</c> member is rejected.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAMissingCertInfoMember()
    {
        byte[] cbor = EncodeTpmAttStmtRaw(ver: "2.0", alg: -7, sig: [1], certInfo: null, pubArea: [3], x5cEntries: [[9]]);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => TpmAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("certInfo", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A statement missing the required <c>pubArea</c> member is rejected.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAMissingPubAreaMember()
    {
        byte[] cbor = EncodeTpmAttStmtRaw(ver: "2.0", alg: -7, sig: [1], certInfo: [2], pubArea: null, x5cEntries: [[9]]);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => TpmAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("pubArea", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A statement missing the required <c>x5c</c> member is rejected — the tpm format has no
    /// self-attestation branch, so <c>x5c</c> is always required on the wire.
    /// </summary>
    [TestMethod]
    public void StatementDefaultRejectsAMissingX5cMember()
    {
        byte[] cbor = EncodeTpmAttStmtRaw(ver: "2.0", alg: -7, sig: [1], certInfo: [2], pubArea: [3], x5cEntries: null);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => TpmAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("x5c", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A statement carrying an unrecognised member is rejected.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAnUnrecognisedMember()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteTextString("foo");
        writer.WriteBoolean(true);
        writer.WriteTextString("ver");
        writer.WriteTextString("2.0");
        writer.WriteEndMap();
        byte[] cbor = writer.Encode();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => TpmAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("foo", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A byte trailing an otherwise-valid statement map is rejected.</summary>
    [TestMethod]
    public void StatementDefaultRejectsTrailingBytes()
    {
        byte[] valid = EncodeTpmAttStmtRaw(ver: "2.0", alg: -7, sig: [1], certInfo: [2], pubArea: [3], x5cEntries: [[9]]);
        byte[] withTrailingByte = [.. valid, 0xFF];

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => TpmAttestationStatementCborReader.Parse(withTrailingByte, BaseMemoryPool.Shared));

        Assert.Contains("trailing", exception.Message, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>The shipped default reader parses a minted, conformant statement — the positive control for the reader alone.</summary>
    [TestMethod]
    public void StatementDefaultParsesAMintedStatement()
    {
        byte[] sig = [1, 2, 3];
        byte[] certInfo = [4, 5, 6, 7];
        byte[] pubArea = [8, 9];
        byte[] certificateBytes = [10, 11, 12];
        byte[] cbor = EncodeTpmAttStmtRaw(ver: "2.0", alg: -65535, sig: sig, certInfo: certInfo, pubArea: pubArea, x5cEntries: [certificateBytes]);

        TpmAttestationStatement statement = TpmAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared);
        try
        {
            Assert.AreEqual(-65535, statement.Alg);
            Assert.IsTrue(statement.Signature.Span.SequenceEqual(sig));
            Assert.IsTrue(statement.CertInfo.Span.SequenceEqual(certInfo));
            Assert.IsTrue(statement.PubArea.Span.SequenceEqual(pubArea));
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
    /// Encodes a tpm <c>attStmt</c> CBOR map (<c>ver</c>/<c>alg</c>/<c>x5c</c>/<c>sig</c>/<c>certInfo</c>/<c>pubArea</c>)
    /// in the CTAP2 canonical CBOR encoding form, omitting any member whose argument is
    /// <see langword="null"/> — the building block for both the positive vector and every
    /// missing-member negative fixture. Member insertion order matches CTAP2 canonical ordering for
    /// these six keys by length-then-bytewise ordinal: "alg"(3), "sig"(3), "ver"(3), "x5c"(3),
    /// "certInfo"(8), "pubArea"(7) — three-letter keys sort "alg" &lt; "sig" &lt; "ver" &lt; "x5c"
    /// bytewise, then "pubArea"(7) before "certInfo"(8) by length.
    /// </summary>
    /// <param name="ver">The <c>ver</c> member's value, or <see langword="null"/> to omit the member.</param>
    /// <param name="alg">The <c>alg</c> member's value, or <see langword="null"/> to omit the member.</param>
    /// <param name="sig">The <c>sig</c> member's bytes, or <see langword="null"/> to omit the member.</param>
    /// <param name="certInfo">The <c>certInfo</c> member's bytes, or <see langword="null"/> to omit the member.</param>
    /// <param name="pubArea">The <c>pubArea</c> member's bytes, or <see langword="null"/> to omit the member.</param>
    /// <param name="x5cEntries">The <c>x5c</c> member's certificate entries, or <see langword="null"/> to omit the member.</param>
    /// <returns>The encoded <c>attStmt</c> CBOR bytes.</returns>
    private static byte[] EncodeTpmAttStmtRaw(string? ver, int? alg, byte[]? sig, byte[]? certInfo, byte[]? pubArea, byte[][]? x5cEntries)
    {
        int memberCount = (alg is not null ? 1 : 0) + (sig is not null ? 1 : 0) + (ver is not null ? 1 : 0)
            + (x5cEntries is not null ? 1 : 0) + (pubArea is not null ? 1 : 0) + (certInfo is not null ? 1 : 0);
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

        if(ver is not null)
        {
            writer.WriteTextString("ver");
            writer.WriteTextString(ver);
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

        if(pubArea is not null)
        {
            writer.WriteTextString("pubArea");
            writer.WriteByteString(pubArea);
        }

        if(certInfo is not null)
        {
            writer.WriteTextString("certInfo");
            writer.WriteByteString(certInfo);
        }

        writer.WriteEndMap();

        return writer.Encode();
    }
}
