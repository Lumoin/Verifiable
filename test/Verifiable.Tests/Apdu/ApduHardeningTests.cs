using System;
using Lumoin.Base;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Adversarial hardening regression tests for the eMRTD parsers and the BER-TLV codec: each test is a malformed
/// chip byte sequence that previously crashed a parser with an undocumented exception type (a slice or index
/// out-of-range) or was silently accepted, together with the writer defect that truncated large lengths. The
/// contract these pin down is that malformed chip input is rejected with the parsers' documented
/// <see cref="InvalidOperationException"/> — never a raw <see cref="ArgumentOutOfRangeException"/> or
/// <see cref="IndexOutOfRangeException"/>, and never a silent success — and that the BER-TLV writer and reader
/// round-trip the long-form lengths that large biometrics and master lists need.
/// </summary>
[TestClass]
internal sealed class ApduHardeningTests
{
    /// <summary>
    /// A data-group template that declares more body than the buffer holds is rejected with the documented
    /// exception, not a raw out-of-range from the unchecked slice the length flowed into. The two-byte inputs are
    /// a tag and a short-form length of 0x7F (127) with no content.
    /// </summary>
    [TestMethod]
    public void RejectsTruncatedDataGroup1() =>
        Assert.ThrowsExactly<InvalidOperationException>(() => DataGroup1.Parse(Convert.FromHexString("617F")));


    /// <summary>The EF.COM truncation twin of <see cref="RejectsTruncatedDataGroup1"/>.</summary>
    [TestMethod]
    public void RejectsTruncatedEfCom() =>
        Assert.ThrowsExactly<InvalidOperationException>(() => EfCom.Parse(Convert.FromHexString("607F")));


    /// <summary>
    /// A single tag byte with no length or content (the smallest possible truncation) is rejected cleanly by the
    /// signed-content LDS Security Object parser rather than crashing with an index out-of-range.
    /// </summary>
    [TestMethod]
    public void RejectsTruncatedLdsSecurityObject() =>
        Assert.ThrowsExactly<InvalidOperationException>(() => LdsSecurityObject.Parse(Convert.FromHexString("30"), BaseMemoryPool.Shared));


    /// <summary>
    /// A CBEFF biometric data block whose declared length is near <see cref="int.MaxValue"/> is rejected. Added to
    /// the block's offset it would overflow int to a negative value that slips past the block's own bounds guard;
    /// the length is instead rejected where it is read, before it can reach a slice.
    /// </summary>
    [TestMethod]
    public void RejectsCbeffBiometricBlockLengthThatOverflows() =>
        Assert.ThrowsExactly<InvalidOperationException>(() =>
            DataGroup2.Parse(Convert.FromHexString("75157F61120201017F600CA1038001005F2E847FFFFFF0"), BaseMemoryPool.Shared));


    /// <summary>
    /// A DG2 facial record truncated before its facial information block is rejected. The header check passed and
    /// the following fixed-offset reads (a 32-bit block length, a feature-point count) previously ran off the end
    /// with a raw out-of-range; a length guard now rejects it cleanly.
    /// </summary>
    [TestMethod]
    public void RejectsDataGroup2FacialRecordTruncatedBeforeItsInformationBlock() =>
        Assert.ThrowsExactly<InvalidOperationException>(() =>
            DataGroup2.Parse(Convert.FromHexString("75207F611D0201017F6017A1038001005F2E0F46414300303130000000000F000100"), BaseMemoryPool.Shared));


    /// <summary>
    /// A DG15 SubjectPublicKeyInfo whose AlgorithmIdentifier carries only the id-ecPublicKey OID with no domain
    /// parameters is rejected: peeking the (absent) parameter tag previously crashed with a raw out-of-range.
    /// </summary>
    [TestMethod]
    public void RejectsDataGroup15WithEmptyEllipticCurveParameters() =>
        Assert.ThrowsExactly<InvalidOperationException>(() =>
            DataGroup15.Parse(Convert.FromHexString("6F0D300B300906072A8648CE3D0201"), BaseMemoryPool.Shared));


    /// <summary>
    /// An LDS Security Object whose data-group-hash SEQUENCE declares a near-<see cref="int.MaxValue"/> length while
    /// supplying no entries is rejected, not silently accepted. Computed as an int end marker the length overflowed
    /// negative, so the entry loop was skipped and the parser returned an empty (but "successful") result.
    /// </summary>
    [TestMethod]
    public void RejectsLdsSecurityObjectListLengthThatOverflows() =>
        Assert.ThrowsExactly<InvalidOperationException>(() =>
            LdsSecurityObject.Parse(Convert.FromHexString("3016020100300B060960864801650304020130847FFFFFF0"), BaseMemoryPool.Shared));


    /// <summary>
    /// A content length that exceeds 64 KiB round-trips through the writer's and reader's long-form length codecs.
    /// The writer previously stopped at the two-byte form, silently emitting the low 16 bits of the length while a
    /// large biometric or master list wrote its full content — a corrupt, self-desynchronising structure.
    /// </summary>
    [TestMethod]
    [DataRow(70000)]
    [DataRow(0x1000000)]
    public void WriterAndReaderRoundTripLongFormLengthsAboveTwoBytes(int length)
    {
        Span<byte> buffer = stackalloc byte[5];
        var writer = new BerTlvWriter(buffer);
        writer.WriteLength(length);
        int written = writer.Written;

        Assert.AreEqual(BerTlvWriter.LengthFieldSize(length), written, "The bytes written must match LengthFieldSize.");

        var reader = new ApduReader(buffer[..written]);
        int decoded = reader.ReadTlvLength();

        Assert.AreEqual(length, decoded, "A large content length must round-trip through the long-form length codec.");
    }


    /// <summary>
    /// Reading more bytes than remain is rejected with the reader's documented exception, not a raw out-of-range
    /// from the underlying span slice — the foundation every LDS parser's truncation rejection rests on.
    /// </summary>
    [TestMethod]
    public void ReaderRejectsReadingPastTheBuffer() =>
        Assert.ThrowsExactly<InvalidOperationException>(ReadThreeBytesFromTwo);


    //A ref struct cannot be captured by the assertion lambda, so the read runs in a helper the lambda calls.
    private static void ReadThreeBytesFromTwo()
    {
        var reader = new ApduReader(Convert.FromHexString("0102"));
        _ = reader.ReadBytes(3);
    }
}
