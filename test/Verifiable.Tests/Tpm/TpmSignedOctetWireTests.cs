using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The wire's signed-octet primitives, <see cref="TpmWriter.WriteInt8"/> and <see cref="TpmReader.ReadInt8"/>:
/// an <c>INT8</c> occupies exactly one octet and carries its value in two's complement, so the negative half of
/// <c>TPM_CLOCK_ADJUST</c>'s range — the first signed scalar this wire carries — frames as <c>FD</c>, <c>FE</c>
/// and <c>FF</c> rather than as a widened or sign-extended field. Every one of Table 19's seven values and both
/// extremes of the type round trip byte-exactly.
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19</see>.
/// </summary>
[TestClass]
internal sealed class TpmSignedOctetWireTests
{
    /// <summary>
    /// "Table 19: Definition of (INT8) TPM_CLOCK_ADJUST Constants" — each of the seven defined steps occupies a
    /// single octet whose bit pattern is the value's two's complement encoding, and reading that octet back
    /// recovers the original value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    /// <param name="value">The Table 19 value under test.</param>
    /// <param name="expectedOctet">The single octet the value's two's complement encoding occupies.</param>
    [TestMethod]
    [DataRow((sbyte)(-3), (byte)0xFD, DisplayName = "TPM_CLOCK_COARSE_SLOWER (-3) frames as FD")]
    [DataRow((sbyte)(-2), (byte)0xFE, DisplayName = "TPM_CLOCK_MEDIUM_SLOWER (-2) frames as FE")]
    [DataRow((sbyte)(-1), (byte)0xFF, DisplayName = "TPM_CLOCK_FINE_SLOWER (-1) frames as FF")]
    [DataRow((sbyte)0, (byte)0x00, DisplayName = "TPM_CLOCK_NO_CHANGE (0) frames as 00")]
    [DataRow((sbyte)1, (byte)0x01, DisplayName = "TPM_CLOCK_FINE_FASTER (1) frames as 01")]
    [DataRow((sbyte)2, (byte)0x02, DisplayName = "TPM_CLOCK_MEDIUM_FASTER (2) frames as 02")]
    [DataRow((sbyte)3, (byte)0x03, DisplayName = "TPM_CLOCK_COARSE_FASTER (3) frames as 03")]
    public void SignedOctetRoundTripsEveryTable19ValueByteExactly(sbyte value, byte expectedOctet)
    {
        AssertRoundTrip(value, expectedOctet);
    }

    /// <summary>
    /// The extremes of the <c>INT8</c> type itself: <c>-128</c> is <c>0x80</c> and <c>127</c> is <c>0x7F</c> in
    /// two's complement, the boundary values that would expose a sign-extension or an unsigned-cast defect in a
    /// primitive that widened the field or clamped it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    /// <param name="value">The extreme value under test.</param>
    /// <param name="expectedOctet">The single octet the value's two's complement encoding occupies.</param>
    [TestMethod]
    [DataRow((sbyte)(-128), (byte)0x80, DisplayName = "the most negative INT8 frames as 80")]
    [DataRow((sbyte)127, (byte)0x7F, DisplayName = "the most positive INT8 frames as 7F")]
    public void SignedOctetRoundTripsTheIntegerExtremesByteExactly(sbyte value, byte expectedOctet)
    {
        AssertRoundTrip(value, expectedOctet);
    }

    /// <summary>
    /// The writer advances by exactly one octet and the reader consumes exactly one, leaving whatever follows
    /// untouched: an <c>INT8</c> parameter is a single-octet field, so a neighbouring octet written after it
    /// must survive the round trip unchanged.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    [TestMethod]
    public void SignedOctetConsumesExactlyOneOctetAndLeavesItsNeighbourUntouched()
    {
        byte[] buffer = new byte[2];
        var writer = new TpmWriter(buffer);
        writer.WriteInt8(-3);
        writer.WriteInt8(127);

        Assert.AreEqual(2, writer.Written, "Two INT8 fields occupy exactly two octets.");
        Assert.AreSequenceEqual(new byte[] { 0xFD, 0x7F }, buffer);

        var reader = new TpmReader(buffer);
        Assert.AreEqual((sbyte)(-3), reader.ReadInt8(), "The first octet decodes to its own value alone.");
        Assert.AreEqual(1, reader.Consumed, "Reading an INT8 consumes exactly one octet.");
        Assert.AreEqual((sbyte)127, reader.ReadInt8(), "The neighbouring octet is unaffected by the first read.");
        Assert.AreEqual(0, reader.Remaining, "Both octets are consumed and nothing remains.");
    }

    /// <summary>
    /// The enum the wire carries is itself declared over <c>sbyte</c>, so a <c>TPM_CLOCK_ADJUST</c> value casts
    /// to the octet the writer emits with no widening step in between: writing the cast enum reproduces the
    /// same octet as writing the raw <c>INT8</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    [TestMethod]
    public void SignedOctetFramesTheClockAdjustEnumThroughItsUnderlyingSignedOctet()
    {
        byte[] buffer = new byte[1];
        var writer = new TpmWriter(buffer);
        writer.WriteInt8((sbyte)TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER);

        Assert.AreSequenceEqual(new byte[] { 0xFD }, buffer, "TPM_CLOCK_COARSE_SLOWER is -3, whose two's complement octet is FD.");

        var reader = new TpmReader(buffer);
        Assert.AreEqual(TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, (TpmClockAdjustConstants)reader.ReadInt8(),
            "The octet read back reconstructs the same Table 19 member.");
    }

    /// <summary>
    /// Writes <paramref name="value"/> as a single <c>INT8</c>, asserts the emitted octet is exactly
    /// <paramref name="expectedOctet"/>, and asserts reading that octet back recovers
    /// <paramref name="value"/> — the two directions of the same two's complement encoding.
    /// </summary>
    /// <param name="value">The value to frame.</param>
    /// <param name="expectedOctet">The octet the value's two's complement encoding occupies.</param>
    private static void AssertRoundTrip(sbyte value, byte expectedOctet)
    {
        byte[] buffer = new byte[1];
        var writer = new TpmWriter(buffer);
        writer.WriteInt8(value);

        Assert.AreEqual(1, writer.Written, "An INT8 occupies exactly one octet on the wire.");
        Assert.AreSequenceEqual(new byte[] { expectedOctet }, buffer, $"'{value}' must frame as its two's complement octet.");

        var reader = new TpmReader(buffer);
        sbyte roundTripped = reader.ReadInt8();

        Assert.AreEqual(value, roundTripped, "Reading the octet back must recover the written value exactly.");
        Assert.AreEqual(1, reader.Consumed, "Reading an INT8 consumes exactly one octet.");
    }
}
