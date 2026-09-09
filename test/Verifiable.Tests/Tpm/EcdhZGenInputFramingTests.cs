using System;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <c>TPM2_ECDH_ZGen()</c>'s command and response against their published tables (TPM 2.0
/// Library Part 3, clause 14.5.2, Tables 50 and 51) through <see cref="Tpm2bEccPoint"/> — the raw <c>TPM_CC</c>
/// pin, <see cref="EcdhZGenInput.FromUncompressedPoint"/>'s SEC1 split, and <see cref="EcdhZGenResponse.Parse"/>'s
/// own refusal of a zero or an inconsistent outer size (Part 2, clause 11.2.5.3, Table 199) — beside
/// <see cref="LoadExternalInputFramingTests"/>'s framing-class shape.
/// </summary>
[TestClass]
internal sealed class EcdhZGenInputFramingTests
{
    /// <summary>The P-256 coordinate length in bytes.</summary>
    private const int P256CoordinateLength = 32;

    /// <summary>A fixed, non-zero handle value naming an ECC key, for framing purposes only.</summary>
    private const uint KeyHandleValue = 0x8000_0001;

    /// <summary>
    /// "TPM2B_ECC_POINT inPoint" (TPM 2.0 Library Part 3, clause 14.5.2, Table 50): the command area is
    /// <c>keyHandle</c> (TPMI_DH_OBJECT, four octets) followed by <c>inPoint</c> framed through
    /// <see cref="Tpm2bEccPoint"/> — the outer size then the two TPM2B-prefixed coordinates — and
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for exactly those octets.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.5.2, Table 50</see>.
    /// </summary>
    [TestMethod]
    public void EcdhZGenInputFramesTheCommandAreaByteExactlyPerTable50()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> x = stackalloc byte[P256CoordinateLength];
        Span<byte> y = stackalloc byte[P256CoordinateLength];
        x.Fill(0x55);
        y.Fill(0x66);

        using EcdhZGenInput input = EcdhZGenInput.Create(TpmiDhObject.FromValue(KeyHandleValue), x, y, pool);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x01];
        byte[] expectedParameters =
        [
            0x00, (byte)(sizeof(ushort) + P256CoordinateLength + sizeof(ushort) + P256CoordinateLength),
            0x00, (byte)P256CoordinateLength, .. x.ToArray(),
            0x00, (byte)P256CoordinateLength, .. y.ToArray()
        ];

        Assert.AreEqual(expectedHandles.Length + expectedParameters.Length, input.GetSerializedSize(), "GetSerializedSize must account for the four-octet keyHandle plus the framed TPM2B_ECC_POINT inPoint.");

        byte[] handles = new byte[expectedHandles.Length];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreSequenceEqual(expectedHandles, handles, "WriteHandles must write exactly the four-octet keyHandle.");

        byte[] parameters = new byte[expectedParameters.Length];
        var parameterWriter = new TpmWriter(parameters);
        input.WriteParameters(ref parameterWriter);
        Assert.AreSequenceEqual(expectedParameters, parameters, "WriteParameters must reproduce the hand-computed TPM2B_ECC_POINT octets exactly.");
    }

    /// <summary>
    /// "TPM_CC_ECDH_ZGen" (TPM 2.0 Library Part 3, clause 14.5.2, Table 50) names the command's raw code, whose
    /// assigned value in Part 2's command-code listing is 0x00000154.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.5.2, Table 50</see>.
    /// </summary>
    [TestMethod]
    public void EcdhZGenInputCommandCodeEqualsTheRawValueForEcdhZGen()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using EcdhZGenInput input = EcdhZGenInput.Create(TpmiDhObject.FromValue(KeyHandleValue), stackalloc byte[P256CoordinateLength], stackalloc byte[P256CoordinateLength], pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_ECDH_ZGen, input.CommandCode, "CommandCode must be TPM_CC_ECDH_ZGen (Part 3, clause 14.5.2, Table 50).");
        Assert.AreEqual(0x00000154u, (uint)input.CommandCode, "TPM_CC_ECDH_ZGen must equal the assigned raw value 0x00000154.");
    }

    /// <summary>
    /// <see cref="EcdhZGenInput.FromUncompressedPoint"/> splits a SEC1 uncompressed point (<c>0x04 ‖ X ‖ Y</c>)
    /// into the same two coordinates <see cref="EcdhZGenInput.Create"/> takes directly — the point-splitting
    /// convenience overload must frame identically to its coordinate-pair counterpart.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.5.2, Table 50</see>.
    /// </summary>
    [TestMethod]
    public void FromUncompressedPointSplitsTheSec1PointIntoTheSameFramingAsCreate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> x = stackalloc byte[P256CoordinateLength];
        Span<byte> y = stackalloc byte[P256CoordinateLength];
        x.Fill(0x77);
        y.Fill(0x88);
        byte[] sec1Point = [0x04, .. x.ToArray(), .. y.ToArray()];

        using EcdhZGenInput fromPoint = EcdhZGenInput.FromUncompressedPoint(TpmiDhObject.FromValue(KeyHandleValue), sec1Point, pool);
        using EcdhZGenInput fromCoordinates = EcdhZGenInput.Create(TpmiDhObject.FromValue(KeyHandleValue), x, y, pool);

        byte[] framedFromPoint = new byte[fromPoint.GetSerializedSize()];
        var pointWriter = new TpmWriter(framedFromPoint);
        fromPoint.WriteHandles(ref pointWriter);
        fromPoint.WriteParameters(ref pointWriter);

        byte[] framedFromCoordinates = new byte[fromCoordinates.GetSerializedSize()];
        var coordinateWriter = new TpmWriter(framedFromCoordinates);
        fromCoordinates.WriteHandles(ref coordinateWriter);
        fromCoordinates.WriteParameters(ref coordinateWriter);

        Assert.AreSequenceEqual(framedFromCoordinates, framedFromPoint, "Splitting a SEC1 point must frame identically to supplying the same coordinates directly.");
    }

    /// <summary>
    /// "TPM2B_ECC_POINT outPoint" (TPM 2.0 Library Part 3, clause 14.5.2, Table 51): <see cref="EcdhZGenResponse.Parse"/>
    /// reads a hand-built <c>TPM2B_ECC_POINT</c> response through <see cref="Tpm2bEccPoint"/>, leaving both
    /// coordinates readable via <see cref="EcdhZGenResponse.OutPointX"/>/<see cref="EcdhZGenResponse.OutPointY"/>,
    /// and <see cref="EcdhZGenResponse.Dispose"/> releases the coordinate rentals it took.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.5.2, Table 51</see>.
    /// </summary>
    [TestMethod]
    public void EcdhZGenResponseParsesTheOutPointAndDisposeReleasesItsRentalsThroughAMeteredPool()
    {
        Span<byte> x = stackalloc byte[P256CoordinateLength];
        Span<byte> y = stackalloc byte[P256CoordinateLength];
        x.Fill(0x99);
        y.Fill(0xAA);
        byte[] wire =
        [
            0x00, (byte)(sizeof(ushort) + P256CoordinateLength + sizeof(ushort) + P256CoordinateLength),
            0x00, (byte)P256CoordinateLength, .. x.ToArray(),
            0x00, (byte)P256CoordinateLength, .. y.ToArray()
        ];

        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        EcdhZGenResponse response = EcdhZGenResponse.Parse(ref reader, trackingPool.Pool);
        Assert.AreEqual(0, reader.Remaining, "The whole TPM2B_ECC_POINT frame must be consumed.");
        Assert.AreSequenceEqual(x.ToArray(), response.OutPointX.AsReadOnlySpan().ToArray(), "OutPointX must read the parsed X coordinate.");
        Assert.AreSequenceEqual(y.ToArray(), response.OutPointY.AsReadOnlySpan().ToArray(), "OutPointY must read the parsed Y coordinate.");
        Assert.AreNotEqual(baseline, trackingPool.OutstandingCount, "Parsing must have rented storage for the two coordinates.");

        response.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the response must release both coordinate rentals.");
    }

    /// <summary>
    /// <see cref="EcdhZGenResponse.Parse"/> rides <see cref="Tpm2bEccPoint.Parse"/>, so a declared outer
    /// <c>size</c> of zero is refused before either coordinate is parsed — "if size is zero, then the required
    /// structure is missing" (Part 4's <c>TPM2B_ECC_POINT_Unmarshal</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.5.3, Table 199</see>.
    /// </summary>
    [TestMethod]
    public void EcdhZGenResponseParseRefusesAZeroOuterSize()
    {
        byte[] wire = [0x00, 0x00];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = EcdhZGenResponse.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A zero outer size is refused before any coordinate rental.");
    }

    /// <summary>
    /// <see cref="EcdhZGenResponse.Parse"/> rides <see cref="Tpm2bEccPoint.Parse"/>'s outer-size consistency
    /// check (Part 4's <c>target-&gt;size != (startSize - *size)</c>) — a declared size that does not equal the
    /// octets the inner <c>TPMS_ECC_POINT</c> actually consumed is refused, and the already-parsed coordinates
    /// are released rather than leaked.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.5.3, Table 199</see>.
    /// </summary>
    [TestMethod]
    public void EcdhZGenResponseParseRefusesAnInconsistentOuterSize()
    {
        //Two 1-octet coordinates consume 6 octets, but the outer size declares 5.
        byte[] wire = [0x00, 0x05, 0x00, 0x01, 0xAA, 0x00, 0x01, 0xBB];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = EcdhZGenResponse.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The already-parsed coordinates must be disposed before the consistency refusal propagates.");
    }
}
