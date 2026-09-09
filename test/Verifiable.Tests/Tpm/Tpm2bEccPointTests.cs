using System;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proving tests for <see cref="Tpm2bEccPoint"/> (TPM2B_ECC_POINT, TPM 2.0 Library Part 2, clause 11.2.5.3,
/// Table 199): the byte-exact round trip, the zero-outer-size refusal, the inconsistent-outer-size refusal, and
/// the <see cref="Tpm2bEccPoint.Empty"/> sentinel — beside <see cref="TpmtPublicEccKeyTests"/>'s coverage of the
/// point's <c>TPMT_PUBLIC</c>-embedded (unsized) form.
/// </summary>
[TestClass]
internal sealed class Tpm2bEccPointTests
{
    /// <summary>The P-256 coordinate length in bytes.</summary>
    private const int P256CoordinateLength = 32;

    /// <summary>The P-384 coordinate length in bytes.</summary>
    private const int P384CoordinateLength = 48;

    /// <summary>
    /// <c>Create</c>/<c>WriteTo</c>/<c>Parse</c> round-trip byte-identically: the outer <c>size</c> equals the
    /// inner <c>TPMS_ECC_POINT</c>'s own serialized size (two <c>TPM2B_ECC_PARAMETER</c> coordinates), and both
    /// coordinates survive unchanged.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.5.2, Table 198</see>.
    /// </summary>
    [TestMethod]
    public void CreateWriteToParseRoundTripsByteIdentically()
    {
        Span<byte> x = stackalloc byte[P256CoordinateLength];
        Span<byte> y = stackalloc byte[P256CoordinateLength];
        x.Fill(0x11);
        y.Fill(0x22);

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bEccPoint point = Tpm2bEccPoint.Create(x, y, pool);

        int expectedSize = sizeof(ushort) + sizeof(ushort) + P256CoordinateLength + sizeof(ushort) + P256CoordinateLength;
        Assert.AreEqual(expectedSize, point.SerializedSize, "The outer size field plus the two TPM2B_ECC_PARAMETER coordinates.");

        byte[] wire = new byte[point.SerializedSize];
        var writer = new TpmWriter(wire);
        point.WriteTo(ref writer);

        var reader = new TpmReader(wire);
        using Tpm2bEccPoint parsed = Tpm2bEccPoint.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, "The whole frame must be consumed.");
        Assert.AreSequenceEqual(x.ToArray(), parsed.Point.X.AsReadOnlySpan().ToArray(), "The X coordinate must survive the round trip.");
        Assert.AreSequenceEqual(y.ToArray(), parsed.Point.Y.AsReadOnlySpan().ToArray(), "The Y coordinate must survive the round trip.");
    }

    /// <summary>
    /// <c>Create</c>/<c>WriteTo</c>/<c>Parse</c> round-trip byte-identically for a P-384 point (48-octet
    /// coordinates, the widest of the two curves this house implements) through a metered pool — confirming both
    /// coordinate rentals a P-384 round trip needs are returned once the parsed and the source points are
    /// disposed, not merely that the wider coordinates read back correctly.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.5.1, Table 197</see>.
    /// </summary>
    [TestMethod]
    public void CreateWriteToParseRoundTripsByteIdenticallyForP384CoordinatesThroughAMeteredPool()
    {
        Span<byte> x = stackalloc byte[P384CoordinateLength];
        Span<byte> y = stackalloc byte[P384CoordinateLength];
        x.Fill(0x33);
        y.Fill(0x44);

        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        using(Tpm2bEccPoint point = Tpm2bEccPoint.Create(x, y, trackingPool.Pool))
        {
            int expectedSize = sizeof(ushort) + sizeof(ushort) + P384CoordinateLength + sizeof(ushort) + P384CoordinateLength;
            Assert.AreEqual(expectedSize, point.SerializedSize, "The outer size field plus the two P-384 TPM2B_ECC_PARAMETER coordinates.");

            byte[] wire = new byte[point.SerializedSize];
            var writer = new TpmWriter(wire);
            point.WriteTo(ref writer);

            var reader = new TpmReader(wire);
            using Tpm2bEccPoint parsed = Tpm2bEccPoint.Parse(ref reader, trackingPool.Pool);

            Assert.AreEqual(0, reader.Remaining, "The whole frame must be consumed.");
            Assert.AreSequenceEqual(x.ToArray(), parsed.Point.X.AsReadOnlySpan().ToArray(), "The P-384 X coordinate must survive the round trip.");
            Assert.AreSequenceEqual(y.ToArray(), parsed.Point.Y.AsReadOnlySpan().ToArray(), "The P-384 Y coordinate must survive the round trip.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Every coordinate rental the round trip took (source point and parsed point, X and Y each) must be returned.");
    }

    /// <summary>
    /// Part 4's <c>TPM2B_ECC_POINT_Unmarshal</c> cross-check
    /// (<c>target-&gt;size != (startSize - *size)</c>) also refuses a declared outer <c>size</c> that OVERSTATES
    /// the coordinates' own combined length — the counterpart of
    /// <see cref="ParseRefusesAnOuterSizeInconsistentWithTheInnerPointsLength"/>, which understates it — and
    /// releases the already-parsed coordinates before propagating rather than leaking their rentals.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.5.3, Table 199</see>.
    /// </summary>
    [TestMethod]
    public void ParseRefusesAnOuterSizeLargerThanTheInnerPointsLength()
    {
        //Two 1-octet coordinates consume 6 octets (two 2-octet size prefixes plus one octet each), but the
        //outer size declares 7 — one more than the inner TPMS_ECC_POINT actually consumes.
        byte[] wire = [0x00, 0x07, 0x00, 0x01, 0xAA, 0x00, 0x01, 0xBB];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bEccPoint.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The already-parsed coordinates are disposed before the consistency refusal propagates, so no rental leaks.");
    }

    /// <summary>
    /// Table 199's minimum size of four is exactly the wire shape of an omitted point: "the minimum value for
    /// size will be four" over two zero-length <c>TPM2B_ECC_PARAMETER</c> coordinates — <c>00 04 00 00 00 00</c>
    /// parses without refusal to a point whose <see cref="Tpm2bEccPoint.IsEmpty"/> reads true.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.5.3, Table 199</see>.
    /// </summary>
    [TestMethod]
    public void ParseOfTheMinimumFourOctetWireParsesToAnEmptyPoint()
    {
        byte[] wire = [0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
        var reader = new TpmReader(wire);

        using Tpm2bEccPoint parsed = Tpm2bEccPoint.Parse(ref reader, BaseMemoryPool.Shared);

        Assert.AreEqual(0, reader.Remaining, "The four-octet minimum frame must be consumed exactly.");
        Assert.IsTrue(parsed.IsEmpty, "A size-four frame over two zero-length coordinates is the omitted-point shape, not a refusal.");
    }

    /// <summary>
    /// <see cref="Tpm2bEccPoint.FromPoint"/> adopts an already-built <see cref="TpmsEccPoint"/>, taking ownership
    /// of its two coordinate rentals; <see cref="Tpm2bEccPoint.Dispose"/> releases them exactly once — a second
    /// call is a documented no-op (<see cref="AssertSecondDisposeReleasesNothingFurther"/>), not a double free.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.5.3, Table 199</see>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the built TpmsEccPoint transfers to Tpm2bEccPoint.FromPoint, disposed via the wrapper below.")]
    public void FromPointDisposeReleasesTheWrappedPointExactlyOnceThroughAMeteredPool()
    {
        byte[] x = [0x01, 0x02, 0x03, 0x04];
        byte[] y = [0x05, 0x06, 0x07, 0x08];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        TpmsEccPoint built = TpmsEccPoint.Create(x, y, trackingPool.Pool);
        Tpm2bEccPoint wrapped = Tpm2bEccPoint.FromPoint(built);
        Assert.AreEqual(baseline + 2, trackingPool.OutstandingCount, "Building the wrapped point rents one carrier for X and one for Y.");

        wrapped.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the wrapper releases both coordinate rentals.");

        AssertSecondDisposeReleasesNothingFurther(wrapped, trackingPool, baseline);
    }

    /// <summary>Disposes an already-disposed <see cref="Tpm2bEccPoint"/> a second time and asserts the pool's outstanding count is unchanged — the guard that makes the first dispose exact rather than merely idempotent by accident.</summary>
    /// <param name="wrapped">The already-disposed wrapper.</param>
    /// <param name="trackingPool">The metered pool observing the wrapper's coordinate rentals.</param>
    /// <param name="baseline">The pool's outstanding count before the wrapper was built.</param>
    private static void AssertSecondDisposeReleasesNothingFurther(Tpm2bEccPoint wrapped, MeteredHousePool trackingPool, long baseline)
    {
        wrapped.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A second Dispose() must not attempt to release already-returned rentals.");
    }

    /// <summary>
    /// "If size is zero, then the required structure is missing" (Part 4's <c>TPM2B_ECC_POINT_Unmarshal</c>) —
    /// a declared outer size of zero is refused before any coordinate is parsed, never treated as an omitted
    /// point ("the minimum value for size will be four").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.5.3, Table 199</see>.
    /// </summary>
    [TestMethod]
    public void ParseRefusesAZeroOuterSize()
    {
        byte[] wire = [0x00, 0x00];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bEccPoint.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A zero outer size is refused before any coordinate rental.");
    }

    /// <summary>
    /// Part 4's <c>TPM2B_ECC_POINT_Unmarshal</c> cross-checks the declared outer <c>size</c> against the octets
    /// the inner <c>TPMS_ECC_POINT</c> actually consumed (<c>target-&gt;size != (startSize - *size)</c>) — a
    /// declared size that understates the coordinates' own combined length is refused, and the already-parsed
    /// coordinates are released rather than leaked.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.5.3, Table 199</see>.
    /// </summary>
    [TestMethod]
    public void ParseRefusesAnOuterSizeInconsistentWithTheInnerPointsLength()
    {
        //Two 1-octet coordinates consume 6 octets (two 2-octet size prefixes plus one octet each), but the
        //outer size declares 5 — one less than the inner TPMS_ECC_POINT actually consumes.
        byte[] wire = [0x00, 0x05, 0x00, 0x01, 0xAA, 0x00, 0x01, 0xBB];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bEccPoint.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The already-parsed coordinates are disposed before the consistency refusal propagates, so no rental leaks.");
    }

    /// <summary>
    /// <see cref="Tpm2bEccPoint.Empty"/> wraps <see cref="TpmsEccPoint.Empty"/> (the omitted-point shape: "the X
    /// and Y coordinates need to be individually set to Empty Buffers") — its serialized size is the Table 199
    /// minimum of four octets (two zero-length <c>TPM2B_ECC_PARAMETER</c> size prefixes), never zero, and it is
    /// dispose-immune.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.5.3, Table 199</see>.
    /// </summary>
    [TestMethod]
    public void EmptyWrapsTheOmittedPointShapeAndIsDisposeImmune()
    {
        Tpm2bEccPoint empty = Tpm2bEccPoint.Empty;

        Assert.IsTrue(empty.IsEmpty, "Tpm2bEccPoint.Empty wraps the omitted-point shape, both coordinates zero-length (Table 199).");
        Assert.AreEqual(sizeof(ushort) + sizeof(ushort) + sizeof(ushort), empty.SerializedSize, "Table 199's minimum size of four (the inner point's own two size prefixes) plus the outer size field.");

        byte[] wire = new byte[empty.SerializedSize];
        var writer = new TpmWriter(wire);
        empty.WriteTo(ref writer);

        Assert.AreEqual(4, wire[1], "The outer size field must read 4 — the Table 199 minimum, never zero.");

        //Disposing the shared Empty instance (even repeatedly) must leave it readable.
        empty.Dispose();
        empty.Dispose();
        Assert.IsTrue(empty.IsEmpty, "Disposing the shared Empty instance must never mark it disposed.");
    }
}
