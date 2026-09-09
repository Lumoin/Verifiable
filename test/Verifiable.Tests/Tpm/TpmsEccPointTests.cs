using System;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// <see cref="TpmsEccPoint"/> (TPMS_ECC_POINT, TPM 2.0 Library Part 2, clause 11.2.5.2, Table 198) on a refused
/// parse or a refused creation: a refused Y coordinate leaves no rental outstanding — the X coordinate parsed or
/// created before it is released, never orphaned — beside <see cref="Tpm2bEccPointTests"/>'s coverage of the outer
/// TPM2B_ECC_POINT (Table 199) envelope's own size refusals.
/// </summary>
[TestClass]
internal sealed class TpmsEccPointTests
{
    /// <summary>
    /// A well-formed X coordinate followed by a Y coordinate declaring a size the reader cannot supply is refused
    /// (<see cref="InvalidOperationException"/>), and no rental is outstanding once the exception propagates: the
    /// X coordinate parsed before the refusal is released. Part 4's <c>TPMS_ECC_POINT_Unmarshal</c> parses X then
    /// Y in the same order, so a truncated Y is the natural malformed frame.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2,
    /// clause 11.2.5.2, Table 198</see>.
    /// </summary>
    [TestMethod]
    public void ParseOfAWellFormedXAndATruncatedYThrowsAndReleasesTheXRental()
    {
        //X: size 4, four data octets (well-formed, fully consumed). Y: size 0xFF (255) with zero octets left in
        //the reader, so Tpm2bEccParameter.Parse's "size > reader.Remaining" check throws before Y is rented.
        byte[] wire = [0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0xFF];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = TpmsEccPoint.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The already-rented X coordinate must be disposed before the Y refusal propagates, leaving no outstanding rental.");
    }

    /// <summary>
    /// A well-formed X coordinate alongside a Y coordinate wider than <see cref="Tpm2bEccParameter.MaxSize"/> is
    /// refused (<see cref="ArgumentException"/>), and no rental is outstanding once the exception propagates: the
    /// X coordinate created before the refusal is released.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2,
    /// clause 11.2.5.2, Table 198</see>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmsEccPoint.Create is expected to throw on this malformed input before ever returning a value; the try/catch exists exactly to observe that refusal, so no object survives to be disposed.")]
    public void CreateOfAWellFormedXAndAnOverLongYThrowsAndReleasesTheXRental()
    {
        byte[] x = [0x01, 0x02, 0x03, 0x04];
        byte[] y = new byte[Tpm2bEccParameter.MaxSize + 1];
        y.AsSpan().Fill(0x5A);

        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        try
        {
            _ = TpmsEccPoint.Create(x, y, trackingPool.Pool);
            Assert.Fail("Expected ArgumentException.");
        }
        catch(ArgumentException)
        {
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The already-rented X coordinate must be disposed before the over-long-Y refusal propagates, leaving no outstanding rental.");
    }

    /// <summary>
    /// The same truncated-Y shape through <see cref="Tpm2bEccPoint.Parse"/>'s outer TPM2B_ECC_POINT envelope — an
    /// outer size of six over a one-octet X and a truncated Y — is refused with no rental outstanding once the
    /// exception propagates through the wrapping type.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2,
    /// clause 11.2.5.3, Table 199</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bEccPointParseOfAWellFormedXAndATruncatedYThrowsAndReleasesTheXRental()
    {
        //Outer size 6; X: size 1, one data octet 0xAA; Y: size 0xFF (255) with zero octets left.
        byte[] wire = [0x00, 0x06, 0x00, 0x01, 0xAA, 0x00, 0xFF];
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

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The already-rented X coordinate must be disposed before the Y refusal propagates through Tpm2bEccPoint.Parse, leaving no outstanding rental.");
    }
}
