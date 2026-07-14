using System.Formats.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Model.Mdoc;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.MdocTestFixtures;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// Tests for <see cref="MdocCborMsoReader"/> — verifies that a hand-crafted
/// Mobile Security Object byte buffer parses back into the structural shape
/// ISO/IEC 18013-5 §9.1.2.4 prescribes (version, digestAlgorithm,
/// valueDigests nested 2-deep, deviceKeyInfo with COSE_Key, docType,
/// validityInfo with tdate fields).
/// </summary>
/// <remarks>
/// <para>
/// The fixtures here are built with <see cref="CborWriter"/> against the
/// canonical conformance mode so the produced bytes match what a
/// spec-conforming issuer emits. Real COSE_Sign1 signing waits for M.3;
/// these tests validate parse-side correctness only.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocCborMsoReaderTests
{
    private const string MdlNamespace = "org.iso.18013.5.1";
    private const string MdlDocType = "org.iso.18013.5.1.mDL";

    //Mirrors the instants MdocTestFixtures.WriteValidityInfo bakes into
    //BuildSampleMso's validityInfo tdate fields. Bit-identical to
    //TestClock.CanonicalEpoch.AddDays(-8) (2026-05-24T12:00:00Z).
    private static readonly DateTimeOffset ExpectedValiditySigned = TestClock.CanonicalEpoch.AddDays(-8);
    private static readonly DateTimeOffset ExpectedValidityValidUntil = ExpectedValiditySigned.AddYears(1);


    [TestMethod]
    public void ReadMsoRoundTripsAllRequiredFields()
    {
        byte[] msoBytes = MdocCborMsoReaderTestFixtures.BuildSampleMso();

        MdocMobileSecurityObject mso = MdocCborMsoReader.Read(msoBytes);

        Assert.AreEqual(MdocMsoWellKnownKeys.Version10, mso.Version);
        Assert.AreEqual(MdocMsoWellKnownKeys.DigestAlgorithmSha256, mso.DigestAlgorithm);
        Assert.AreEqual(MdlDocType, mso.DocType);
    }


    [TestMethod]
    public void ReadMsoPopulatesValueDigestsNestedTwoDeep()
    {
        byte[] msoBytes = MdocCborMsoReaderTestFixtures.BuildSampleMso();

        MdocMobileSecurityObject mso = MdocCborMsoReader.Read(msoBytes);

        Assert.HasCount(1, mso.ValueDigests);
        Assert.IsTrue(mso.ValueDigests.ContainsKey(MdlNamespace));

        IReadOnlyDictionary<uint, ReadOnlyMemory<byte>> nsDigests = mso.ValueDigests[MdlNamespace];
        Assert.HasCount(2, nsDigests);
        Assert.IsTrue(nsDigests.ContainsKey(0u));
        Assert.IsTrue(nsDigests.ContainsKey(1u));

        Assert.AreEqual(32, nsDigests[0u].Length, "SHA-256 digest is 32 bytes.");
        Assert.AreEqual(32, nsDigests[1u].Length);
    }


    [TestMethod]
    public void ReadMsoPopulatesValidityInfoTdateFields()
    {
        byte[] msoBytes = MdocCborMsoReaderTestFixtures.BuildSampleMso();

        MdocMobileSecurityObject mso = MdocCborMsoReader.Read(msoBytes);

        Assert.AreEqual(ExpectedValiditySigned, mso.ValidityInfo.Signed);
        Assert.AreEqual(ExpectedValiditySigned, mso.ValidityInfo.ValidFrom);
        Assert.AreEqual(ExpectedValidityValidUntil, mso.ValidityInfo.ValidUntil);
        Assert.IsNull(mso.ValidityInfo.ExpectedUpdate, "Sample MSO omits expectedUpdate; null is the parsed-absence sentinel.");
    }


    [TestMethod]
    public void ReadMsoPopulatesDeviceKeyInfoWithEc2P256DeviceKey()
    {
        byte[] msoBytes = MdocCborMsoReaderTestFixtures.BuildSampleMso();

        MdocMobileSecurityObject mso = MdocCborMsoReader.Read(msoBytes);

        CoseKey deviceKey = mso.DeviceKeyInfo.DeviceKey;
        Assert.AreEqual(CoseKeyTypes.Ec2, deviceKey.Kty);
        Assert.AreEqual(CoseKeyCurves.P256, deviceKey.Curve);
        Assert.IsNotNull(deviceKey.X);
        Assert.IsNotNull(deviceKey.Y);
        Assert.AreEqual(32, deviceKey.X!.Value.Length);
        Assert.AreEqual(32, deviceKey.Y!.Value.Length);
        Assert.IsNull(mso.DeviceKeyInfo.EncodedKeyAuthorizations);
        Assert.IsNull(mso.DeviceKeyInfo.EncodedKeyInfo);
    }


    [TestMethod]
    public void ReadMsoSkipsUnknownTopLevelFieldPerForwardCompat()
    {
        //ISO 18013-5 specifies the MSO fields but expects readers to skip
        //unknown keys forward-compatibly. A future revision adding a new
        //field must not break today's reader.
        byte[] msoBytes = BuildSampleMsoWithExtraField();

        MdocMobileSecurityObject mso = MdocCborMsoReader.Read(msoBytes);

        //The reader still produces all required fields; the unknown one is silently skipped.
        Assert.AreEqual(MdocMsoWellKnownKeys.Version10, mso.Version);
        Assert.AreEqual(MdlDocType, mso.DocType);
    }


    [TestMethod]
    public void ReadMsoFailsWhenRequiredFieldMissing()
    {
        //Omit docType from the encoded map; the reader must surface the gap
        //rather than producing a half-formed MSO.
        byte[] msoBytes = BuildIncompleteMso();

        CborContentException ex = Assert.ThrowsExactly<CborContentException>(() => MdocCborMsoReader.Read(msoBytes));
        Assert.Contains("required fields", ex.Message);
    }


    private static byte[] BuildSampleMsoWithExtraField()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);

        //Lax mode used so we can add an extra key without canonical ordering
        //constraints — the test point is that the reader skips the unknown
        //key, not that the producer emitted it canonically.
        writer.WriteStartMap(7);

        writer.WriteTextString(MdocMsoWellKnownKeys.Version);
        writer.WriteTextString(MdocMsoWellKnownKeys.Version10);

        writer.WriteTextString(MdocMsoWellKnownKeys.DigestAlgorithm);
        writer.WriteTextString(MdocMsoWellKnownKeys.DigestAlgorithmSha256);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValueDigests);
        WriteValueDigests(writer, MdlNamespace);

        writer.WriteTextString(MdocMsoWellKnownKeys.DeviceKeyInfo);
        WriteDeviceKeyInfo(writer);

        writer.WriteTextString(MdocMsoWellKnownKeys.DocType);
        writer.WriteTextString(MdlDocType);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValidityInfo);
        WriteValidityInfo(writer);

        //The forward-compat extra field — not in ISO 18013-5:2021 but the
        //reader must tolerate it gracefully.
        writer.WriteTextString("futureExtension");
        writer.WriteInt32(42);

        writer.WriteEndMap();

        return writer.Encode();
    }


    private static byte[] BuildIncompleteMso()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);

        //Missing docType deliberately — reader must surface the gap.
        writer.WriteStartMap(5);

        writer.WriteTextString(MdocMsoWellKnownKeys.Version);
        writer.WriteTextString(MdocMsoWellKnownKeys.Version10);

        writer.WriteTextString(MdocMsoWellKnownKeys.DigestAlgorithm);
        writer.WriteTextString(MdocMsoWellKnownKeys.DigestAlgorithmSha256);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValueDigests);
        WriteValueDigests(writer, MdlNamespace);

        writer.WriteTextString(MdocMsoWellKnownKeys.DeviceKeyInfo);
        WriteDeviceKeyInfo(writer);

        writer.WriteTextString(MdocMsoWellKnownKeys.ValidityInfo);
        WriteValidityInfo(writer);

        writer.WriteEndMap();

        return writer.Encode();
    }
}
