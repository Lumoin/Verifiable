using System;
using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2.Ctap;
using Verifiable.JCose;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapClientPinResponseCborReader"/>: round-tripping against the paired writer
/// (including the nested <c>keyAgreement</c> COSE_Key), and the section 8 forward-compatibility rule
/// that unknown member keys are ignored rather than rejected.
/// </summary>
[TestClass]
internal sealed class CtapClientPinResponseCborReaderTests
{
    /// <summary>Round-tripping an empty response recovers every member as <see langword="null"/>.</summary>
    [TestMethod]
    public void RoundTripsEmptyResponse()
    {
        var written = new CtapClientPinResponse();

        TaggedMemory<byte> encoded = CtapClientPinResponseCborWriter.Write(written);
        CtapClientPinResponse decoded = CtapClientPinResponseCborReader.Read(encoded.Memory);

        Assert.IsNull(decoded.KeyAgreement);
        Assert.IsNull(decoded.PinUvAuthToken);
        Assert.IsNull(decoded.PinRetries);
        Assert.IsNull(decoded.PowerCycleState);
        Assert.IsNull(decoded.UvRetries);
    }


    /// <summary>Round-tripping a response carrying every member, including the nested <c>keyAgreement</c> COSE_Key, recovers every value.</summary>
    [TestMethod]
    public void RoundTripsEveryMember()
    {
        using IMemoryOwner<byte> x = BaseMemoryPool.Shared.Rent(32);
        using IMemoryOwner<byte> y = BaseMemoryPool.Shared.Rent(32);
        var keyAgreement = new CoseKey(
            kty: CoseKeyTypes.Ec2,
            alg: -25,
            curve: CoseKeyCurves.P256,
            x: x.Memory,
            y: y.Memory);

        using IMemoryOwner<byte> pinUvAuthToken = BaseMemoryPool.Shared.Rent(2);
        pinUvAuthToken.Memory.Span[0] = 0xAA;
        pinUvAuthToken.Memory.Span[1] = 0xBB;
        var written = new CtapClientPinResponse(
            KeyAgreement: keyAgreement,
            PinUvAuthToken: pinUvAuthToken.Memory,
            PinRetries: 7,
            PowerCycleState: false,
            UvRetries: 3);

        TaggedMemory<byte> encoded = CtapClientPinResponseCborWriter.Write(written);
        CtapClientPinResponse decoded = CtapClientPinResponseCborReader.Read(encoded.Memory);

        Assert.IsNotNull(decoded.KeyAgreement);
        Assert.AreEqual(CoseKeyTypes.Ec2, decoded.KeyAgreement!.Kty);
        Assert.AreEqual(-25, decoded.KeyAgreement.Alg);
        Assert.AreEqual(CoseKeyCurves.P256, decoded.KeyAgreement.Curve);
        Assert.AreSequenceEqual(new byte[] { 0xAA, 0xBB }, decoded.PinUvAuthToken!.Value.ToArray());
        Assert.AreEqual(7, decoded.PinRetries);
        Assert.IsFalse(decoded.PowerCycleState!.Value);
        Assert.AreEqual(3, decoded.UvRetries);
    }


    /// <summary>
    /// A response carrying an unrecognized member key (here <c>0x06</c>, sorted after <c>uvRetries</c>)
    /// is decoded successfully with the unknown member ignored, per CTAP 2.3 section 8's
    /// forward-compatibility rule.
    /// </summary>
    [TestMethod]
    public void IgnoresUnrecognizedMemberKey()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(WellKnownCtapClientPinResponseKeys.PinRetries);
        writer.WriteInt32(8);
        writer.WriteInt32(0x06);
        writer.WriteUInt32(42);
        writer.WriteEndMap();

        CtapClientPinResponse decoded = CtapClientPinResponseCborReader.Read(writer.Encode());

        Assert.AreEqual(8, decoded.PinRetries);
    }
}
