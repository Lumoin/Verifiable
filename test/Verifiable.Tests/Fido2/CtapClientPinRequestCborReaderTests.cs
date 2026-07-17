using System;
using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.JCose;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapClientPinRequestCborReader"/>: round-tripping against the paired writer
/// (including the nested <c>keyAgreement</c> COSE_Key), the Required-member negative, and the section 8
/// forward-compatibility rule that unknown member keys are ignored rather than rejected.
/// </summary>
[TestClass]
internal sealed class CtapClientPinRequestCborReaderTests
{
    /// <summary>Round-tripping a request with only the Required <c>subCommand</c> recovers it, with every Optional member left <see langword="null"/>.</summary>
    [TestMethod]
    public void RoundTripsSubCommandOnly()
    {
        var written = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetUvRetries);

        TaggedMemory<byte> encoded = CtapClientPinRequestCborWriter.Write(written);
        CtapClientPinRequest decoded = CtapClientPinRequestCborReader.Read(encoded.Memory);

        Assert.AreEqual(WellKnownCtapClientPinSubCommands.GetUvRetries, decoded.SubCommand);
        Assert.IsNull(decoded.PinUvAuthProtocol);
        Assert.IsNull(decoded.KeyAgreement);
        Assert.IsNull(decoded.PinUvAuthParam);
        Assert.IsNull(decoded.NewPinEnc);
        Assert.IsNull(decoded.PinHashEnc);
        Assert.IsNull(decoded.Permissions);
        Assert.IsNull(decoded.RpId);
    }


    /// <summary>Round-tripping a request carrying every Optional member, including the nested <c>keyAgreement</c> COSE_Key, recovers every value.</summary>
    [TestMethod]
    public void RoundTripsEveryOptionalMember()
    {
        using IMemoryOwner<byte> x = BaseMemoryPool.Shared.Rent(32);
        using IMemoryOwner<byte> y = BaseMemoryPool.Shared.Rent(32);
        var keyAgreement = new CoseKey(
            kty: CoseKeyTypes.Ec2,
            alg: -25,
            curve: CoseKeyCurves.P256,
            x: x.Memory,
            y: y.Memory);

        using IMemoryOwner<byte> pinUvAuthParam = BaseMemoryPool.Shared.Rent(3);
        pinUvAuthParam.Memory.Span[0] = 0x01;
        pinUvAuthParam.Memory.Span[1] = 0x02;
        pinUvAuthParam.Memory.Span[2] = 0x03;

        using IMemoryOwner<byte> newPinEnc = BaseMemoryPool.Shared.Rent(2);
        newPinEnc.Memory.Span[0] = 0x04;
        newPinEnc.Memory.Span[1] = 0x05;

        using IMemoryOwner<byte> pinHashEnc = BaseMemoryPool.Shared.Rent(1);
        pinHashEnc.Memory.Span[0] = 0x06;

        var written = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin,
            PinUvAuthProtocol: 2,
            KeyAgreement: keyAgreement,
            PinUvAuthParam: pinUvAuthParam.Memory,
            NewPinEnc: newPinEnc.Memory,
            PinHashEnc: pinHashEnc.Memory,
            Permissions: 0x03,
            RpId: "example.com");

        TaggedMemory<byte> encoded = CtapClientPinRequestCborWriter.Write(written);
        CtapClientPinRequest decoded = CtapClientPinRequestCborReader.Read(encoded.Memory);

        Assert.AreEqual(written.SubCommand, decoded.SubCommand);
        Assert.AreEqual(written.PinUvAuthProtocol, decoded.PinUvAuthProtocol);
        Assert.IsNotNull(decoded.KeyAgreement);
        Assert.AreEqual(CoseKeyTypes.Ec2, decoded.KeyAgreement!.Kty);
        Assert.AreEqual(-25, decoded.KeyAgreement.Alg);
        Assert.AreEqual(CoseKeyCurves.P256, decoded.KeyAgreement.Curve);
        CollectionAssert.AreEqual(new byte[] { 0x01, 0x02, 0x03 }, decoded.PinUvAuthParam!.Value.ToArray());
        CollectionAssert.AreEqual(new byte[] { 0x04, 0x05 }, decoded.NewPinEnc!.Value.ToArray());
        CollectionAssert.AreEqual(new byte[] { 0x06 }, decoded.PinHashEnc!.Value.ToArray());
        Assert.AreEqual(written.Permissions, decoded.Permissions);
        Assert.AreEqual(written.RpId, decoded.RpId);
    }


    /// <summary>A request missing the Required <c>subCommand</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenSubCommandMemberIsMissing()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapClientPinRequestKeys.PinUvAuthProtocol);
        writer.WriteInt32(2);
        writer.WriteEndMap();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapClientPinRequestCborReader.Read(writer.Encode()));

        Assert.Contains("subCommand", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A request carrying an unrecognized top-level member key (here <c>0x07</c>, between
    /// <c>pinHashEnc</c> and <c>permissions</c>) is decoded successfully with the unknown member
    /// ignored, per CTAP 2.3 section 8's forward-compatibility rule.
    /// </summary>
    [TestMethod]
    public void IgnoresUnrecognizedTopLevelMemberKey()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(WellKnownCtapClientPinRequestKeys.SubCommand);
        writer.WriteInt32(WellKnownCtapClientPinSubCommands.GetPinRetries);
        writer.WriteInt32(0x07);
        writer.WriteUInt32(42);
        writer.WriteEndMap();

        CtapClientPinRequest decoded = CtapClientPinRequestCborReader.Read(writer.Encode());

        Assert.AreEqual(WellKnownCtapClientPinSubCommands.GetPinRetries, decoded.SubCommand);
    }
}
