using System;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Byte-exactness tests for <see cref="CtapClientPinRequestCborWriter"/>.
/// </summary>
[TestClass]
internal sealed class CtapClientPinRequestCborWriterTests
{
    /// <summary>
    /// A request carrying only the Required <c>subCommand</c> member encodes to a 1-entry map.
    /// </summary>
    [TestMethod]
    public void WriteEncodesSubCommandOnlyToExactCanonicalBytes()
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);

        TaggedMemory<byte> result = CtapClientPinRequestCborWriter.Write(request);

        byte[] expected = [0xA1, 0x02, 0x01]; //map(1): key 2 (subCommand) -> 1 (getPINRetries)

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>pinUvAuthProtocol</c> (key <c>0x01</c>) writes before <c>subCommand</c> (key <c>0x02</c>),
    /// preserving the outer map's ascending key order.
    /// </summary>
    [TestMethod]
    public void WriteOrdersPinUvAuthProtocolBeforeSubCommand()
    {
        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement, PinUvAuthProtocol: 2);

        TaggedMemory<byte> result = CtapClientPinRequestCborWriter.Write(request);

        byte[] expected = [0xA2, 0x01, 0x02, 0x02, 0x02]; //map(2): key 1 (pinUvAuthProtocol) -> 2, key 2 (subCommand) -> 2 (getKeyAgreement)

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>rpId</c> (key <c>0x0A</c>) writes after <c>subCommand</c>, as a CBOR text string.
    /// </summary>
    [TestMethod]
    public void WriteEncodesRpIdAsTextStringAfterSubCommand()
    {
        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions, RpId: "ex");

        TaggedMemory<byte> result = CtapClientPinRequestCborWriter.Write(request);

        byte[] expected = [0xA2, 0x02, 0x09, 0x0A, 0x62, 0x65, 0x78]; //map(2): subCommand -> 9, rpId -> text(2) "ex"

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// A request carrying only <c>permissions</c> (key <c>0x09</c>) alongside <c>subCommand</c> encodes
    /// both as CBOR unsigned integers, with no other Optional member synthesized.
    /// </summary>
    [TestMethod]
    public void WriteEncodesPermissionsAndOmitsEveryOtherOptionalMember()
    {
        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions, Permissions: 0x03);

        TaggedMemory<byte> result = CtapClientPinRequestCborWriter.Write(request);

        byte[] expected = [0xA2, 0x02, 0x09, 0x09, 0x03]; //map(2): subCommand -> 9, permissions -> 3

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }
}
