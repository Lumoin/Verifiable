using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Byte-exact tests for the seven <c>authenticatorClientPIN</c> PIN-path status codes wave-5b adds to
/// <see cref="WellKnownCtapStatusCodes"/>, wave-5c's <see cref="WellKnownCtapStatusCodes.PuatRequired"/>,
/// this wave's <see cref="WellKnownCtapStatusCodes.InvalidSubcommand"/> (R1), and the
/// <c>pinUvAuthToken</c> permission bit values in <see cref="WellKnownCtapPinUvAuthTokenPermissions"/>
/// (CTAP 2.3 §8.2/§6.5.5).
/// </summary>
[TestClass]
internal sealed class WellKnownCtapStatusCodesPinTests
{
    /// <summary>Every new status code must carry its exact CTAP 2.3 §8.2 wire value.</summary>
    [TestMethod]
    [DataRow(0x31, DisplayName = "PinInvalid")]
    [DataRow(0x32, DisplayName = "PinBlocked")]
    [DataRow(0x33, DisplayName = "PinAuthInvalid")]
    [DataRow(0x34, DisplayName = "PinAuthBlocked")]
    [DataRow(0x35, DisplayName = "PinNotSet")]
    [DataRow(0x36, DisplayName = "PuatRequired")]
    [DataRow(0x37, DisplayName = "PinPolicyViolation")]
    [DataRow(0x3E, DisplayName = "InvalidSubcommand")]
    [DataRow(0x40, DisplayName = "UnauthorizedPermission")]
    public void EveryNewPinStatusCodeHasItsSpecMandatedWireValue(int expected)
    {
        byte actual = expected switch
        {
            0x31 => WellKnownCtapStatusCodes.PinInvalid,
            0x32 => WellKnownCtapStatusCodes.PinBlocked,
            0x33 => WellKnownCtapStatusCodes.PinAuthInvalid,
            0x34 => WellKnownCtapStatusCodes.PinAuthBlocked,
            0x35 => WellKnownCtapStatusCodes.PinNotSet,
            0x36 => WellKnownCtapStatusCodes.PuatRequired,
            0x37 => WellKnownCtapStatusCodes.PinPolicyViolation,
            0x3E => WellKnownCtapStatusCodes.InvalidSubcommand,
            0x40 => WellKnownCtapStatusCodes.UnauthorizedPermission,
            _ => throw new System.NotSupportedException()
        };

        Assert.AreEqual((byte)expected, actual);
    }


    /// <summary>Every new <c>Is*</c> predicate matches its own code and rejects every sibling code.</summary>
    [TestMethod]
    public void EveryNewIsPredicateMatchesOnlyItsOwnCode()
    {
        byte[] codes =
        [
            WellKnownCtapStatusCodes.PinInvalid,
            WellKnownCtapStatusCodes.PinBlocked,
            WellKnownCtapStatusCodes.PinAuthInvalid,
            WellKnownCtapStatusCodes.PinAuthBlocked,
            WellKnownCtapStatusCodes.PinNotSet,
            WellKnownCtapStatusCodes.PuatRequired,
            WellKnownCtapStatusCodes.PinPolicyViolation,
            WellKnownCtapStatusCodes.InvalidSubcommand,
            WellKnownCtapStatusCodes.UnauthorizedPermission
        ];

        Assert.IsTrue(WellKnownCtapStatusCodes.IsPinInvalid(codes[0]));
        Assert.IsTrue(WellKnownCtapStatusCodes.IsPinBlocked(codes[1]));
        Assert.IsTrue(WellKnownCtapStatusCodes.IsPinAuthInvalid(codes[2]));
        Assert.IsTrue(WellKnownCtapStatusCodes.IsPinAuthBlocked(codes[3]));
        Assert.IsTrue(WellKnownCtapStatusCodes.IsPinNotSet(codes[4]));
        Assert.IsTrue(WellKnownCtapStatusCodes.IsPuatRequired(codes[5]));
        Assert.IsTrue(WellKnownCtapStatusCodes.IsPinPolicyViolation(codes[6]));
        Assert.IsTrue(WellKnownCtapStatusCodes.IsInvalidSubcommand(codes[7]));
        Assert.IsTrue(WellKnownCtapStatusCodes.IsUnauthorizedPermission(codes[8]));

        foreach(byte code in codes)
        {
            int matchCount = 0;
            matchCount += WellKnownCtapStatusCodes.IsPinInvalid(code) ? 1 : 0;
            matchCount += WellKnownCtapStatusCodes.IsPinBlocked(code) ? 1 : 0;
            matchCount += WellKnownCtapStatusCodes.IsPinAuthInvalid(code) ? 1 : 0;
            matchCount += WellKnownCtapStatusCodes.IsPinAuthBlocked(code) ? 1 : 0;
            matchCount += WellKnownCtapStatusCodes.IsPinNotSet(code) ? 1 : 0;
            matchCount += WellKnownCtapStatusCodes.IsPuatRequired(code) ? 1 : 0;
            matchCount += WellKnownCtapStatusCodes.IsPinPolicyViolation(code) ? 1 : 0;
            matchCount += WellKnownCtapStatusCodes.IsInvalidSubcommand(code) ? 1 : 0;
            matchCount += WellKnownCtapStatusCodes.IsUnauthorizedPermission(code) ? 1 : 0;

            Assert.AreEqual(1, matchCount, $"Status code 0x{code:X2} must match exactly one of the new Is* predicates.");
        }
    }


    /// <summary>The seven <c>pinUvAuthToken</c> permission bits must carry their exact CTAP 2.3 §6.5.5 wire values.</summary>
    [TestMethod]
    public void EveryPermissionBitHasItsSpecMandatedWireValue()
    {
        //Reading through int locals so MSTest's analyzer doesn't conclude the assertion is
        //trivially true at compile time — the constants are exactly what's under test.
        int mc = WellKnownCtapPinUvAuthTokenPermissions.Mc;
        int ga = WellKnownCtapPinUvAuthTokenPermissions.Ga;
        int cm = WellKnownCtapPinUvAuthTokenPermissions.Cm;
        int be = WellKnownCtapPinUvAuthTokenPermissions.Be;
        int lbw = WellKnownCtapPinUvAuthTokenPermissions.Lbw;
        int acfg = WellKnownCtapPinUvAuthTokenPermissions.Acfg;
        int pcmr = WellKnownCtapPinUvAuthTokenPermissions.Pcmr;

        Assert.AreEqual(0x01, mc);
        Assert.AreEqual(0x02, ga);
        Assert.AreEqual(0x04, cm);
        Assert.AreEqual(0x08, be);
        Assert.AreEqual(0x10, lbw);
        Assert.AreEqual(0x20, acfg);
        Assert.AreEqual(0x40, pcmr);
    }
}
