using Verifiable.Core.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusTypes"/>.
/// </summary>
[TestClass]
internal sealed class StatusTypesTests
{
    [TestMethod]
    [DataRow(StatusTypes.Valid, true, DisplayName = "Valid (0x00) is a standard status.")]
    [DataRow(StatusTypes.Invalid, true, DisplayName = "Invalid (0x01) is a standard status.")]
    [DataRow(StatusTypes.Suspended, true, DisplayName = "Suspended (0x02) is a standard status.")]
    [DataRow(StatusTypes.ApplicationSpecific03, false, DisplayName = "ApplicationSpecific03 (0x03) is not a standard status.")]
    [DataRow((byte)0x04, false, DisplayName = "Value 0x04 is not a standard status.")]
    [DataRow((byte)0xFF, false, DisplayName = "Value 0xFF is not a standard status.")]
    public void IsStandardStatusReturnsExpected(byte value, bool expected)
    {
        Assert.AreEqual(expected, StatusTypes.IsStandardStatus(value));
    }

    [TestMethod]
    [DataRow(StatusTypes.ApplicationSpecific03, true, DisplayName = "ApplicationSpecific03 (0x03) is application-specific.")]
    [DataRow(StatusTypes.ApplicationSpecific0C, true, DisplayName = "ApplicationSpecific0C (0x0C) is application-specific.")]
    [DataRow(StatusTypes.ApplicationSpecific0D, true, DisplayName = "ApplicationSpecific0D (0x0D) is application-specific.")]
    [DataRow(StatusTypes.ApplicationSpecific0E, true, DisplayName = "ApplicationSpecific0E (0x0E) is application-specific.")]
    [DataRow(StatusTypes.ApplicationSpecific0F, true, DisplayName = "ApplicationSpecific0F (0x0F) is application-specific.")]
    [DataRow(StatusTypes.Valid, false, DisplayName = "Valid (0x00) is not application-specific.")]
    [DataRow((byte)0x04, false, DisplayName = "Value 0x04 is not application-specific.")]
    [DataRow((byte)0x0B, false, DisplayName = "Value 0x0B is not application-specific.")]
    [DataRow((byte)0x10, false, DisplayName = "Value 0x10 is not application-specific.")]
    public void IsApplicationSpecificReturnsExpected(byte value, bool expected)
    {
        Assert.AreEqual(expected, StatusTypes.IsApplicationSpecific(value));
    }
}