using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

[TestClass]
internal sealed class WellKnownWebAuthnAttestationFormatsTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void NoneFormatHasRegisteredIdentifier()
    {
        Assert.AreEqual("none", WellKnownWebAuthnAttestationFormats.None);
    }

    [TestMethod]
    public void PackedFormatHasRegisteredIdentifier()
    {
        Assert.AreEqual("packed", WellKnownWebAuthnAttestationFormats.Packed);
    }

    [TestMethod]
    public void TpmFormatHasRegisteredIdentifier()
    {
        Assert.AreEqual("tpm", WellKnownWebAuthnAttestationFormats.Tpm);
    }

    [TestMethod]
    public void RegisteredIdentifierIsRecognized()
    {
        Assert.IsTrue(WellKnownWebAuthnAttestationFormats.IsRegisteredFormatIdentifier("tpm"));
    }

    [TestMethod]
    public void UnknownIdentifierIsNotRecognized()
    {
        Assert.IsFalse(WellKnownWebAuthnAttestationFormats.IsRegisteredFormatIdentifier("bogus"));
    }
}
