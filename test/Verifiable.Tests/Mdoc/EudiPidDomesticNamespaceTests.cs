using Verifiable.JCose.Eudi;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// Tests for the M.6 <see cref="EudiPid.DomesticNamespace"/> +
/// <see cref="EudiPid.TryParseDomesticNamespace"/> +
/// <see cref="EudiPid.IsPidNamespace"/> helpers — parallels the existing
/// <see cref="EudiPid.DomesticVct"/> set on the SD-JWT VC side, applied to
/// the mdoc namespace convention <c>eu.europa.ec.eudi.pid.{country}.1</c>.
/// </summary>
[TestClass]
internal sealed class EudiPidDomesticNamespaceTests
{
    [TestMethod]
    public void DomesticNamespaceBuildsForLowercaseTwoLetterCountry()
    {
        Assert.AreEqual("eu.europa.ec.eudi.pid.fi.1", EudiPid.DomesticNamespace("fi"));
        Assert.AreEqual("eu.europa.ec.eudi.pid.de.1", EudiPid.DomesticNamespace("de"));
    }


    [TestMethod]
    public void DomesticNamespaceNormalisesCountryCodeToLowercase()
    {
        Assert.AreEqual("eu.europa.ec.eudi.pid.fi.1", EudiPid.DomesticNamespace("FI"));
        Assert.AreEqual("eu.europa.ec.eudi.pid.de.1", EudiPid.DomesticNamespace("DE"));
    }


    [TestMethod]
    public void DomesticNamespaceRejectsNonTwoCharacterCountryCode()
    {
        Assert.ThrowsExactly<ArgumentException>(() => EudiPid.DomesticNamespace("FIN"));
        Assert.ThrowsExactly<ArgumentException>(() => EudiPid.DomesticNamespace("f"));
        Assert.ThrowsExactly<ArgumentException>(() => EudiPid.DomesticNamespace(string.Empty));
    }


    [TestMethod]
    public void TryParseDomesticNamespaceExtractsCountryCode()
    {
        Assert.IsTrue(EudiPid.TryParseDomesticNamespace("eu.europa.ec.eudi.pid.fi.1", out string? country));
        Assert.AreEqual("fi", country);

        Assert.IsTrue(EudiPid.TryParseDomesticNamespace("eu.europa.ec.eudi.pid.de.1", out country));
        Assert.AreEqual("de", country);
    }


    [TestMethod]
    public void TryParseDomesticNamespaceRejectsBaseNamespaceWithoutCountrySegment()
    {
        //The base namespace eu.europa.ec.eudi.pid.1 has no country segment
        //and must NOT be parsed as a domestic one. Matches the
        //TryParseDomesticVct behaviour.
        Assert.IsFalse(EudiPid.TryParseDomesticNamespace(EudiPid.Mdoc.Namespace, out string? country));
        Assert.IsNull(country);
    }


    [TestMethod]
    public void TryParseDomesticNamespaceRejectsMalformedInputs()
    {
        Assert.IsFalse(EudiPid.TryParseDomesticNamespace(string.Empty, out _));
        Assert.IsFalse(EudiPid.TryParseDomesticNamespace("eu.europa.ec.eudi.pid.fi.2", out _));
        Assert.IsFalse(EudiPid.TryParseDomesticNamespace("some.other.namespace", out _));
        Assert.IsFalse(EudiPid.TryParseDomesticNamespace("eu.europa.ec.eudi.pid.fin.1", out _));
    }


    [TestMethod]
    public void IsPidNamespaceAcceptsBaseAndDomesticForms()
    {
        Assert.IsTrue(EudiPid.IsPidNamespace(EudiPid.Mdoc.Namespace),
            "Base namespace must be recognised as a PID namespace.");
        Assert.IsTrue(EudiPid.IsPidNamespace("eu.europa.ec.eudi.pid.fi.1"),
            "Domestic namespace must be recognised as a PID namespace.");
        Assert.IsFalse(EudiPid.IsPidNamespace("org.iso.18013.5.1"),
            "ISO mDL namespace must not be recognised as a PID namespace.");
    }
}
