using Verifiable.JCose.Eudi;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// Tests for <see cref="EudiAv"/> — the EUDI Age Verification (Pseudonym)
/// constants. Mirrors the shape of <see cref="EudiPidDomesticNamespaceTests"/>
/// for the PID side; AV uses the same per-country convention.
/// </summary>
[TestClass]
internal sealed class EudiAvConstantsTests
{
    [TestMethod]
    public void AttestationTypeAndMdocNamespaceShareTheSameValue()
    {
        //Reading through non-const locals so MSTest doesn't conclude the
        //assertion is trivially true at compile time — the equality is the
        //test subject.
        string attestationType = EudiAv.AttestationType;
        string mdocNamespace = EudiAv.Mdoc.Namespace;

        Assert.AreEqual(attestationType, mdocNamespace,
            "Per the EUDI rulebook convention, the AV attestation type and " +
            "mdoc namespace are the same string.");
    }


    [TestMethod]
    public void DomesticVctEmitsExpectedShape()
    {
        Assert.AreEqual("urn:eudi:av:fi:1", EudiAv.DomesticVct("fi"));
        Assert.AreEqual("urn:eudi:av:de:1", EudiAv.DomesticVct("DE"),
            "Country code must normalise to lowercase.");
    }


    [TestMethod]
    public void DomesticNamespaceEmitsExpectedShape()
    {
        Assert.AreEqual("eu.europa.ec.eudi.pseudonym.age_over_18.fi.1", EudiAv.DomesticNamespace("fi"));
        Assert.AreEqual("eu.europa.ec.eudi.pseudonym.age_over_18.de.1", EudiAv.DomesticNamespace("DE"));
    }


    [TestMethod]
    public void DomesticVctRejectsNonTwoLetterCountryCode()
    {
        Assert.ThrowsExactly<ArgumentException>(() => EudiAv.DomesticVct("FIN"));
        Assert.ThrowsExactly<ArgumentException>(() => EudiAv.DomesticVct("f"));
        Assert.ThrowsExactly<ArgumentException>(() => EudiAv.DomesticVct(string.Empty));
    }


    [TestMethod]
    public void DomesticNamespaceRejectsNonTwoLetterCountryCode()
    {
        Assert.ThrowsExactly<ArgumentException>(() => EudiAv.DomesticNamespace("FIN"));
        Assert.ThrowsExactly<ArgumentException>(() => EudiAv.DomesticNamespace("f"));
    }


    [TestMethod]
    public void TryParseDomesticNamespaceExtractsCountryCode()
    {
        Assert.IsTrue(EudiAv.TryParseDomesticNamespace(
            "eu.europa.ec.eudi.pseudonym.age_over_18.fi.1", out string? country));
        Assert.AreEqual("fi", country);

        Assert.IsTrue(EudiAv.TryParseDomesticNamespace(
            "eu.europa.ec.eudi.pseudonym.age_over_18.de.1", out country));
        Assert.AreEqual("de", country);
    }


    [TestMethod]
    public void TryParseDomesticNamespaceRejectsBaseNamespace()
    {
        //The base namespace has no country segment — same convention as PID.
        Assert.IsFalse(EudiAv.TryParseDomesticNamespace(EudiAv.AttestationType, out string? country));
        Assert.IsNull(country);
    }


    [TestMethod]
    public void TryParseDomesticNamespaceRejectsMalformedInputs()
    {
        Assert.IsFalse(EudiAv.TryParseDomesticNamespace(string.Empty, out _));
        Assert.IsFalse(EudiAv.TryParseDomesticNamespace("eu.europa.ec.eudi.pid.fi.1", out _),
            "PID-shaped namespace must NOT parse as AV.");
        Assert.IsFalse(EudiAv.TryParseDomesticNamespace(
            "eu.europa.ec.eudi.pseudonym.age_over_18.fin.1", out _),
            "Three-letter country code must be rejected.");
    }


    [TestMethod]
    public void IsAvNamespaceAcceptsBaseAndDomesticForms()
    {
        Assert.IsTrue(EudiAv.IsAvNamespace(EudiAv.AttestationType));
        Assert.IsTrue(EudiAv.IsAvNamespace("eu.europa.ec.eudi.pseudonym.age_over_18.fi.1"));
        Assert.IsFalse(EudiAv.IsAvNamespace(EudiPid.AttestationType),
            "PID namespace must not be recognised as AV.");
        Assert.IsFalse(EudiAv.IsAvNamespace("org.iso.18013.5.1"));
    }


    [TestMethod]
    public void MdocAgeOver18ConstantMatchesPidAndMdlEquivalent()
    {
        //All three EUDI attestations name the over-18 boolean the same
        //way in mdoc encoding — keeps verifier-side queries portable
        //across attestation types. Read through locals to dodge the
        //compile-time-constant-equality analyzer.
        string avAge = EudiAv.Mdoc.AgeOver18;
        string pidAge = EudiPid.Mdoc.AgeOver18;
        string mdlAge = EudiMdl.Attributes.AgeOver18;

        Assert.AreEqual(pidAge, avAge);
        Assert.AreEqual(mdlAge, avAge);
    }
}
