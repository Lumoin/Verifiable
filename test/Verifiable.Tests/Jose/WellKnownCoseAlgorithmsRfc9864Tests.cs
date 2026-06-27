using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests for the RFC 9864 fully-specified ECDSA (ESP) and Brainpool ECDSA
/// (ESB) COSE algorithm identifiers landed in P.2 of the mdoc workstream's
/// Thread Q.
/// </summary>
/// <remarks>
/// <para>
/// ESP constants pin both curve AND hash (ESP256 = ECDSA + P-256 +
/// SHA-256, ESP384 = ECDSA + P-384 + SHA-384, ESP512 = ECDSA + P-521 +
/// SHA-512). They share key material with the older ES variants and the
/// converter maps them onto the same P-curve key tags. ESB constants
/// represent Brainpool variants; their converter wiring lands in Q.2
/// alongside the Brainpool curve tags themselves.
/// </para>
/// </remarks>
[TestClass]
internal sealed class WellKnownCoseAlgorithmsRfc9864Tests
{
    [TestMethod]
    public void EspConstantsMatchRfc9864AssignedValues()
    {
        //RFC 9864 / IANA COSE Algorithms: ESP256 = -9, ESP384 = -51, ESP512 = -52.
        //Reading through int locals so MSTest's analyzer doesn't conclude the
        //assertion is trivially true at compile time — the constants are exactly
        //what's under test.
        int esp256 = WellKnownCoseAlgorithms.Esp256;
        int esp384 = WellKnownCoseAlgorithms.Esp384;
        int esp512 = WellKnownCoseAlgorithms.Esp512;

        Assert.AreEqual(-9, esp256);
        Assert.AreEqual(-51, esp384);
        Assert.AreEqual(-52, esp512);
    }


    [TestMethod]
    public void EsbConstantsMatchRfc9864AssignedValues()
    {
        //RFC 9864 / IANA COSE Algorithms: ESB256 = -265, ESB320 = -266, ESB384 = -267, ESB512 = -268.
        int esb256 = WellKnownCoseAlgorithms.Esb256;
        int esb320 = WellKnownCoseAlgorithms.Esb320;
        int esb384 = WellKnownCoseAlgorithms.Esb384;
        int esb512 = WellKnownCoseAlgorithms.Esb512;

        Assert.AreEqual(-265, esb256);
        Assert.AreEqual(-266, esb320);
        Assert.AreEqual(-267, esb384);
        Assert.AreEqual(-268, esb512);
    }


    [TestMethod]
    public void EspIsHelpersIdentifyOnlyTheirOwnVariant()
    {
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsp256(WellKnownCoseAlgorithms.Esp256));
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsp384(WellKnownCoseAlgorithms.Esp384));
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsp512(WellKnownCoseAlgorithms.Esp512));

        //Cross-checks: each helper rejects the others' values.
        Assert.IsFalse(WellKnownCoseAlgorithms.IsEsp256(WellKnownCoseAlgorithms.Esp384));
        Assert.IsFalse(WellKnownCoseAlgorithms.IsEsp384(WellKnownCoseAlgorithms.Esp512));
        Assert.IsFalse(WellKnownCoseAlgorithms.IsEsp512(WellKnownCoseAlgorithms.Esp256));

        //Cross-checks: ES (non-fully-specified) does NOT satisfy ESP helpers.
        Assert.IsFalse(WellKnownCoseAlgorithms.IsEsp256(WellKnownCoseAlgorithms.Es256));
    }


    [TestMethod]
    public void EsbIsHelpersIdentifyOnlyTheirOwnVariant()
    {
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsb256(WellKnownCoseAlgorithms.Esb256));
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsb320(WellKnownCoseAlgorithms.Esb320));
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsb384(WellKnownCoseAlgorithms.Esb384));
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsb512(WellKnownCoseAlgorithms.Esb512));

        Assert.IsFalse(WellKnownCoseAlgorithms.IsEsb256(WellKnownCoseAlgorithms.Esb320));
        Assert.IsFalse(WellKnownCoseAlgorithms.IsEsb384(WellKnownCoseAlgorithms.Esb512));
    }


    [TestMethod]
    public void IsEspFamilyHelperMatchesAllEspVariants()
    {
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsp(WellKnownCoseAlgorithms.Esp256));
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsp(WellKnownCoseAlgorithms.Esp384));
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsp(WellKnownCoseAlgorithms.Esp512));

        Assert.IsFalse(WellKnownCoseAlgorithms.IsEsp(WellKnownCoseAlgorithms.Es256));
        Assert.IsFalse(WellKnownCoseAlgorithms.IsEsp(WellKnownCoseAlgorithms.Esb256));
    }


    [TestMethod]
    public void IsEsbFamilyHelperMatchesAllEsbVariants()
    {
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsb(WellKnownCoseAlgorithms.Esb256));
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsb(WellKnownCoseAlgorithms.Esb320));
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsb(WellKnownCoseAlgorithms.Esb384));
        Assert.IsTrue(WellKnownCoseAlgorithms.IsEsb(WellKnownCoseAlgorithms.Esb512));

        Assert.IsFalse(WellKnownCoseAlgorithms.IsEsb(WellKnownCoseAlgorithms.Esp256));
    }


    //ESP→P-curve tag converter wiring (CryptoFormatConversions.Default-
    //CoseToTagConverter). ESP variants share key material with the
    //non-fully-specified ES variants, so the converter maps them onto
    //the same P-curve key tags.

    [TestMethod]
    public void DefaultCoseToTagConverterMapsEspSigningToPCurvePrivateKeys()
    {
        Tag esp256Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esp256, Purpose.Signing);
        Tag esp384Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esp384, Purpose.Signing);
        Tag esp512Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esp512, Purpose.Signing);

        Assert.AreEqual(CryptoTags.P256PrivateKey, esp256Tag);
        Assert.AreEqual(CryptoTags.P384PrivateKey, esp384Tag);
        Assert.AreEqual(CryptoTags.P521PrivateKey, esp512Tag);
    }


    [TestMethod]
    public void DefaultCoseToTagConverterMapsEspVerificationToPCurvePublicKeys()
    {
        Tag esp256Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esp256, Purpose.Verification);
        Tag esp384Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esp384, Purpose.Verification);
        Tag esp512Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esp512, Purpose.Verification);

        Assert.AreEqual(CryptoTags.P256PublicKey, esp256Tag);
        Assert.AreEqual(CryptoTags.P384PublicKey, esp384Tag);
        Assert.AreEqual(CryptoTags.P521PublicKey, esp512Tag);
    }


    [TestMethod]
    public void DefaultCoseToTagConverterMapsEsbSigningToBrainpoolPrivateKeys()
    {
        //Q.2 lands the Brainpool curve tags and the BouncyCastle backend, so
        //ESB COSE identifiers now resolve to the corresponding Brainpool
        //CryptoTags entries instead of throwing.
        Tag esb256Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esb256, Purpose.Signing);
        Tag esb320Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esb320, Purpose.Signing);
        Tag esb384Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esb384, Purpose.Signing);
        Tag esb512Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esb512, Purpose.Signing);

        Assert.AreEqual(CryptoTags.BrainpoolP256r1PrivateKey, esb256Tag);
        Assert.AreEqual(CryptoTags.BrainpoolP320r1PrivateKey, esb320Tag);
        Assert.AreEqual(CryptoTags.BrainpoolP384r1PrivateKey, esb384Tag);
        Assert.AreEqual(CryptoTags.BrainpoolP512r1PrivateKey, esb512Tag);
    }


    [TestMethod]
    public void DefaultCoseToTagConverterMapsEsbVerificationToBrainpoolPublicKeys()
    {
        Tag esb256Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esb256, Purpose.Verification);
        Tag esb320Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esb320, Purpose.Verification);
        Tag esb384Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esb384, Purpose.Verification);
        Tag esb512Tag = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esb512, Purpose.Verification);

        Assert.AreEqual(CryptoTags.BrainpoolP256r1PublicKey, esb256Tag);
        Assert.AreEqual(CryptoTags.BrainpoolP320r1PublicKey, esb320Tag);
        Assert.AreEqual(CryptoTags.BrainpoolP384r1PublicKey, esb384Tag);
        Assert.AreEqual(CryptoTags.BrainpoolP512r1PublicKey, esb512Tag);
    }


    [TestMethod]
    public void EspAndEsCoseToTagConvertersAgreeOnKeyMaterial()
    {
        //ESP and ES variants for the same curve carry the same key
        //material — the converter must map them onto identical tags.
        Assert.AreEqual(
            CryptoFormatConversions.DefaultCoseToTagConverter(
                WellKnownCoseAlgorithms.Es256, Purpose.Signing),
            CryptoFormatConversions.DefaultCoseToTagConverter(
                WellKnownCoseAlgorithms.Esp256, Purpose.Signing));
        Assert.AreEqual(
            CryptoFormatConversions.DefaultCoseToTagConverter(
                WellKnownCoseAlgorithms.Es512, Purpose.Verification),
            CryptoFormatConversions.DefaultCoseToTagConverter(
                WellKnownCoseAlgorithms.Esp512, Purpose.Verification));
    }
}
