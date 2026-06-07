using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests for the Q.2 Brainpool wiring in
/// <see cref="CryptoFormatConversions"/> — JWA→Tag (inbound) and Tag→JWA /
/// Tag→COSE (outbound). The COSE→Tag direction lives in
/// <c>WellKnownCoseAlgorithmsRfc9784Tests</c> alongside the Q.1 ESP coverage.
/// </summary>
/// <remarks>
/// <para>
/// RFC 9784 / draft-ietf-jose-fully-specified-algorithms binds each Brainpool
/// r1 curve to a specific hash family. The converter must produce signing
/// keys for <see cref="Purpose.Signing"/> and verification keys for
/// <see cref="Purpose.Verification"/>; the curve discriminator is carried by
/// the JWA name (<c>ESB256</c>/<c>ESB320</c>/<c>ESB384</c>/<c>ESB512</c>).
/// </para>
/// </remarks>
[TestClass]
internal sealed class CryptoFormatConversionsBrainpoolTests
{
    [TestMethod]
    public void DefaultJwaToTagConverterMapsEsbSigningToBrainpoolPrivateKeys()
    {
        Tag esb256 = CryptoFormatConversions.DefaultJwaToTagConverter(
            WellKnownJwaValues.Esb256, Purpose.Signing);
        Tag esb320 = CryptoFormatConversions.DefaultJwaToTagConverter(
            WellKnownJwaValues.Esb320, Purpose.Signing);
        Tag esb384 = CryptoFormatConversions.DefaultJwaToTagConverter(
            WellKnownJwaValues.Esb384, Purpose.Signing);
        Tag esb512 = CryptoFormatConversions.DefaultJwaToTagConverter(
            WellKnownJwaValues.Esb512, Purpose.Signing);

        Assert.AreEqual(CryptoTags.BrainpoolP256r1PrivateKey, esb256);
        Assert.AreEqual(CryptoTags.BrainpoolP320r1PrivateKey, esb320);
        Assert.AreEqual(CryptoTags.BrainpoolP384r1PrivateKey, esb384);
        Assert.AreEqual(CryptoTags.BrainpoolP512r1PrivateKey, esb512);
    }


    [TestMethod]
    public void DefaultJwaToTagConverterMapsEsbVerificationToBrainpoolPublicKeys()
    {
        Tag esb256 = CryptoFormatConversions.DefaultJwaToTagConverter(
            WellKnownJwaValues.Esb256, Purpose.Verification);
        Tag esb320 = CryptoFormatConversions.DefaultJwaToTagConverter(
            WellKnownJwaValues.Esb320, Purpose.Verification);
        Tag esb384 = CryptoFormatConversions.DefaultJwaToTagConverter(
            WellKnownJwaValues.Esb384, Purpose.Verification);
        Tag esb512 = CryptoFormatConversions.DefaultJwaToTagConverter(
            WellKnownJwaValues.Esb512, Purpose.Verification);

        Assert.AreEqual(CryptoTags.BrainpoolP256r1PublicKey, esb256);
        Assert.AreEqual(CryptoTags.BrainpoolP320r1PublicKey, esb320);
        Assert.AreEqual(CryptoTags.BrainpoolP384r1PublicKey, esb384);
        Assert.AreEqual(CryptoTags.BrainpoolP512r1PublicKey, esb512);
    }


    [TestMethod]
    public void DefaultTagToJwaConverterMapsBrainpoolTagsToEsbStrings()
    {
        Assert.AreEqual(WellKnownJwaValues.Esb256,
            CryptoFormatConversions.DefaultTagToJwaConverter(CryptoTags.BrainpoolP256r1PrivateKey));
        Assert.AreEqual(WellKnownJwaValues.Esb320,
            CryptoFormatConversions.DefaultTagToJwaConverter(CryptoTags.BrainpoolP320r1PublicKey));
        Assert.AreEqual(WellKnownJwaValues.Esb384,
            CryptoFormatConversions.DefaultTagToJwaConverter(CryptoTags.BrainpoolP384r1PrivateKey));
        Assert.AreEqual(WellKnownJwaValues.Esb512,
            CryptoFormatConversions.DefaultTagToJwaConverter(CryptoTags.BrainpoolP512r1PublicKey));
    }


    [TestMethod]
    public void DefaultTagToCoseConverterMapsBrainpoolTagsToEsbIdentifiers()
    {
        Assert.AreEqual(WellKnownCoseAlgorithms.Esb256,
            CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.BrainpoolP256r1PrivateKey));
        Assert.AreEqual(WellKnownCoseAlgorithms.Esb320,
            CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.BrainpoolP320r1PublicKey));
        Assert.AreEqual(WellKnownCoseAlgorithms.Esb384,
            CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.BrainpoolP384r1PrivateKey));
        Assert.AreEqual(WellKnownCoseAlgorithms.Esb512,
            CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.BrainpoolP512r1PublicKey));
    }


    [TestMethod]
    public void EsbCoseAndJwaConvertersAgreeOnTagIdentity()
    {
        //The JWA "ESB256" and COSE -261 carry the same algorithm semantics —
        //the converter must produce the same tag from either path.
        Tag fromJwa = CryptoFormatConversions.DefaultJwaToTagConverter(
            WellKnownJwaValues.Esb256, Purpose.Verification);
        Tag fromCose = CryptoFormatConversions.DefaultCoseToTagConverter(
            WellKnownCoseAlgorithms.Esb256, Purpose.Verification);

        Assert.AreEqual(fromJwa, fromCose);
    }


    [TestMethod]
    public void GetAlgorithmNameRoundTripsEsbAndEspIdentifiers()
    {
        //WellKnownCoseAlgorithms.GetAlgorithmName must produce the JWA spelling
        //that draft-ietf-jose-fully-specified-algorithms registers — same
        //string in both directions of the JOSE/COSE bridge.
        Assert.AreEqual("ESP256", WellKnownCoseAlgorithms.GetAlgorithmName(WellKnownCoseAlgorithms.Esp256));
        Assert.AreEqual("ESP384", WellKnownCoseAlgorithms.GetAlgorithmName(WellKnownCoseAlgorithms.Esp384));
        Assert.AreEqual("ESP512", WellKnownCoseAlgorithms.GetAlgorithmName(WellKnownCoseAlgorithms.Esp512));
        Assert.AreEqual(WellKnownJwaValues.Esb256, WellKnownCoseAlgorithms.GetAlgorithmName(WellKnownCoseAlgorithms.Esb256));
        Assert.AreEqual(WellKnownJwaValues.Esb320, WellKnownCoseAlgorithms.GetAlgorithmName(WellKnownCoseAlgorithms.Esb320));
        Assert.AreEqual(WellKnownJwaValues.Esb384, WellKnownCoseAlgorithms.GetAlgorithmName(WellKnownCoseAlgorithms.Esb384));
        Assert.AreEqual(WellKnownJwaValues.Esb512, WellKnownCoseAlgorithms.GetAlgorithmName(WellKnownCoseAlgorithms.Esb512));
    }
}
