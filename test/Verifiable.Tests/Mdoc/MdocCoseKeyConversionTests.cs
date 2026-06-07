using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// Tests for the M.2 <see cref="CoseKeyToAlgorithmDelegate"/> default
/// implementation in <see cref="CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter"/>.
/// </summary>
/// <remarks>
/// <para>
/// The delegate's job is to bridge a parsed COSE_Key (kty, crv) tuple onto
/// the internal <see cref="Tag"/> registry the rest of the crypto pipeline
/// resolves through. The cases mirror what shows up inside MSO
/// <c>DeviceKeyInfo.deviceKey</c> structures: P-256/384/521, secp256k1,
/// Brainpool r1 family (all under kty=EC2), and Ed25519 / X25519 (under
/// kty=OKP).
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocCoseKeyConversionTests
{
    [TestMethod]
    public void Ec2P256VerificationMapsToP256PublicKeyTag()
    {
        Tag tag = CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(
            kty: 2, curve: 1, purpose: Purpose.Verification);

        Assert.AreEqual(CryptoTags.P256PublicKey, tag);
    }


    [TestMethod]
    public void Ec2P384VerificationMapsToP384PublicKeyTag()
    {
        Tag tag = CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(
            kty: 2, curve: 2, purpose: Purpose.Verification);

        Assert.AreEqual(CryptoTags.P384PublicKey, tag);
    }


    [TestMethod]
    public void Ec2P521VerificationMapsToP521PublicKeyTag()
    {
        Tag tag = CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(
            kty: 2, curve: 3, purpose: Purpose.Verification);

        Assert.AreEqual(CryptoTags.P521PublicKey, tag);
    }


    [TestMethod]
    public void Ec2Secp256k1VerificationMapsToSecp256k1PublicKeyTag()
    {
        Tag tag = CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(
            kty: 2, curve: 8, purpose: Purpose.Verification);

        Assert.AreEqual(CryptoTags.Secp256k1PublicKey, tag);
    }


    [TestMethod]
    public void Ec2BrainpoolFamilyVerificationMapsToCorrespondingTags()
    {
        //COSE Elliptic Curves registry assignments for Brainpool — the M.2
        //delegate plugs into the Q.2 Brainpool wiring landed earlier so the
        //EU domestic curves resolve through one path with the NIST ones.
        Assert.AreEqual(CryptoTags.BrainpoolP256r1PublicKey,
            CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(2, 256, Purpose.Verification));
        Assert.AreEqual(CryptoTags.BrainpoolP320r1PublicKey,
            CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(2, 257, Purpose.Verification));
        Assert.AreEqual(CryptoTags.BrainpoolP384r1PublicKey,
            CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(2, 258, Purpose.Verification));
        Assert.AreEqual(CryptoTags.BrainpoolP512r1PublicKey,
            CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(2, 259, Purpose.Verification));
    }


    [TestMethod]
    public void OkpEd25519MapsToEd25519PublicKeyTagForVerification()
    {
        Tag tag = CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(
            kty: 1, curve: 6, purpose: Purpose.Verification);

        Assert.AreEqual(CryptoTags.Ed25519PublicKey, tag);
    }


    [TestMethod]
    public void OkpX25519MapsToX25519PublicKeyTagForExchange()
    {
        Tag tag = CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(
            kty: 1, curve: 4, purpose: Purpose.Exchange);

        Assert.AreEqual(CryptoTags.X25519PublicKey, tag);
    }


    [TestMethod]
    public void Ec2P256SigningMapsToPrivateKeyTagSymmetricToVerification()
    {
        //A device-side path that needs the private-key tag (e.g. constructing
        //a key handle from a parsed COSE_Key with d-parameter present) hits
        //the signing arm of the switch.
        Tag tag = CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(
            kty: 2, curve: 1, purpose: Purpose.Signing);

        Assert.AreEqual(CryptoTags.P256PrivateKey, tag);
    }


    [TestMethod]
    public void UnknownCurveSurfacesNotSupportedException()
    {
        //An unrecognised crv must not fall through to a generic tag — the
        //caller has to know we didn't understand the COSE_Key.
        Assert.ThrowsExactly<NotSupportedException>(() =>
            CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(
                kty: 2, curve: 999, purpose: Purpose.Verification));
    }


    [TestMethod]
    public void RsaKtySurfacesNotSupportedExceptionInsteadOfGuessingSize()
    {
        //kty=3 (RSA) lacks a size discriminator at the COSE_Key map level;
        //the delegate cannot honestly pick between Rsa2048 and Rsa4096
        //without inspecting the modulus length. The contract: raise so the
        //caller resolves size from the n parameter downstream.
        Assert.ThrowsExactly<NotSupportedException>(() =>
            CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(
                kty: 3, curve: null, purpose: Purpose.Verification));
    }
}
