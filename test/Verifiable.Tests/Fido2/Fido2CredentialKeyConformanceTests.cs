using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Reader-path tests for the WebAuthn L3 credential public key conformance clauses
/// (<see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">section 6.5.1: Attested
/// Credential Data</see>, <see href="https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier">section 5.8.5:
/// Cryptographic Algorithm Identifier</see>) enforced at the parse boundary in
/// <see cref="AuthenticatorDataReader.Read"/>: every malformed shape is driven through the real reader over
/// crafted CBOR bytes, and every failure asserted is the exact <see cref="Fido2FormatException"/> the
/// enforcement raises. <see cref="Verifiable.Tests.JCose.CoseKeyConformanceTests"/> covers the underlying
/// <see cref="CoseKeyConformance"/> table in isolation.
/// </summary>
[TestClass]
internal sealed class Fido2CredentialKeyConformanceTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A credential public key carrying the optional <c>kid</c> label (2) alongside the required EC2
    /// parameters is rejected: WebAuthn L3 section 6.5.1 permits only <c>alg</c> plus the REQUIRED
    /// key-type parameters.
    /// </summary>
    [TestMethod]
    public void ExtraOptionalKidLabelIsRejected()
    {
        (byte[] x, byte[] y) = CreateEcPoint(CoseKeyCurves.P256);
        byte[] credentialPublicKeyCbor = EncodeRawCoseKey(
            (CoseKeyParameters.Kty, IntValue(CoseKeyTypes.Ec2)),
            (CoseKeyParameters.Alg, IntValue(WellKnownCoseAlgorithms.Es256)),
            (CoseKeyParameters.Crv, IntValue(CoseKeyCurves.P256)),
            (CoseKeyParameters.X, BytesValue(x)),
            (CoseKeyParameters.Y, BytesValue(y)),
            (CoseKeyParameters.Kid, BytesValue([0x01, 0x02])));

        Fido2FormatException exception = AssertRejectedAttestedCredentialData(credentialPublicKeyCbor);

        Assert.IsTrue(exception.Message.Contains($"label {CoseKeyParameters.Kid}", StringComparison.Ordinal), $"The message must name the offending label; was: {exception.Message}");
    }


    /// <summary>
    /// A credential public key with no <c>alg</c> parameter is rejected: WebAuthn L3 section 6.5.1 requires
    /// the COSE_Key-encoded credential public key to contain <c>alg</c>.
    /// </summary>
    [TestMethod]
    public void MissingAlgIsRejected()
    {
        (byte[] x, byte[] y) = CreateEcPoint(CoseKeyCurves.P256);
        byte[] credentialPublicKeyCbor = EncodeRawCoseKey(
            (CoseKeyParameters.Kty, IntValue(CoseKeyTypes.Ec2)),
            (CoseKeyParameters.Crv, IntValue(CoseKeyCurves.P256)),
            (CoseKeyParameters.X, BytesValue(x)),
            (CoseKeyParameters.Y, BytesValue(y)));

        Fido2FormatException exception = AssertRejectedAttestedCredentialData(credentialPublicKeyCbor);

        Assert.IsTrue(exception.Message.Contains($"required label {CoseKeyParameters.Alg}", StringComparison.Ordinal), $"The message must name the missing alg label; was: {exception.Message}");
    }


    /// <summary>A credential public key carrying the same label twice is rejected.</summary>
    [TestMethod]
    public void DuplicateLabelIsRejected()
    {
        (byte[] x, byte[] y) = CreateEcPoint(CoseKeyCurves.P256);
        byte[] credentialPublicKeyCbor = EncodeRawCoseKey(
            (CoseKeyParameters.Kty, IntValue(CoseKeyTypes.Ec2)),
            (CoseKeyParameters.Alg, IntValue(WellKnownCoseAlgorithms.Es256)),
            (CoseKeyParameters.Alg, IntValue(WellKnownCoseAlgorithms.Es256)),
            (CoseKeyParameters.Crv, IntValue(CoseKeyCurves.P256)),
            (CoseKeyParameters.X, BytesValue(x)),
            (CoseKeyParameters.Y, BytesValue(y)));

        Fido2FormatException exception = AssertRejectedAttestedCredentialData(credentialPublicKeyCbor);

        Assert.IsTrue(exception.Message.Contains($"label {CoseKeyParameters.Alg} more than once", StringComparison.Ordinal), $"The message must name the repeated label; was: {exception.Message}");
    }


    /// <summary>An EC2 credential public key missing its required <c>y</c> coordinate label is rejected.</summary>
    [TestMethod]
    public void Ec2MissingYIsRejected()
    {
        (byte[] x, byte[] _) = CreateEcPoint(CoseKeyCurves.P256);
        byte[] credentialPublicKeyCbor = EncodeRawCoseKey(
            (CoseKeyParameters.Kty, IntValue(CoseKeyTypes.Ec2)),
            (CoseKeyParameters.Alg, IntValue(WellKnownCoseAlgorithms.Es256)),
            (CoseKeyParameters.Crv, IntValue(CoseKeyCurves.P256)),
            (CoseKeyParameters.X, BytesValue(x)));

        Fido2FormatException exception = AssertRejectedAttestedCredentialData(credentialPublicKeyCbor);

        Assert.IsTrue(exception.Message.Contains($"required label {CoseKeyParameters.Y}", StringComparison.Ordinal), $"The message must name the missing y label; was: {exception.Message}");
    }


    /// <summary>
    /// An RSA credential public key missing its required <c>e</c> (exponent) label is rejected. Driven
    /// through a stub <see cref="ReadCredentialPublicKeyDelegate"/> rather than
    /// <see cref="TestCredentialPublicKeyReader"/>: <see cref="Verifiable.Cbor.Mdoc.MdocCborCoseKeyReader"/>
    /// cannot parse RSA COSE_Keys at all today (label -1 collides with <c>crv</c> and is always read as an
    /// integer, so RSA's byte-string <c>n</c> throws before this test's enforcement is even reached) — a
    /// confirmed, separate, pre-existing defect this wave leaves deferred to the CBOR codec switch. The
    /// stub exercises the real <see cref="AuthenticatorDataReader.Read"/> conformance enforcement this test
    /// targets without depending on that unrelated, out-of-scope defect.
    /// </summary>
    [TestMethod]
    public void RsaMissingEIsRejected()
    {
        (byte[] modulus, byte[] _) = CreateRsaComponents();
        var incompleteRsaKey = new CoseKey(kty: CoseKeyTypes.Rsa, alg: WellKnownCoseAlgorithms.Rs256, n: modulus);
        ReadCredentialPublicKeyDelegate stubReader = source =>
            new CredentialPublicKeyReadResult(incompleteRsaKey, 1, [CoseKeyParameters.Kty, CoseKeyParameters.Alg, CoseKeyParameters.RsaN]);

        Fido2FormatException exception = AssertRejectedAttestedCredentialData(stubReader);

        Assert.IsTrue(exception.Message.Contains($"required label {CoseKeyParameters.RsaE}", StringComparison.Ordinal), $"The message must name the missing e label; was: {exception.Message}");
    }


    /// <summary>ES256 (-7) paired with the P-384 curve rather than its pinned P-256 is rejected.</summary>
    [TestMethod]
    public void Es256WithP384CrvIsRejected()
    {
        (byte[] x, byte[] y) = CreateEcPoint(CoseKeyCurves.P384);
        byte[] credentialPublicKeyCbor = EncodeRawCoseKey(
            (CoseKeyParameters.Kty, IntValue(CoseKeyTypes.Ec2)),
            (CoseKeyParameters.Alg, IntValue(WellKnownCoseAlgorithms.Es256)),
            (CoseKeyParameters.Crv, IntValue(CoseKeyCurves.P384)),
            (CoseKeyParameters.X, BytesValue(x)),
            (CoseKeyParameters.Y, BytesValue(y)));

        Fido2FormatException exception = AssertRejectedAttestedCredentialData(credentialPublicKeyCbor);

        Assert.IsTrue(exception.Message.Contains($"Algorithm {WellKnownCoseAlgorithms.Es256} is not consistent", StringComparison.Ordinal), $"The message must name the offending algorithm and the inconsistency; was: {exception.Message}");
    }


    /// <summary>
    /// An OKP credential public key declaring EdDSA (-8) but a curve other than its pinned Ed25519 (6) is
    /// rejected — closes tally clause 4354.
    /// </summary>
    [TestMethod]
    public void OkpEdDsaWithWrongCrvIsRejected()
    {
        byte[] x = CreateX25519PublicKeyBytes();
        byte[] credentialPublicKeyCbor = EncodeRawCoseKey(
            (CoseKeyParameters.Kty, IntValue(CoseKeyTypes.Okp)),
            (CoseKeyParameters.Alg, IntValue(WellKnownCoseAlgorithms.EdDsa)),
            (CoseKeyParameters.Crv, IntValue(CoseKeyCurves.X25519)),
            (CoseKeyParameters.X, BytesValue(x)));

        Fido2FormatException exception = AssertRejectedAttestedCredentialData(credentialPublicKeyCbor);

        Assert.IsTrue(exception.Message.Contains($"Algorithm {WellKnownCoseAlgorithms.EdDsa} is not consistent", StringComparison.Ordinal), $"The message must name the offending algorithm and the inconsistency; was: {exception.Message}");
    }


    /// <summary>
    /// Every algorithm the WebAuthn L3 section 5.8.5 uncompressed-point clause set covers — the legacy ES*
    /// family and the RFC 9864 fully-specified ESP* family — is rejected when its EC2 credential public key
    /// encodes <c>y</c> as the compressed sign bit rather than the uncompressed coordinate.
    /// </summary>
    [TestMethod]
    [DataRow(WellKnownCoseAlgorithms.Es256, CoseKeyCurves.P256)]
    [DataRow(WellKnownCoseAlgorithms.Es384, CoseKeyCurves.P384)]
    [DataRow(WellKnownCoseAlgorithms.Es512, CoseKeyCurves.P521)]
    [DataRow(WellKnownCoseAlgorithms.Esp256, CoseKeyCurves.P256)]
    [DataRow(WellKnownCoseAlgorithms.Esp384, CoseKeyCurves.P384)]
    [DataRow(WellKnownCoseAlgorithms.Esp512, CoseKeyCurves.P521)]
    public void CompressedPointEncodingIsRejectedForEachUncompressedOnlyAlgorithm(int algorithm, int curve)
    {
        (byte[] x, byte[] _) = CreateEcPoint(curve);
        byte[] credentialPublicKeyCbor = EncodeRawCoseKey(
            (CoseKeyParameters.Kty, IntValue(CoseKeyTypes.Ec2)),
            (CoseKeyParameters.Alg, IntValue(algorithm)),
            (CoseKeyParameters.Crv, IntValue(curve)),
            (CoseKeyParameters.X, BytesValue(x)),
            (CoseKeyParameters.Y, BoolValue(true)));

        Fido2FormatException exception = AssertRejectedAttestedCredentialData(credentialPublicKeyCbor);

        Assert.IsTrue(exception.Message.Contains($"Algorithm {algorithm} MUST NOT use the compressed", StringComparison.Ordinal), $"The message must name the offending algorithm and the compressed-point violation; was: {exception.Message}");
    }


    /// <summary>A well-formed EC2 credential public key (P-256, ES256, alg present, no extras) is accepted.</summary>
    [TestMethod]
    public void WellFormedEc2CredentialPublicKeyIsAccepted()
    {
        using AuthenticatorData parsed = AuthenticatorDataReader.Read(
            BuildAuthenticatorData(CreateRpIdHash(), flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit, signCount: 0, attestedCredentialData: BuildAttestedCredentialData(Guid.NewGuid(), [0x01], EncodeP256CoseKey())),
            TestCredentialPublicKeyReader,
            BaseMemoryPool.Shared);

        Assert.IsNotNull(parsed.AttestedCredentialData);
        Assert.AreEqual(CoseKeyTypes.Ec2, parsed.AttestedCredentialData.CredentialPublicKey.Kty);
    }


    /// <summary>A well-formed OKP credential public key (Ed25519, EdDSA, alg present, no extras) is accepted.</summary>
    [TestMethod]
    public void WellFormedOkpCredentialPublicKeyIsAccepted()
    {
        byte[] x = CreateEd25519PublicKeyBytes();
        byte[] credentialPublicKeyCbor = EncodeRawCoseKey(
            (CoseKeyParameters.Kty, IntValue(CoseKeyTypes.Okp)),
            (CoseKeyParameters.Alg, IntValue(WellKnownCoseAlgorithms.EdDsa)),
            (CoseKeyParameters.Crv, IntValue(CoseKeyCurves.Ed25519)),
            (CoseKeyParameters.X, BytesValue(x)));

        using AuthenticatorData parsed = AuthenticatorDataReader.Read(
            BuildAuthenticatorData(CreateRpIdHash(), flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit, signCount: 0, attestedCredentialData: BuildAttestedCredentialData(Guid.NewGuid(), [0x01], credentialPublicKeyCbor)),
            TestCredentialPublicKeyReader,
            BaseMemoryPool.Shared);

        Assert.IsNotNull(parsed.AttestedCredentialData);
        Assert.AreEqual(CoseKeyTypes.Okp, parsed.AttestedCredentialData.CredentialPublicKey.Kty);
    }


    /// <summary>
    /// A well-formed RSA credential public key (RS256, alg present, no extras) is accepted. Driven through
    /// a stub <see cref="ReadCredentialPublicKeyDelegate"/> rather than <see cref="TestCredentialPublicKeyReader"/>
    /// for the same reason as <see cref="RsaMissingEIsRejected"/>: the CBOR reader cannot parse an RSA
    /// COSE_Key at all today, well-formed or not.
    /// </summary>
    [TestMethod]
    public void WellFormedRsaCredentialPublicKeyIsAccepted()
    {
        (byte[] modulus, byte[] exponent) = CreateRsaComponents();
        var rsaKey = new CoseKey(kty: CoseKeyTypes.Rsa, alg: WellKnownCoseAlgorithms.Rs256, n: modulus, e: exponent);
        ReadCredentialPublicKeyDelegate stubReader = source =>
            new CredentialPublicKeyReadResult(rsaKey, 1, [CoseKeyParameters.Kty, CoseKeyParameters.Alg, CoseKeyParameters.RsaN, CoseKeyParameters.RsaE]);

        using AuthenticatorData parsed = AuthenticatorDataReader.Read(
            BuildAuthenticatorData(CreateRpIdHash(), flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit, signCount: 0, attestedCredentialData: BuildAttestedCredentialData(Guid.NewGuid(), [0x01], [0xFF])),
            stubReader,
            BaseMemoryPool.Shared);

        Assert.IsNotNull(parsed.AttestedCredentialData);
        Assert.AreEqual(CoseKeyTypes.Rsa, parsed.AttestedCredentialData.CredentialPublicKey.Kty);
    }


    /// <summary>
    /// Wraps <paramref name="credentialPublicKeyCbor"/> in a minimum attested-credential-data / authenticator-data
    /// layout and asserts that <see cref="AuthenticatorDataReader.Read"/> rejects it with exactly
    /// <see cref="Fido2FormatException"/>, using the real <see cref="TestCredentialPublicKeyReader"/> CBOR codec.
    /// </summary>
    /// <param name="credentialPublicKeyCbor">The crafted COSE_Key CBOR bytes to embed as the credential public key.</param>
    /// <returns>The thrown exception, for message-content assertions.</returns>
    private static Fido2FormatException AssertRejectedAttestedCredentialData(byte[] credentialPublicKeyCbor) =>
        AssertRejectedAttestedCredentialData(TestCredentialPublicKeyReader, credentialPublicKeyCbor);


    /// <summary>
    /// Wraps a one-byte placeholder credential public key in a minimum attested-credential-data /
    /// authenticator-data layout and asserts that <see cref="AuthenticatorDataReader.Read"/> rejects it with
    /// exactly <see cref="Fido2FormatException"/>, using <paramref name="readCredentialPublicKey"/> in place
    /// of the real CBOR codec.
    /// </summary>
    /// <param name="readCredentialPublicKey">The stub codec under test.</param>
    /// <returns>The thrown exception, for message-content assertions.</returns>
    private static Fido2FormatException AssertRejectedAttestedCredentialData(ReadCredentialPublicKeyDelegate readCredentialPublicKey) =>
        AssertRejectedAttestedCredentialData(readCredentialPublicKey, [0xFF]);


    /// <summary>
    /// Wraps <paramref name="credentialPublicKeyBytes"/> in a minimum attested-credential-data /
    /// authenticator-data layout and asserts that <see cref="AuthenticatorDataReader.Read"/> rejects it with
    /// exactly <see cref="Fido2FormatException"/> under <paramref name="readCredentialPublicKey"/>.
    /// </summary>
    /// <param name="readCredentialPublicKey">The codec (real or stub) under test.</param>
    /// <param name="credentialPublicKeyBytes">The bytes to embed as the credential public key.</param>
    /// <returns>The thrown exception, for message-content assertions.</returns>
    private static Fido2FormatException AssertRejectedAttestedCredentialData(ReadCredentialPublicKeyDelegate readCredentialPublicKey, byte[] credentialPublicKeyBytes)
    {
        byte[] attestedCredentialData = BuildAttestedCredentialData(Guid.NewGuid(), [0x01], credentialPublicKeyBytes);
        byte[] authenticatorData = BuildAuthenticatorData(CreateRpIdHash(), flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit, signCount: 0, attestedCredentialData: attestedCredentialData);

        return Assert.ThrowsExactly<Fido2FormatException>(
            () => AuthenticatorDataReader.Read(authenticatorData, readCredentialPublicKey, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// Mints fresh EC key material on the COSE curve <paramref name="coseCurve"/> identifies, recovers its
    /// uncompressed <c>x</c>/<c>y</c> coordinates, and disposes the key material before returning — the
    /// coordinates alone, not the key object, cross into the crafted COSE_Key vector.
    /// </summary>
    /// <param name="coseCurve">The COSE curve identifier (<see cref="CoseKeyCurves"/>).</param>
    /// <returns>The recovered <c>x</c> and <c>y</c> coordinates.</returns>
    private static (byte[] X, byte[] Y) CreateEcPoint(int coseCurve)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = coseCurve switch
        {
            CoseKeyCurves.P256 => TestKeyMaterialProvider.CreateP256KeyMaterial(),
            CoseKeyCurves.P384 => TestKeyMaterialProvider.CreateP384KeyMaterial(),
            CoseKeyCurves.P521 => TestKeyMaterialProvider.CreateP521KeyMaterial(),
            _ => throw new NotSupportedException($"No test key material source for COSE curve {coseCurve}.")
        };
        try
        {
            EllipticCurveTypes curveType = coseCurve switch
            {
                CoseKeyCurves.P256 => EllipticCurveTypes.P256,
                CoseKeyCurves.P384 => EllipticCurveTypes.P384,
                CoseKeyCurves.P521 => EllipticCurveTypes.P521,
                _ => throw new NotSupportedException($"No curve mapping for COSE curve {coseCurve}.")
            };

            return DecodeEcPoint(keyMaterial.PublicKey.AsReadOnlySpan(), curveType);
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }


    /// <summary>Mints fresh Ed25519 key material and returns its raw public-key bytes, disposing the key material.</summary>
    /// <returns>The raw Ed25519 public-key bytes.</returns>
    private static byte[] CreateEd25519PublicKeyBytes()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        try
        {
            return keyMaterial.PublicKey.AsReadOnlySpan().ToArray();
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }


    /// <summary>Mints fresh X25519 key material and returns its raw public-key bytes, disposing the key material.</summary>
    /// <returns>The raw X25519 public-key bytes.</returns>
    private static byte[] CreateX25519PublicKeyBytes()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateX25519KeyMaterial();
        try
        {
            return keyMaterial.PublicKey.AsReadOnlySpan().ToArray();
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }


    /// <summary>Mints fresh RSA-2048 key material and recovers its DER modulus/exponent, disposing the key material.</summary>
    /// <returns>The unsigned big-endian modulus and public exponent.</returns>
    private static (byte[] Modulus, byte[] Exponent) CreateRsaComponents()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        try
        {
            return DecodeRsaPublicKeyComponents(keyMaterial.PublicKey.AsReadOnlyMemory());
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }
}
