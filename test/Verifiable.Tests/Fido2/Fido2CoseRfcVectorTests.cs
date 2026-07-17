using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Self-validating tests over EC key pairs printed in RFC 9052 (COSE Structures and Process) Appendix C.7
/// (COSE Keys; the P-256 key also appears worked into the single-ECDSA-signature example at Appendix C.2.1)
/// and the Ed25519 key printed in RFC 8037 (CFRG ECDH and Signatures in JOSE) Appendix A.1.
/// </summary>
/// <remarks>
/// <para>
/// Every vector is derived and checked BEFORE use: the public key is recomputed from the printed private
/// scalar via BouncyCastle and compared against the printed public coordinates. A mismatch means the
/// transcribed constant is wrong — the vector is dropped rather than shipped; see
/// <see cref="Es256PublicKeyDerivedFromThePrintedPrivateScalarMatchesThePrintedCoordinates"/>,
/// <see cref="Es512PublicKeyDerivedFromThePrintedPrivateScalarMatchesThePrintedCoordinates"/>, and
/// <see cref="EdDsaPublicKeyDerivedFromThePrintedPrivateSeedMatchesThePrintedPublicKey"/>.
/// </para>
/// <para>
/// The P-521 key (RFC 9052 Appendix C.7, key id <c>bilbo.baggins@hobbiton.example</c>) is cross-checked
/// against <see href="https://www.rfc-editor.org/rfc/rfc7520#section-3.4">RFC 7520 section 3.4, Figures
/// 1-2</see>, which prints the identical key material in JOSE JWK form — an independent second source for
/// the same byte values.
/// </para>
/// <para>
/// No RSA vector is included: no RFC in this family prints a full RSA-PSS key (modulus, both exponents, and
/// the CRT primes) with complete parameters, so RS/PS coverage is left to the freshly generated key material
/// the rest of the FIDO2 assertion suite already exercises.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Fido2CoseRfcVectorTests
{
    /// <summary>The base64url-encoded challenge a minted assertion embeds and the ceremony expects.</summary>
    private const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin a minted assertion embeds and the ceremony expects.</summary>
    private const string ValidOrigin = "https://relyingparty.example";

    /// <summary>
    /// RFC 9052 Appendix C.7.2 / C.2.1: the P-256 (<c>crv</c> 1) private key scalar <c>d</c> for the key
    /// printed there as <c>kid: "11"</c>.
    /// </summary>
    private const string Es256PrivateScalarBase64Url = "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM";

    /// <summary>RFC 9052 Appendix C.7.1 / C.2.1: the matching public <c>x</c> coordinate.</summary>
    private const string Es256PublicXBase64Url = "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8";

    /// <summary>RFC 9052 Appendix C.7.1 / C.2.1: the matching public <c>y</c> coordinate.</summary>
    private const string Es256PublicYBase64Url = "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4";

    /// <summary>
    /// RFC 9052 Appendix C.7.2: the P-521 (<c>crv</c> 3) private key scalar <c>d</c> for the key printed
    /// there as <c>kid: "bilbo.baggins@hobbiton.example"</c>. Cross-checked against RFC 7520 section 3.4,
    /// Figures 1-2, which print the identical key material in JOSE JWK form.
    /// </summary>
    private const string Es512PrivateScalarBase64Url = "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt";

    /// <summary>RFC 9052 Appendix C.7.1, cross-checked against RFC 7520 Figure 1: the matching public <c>x</c> coordinate.</summary>
    private const string Es512PublicXBase64Url = "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt";

    /// <summary>RFC 9052 Appendix C.7.1, cross-checked against RFC 7520 Figure 1: the matching public <c>y</c> coordinate.</summary>
    private const string Es512PublicYBase64Url = "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1";

    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8037#appendix-A.1">RFC 8037 Appendix A.1</see>: the
    /// Ed25519 private key seed <c>d</c>.
    /// </summary>
    private const string EdDsaPrivateSeedBase64Url = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

    /// <summary>RFC 8037 Appendix A.1: the matching Ed25519 public key <c>x</c>.</summary>
    private const string EdDsaPublicKeyBase64Url = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The public key recomputed from the printed P-256 private scalar (Appendix C.7.2 <c>d</c>) equals the
    /// printed public coordinates (Appendix C.7.1 <c>x</c>/<c>y</c>).
    /// </summary>
    [TestMethod]
    public void Es256PublicKeyDerivedFromThePrintedPrivateScalarMatchesThePrintedCoordinates()
    {
        (byte[] x, byte[] y) = DeriveEcPublicKeyCoordinates(Es256PrivateScalarBase64Url, "secp256r1");

        CollectionAssert.AreEqual(DecodeBase64Url(Es256PublicXBase64Url), x);
        CollectionAssert.AreEqual(DecodeBase64Url(Es256PublicYBase64Url), y);
    }


    /// <summary>
    /// The public key recomputed from the printed P-521 private scalar (Appendix C.7.2 <c>d</c>) equals the
    /// printed public coordinates (Appendix C.7.1 <c>x</c>/<c>y</c>).
    /// </summary>
    [TestMethod]
    public void Es512PublicKeyDerivedFromThePrintedPrivateScalarMatchesThePrintedCoordinates()
    {
        (byte[] x, byte[] y) = DeriveEcPublicKeyCoordinates(Es512PrivateScalarBase64Url, "secp521r1");

        CollectionAssert.AreEqual(DecodeBase64Url(Es512PublicXBase64Url), x);
        CollectionAssert.AreEqual(DecodeBase64Url(Es512PublicYBase64Url), y);
    }


    /// <summary>
    /// The Ed25519 public key recomputed from the printed private seed (RFC 8037 Appendix A.1 <c>d</c>)
    /// equals the printed public key (<c>x</c>).
    /// </summary>
    [TestMethod]
    public void EdDsaPublicKeyDerivedFromThePrintedPrivateSeedMatchesThePrintedPublicKey()
    {
        byte[] seed = DecodeBase64Url(EdDsaPrivateSeedBase64Url);

        byte[] derivedPublicKey = DeriveEd25519PublicKey(seed);

        CollectionAssert.AreEqual(DecodeBase64Url(EdDsaPublicKeyBase64Url), derivedPublicKey);
    }


    /// <summary>
    /// An assertion signed with the printed RFC 9052 P-256 private key verifies through the shipped
    /// <see cref="Fido2AssertionVerifier"/>, against a credential public key built from the printed
    /// coordinates.
    /// </summary>
    [TestMethod]
    public async Task Es256AssertionSignedWithThePrintedRfcKeyVerifiesThroughTheShippedPath()
    {
        byte[] privateScalar = DecodeBase64Url(Es256PrivateScalarBase64Url);
        var credentialPublicKey = new CoseKey(
            kty: CoseKeyTypes.Ec2,
            alg: WellKnownCoseAlgorithms.Es256,
            curve: CoseKeyCurves.P256,
            x: DecodeBase64Url(Es256PublicXBase64Url),
            y: DecodeBase64Url(Es256PublicYBase64Url));

        Fido2AssertionOutcome outcome = await MintAndVerifyAssertionAsync(
            privateScalar, credentialPublicKey, BouncyCastleCryptographicFunctions.SignP256Async, isEcdsaSignature: true, TestContext.CancellationToken);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsTrue(outcome.IsAcceptable);
    }


    /// <summary>
    /// An assertion signed with the printed RFC 9052 P-521 private key verifies through the shipped
    /// <see cref="Fido2AssertionVerifier"/>, against a credential public key built from the printed
    /// coordinates.
    /// </summary>
    [TestMethod]
    public async Task Es512AssertionSignedWithThePrintedRfcKeyVerifiesThroughTheShippedPath()
    {
        byte[] privateScalar = DecodeBase64Url(Es512PrivateScalarBase64Url);
        var credentialPublicKey = new CoseKey(
            kty: CoseKeyTypes.Ec2,
            alg: WellKnownCoseAlgorithms.Es512,
            curve: CoseKeyCurves.P521,
            x: DecodeBase64Url(Es512PublicXBase64Url),
            y: DecodeBase64Url(Es512PublicYBase64Url));

        Fido2AssertionOutcome outcome = await MintAndVerifyAssertionAsync(
            privateScalar, credentialPublicKey, BouncyCastleCryptographicFunctions.SignP521Async, isEcdsaSignature: true, TestContext.CancellationToken);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsTrue(outcome.IsAcceptable);
    }


    /// <summary>
    /// An assertion signed with the printed RFC 8037 Ed25519 private key verifies through the shipped
    /// <see cref="Fido2AssertionVerifier"/>, against a credential public key built from the printed key.
    /// </summary>
    [TestMethod]
    public async Task EdDsaAssertionSignedWithThePrintedRfcKeyVerifiesThroughTheShippedPath()
    {
        byte[] privateSeed = DecodeBase64Url(EdDsaPrivateSeedBase64Url);
        var credentialPublicKey = new CoseKey(
            kty: CoseKeyTypes.Okp,
            alg: WellKnownCoseAlgorithms.EdDsa,
            curve: CoseKeyCurves.Ed25519,
            x: DecodeBase64Url(EdDsaPublicKeyBase64Url));

        Fido2AssertionOutcome outcome = await MintAndVerifyAssertionAsync(
            privateSeed, credentialPublicKey, BouncyCastleCryptographicFunctions.SignEd25519Async, isEcdsaSignature: false, TestContext.CancellationToken);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsTrue(outcome.IsAcceptable);
    }


    /// <summary>
    /// Mints a firewalled assertion signed directly with <paramref name="independentSigner"/> over
    /// <paramref name="privateKeyBytes"/> — never through the library's registered signing path — then
    /// reconstructs the ceremony input from the minted wire bytes only and runs it through the shipped
    /// <see cref="Fido2AssertionVerifier.VerifyAsync(CoseKey, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, AssertionCeremonyInput, string, MemoryPool{byte}, TimeProvider?, CancellationToken)"/>.
    /// </summary>
    /// <param name="privateKeyBytes">The raw private key bytes to sign with.</param>
    /// <param name="credentialPublicKey">The stored credential public key the verifier checks the signature against.</param>
    /// <param name="independentSigner">The BouncyCastle signing primitive minting the assertion.</param>
    /// <param name="isEcdsaSignature">
    /// Whether the minted signature must be re-encoded from IEEE P1363 to ASN.1 DER before verification, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types">WebAuthn L3 section
    /// 6.5.5</see>.
    /// </param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The verifier's combined signature and ceremony-rule outcome.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the credential identifiers transfers to the ceremony input's " +
            "CredentialId and AllowedCredentialIds properties, which the method's using declaration disposes.")]
    private static async Task<Fido2AssertionOutcome> MintAndVerifyAssertionAsync(
        byte[] privateKeyBytes,
        CoseKey credentialPublicKey,
        SigningDelegate independentSigner,
        bool isEcdsaSignature,
        CancellationToken cancellationToken)
    {
        byte[] rpIdHash = CreateRpIdHash();
        const byte userPresentAndVerifiedFlags = (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit);
        byte[] authenticatorData = BuildAuthenticatorData(rpIdHash, userPresentAndVerifiedFlags, signCount: 1);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, ValidChallenge, ValidOrigin, crossOrigin: null, topOrigin: null);

        using DigestValue clientDataHash = Fido2ClientDataHash.Compute(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Concat(authenticatorData, clientDataHash.AsReadOnlySpan().ToArray());

        (Signature mintedSignature, CryptoEvent? _) = await independentSigner(privateKeyBytes, toBeSigned, BaseMemoryPool.Shared, context: null, cancellationToken).ConfigureAwait(false);
        using Signature wireSignature = ReencodeToDerIfEcdsa(mintedSignature, isEcdsaSignature, BaseMemoryPool.Shared);

        ClientData clientData = ClientDataJsonReader.Read(clientDataJson);
        AuthenticatorData parsedAuthenticatorData = AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);
        CredentialId assertedCredentialId = CredentialId.Create([0x01, 0x02, 0x03, 0x04], BaseMemoryPool.Shared);

        using var ceremonyInput = new AssertionCeremonyInput
        {
            ClientData = clientData,
            AuthenticatorData = parsedAuthenticatorData,
            ExpectedChallenge = ValidChallenge,
            ExpectedOrigins = new HashSet<string> { ValidOrigin },
            ExpectedRpIdHash = WrapRpIdHash(rpIdHash, BaseMemoryPool.Shared),
            UserVerification = UserVerificationRequirement.Required,
            StoredSignCount = 0,
            StoredUvInitialized = true,
            CredentialId = assertedCredentialId,
            AllowedCredentialIds = [CredentialId.Create([0x01, 0x02, 0x03, 0x04], BaseMemoryPool.Shared)]
        };

        return await Fido2AssertionVerifier.VerifyAsync(
            credentialPublicKey,
            wireSignature.AsReadOnlyMemory(),
            authenticatorData,
            clientDataJson,
            ceremonyInput,
            correlationId: "fido2-cose-rfc-vector-test-correlation",
            pool: BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch),
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Re-encodes <paramref name="mintedSignature"/> from IEEE P1363 to ASN.1 DER when
    /// <paramref name="isEcdsaSignature"/> is set — the WebAuthn L3 section 6.5.5 requirement the raw
    /// BouncyCastle ECDSA primitive does not itself apply. EdDSA passes through unchanged (section 6.5.5
    /// leaves it "not ASN.1 wrapped").
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the signature (re-encoded or passed through) transfers to the caller, which disposes it.")]
    private static Signature ReencodeToDerIfEcdsa(Signature mintedSignature, bool isEcdsaSignature, MemoryPool<byte> pool)
    {
        if(!isEcdsaSignature)
        {
            return mintedSignature;
        }

        using(mintedSignature)
        {
            IMemoryOwner<byte> derOwner = EcdsaSignatureEncoding.ConvertP1363ToDer(mintedSignature.AsReadOnlySpan(), pool, out _);

            return new Signature(derOwner, CryptoTags.AlgorithmAgnosticSignature);
        }
    }


    /// <summary>
    /// Derives the EC public key point from a printed private scalar via direct BouncyCastle domain-parameter
    /// multiplication (<c>Q = d · G</c>) — independent of, and prior to, any use of the shipped verification
    /// path — and returns its affine coordinates zero-padded to the curve's field byte length.
    /// </summary>
    /// <param name="privateScalarBase64Url">The printed private scalar <c>d</c>, base64url-encoded.</param>
    /// <param name="curveName">The BouncyCastle SEC curve name (e.g. <c>secp256r1</c>).</param>
    /// <returns>The derived, field-length-padded <c>x</c> and <c>y</c> coordinates.</returns>
    private static (byte[] X, byte[] Y) DeriveEcPublicKeyCoordinates(string privateScalarBase64Url, string curveName)
    {
        byte[] privateScalarBytes = DecodeBase64Url(privateScalarBase64Url);
        X9ECParameters curveParameters = ECNamedCurveTable.GetByName(curveName);
        var d = new BigInteger(1, privateScalarBytes);
        var publicPoint = curveParameters.G.Multiply(d).Normalize();

        int fieldByteLength = (curveParameters.Curve.FieldSize + 7) / 8;
        byte[] x = PadLeft(publicPoint.AffineXCoord.ToBigInteger().ToByteArrayUnsigned(), fieldByteLength);
        byte[] y = PadLeft(publicPoint.AffineYCoord.ToBigInteger().ToByteArrayUnsigned(), fieldByteLength);

        return (x, y);

        //Zero-pads a big-endian unsigned magnitude on the left to a fixed field byte length; BouncyCastle's
        //ToByteArrayUnsigned omits leading zero bytes, which the printed coordinate constants do not.
        static byte[] PadLeft(byte[] value, int length)
        {
            if(value.Length == length)
            {
                return value;
            }

            byte[] padded = new byte[length];
            value.CopyTo(padded, length - value.Length);

            return padded;
        }
    }


    /// <summary>
    /// Derives the Ed25519 public key from a printed private seed via direct BouncyCastle scalar
    /// clamping/point multiplication — independent of, and prior to, any use of the shipped verification path.
    /// </summary>
    /// <param name="privateSeed">The 32-byte Ed25519 private key seed.</param>
    /// <returns>The derived 32-byte Ed25519 public key.</returns>
    private static byte[] DeriveEd25519PublicKey(byte[] privateSeed)
    {
        var privateKey = new Ed25519PrivateKeyParameters(privateSeed, 0);
        Ed25519PublicKeyParameters publicKey = privateKey.GeneratePublicKey();

        return publicKey.GetEncoded();
    }


    /// <summary>Decodes a base64url-encoded RFC-printed value into its raw bytes.</summary>
    /// <param name="value">The base64url text, exactly as printed in the RFC.</param>
    /// <returns>The decoded bytes.</returns>
    private static byte[] DecodeBase64Url(string value)
    {
        int maxLength = System.Buffers.Text.Base64Url.GetMaxDecodedLength(value.Length);
        byte[] buffer = new byte[maxLength];
        OperationStatus status = System.Buffers.Text.Base64Url.DecodeFromChars(value, buffer, out _, out int bytesWritten);
        if(status != OperationStatus.Done)
        {
            throw new FormatException($"The base64url value '{value}' could not be decoded ({status}).");
        }

        return bytesWritten == buffer.Length ? buffer : buffer[..bytesWritten];
    }
}
