using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Firewalled tests for <see cref="Fido2CredentialSigner"/>: it turns a credential's private key into a
/// first-class WebAuthn assertion/self-attestation signer, so a passkey — software, TPM-held, or
/// APDU-held — signs through the exact same seam <see cref="Verifiable.Apdu.Eac.TerminalAuthenticationSignature"/>
/// already proves for a Terminal Authentication key.
/// </summary>
/// <remarks>
/// <para>
/// Every test mints its own credential key pair on <see cref="BouncyCastleKeyMaterialCreator"/> — the
/// key under test — then signs through <see cref="Fido2CredentialSigner"/>, which dispatches to
/// whichever backend <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> has
/// registered for signing (Microsoft's ECDsa for P-256/384/521, BouncyCastle for RSA-2048 and Ed25519,
/// per this test run's wiring). The SAME signature is then checked two independent ways:
/// </para>
/// <list type="number">
/// <item><description>
/// through the shipped <see cref="Fido2AssertionVerifier"/>, reconstructing the ceremony entirely from
/// wire bytes plus the stored credential public key — never sharing the private key or any in-memory
/// signer object across the boundary;
/// </description></item>
/// <item><description>
/// through an oracle built directly on <see cref="System.Security.Cryptography.ECDsa"/>/<see cref="RSA"/>
/// or a raw BouncyCastle EdDSA primitive, never through this library's own <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
/// dispatch — so an independently implemented verifier agrees the signature is valid, not just this
/// library's own verify path.
/// </description></item>
/// </list>
/// <para>
/// For the EC algorithms this doubles as the ES256/384/512 encoding proof the type's remarks describe:
/// the shipped verifier only accepts the signature because <see cref="Fido2CredentialSigner"/> re-encoded
/// it to ASN.1 DER, and the independent oracle verifies it by explicitly parsing that DER encoding
/// (<see cref="DSASignatureFormat.Rfc3279DerSequence"/>) — an oracle that only accepts IEEE P1363 would
/// reject it.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Fido2CredentialSignerTests
{
    /// <summary>The base64url-encoded challenge a valid ceremony embeds and expects.</summary>
    private const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin a valid ceremony embeds and expects.</summary>
    internal const string ValidOrigin = "https://relyingparty.example";

    /// <summary>The key identifier passed to <see cref="CryptographicKeyFactory"/> for the credential key under test.</summary>
    private const string CredentialKeyIdentifier = "fido2-credential-signer-test-key";

    /// <summary>
    /// A default user handle <see cref="VerifyAsync"/> uses for both <c>response.userHandle</c> and
    /// the relying party's stored record, so <see cref="Fido2AssertionChecks.CheckAssertionUserHandle"/>
    /// succeeds and every test here stays focused on the signing/verification round trip it drives.
    /// </summary>
    private static byte[] DefaultUserHandleBytes { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The COSE algorithm matrix under test, named for <see cref="DynamicDataAttribute"/> display.</summary>
    public static IEnumerable<object[]> AssertionAlgorithms =>
    [
        [WellKnownCoseAlgorithms.Es256],
        [WellKnownCoseAlgorithms.Es384],
        [WellKnownCoseAlgorithms.Es512],
        [WellKnownCoseAlgorithms.Rs256],
        [WellKnownCoseAlgorithms.EdDsa]
    ];


    /// <summary>
    /// A <see cref="Fido2CredentialSigner"/> signature verifies through the shipped
    /// <see cref="Fido2AssertionVerifier"/> AND through an independent oracle, across every algorithm
    /// section 6.5.5 defines (ES256, ES384, ES512 — the ASN.1 DER path — plus RS256 and EdDSA,
    /// which pass through unencoded).
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(AssertionAlgorithms))]
    public async Task SignedAssertionVerifiesThroughTheShippedVerifierAndAnIndependentOracle(int coseAlgorithm)
    {
        using CredentialFixture credential = CreateCredential(coseAlgorithm);

        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, ValidFlags, signCount: 1);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, ValidChallenge, ValidOrigin, crossOrigin: null, topOrigin: null);

        (Fido2AssertionOutcome outcome, byte[] signatureBytes, byte[] toBeSigned) = await SignAndVerifyAsync(
            credential, authenticatorData, clientDataJson, ValidChallenge, rpIdHash, TestContext.CancellationToken);

        Assert.IsTrue(outcome.SignatureValid, "The production Fido2AssertionVerifier must accept a Fido2CredentialSigner signature.");
        Assert.IsTrue(outcome.IsAcceptable);

        bool independentlyVerified = VerifyIndependently(coseAlgorithm, credential.PublicKeyMemory, toBeSigned, signatureBytes);
        Assert.IsTrue(independentlyVerified, "An independent oracle must accept the same signature the shipped verifier accepted.");

        if(WellKnownCoseAlgorithms.IsEs256(coseAlgorithm) || WellKnownCoseAlgorithms.IsEs384(coseAlgorithm) || WellKnownCoseAlgorithms.IsEs512(coseAlgorithm))
        {
            AssertIsWellFormedDerSequenceOfTwoIntegers(signatureBytes);
        }
    }


    /// <summary>
    /// A signature is bound to the exact transcript it was computed over: reconstructing the ceremony
    /// from a different <c>authData</c> (a bumped <c>signCount</c>, so no surface-field rule reacts to
    /// it) invalidates the signature.
    /// </summary>
    [TestMethod]
    public async Task SignatureOverADifferentTranscriptFailsVerification()
    {
        using CredentialFixture credential = CreateCredential(WellKnownCoseAlgorithms.Es256);

        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();
        byte[] signedAuthenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, ValidFlags, signCount: 1);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, ValidChallenge, ValidOrigin, crossOrigin: null, topOrigin: null);

        using DigestValue clientDataHash = Fido2ClientDataHash.Compute(clientDataJson, BaseMemoryPool.Shared);
        using Signature signature = await Fido2CredentialSigner.SignAssertionAsync(
            credential.CredentialKey, signedAuthenticatorData, clientDataHash, credential.CoseAlgorithm, BaseMemoryPool.Shared, TestContext.CancellationToken);

        //A different signCount changes the signed transcript without touching rpIdHash or flags.
        byte[] differentAuthenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, ValidFlags, signCount: 2);

        Fido2AssertionOutcome outcome = await VerifyAsync(
            credential.CredentialPublicKey, signature.AsReadOnlyMemory(), differentAuthenticatorData, clientDataJson, ValidChallenge, rpIdHash, TestContext.CancellationToken);

        Assert.IsFalse(outcome.SignatureValid, "A signature must not verify against a transcript other than the one it was computed over.");
        Assert.IsFalse(outcome.IsAcceptable);
    }


    /// <summary>The <c>authData</c> flags byte every valid ceremony in this class carries: user present and user verified.</summary>
    internal static byte ValidFlags => (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit);


    /// <summary>
    /// Signs <paramref name="authenticatorData"/>/<paramref name="clientDataJson"/> with
    /// <paramref name="credential"/> and verifies the result through the shipped
    /// <see cref="Fido2AssertionVerifier"/>, reconstructed from wire bytes only.
    /// </summary>
    /// <returns>
    /// The verification outcome, a copy of the raw signature bytes, and a copy of the signed transcript
    /// (<c>authenticatorData ‖ clientDataHash</c>) — both copies outlive the pooled carriers this method
    /// disposes, for the caller's independent-oracle cross-check.
    /// </returns>
    internal static async ValueTask<(Fido2AssertionOutcome Outcome, byte[] SignatureBytes, byte[] ToBeSigned)> SignAndVerifyAsync(
        CredentialFixture credential, byte[] authenticatorData, byte[] clientDataJson, string expectedChallenge, byte[] expectedRpIdHash, CancellationToken cancellationToken)
    {
        using DigestValue clientDataHash = Fido2ClientDataHash.Compute(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2TestVectors.Concat(authenticatorData, clientDataHash.AsReadOnlySpan().ToArray());

        using Signature signature = await Fido2CredentialSigner.SignAssertionAsync(
            credential.CredentialKey, authenticatorData, clientDataHash, credential.CoseAlgorithm, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
        byte[] signatureBytes = signature.AsReadOnlySpan().ToArray();

        Fido2AssertionOutcome outcome = await VerifyAsync(
            credential.CredentialPublicKey, signature.AsReadOnlyMemory(), authenticatorData, clientDataJson, expectedChallenge, expectedRpIdHash, cancellationToken).ConfigureAwait(false);

        return (outcome, signatureBytes, toBeSigned);
    }


    /// <summary>Runs <see cref="Fido2AssertionVerifier.VerifyAsync"/>, reconstructing the ceremony input from wire bytes only.</summary>
    private static async ValueTask<Fido2AssertionOutcome> VerifyAsync(
        CoseKey credentialPublicKey, ReadOnlyMemory<byte> signature, byte[] authenticatorDataBytes, byte[] clientDataJson,
        string expectedChallenge, byte[] expectedRpIdHash, CancellationToken cancellationToken)
    {
        ClientData clientData = ClientDataJsonReader.Read(clientDataJson);
        AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(authenticatorDataBytes, Fido2TestVectors.TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        //WebAuthn L3 section 7.2 step 6 requires a response user handle identifying the account on
        //the discoverable-credential path this helper exercises (no allowlist is supplied below); a
        //matching response/stored pair keeps this signing/verification round trip focused on its own concern.
        UserHandle responseUserHandle = UserHandle.Create(DefaultUserHandleBytes, BaseMemoryPool.Shared);
        UserHandle storedUserHandle = UserHandle.Create(DefaultUserHandleBytes, BaseMemoryPool.Shared);

        using var ceremonyInput = new AssertionCeremonyInput
        {
            ClientData = clientData,
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = expectedChallenge,
            ExpectedOrigins = new HashSet<string> { ValidOrigin },
            ExpectedRpIdHash = Fido2TestVectors.WrapRpIdHash(expectedRpIdHash, BaseMemoryPool.Shared),
            AllowCrossOrigin = false,
            UserVerification = UserVerificationRequirement.Required,
            StoredSignCount = 0,
            StoredUvInitialized = true,
            ResponseUserHandle = responseUserHandle,
            StoredUserHandle = storedUserHandle
        };

        return await Fido2AssertionVerifier.VerifyAsync(
            credentialPublicKey,
            signature,
            authenticatorDataBytes,
            clientDataJson,
            ceremonyInput,
            correlationId: "fido2-credential-signer-test-correlation",
            pool: BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch),
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Mints a fresh credential key pair for <paramref name="coseAlgorithm"/> and its stored COSE public-key view.</summary>
    internal static CredentialFixture CreateCredential(int coseAlgorithm) => coseAlgorithm switch
    {
        int a when WellKnownCoseAlgorithms.IsEs256(a) => CreateEcCredential(BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared), CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256),
        int a when WellKnownCoseAlgorithms.IsEs384(a) => CreateEcCredential(BouncyCastleKeyMaterialCreator.CreateP384Keys(BaseMemoryPool.Shared), CoseKeyCurves.P384, WellKnownCoseAlgorithms.Es384),
        int a when WellKnownCoseAlgorithms.IsEs512(a) => CreateEcCredential(BouncyCastleKeyMaterialCreator.CreateP521Keys(BaseMemoryPool.Shared), CoseKeyCurves.P521, WellKnownCoseAlgorithms.Es512),
        int a when WellKnownCoseAlgorithms.IsRs256(a) => CreateRsaCredential(),
        int a when WellKnownCoseAlgorithms.IsEdDsa(a) => CreateEdDsaCredential(),
        _ => throw new UnreachableException($"Unhandled COSE algorithm '{coseAlgorithm}'.")
    };


    /// <summary>Builds a P-256/384/521 credential fixture from freshly minted EC key material.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the private key transfers to the returned CredentialFixture, which the test disposes via a using declaration.")]
    private static CredentialFixture CreateEcCredential(PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys, int coseCurve, int coseAlgorithm)
    {
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(keys.PublicKey, coseCurve, coseAlgorithm);
        PrivateKey credentialKey = CryptographicKeyFactory.CreatePrivateKey(keys.PrivateKey, CredentialKeyIdentifier, keys.PrivateKey.Tag);

        return new CredentialFixture(keys.PublicKey, credentialKey, credentialPublicKey, coseAlgorithm);
    }


    /// <summary>Builds an RS256 credential fixture from freshly minted RSA-2048 key material.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the private key transfers to the returned CredentialFixture, which the test disposes via a using declaration.")]
    private static CredentialFixture CreateRsaCredential()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildRsaCoseKey(keys.PublicKey, WellKnownCoseAlgorithms.Rs256);
        PrivateKey credentialKey = CryptographicKeyFactory.CreatePrivateKey(keys.PrivateKey, CredentialKeyIdentifier, keys.PrivateKey.Tag);

        return new CredentialFixture(keys.PublicKey, credentialKey, credentialPublicKey, WellKnownCoseAlgorithms.Rs256);
    }


    /// <summary>Builds an EdDSA credential fixture from freshly minted Ed25519 key material.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the private key transfers to the returned CredentialFixture, which the test disposes via a using declaration.")]
    private static CredentialFixture CreateEdDsaCredential()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildOkpCoseKey(keys.PublicKey, CoseKeyCurves.Ed25519, WellKnownCoseAlgorithms.EdDsa);
        PrivateKey credentialKey = CryptographicKeyFactory.CreatePrivateKey(keys.PrivateKey, CredentialKeyIdentifier, keys.PrivateKey.Tag);

        return new CredentialFixture(keys.PublicKey, credentialKey, credentialPublicKey, WellKnownCoseAlgorithms.EdDsa);
    }


    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="message"/> through an oracle built
    /// directly on the framework/BouncyCastle primitive for <paramref name="coseAlgorithm"/> — never
    /// through this library's <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
    /// dispatch — so the check is independent of this library's own verification seam.
    /// </summary>
    private static bool VerifyIndependently(int coseAlgorithm, PublicKeyMemory publicKeyMemory, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature) => coseAlgorithm switch
    {
        int a when WellKnownCoseAlgorithms.IsEs256(a) => VerifyEcIndependently(publicKeyMemory, message, signature, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, CryptoAlgorithm.P256),
        int a when WellKnownCoseAlgorithms.IsEs384(a) => VerifyEcIndependently(publicKeyMemory, message, signature, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, CryptoAlgorithm.P384),
        int a when WellKnownCoseAlgorithms.IsEs512(a) => VerifyEcIndependently(publicKeyMemory, message, signature, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, CryptoAlgorithm.P521),
        int a when WellKnownCoseAlgorithms.IsRs256(a) => VerifyRsaIndependently(publicKeyMemory, message, signature),
        int a when WellKnownCoseAlgorithms.IsEdDsa(a) => VerifyEd25519Independently(publicKeyMemory, message, signature),
        _ => throw new UnreachableException($"Unhandled COSE algorithm '{coseAlgorithm}'.")
    };


    /// <summary>
    /// Verifies an EC signature with the framework's own <see cref="ECDsa"/>, explicitly parsing the
    /// wire value as <see cref="DSASignatureFormat.Rfc3279DerSequence"/> — independent of, and using a
    /// different signature-format assumption than, this library's registered EC verification seam (which
    /// expects <see cref="DSASignatureFormat.IeeeP1363FixedFieldConcatenation"/>).
    /// </summary>
    private static bool VerifyEcIndependently(
        PublicKeyMemory publicKeyMemory, ReadOnlySpan<byte> message, ReadOnlySpan<byte> derSignature, ECCurve curve, HashAlgorithmName hashAlgorithmName, CryptoAlgorithm algorithm)
    {
        EllipticCurveTypes curveType = EllipticCurveUtilities.CurveTypeFor(algorithm);
        ReadOnlySpan<byte> compressed = publicKeyMemory.AsReadOnlySpan();
        byte[] y = EllipticCurveUtilities.Decompress(compressed, curveType);
        byte[] x = compressed[1..].ToArray();

        //Independent-oracle carve-out: framework ECDsa verifies against this library's registered EC seam, not through it.
        using ECDsa key = ECDsa.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = x, Y = y } });

        return key.VerifyData(message, derSignature, hashAlgorithmName, DSASignatureFormat.Rfc3279DerSequence);
    }


    /// <summary>
    /// Verifies an RS256 signature with the framework's own <see cref="RSA"/> — independent of the
    /// BouncyCastle backend this library's registered RSA-2048 verification seam uses.
    /// </summary>
    private static bool VerifyRsaIndependently(PublicKeyMemory publicKeyMemory, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        //Independent-oracle carve-out: framework RSA verifies against this library's registered RSA-2048 seam, not through it.
        using RSA rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKeyMemory.AsReadOnlySpan(), out _);

        return rsa.VerifyData(message, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }


    /// <summary>
    /// Verifies an EdDSA signature with a raw BouncyCastle Ed25519 primitive called directly — never
    /// through <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> dispatch, so the
    /// check does not merely reuse the same registered verification delegate this library would use.
    /// </summary>
    private static bool VerifyEd25519Independently(PublicKeyMemory publicKeyMemory, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        //Independent-oracle carve-out: a raw BouncyCastle Ed25519 primitive, called directly rather than through this library's CryptoFunctionRegistry dispatch.
        var publicKey = new Ed25519PublicKeyParameters(publicKeyMemory.AsReadOnlySpan().ToArray(), 0);
        var validator = new Ed25519Signer();
        validator.Init(forSigning: false, publicKey);
        byte[] messageBytes = message.ToArray();
        validator.BlockUpdate(messageBytes, off: 0, len: messageBytes.Length);

        return validator.VerifySignature(signature.ToArray());
    }


    /// <summary>
    /// Asserts that <paramref name="signature"/> parses as a well-formed ASN.1 DER
    /// <c>Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }</c> with no trailing data — the spec
    /// conformance section 6.5.5 requires for an ES256/384/512 <c>sig</c> value.
    /// </summary>
    private static void AssertIsWellFormedDerSequenceOfTwoIntegers(ReadOnlySpan<byte> signature)
    {
        var reader = new AsnReader(signature.ToArray(), AsnEncodingRules.DER);
        AsnReader sequence = reader.ReadSequence();
        _ = sequence.ReadIntegerBytes();
        _ = sequence.ReadIntegerBytes();

        Assert.IsFalse(sequence.HasData, "The DER Ecdsa-Sig-Value must contain exactly two INTEGERs and no more.");
        Assert.IsFalse(reader.HasData, "The signature must contain no bytes beyond the single top-level SEQUENCE.");
    }


    /// <summary>
    /// A freshly minted credential key pair, its stored COSE public-key view, and the COSE algorithm it
    /// signs for — bundled so a test can dispose the underlying key material in one place.
    /// </summary>
    internal sealed class CredentialFixture(PublicKeyMemory publicKeyMemory, PrivateKey credentialKey, CoseKey credentialPublicKey, int coseAlgorithm): IDisposable
    {
        /// <summary>The credential's public key memory, kept for the independent-oracle cross-check.</summary>
        public PublicKeyMemory PublicKeyMemory { get; } = publicKeyMemory;

        /// <summary>The credential's private key, with its signing function bound.</summary>
        public PrivateKey CredentialKey { get; } = credentialKey;

        /// <summary>The stored credential public key view a relying party would have recorded at registration time.</summary>
        public CoseKey CredentialPublicKey { get; } = credentialPublicKey;

        /// <summary>The COSE algorithm identifier this credential signs for.</summary>
        public int CoseAlgorithm { get; } = coseAlgorithm;


        /// <summary>Releases the credential's private and public key memory.</summary>
        public void Dispose()
        {
            CredentialKey.Dispose();
            PublicKeyMemory.Dispose();
        }
    }
}
