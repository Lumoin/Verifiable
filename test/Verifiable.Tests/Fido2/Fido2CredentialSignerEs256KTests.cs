using System.Formats.Asn1;
using System.Security.Cryptography;
using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Regression coverage for the wave-8 fix to <see cref="Fido2CredentialSigner"/>'s <c>IsEcAlgorithm</c>
/// table, which omitted ES256K (secp256k1, <c>COSEAlgorithmIdentifier</c> -47, RFC 8812 §3): signing an
/// ES256K assertion through <see cref="Fido2CredentialSigner.SignAssertionAsync"/> left the wire
/// signature in raw IEEE P1363 form instead of ASN.1 DER, so the shipped <see cref="Fido2AssertionVerifier"/>
/// (whose sibling helper <see cref="Fido2EcdsaWireSignature.TryGetEcFieldWidth"/> already covered
/// secp256k1) would reject a legitimately-signed ES256K assertion.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <c>Fido2CredentialSignerTests</c>'s shape for the ES256/384/512/RS256/EdDSA matrix, extended
/// to ES256K in its own file per the wave-8 file discipline (new test files only). The credential key
/// pair is minted directly through <see cref="TestKeyMaterialProvider.CreateFreshSecp256k1KeyMaterial"/>
/// (mirroring <c>Fido2AssertionOracle.CreateEs256K</c>) and bound to a <see cref="PrivateKey"/> via
/// <see cref="CryptographicKeyFactory"/>, so signing dispatches through the exact same
/// <see cref="Fido2CredentialSigner.SignAssertionAsync"/> choke point the fix touches.
/// </para>
/// <para>
/// The independent oracle here is a raw BouncyCastle <see cref="ECDsaSigner"/> over the secp256k1
/// domain parameters — not <see cref="System.Security.Cryptography.ECDsa"/>, which has no built-in named
/// curve for secp256k1 (the same limitation <c>Fido2AttestationTestVectors.SignWithSecp256k1Async</c>'s
/// remarks document) — verifying a signature whose DER envelope is parsed with the framework's own
/// <see cref="AsnReader"/>, never this library's <see cref="EcdsaSignatureEncoding"/>. The SHA-256
/// message digest is computed directly via <see cref="SHA256.HashData(ReadOnlySpan{byte})"/>, not through
/// the registered digest seam, so all three moving parts under test — the digest, the DER encoding, and
/// the elliptic-curve arithmetic — are checked by code paths independent of the production dispatch.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Fido2CredentialSignerEs256KTests
{
    /// <summary>The base64url-encoded challenge a valid ceremony embeds and expects.</summary>
    private const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin a valid ceremony embeds and expects.</summary>
    private const string ValidOrigin = "https://relyingparty.example";

    /// <summary>The key identifier passed to <see cref="CryptographicKeyFactory"/> for the credential key under test.</summary>
    private const string CredentialKeyIdentifier = "fido2-credential-signer-es256k-test-key";

    /// <summary>The <c>authData</c> flags byte this class's ceremony carries: user present and user verified.</summary>
    private const byte ValidFlags = (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit);

    /// <summary>
    /// A default user handle <see cref="VerifyAsync"/> uses for both <c>response.userHandle</c> and the
    /// relying party's stored record, so <see cref="Fido2AssertionChecks.CheckAssertionUserHandle"/>
    /// succeeds and this test stays focused on the ES256K signing/verification round trip — mirroring
    /// <c>Fido2CredentialSignerTests</c>'s identical rationale.
    /// </summary>
    private static byte[] DefaultUserHandleBytes { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// An ES256K assertion signed via <see cref="Fido2CredentialSigner.SignAssertionAsync"/> is DER-encoded
    /// (not left as raw P1363), verifies through the shipped <see cref="Fido2AssertionVerifier"/>, and
    /// verifies through an independent BouncyCastle secp256k1 oracle — the regression for the fixed
    /// <c>IsEcAlgorithm</c> omission.
    /// </summary>
    [TestMethod]
    public async Task Es256KSignedAssertionIsDerEncodedAndVerifiesThroughTheShippedVerifierAndAnIndependentOracle()
    {
        var keys = TestKeyMaterialProvider.CreateFreshSecp256k1KeyMaterial();
        using PublicKeyMemory publicKeyMemory = keys.PublicKey;
        using PrivateKey credentialKey = CryptographicKeyFactory.CreatePrivateKey(keys.PrivateKey, CredentialKeyIdentifier, keys.PrivateKey.Tag);
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(publicKeyMemory, CoseKeyCurves.Secp256k1, WellKnownCoseAlgorithms.Es256K);

        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, ValidFlags, signCount: 1);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, ValidChallenge, ValidOrigin, crossOrigin: null, topOrigin: null);

        using DigestValue clientDataHash = Fido2ClientDataHash.Compute(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2TestVectors.Concat(authenticatorData, clientDataHash.AsReadOnlySpan().ToArray());

        using Signature signature = await Fido2CredentialSigner.SignAssertionAsync(
            credentialKey, authenticatorData, clientDataHash, WellKnownCoseAlgorithms.Es256K, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] signatureBytes = signature.AsReadOnlySpan().ToArray();

        AssertIsWellFormedDerSequenceOfTwoIntegers(signatureBytes);

        Fido2AssertionOutcome outcome = await VerifyAsync(
            credentialPublicKey, signature.AsReadOnlyMemory(), authenticatorData, clientDataJson, rpIdHash).ConfigureAwait(false);
        Assert.IsTrue(outcome.SignatureValid, "The production Fido2AssertionVerifier must accept a Fido2CredentialSigner ES256K signature.");
        Assert.IsTrue(outcome.IsAcceptable);

        Assert.IsTrue(
            VerifyEs256KIndependently(publicKeyMemory, toBeSigned, signatureBytes),
            "An independent BouncyCastle secp256k1 oracle must accept the same DER signature the shipped verifier accepted.");
    }


    /// <summary>Runs <see cref="Fido2AssertionVerifier.VerifyAsync"/>, reconstructing the ceremony input from wire bytes only.</summary>
    private static async ValueTask<Fido2AssertionOutcome> VerifyAsync(
        CoseKey credentialPublicKey, ReadOnlyMemory<byte> signature, byte[] authenticatorDataBytes, byte[] clientDataJson, byte[] expectedRpIdHash)
    {
        ClientData clientData = ClientDataJsonReader.Read(clientDataJson);
        AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(authenticatorDataBytes, Fido2TestVectors.TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        //WebAuthn L3 section 7.2 step 6 requires a response user handle identifying the account on the
        //discoverable-credential path this helper exercises (no allowlist is supplied below); a matching
        //response/stored pair keeps this signing/verification round trip focused on its own concern.
        UserHandle responseUserHandle = UserHandle.Create(DefaultUserHandleBytes, BaseMemoryPool.Shared);
        UserHandle storedUserHandle = UserHandle.Create(DefaultUserHandleBytes, BaseMemoryPool.Shared);

        using var ceremonyInput = new AssertionCeremonyInput
        {
            ClientData = clientData,
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = ValidChallenge,
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
            correlationId: "fido2-credential-signer-es256k-test-correlation",
            pool: BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch),
            cancellationToken: default).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a DER-encoded ECDSA/secp256k1 signature with a raw BouncyCastle <see cref="ECDsaSigner"/> —
    /// independent of this library's <see cref="EcdsaSignatureEncoding"/> DER parsing and of the registered
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> verification dispatch. The DER
    /// envelope is parsed with the framework's own <see cref="AsnReader"/> and the message digest is computed
    /// directly, so no part of this check reuses the production code path under test.
    /// </summary>
    private static bool VerifyEs256KIndependently(PublicKeyMemory publicKeyMemory, ReadOnlySpan<byte> message, ReadOnlySpan<byte> derSignature)
    {
        var reader = new AsnReader(derSignature.ToArray(), AsnEncodingRules.DER);
        AsnReader sequence = reader.ReadSequence();
        byte[] rBytes = sequence.ReadIntegerBytes().ToArray();
        byte[] sBytes = sequence.ReadIntegerBytes().ToArray();

        byte[] digest = SHA256.HashData(message);

        X9ECParameters curveParams = ECNamedCurveTable.GetByName("secp256k1");
        var domainParams = new ECDomainParameters(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);
        Org.BouncyCastle.Math.EC.ECPoint point = curveParams.Curve.DecodePoint(publicKeyMemory.AsReadOnlySpan().ToArray());
        var publicKey = new ECPublicKeyParameters(point, domainParams);

        var signer = new ECDsaSigner();
        signer.Init(forSigning: false, publicKey);

        return signer.VerifySignature(digest, new BigInteger(1, rBytes), new BigInteger(1, sBytes));
    }


    /// <summary>
    /// Asserts that <paramref name="signature"/> parses as a well-formed ASN.1 DER
    /// <c>Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }</c> with no trailing data — the spec
    /// conformance section 6.5.5 requires for an ES256K <c>sig</c> value, and precisely the shape
    /// the fixed <c>IsEcAlgorithm</c> omission previously skipped.
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
}
