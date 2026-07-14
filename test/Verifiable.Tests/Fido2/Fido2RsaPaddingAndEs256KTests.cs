using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Regression coverage for the alg-aware RSA COSE_Key tag resolution — <c>CoseKeyExtensions.ToPublicKeyMemory</c>
/// used to resolve every RSA COSE_Key from modulus length alone, silently verifying a genuine PS256/384/512 or
/// RS384/512 assertion signature as PKCS#1 v1.5 SHA-256/512 — and for ES256K (secp256k1, RFC 8812 §3) assertion
/// verification end to end.
/// </summary>
/// <remarks>
/// Every test reconstructs the ceremony from <see cref="Fido2AssertionOracle"/>'s wire bytes, mirroring the
/// firewall <see cref="Fido2AssertionVerifierTests"/> establishes: the verifier never sees the oracle's private
/// key or in-memory signing state, only wire bytes plus a stored credential <see cref="CoseKey"/>. Assertions here
/// check only <see cref="Fido2AssertionOutcome.SignatureValid"/> — the surface-field ceremony rules (challenge,
/// origin, user handle, and so on) are exercised elsewhere and are not this file's concern.
/// </remarks>
[TestClass]
internal sealed class Fido2RsaPaddingAndEs256KTests
{
    /// <summary>The base64url-encoded challenge every ceremony in this file embeds and expects.</summary>
    private const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin every ceremony in this file embeds and expects.</summary>
    private const string ValidOrigin = "https://relyingparty.example";

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A PS256/PS384/PS512 assertion signed with a genuine RSASSA-PSS signature verifies — the regression for the
    /// defect where <c>ToPublicKeyMemory</c> resolved every RSA COSE_Key to PKCS#1 v1.5 SHA-256/512 by modulus
    /// length alone, ignoring the credential's declared <c>alg</c>.
    /// </summary>
    [TestMethod]
    [DataRow(nameof(Fido2AssertionOracle.CreatePs256))]
    [DataRow(nameof(Fido2AssertionOracle.CreatePs384))]
    [DataRow(nameof(Fido2AssertionOracle.CreatePs512))]
    public async Task GenuinePssAssertionVerifies(string oracleFactoryName)
    {
        using Fido2AssertionOracle oracle = CreateRsaFamilyOracle(oracleFactoryName);
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyAsync(oracle.CredentialPublicKey, minted);

        Assert.IsTrue(outcome.SignatureValid);
    }


    /// <summary>
    /// A genuine RS384/RS512 (PKCS#1 v1.5) assertion verifies — the RSA-family algorithms the modulus-length
    /// fallback previously mapped only to SHA-256 (RS256) verification.
    /// </summary>
    [TestMethod]
    [DataRow(nameof(Fido2AssertionOracle.CreateRs384))]
    [DataRow(nameof(Fido2AssertionOracle.CreateRs512))]
    public async Task GenuinePkcs1WithNonSha256HashAssertionVerifies(string oracleFactoryName)
    {
        using Fido2AssertionOracle oracle = CreateRsaFamilyOracle(oracleFactoryName);
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyAsync(oracle.CredentialPublicKey, minted);

        Assert.IsTrue(outcome.SignatureValid);
    }


    /// <summary>
    /// A PKCS#1 v1.5 signature presented under a credential key whose COSE <c>alg</c> declares PS256 fails:
    /// padding confusion must not verify even though the modulus and exponent bytes are identical.
    /// </summary>
    [TestMethod]
    public async Task Pkcs1SignatureUnderPs256CredentialAlgFails()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateRs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        CoseKey ps256CredentialKey = new(
            kty: oracle.CredentialPublicKey.Kty,
            alg: WellKnownCoseAlgorithms.Ps256,
            n: oracle.CredentialPublicKey.N,
            e: oracle.CredentialPublicKey.E);

        Fido2AssertionOutcome outcome = await VerifyAsync(ps256CredentialKey, minted);

        Assert.IsFalse(outcome.SignatureValid);
    }


    /// <summary>
    /// The mirror case: a genuine PSS signature presented under a credential key whose COSE <c>alg</c> declares
    /// RS256 (PKCS#1 v1.5) fails.
    /// </summary>
    [TestMethod]
    public async Task PssSignatureUnderRs256CredentialAlgFails()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreatePs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        CoseKey rs256CredentialKey = new(
            kty: oracle.CredentialPublicKey.Kty,
            alg: WellKnownCoseAlgorithms.Rs256,
            n: oracle.CredentialPublicKey.N,
            e: oracle.CredentialPublicKey.E);

        Fido2AssertionOutcome outcome = await VerifyAsync(rs256CredentialKey, minted);

        Assert.IsFalse(outcome.SignatureValid);
    }


    /// <summary>
    /// An RSA COSE_Key whose <c>alg</c> is <see langword="null"/> still verifies via the modulus-length fallback
    /// (RS256, 2048-bit) — the alg-aware resolution this change adds does not regress a credential that omits
    /// <c>alg</c>.
    /// </summary>
    [TestMethod]
    public async Task NullAlgRsaCredentialStillVerifiesViaModulusLengthFallback()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateRs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        CoseKey noAlgCredentialKey = new(
            kty: oracle.CredentialPublicKey.Kty,
            alg: null,
            n: oracle.CredentialPublicKey.N,
            e: oracle.CredentialPublicKey.E);

        Fido2AssertionOutcome outcome = await VerifyAsync(noAlgCredentialKey, minted);

        Assert.IsTrue(outcome.SignatureValid);
    }


    /// <summary>An ES256K (secp256k1) assertion round-trips through the shipped verifier end to end.</summary>
    [TestMethod]
    public async Task Es256KAssertionRoundTripsThroughShippedVerifier()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256K();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyAsync(oracle.CredentialPublicKey, minted);

        Assert.IsTrue(outcome.SignatureValid);
    }


    /// <summary>
    /// A P-256 (ES256) signature presented under an unrelated ES256K (secp256k1) credential fails: the two
    /// curves are algebraically distinct even though both COSE keys are EC2 with a 32-byte field width, so the
    /// wire signature's DER-to-P1363 re-encoding succeeds but the elliptic-curve verification itself does not.
    /// </summary>
    [TestMethod]
    public async Task P256SignatureUnderEs256KCredentialFails()
    {
        using Fido2AssertionOracle es256Oracle = Fido2AssertionOracle.CreateEs256();
        using Fido2AssertionOracle es256KOracle = Fido2AssertionOracle.CreateEs256K();
        using MintedAssertion minted = await es256Oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyAsync(es256KOracle.CredentialPublicKey, minted);

        Assert.IsFalse(outcome.SignatureValid);
    }


    /// <summary>
    /// Unit tests for the COSE-alg-to-<see cref="CryptoAlgorithm"/> converter arms this change adds: ES256K (-47),
    /// RS384 (-258), RS512 (-259), PS384 (-38), and PS512 (-39).
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(CoseAlgorithmToCryptoAlgorithmCases))]
    public void CoseAlgorithmToCryptoAlgorithmResolvesNewArms(int coseAlgorithm, CryptoAlgorithm expected)
    {
        CryptoAlgorithm? resolved = CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(coseAlgorithm);

        Assert.IsTrue(resolved.HasValue);
        Assert.AreEqual(expected, resolved!.Value);
    }


    /// <summary>The (COSE algorithm, expected <see cref="CryptoAlgorithm"/>) pairs <see cref="CoseAlgorithmToCryptoAlgorithmResolvesNewArms"/> checks.</summary>
    public static IEnumerable<object[]> CoseAlgorithmToCryptoAlgorithmCases =>
    [
        [WellKnownCoseAlgorithms.Es256K, CryptoAlgorithm.Secp256k1],
        [WellKnownCoseAlgorithms.Rs384, CryptoAlgorithm.RsaSha384],
        [WellKnownCoseAlgorithms.Rs512, CryptoAlgorithm.RsaSha512],
        [WellKnownCoseAlgorithms.Ps384, CryptoAlgorithm.RsaSha384Pss],
        [WellKnownCoseAlgorithms.Ps512, CryptoAlgorithm.RsaSha512Pss]
    ];


    /// <summary>Maps an RSA-family oracle factory name to the oracle it builds.</summary>
    private static Fido2AssertionOracle CreateRsaFamilyOracle(string oracleFactoryName) => oracleFactoryName switch
    {
        nameof(Fido2AssertionOracle.CreatePs256) => Fido2AssertionOracle.CreatePs256(),
        nameof(Fido2AssertionOracle.CreatePs384) => Fido2AssertionOracle.CreatePs384(),
        nameof(Fido2AssertionOracle.CreatePs512) => Fido2AssertionOracle.CreatePs512(),
        nameof(Fido2AssertionOracle.CreateRs384) => Fido2AssertionOracle.CreateRs384(),
        nameof(Fido2AssertionOracle.CreateRs512) => Fido2AssertionOracle.CreateRs512(),
        _ => throw new ArgumentException($"Unknown oracle factory '{oracleFactoryName}'.", nameof(oracleFactoryName))
    };


    /// <summary>
    /// Reconstructs an <see cref="AssertionCeremonyInput"/> from <paramref name="minted"/>'s wire bytes only —
    /// via <see cref="ClientDataJsonReader"/> and <see cref="AuthenticatorDataReader"/> — and runs
    /// <see cref="Fido2AssertionVerifier"/> against <paramref name="credentialPublicKey"/>, which may differ
    /// from the key <paramref name="minted"/> was signed with (the algorithm-confusion tests above).
    /// </summary>
    private async Task<Fido2AssertionOutcome> VerifyAsync(CoseKey credentialPublicKey, MintedAssertion minted)
    {
        ClientData clientData = ClientDataJsonReader.Read(minted.ClientDataJson);
        AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(
            minted.AuthenticatorData, Fido2TestVectors.TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        using var ceremonyInput = new AssertionCeremonyInput
        {
            ClientData = clientData,
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = ValidChallenge,
            ExpectedOrigins = new HashSet<string> { ValidOrigin },
            ExpectedRpIdHash = Fido2TestVectors.WrapRpIdHash(Fido2TestVectors.CreateRpIdHash(), BaseMemoryPool.Shared),
            AllowCrossOrigin = false,
            UserVerification = UserVerificationRequirement.Required,
            StoredSignCount = 0,
            StoredUvInitialized = true
        };

        return await Fido2AssertionVerifier.VerifyAsync(
            credentialPublicKey,
            minted.Signature.AsReadOnlyMemory(),
            minted.AuthenticatorData,
            minted.ClientDataJson,
            ceremonyInput,
            correlationId: "fido2-rsa-padding-es256k-test-correlation",
            pool: BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }
}
