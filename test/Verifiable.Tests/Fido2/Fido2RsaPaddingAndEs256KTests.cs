using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Crypto.Parameters;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

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


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "In a valid RSA
    /// public key, the RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2, ..., u, where u &gt;= 2,
    /// and the RSA public exponent e is an integer between 3 and n - 1 satisfying GCD(e,\lambda(n)) = 1, where
    /// \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)." Under the exponent 1 the RSA function is the identity, so the
    /// RSASSA-PKCS1-v1_5 SHA-256 encoded message of an assertion's signed data (the authenticator data followed by
    /// the hash of the client data), computed with the exponent 1 over the same modulus, which needs no secret, is
    /// its own signature. A stored RS256 credential
    /// key whose COSE_Key carries the modulus of a 2048-bit key pair and <c>e</c> = 1 is no valid RSA public key: an
    /// assertion that presents that encoded message as its signature is not verified by
    /// <see cref="Fido2AssertionVerifier"/>, which turns the COSE_Key into the DER RSAPublicKey the test registry's
    /// RSA verification function reads.
    /// </summary>
    /// <returns>A task that completes when the answer was asserted.</returns>
    [TestMethod]
    public async Task Rs256AssertionUnderACredentialKeyWithThePublicExponentOneIsNotVerified()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateRs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        ReadOnlyMemory<byte> modulusOctets = oracle.CredentialPublicKey.N.GetValueOrDefault();
        Assert.HasCount(256, modulusOctets.ToArray(), "The stored credential key carries the 256-octet modulus of a 2048-bit key pair.");
        BcBigInteger modulus = new(1, modulusOctets.ToArray());
        CoseKey exponentOneCredentialKey = new(
            kty: oracle.CredentialPublicKey.Kty,
            alg: WellKnownCoseAlgorithms.Rs256,
            n: modulusOctets,
            e: new byte[] { 0x01 });

        using DigestValue clientDataHash = Fido2ClientDataHash.Compute(minted.ClientDataJson, BaseMemoryPool.Shared);
        byte[] signedData = [.. minted.AuthenticatorData, .. clientDataHash.AsReadOnlySpan()];
        byte[] encodedMessage = RsaSignatureFixtures.Sign("Pkcs1", "Sha256", new RsaKeyParameters(isPrivate: true, modulus, BcBigInteger.One), signedData);
        Assert.HasCount(256, encodedMessage);

        Fido2AssertionOutcome outcome = await VerifyAsync(exponentOneCredentialKey, encodedMessage, minted.AuthenticatorData, minted.ClientDataJson);

        Assert.IsFalse(outcome.SignatureValid, "The encoded message under a credential key with the public exponent 1 is not a verified assertion signature.");
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
        Assert.AreEqual(expected, resolved.Value);
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
    /// <param name="credentialPublicKey">The stored credential public key.</param>
    /// <param name="minted">The minted assertion's wire bytes and signature.</param>
    /// <returns>The verifier's outcome.</returns>
    private Task<Fido2AssertionOutcome> VerifyAsync(CoseKey credentialPublicKey, MintedAssertion minted) =>
        VerifyAsync(credentialPublicKey, minted.Signature.AsReadOnlyMemory(), minted.AuthenticatorData, minted.ClientDataJson);


    /// <summary>
    /// Reconstructs an <see cref="AssertionCeremonyInput"/> from the wire bytes <paramref name="authenticatorData"/>
    /// and <paramref name="clientDataJson"/> only and runs <see cref="Fido2AssertionVerifier"/> over
    /// <paramref name="signature"/> against <paramref name="credentialPublicKey"/>: the ceremony an assertion whose
    /// signature octets are presented as they are (not minted by a signer) goes through.
    /// </summary>
    /// <param name="credentialPublicKey">The stored credential public key.</param>
    /// <param name="signature">The presented assertion signature octets.</param>
    /// <param name="authenticatorData">The presented <c>authData</c>.</param>
    /// <param name="clientDataJson">The presented <c>clientDataJSON</c>.</param>
    /// <returns>The verifier's outcome.</returns>
    private async Task<Fido2AssertionOutcome> VerifyAsync(CoseKey credentialPublicKey, ReadOnlyMemory<byte> signature, byte[] authenticatorData, byte[] clientDataJson)
    {
        ClientData clientData = ClientDataJsonReader.Read(clientDataJson);
        AuthenticatorData readAuthenticatorData = AuthenticatorDataReader.Read(
            authenticatorData, Fido2TestVectors.TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        using var ceremonyInput = new AssertionCeremonyInput
        {
            ClientData = clientData,
            AuthenticatorData = readAuthenticatorData,
            ExpectedChallenge = ValidChallenge,
            ExpectedOrigins = new HashSet<string> { ValidOrigin },
            ExpectedRpIdHash = Fido2TestVectors.WrapRpIdHash(Fido2TestVectors.CreateRpIdHash(), BaseMemoryPool.Shared),
            AllowCrossOrigin = false,
            UserVerification = UserVerificationRequirement.Required,
            StoredSignCount = 0,
            StoredUvInitialized = true,
            ExtensionProcessingPool = BaseMemoryPool.Shared
        };

        return await Fido2AssertionVerifier.VerifyAsync(
            credentialPublicKey,
            signature,
            authenticatorData,
            clientDataJson,
            ceremonyInput,
            correlationId: "fido2-rsa-padding-es256k-test-correlation",
            pool: BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }
}
