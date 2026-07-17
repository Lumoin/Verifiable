using System.Diagnostics.CodeAnalysis;
using CsCheck;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.Fido2.Fido2RegistrationVerifierTests;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Property-based tests (CsCheck) for <see cref="Fido2RegistrationVerifier"/>: invariants that must
/// hold for every base64url-alphabet challenge in the input space, not just the hand-picked vector in
/// <see cref="Fido2RegistrationVerifierTests"/>.
/// </summary>
[TestClass]
internal sealed class Fido2RegistrationVerifierPropertyTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Property test: for any base64url-alphabet challenge, a validly minted <c>none</c>-attestation
    /// registration echoing that exact challenge is always acceptable and always yields a
    /// credential record — the ceremony rules and the attestation dispatch agree on "valid" across
    /// the challenge input space, not just the hand-picked vector in
    /// <see cref="Fido2RegistrationVerifierTests.ValidNoneAttestationRegistrationIsAcceptableWithPopulatedCredentialRecord"/>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "CsCheck's Sample callback is synchronous and cannot await; GetAwaiter().GetResult() blocks until the verification call fully completes, so the using declarations' dispose runs strictly after it returns.")]
    public void ValidNoneAttestationRegistrationsAlwaysAcceptableAcrossRandomChallenges()
    {
        //The public key's content is immaterial to this property — only its P-256 shape (kty/curve)
        //is observed by the verifier below — so the shared provider material stands in for a freshly
        //minted key pair.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory credentialKeyPublicKey = credentialKeyMaterial.PublicKey;
        using PrivateKeyMemory credentialKeyPrivateKey = credentialKeyMaterial.PrivateKey;
        byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(credentialKeyPublicKey.AsReadOnlySpan(), EllipticCurveTypes.P256);
        CoseKey credentialPublicKey = new(
            kty: CoseKeyTypes.Ec2,
            alg: WellKnownCoseAlgorithms.Es256,
            curve: CoseKeyCurves.P256,
            x: EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint).ToArray(),
            y: EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint).ToArray());
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        (from length in Gen.Int[1, 32]
         from seed in Gen.Int[0, int.MaxValue]
         select (length, seed))
        .Sample(sample =>
        {
            string challenge = BuildBase64UrlChallenge(sample.length, sample.seed);
            AuthenticatorData authenticatorData = BuildRegistrationAuthenticatorData(rpIdHash, Guid.NewGuid(), credentialPublicKey, [0x01, 0x02, 0x03], out byte[] authDataBytes);
            byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, challenge, ValidOrigin);
            using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
                clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
                authenticatorDataOverride: authenticatorData,
                expectedRpIdHash: rpIdHash,
                expectedChallenge: challenge);

            SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
                (WellKnownWebAuthnAttestationFormats.None, NoneAttestation.Build()));

            Fido2RegistrationOutcome outcome = Fido2RegistrationVerifier.VerifyAsync(
                WellKnownWebAuthnAttestationFormats.None,
                attestationStatement: new byte[] { CanonicalEmptyMap },
                authDataBytes,
                clientDataJson,
                ceremonyInput,
                selectVerifier,
                AlwaysUnique,
                trustAnchors: [],
                validationTime: TestClock.CanonicalEpoch,
                CorrelationId,
                BaseMemoryPool.Shared,
                cancellationToken: TestContext.CancellationToken)
                .AsTask().GetAwaiter().GetResult();

            using Fido2CredentialRecord? record = outcome.CredentialRecord;

            return outcome.IsAcceptable && record is not null;
        });
    }


    /// <summary>
    /// Deterministically builds a base64url-alphabet challenge string of the given length from a
    /// seed, for the property test's random-challenge axis. Not security-sensitive — this only
    /// varies the ceremony's test input, never key or nonce material — so the deterministic,
    /// seedable <see cref="Random"/> is appropriate; a cryptographic RNG cannot be seeded for
    /// reproducible shrinking.
    /// </summary>
    [SuppressMessage("Security", "CA5394:Do not use insecure randomness",
        Justification = "Test-only ceremony input diversity, not key/nonce/salt material; determinism from an explicit seed is required, which a cryptographic RNG cannot provide.")]
    private static string BuildBase64UrlChallenge(int length, int seed)
    {
        const string Base64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        var random = new Random(seed);
        Span<char> characters = length <= 64 ? stackalloc char[length] : new char[length];
        for(int i = 0; i < length; i++)
        {
            characters[i] = Base64UrlAlphabet[random.Next(Base64UrlAlphabet.Length)];
        }

        return new string(characters);
    }
}
