using System.Diagnostics.CodeAnalysis;
using CsCheck;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

using static Verifiable.Tests.Fido2.Fido2CredentialSignerTests;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Property-based tests (CsCheck) for <see cref="Fido2CredentialSigner"/>: the sign-then-verify round
/// trip through the shipped <see cref="Fido2AssertionVerifier"/> holds for any base64url-alphabet
/// challenge and any signature counter, not just the hand-picked vectors in
/// <see cref="Fido2CredentialSignerTests"/>.
/// </summary>
[TestClass]
internal sealed class Fido2CredentialSignerPropertyTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Property test: for any base64url-alphabet challenge and any signature counter, a
    /// <see cref="Fido2CredentialSigner"/> ES256 signature always verifies and is always acceptable
    /// through the shipped <see cref="Fido2AssertionVerifier"/> — the sign-then-verify round trip holds
    /// across the input space, not just the hand-picked vectors in the other tests of this class.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "CsCheck's Sample callback is synchronous and cannot await; GetAwaiter().GetResult() blocks until each async call fully completes.")]
    public void SignThenVerifyRoundTripsAcrossRandomChallengesAndSignCountsForEs256()
    {
        using CredentialFixture credential = CreateCredential(WellKnownCoseAlgorithms.Es256);

        (from challengeLength in Gen.Int[1, 32]
         from challengeSeed in Gen.Int[0, int.MaxValue]
         from signCount in Gen.UInt[1, 1000]
         select (challengeLength, challengeSeed, signCount))
        .Sample(sample =>
        {
            string challenge = BuildBase64UrlChallenge(sample.challengeLength, sample.challengeSeed);
            byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();
            byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, ValidFlags, sample.signCount);
            byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, challenge, ValidOrigin, crossOrigin: null, topOrigin: null);

            (Fido2AssertionOutcome outcome, _, _) = SignAndVerifyAsync(
                credential, authenticatorData, clientDataJson, challenge, rpIdHash, TestContext.CancellationToken)
                .AsTask().GetAwaiter().GetResult();

            Assert.IsTrue(outcome.SignatureValid);
            Assert.IsTrue(outcome.IsAcceptable);
        });
    }


    /// <summary>
    /// Deterministically builds a base64url-alphabet challenge string of the given length from a seed,
    /// for the property test's random-challenge axis. Not security-sensitive — this only varies the
    /// ceremony's test input, never key or nonce material — so the deterministic, seedable
    /// <see cref="Random"/> is appropriate; a cryptographic RNG cannot be seeded for reproducible shrinking.
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
