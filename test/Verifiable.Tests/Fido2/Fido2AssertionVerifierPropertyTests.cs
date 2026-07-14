using System.Diagnostics.CodeAnalysis;
using CsCheck;
using Verifiable.Fido2;
using Verifiable.JCose;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Property-based tests (CsCheck) for <see cref="Fido2AssertionVerifier"/>: invariants that must
/// hold for every challenge and signature counter in the input space, not just the hand-picked
/// vectors in <see cref="Fido2AssertionVerifierTests"/>.
/// </summary>
[TestClass]
internal sealed class Fido2AssertionVerifierPropertyTests
{
    /// <summary>The relying party origin a valid ceremony embeds and expects, mirroring <see cref="Fido2AssertionVerifierTests.ValidOrigin"/>.</summary>
    private const string ValidOrigin = Fido2AssertionVerifierTests.ValidOrigin;

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Property test: for any base64url-alphabet challenge and any signature counter, a validly
    /// minted ES256 assertion always verifies and is always acceptable — the signature check and
    /// the ceremony rules agree on "valid" across the input space, not just the hand-picked vectors
    /// in the other tests of this class.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "CsCheck's Sample callback is synchronous and cannot await; GetAwaiter().GetResult() blocks until each async call fully completes, so mintedAssertion.Dispose() in the finally block runs strictly after VerifyMintedAssertionAsync returns.")]
    public void ValidAssertionsAlwaysVerifyAcrossRandomChallengesAndSignCounts()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();

        (from challengeLength in Gen.Int[1, 32]
         from challengeSeed in Gen.Int[0, int.MaxValue]
         from signCount in Gen.UInt[1, 1000]
         select (challengeLength, challengeSeed, signCount))
        .Sample(sample =>
        {
            string challenge = BuildBase64UrlChallenge(sample.challengeLength, sample.challengeSeed);

            MintedAssertion minted = oracle.MintAsync(challenge, ValidOrigin, signCount: sample.signCount, cancellationToken: TestContext.CancellationToken)
                .AsTask().GetAwaiter().GetResult();
            try
            {
                Fido2AssertionOutcome outcome = VerifyMintedAssertionAsync(oracle.CredentialPublicKey, minted, expectedChallenge: challenge)
                    .GetAwaiter().GetResult();

                Assert.IsTrue(outcome.SignatureValid);
                Assert.IsTrue(outcome.IsAcceptable);
            }
            finally
            {
                minted.Dispose();
            }
        });
    }


    /// <summary>
    /// Forwards to <see cref="Fido2AssertionVerifierTests.VerifyMintedAssertionAsync"/>, the shared
    /// wire-bytes-only assertion verification helper the hand-picked vectors in
    /// <see cref="Fido2AssertionVerifierTests"/> also exercise, so this property test reconstructs
    /// the ceremony input the same way every other assertion-verifier test does.
    /// </summary>
    private Task<Fido2AssertionOutcome> VerifyMintedAssertionAsync(CoseKey credentialPublicKey, MintedAssertion minted, string expectedChallenge)
    {
        return new Fido2AssertionVerifierTests { TestContext = TestContext }
            .VerifyMintedAssertionAsync(credentialPublicKey, minted, expectedChallenge: expectedChallenge);
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
