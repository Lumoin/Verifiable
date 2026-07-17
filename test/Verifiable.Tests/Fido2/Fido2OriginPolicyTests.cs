using Verifiable.Core.Assessment;
using Verifiable.Fido2;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Rule-level coverage for <see cref="Fido2AssertionChecks.CheckAssertionOrigin"/> and
/// <see cref="Fido2AssertionChecks.CheckAssertionTopOrigin"/>: the origin comparison is an EXACT ordinal
/// set-membership test, per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web Authentication Level 3,
/// section 7.2: Verifying an Authentication Assertion</see>, steps 10-11 (origin) and 13-14 (top-level
/// origin). Every input is built inline by this file's own helper — the shared
/// <c>Fido2CeremonyInputFactory</c> is not touched.
/// </summary>
[TestClass]
internal sealed class Fido2OriginPolicyTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Cases where the client-reported origin does not ordinally equal the relying party's single expected origin.</summary>
    public static IEnumerable<object[]> MismatchedOriginCases =>
    [
        ["DifferentPort", "https://rp.example:8443", "https://rp.example"],
        ["SchemeDowngrade", "http://rp.example", "https://rp.example"],
        ["Subdomain", "https://sub.rp.example", "https://rp.example"],
        ["TrailingSlash", "https://rp.example/", "https://rp.example"],
        ["IPv6LiteralVersusHostname", "https://[::1]", "https://localhost"]
    ];


    /// <summary>
    /// Each near-miss origin variant (different port, scheme downgrade, subdomain, trailing slash, an IPv6
    /// literal presented where a hostname is expected) fails the origin claim: the comparison is exact
    /// ordinal string equality, not a permissive same-site or same-host match.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(MismatchedOriginCases))]
    public async Task MismatchedOriginVariantFailsTheOriginClaim(string caseName, string actualOrigin, string expectedOrigin)
    {
        using AssertionCeremonyInput input = BuildAssertionInput(clientDataOrigin: actualOrigin, expectedOrigins: new HashSet<string> { expectedOrigin });

        List<Claim> claims = await Fido2AssertionChecks.CheckAssertionOrigin(input, TestContext.CancellationToken);

        Assert.AreEqual(ClaimOutcome.Failure, claims[0].Outcome, caseName);
    }


    /// <summary>
    /// A multi-entry <see cref="AssertionCeremonyInput.ExpectedOrigins"/> accepts the ceremony's origin as
    /// long as it is ANY member of the set — the related-origin allowlisting shape a relying party uses to
    /// accept several equally-trusted origins.
    /// </summary>
    [TestMethod]
    public async Task MultiEntryExpectedOriginsAcceptsAnyMember()
    {
        var expectedOrigins = new HashSet<string> { "https://a.rp.example", "https://rp.example", "https://b.rp.example" };
        using AssertionCeremonyInput input = BuildAssertionInput(clientDataOrigin: "https://rp.example", expectedOrigins: expectedOrigins);

        List<Claim> claims = await Fido2AssertionChecks.CheckAssertionOrigin(input, TestContext.CancellationToken);

        Assert.AreEqual(ClaimOutcome.Success, claims[0].Outcome);
    }


    /// <summary>
    /// A <c>topOrigin</c> that is a member of <see cref="AssertionCeremonyInput.ExpectedTopOrigins"/> succeeds.
    /// </summary>
    [TestMethod]
    public async Task MatchingTopOriginSucceeds()
    {
        using AssertionCeremonyInput input = BuildAssertionInput(
            clientDataTopOrigin: "https://embedder.example",
            expectedTopOrigins: new HashSet<string> { "https://embedder.example" });

        List<Claim> claims = await Fido2AssertionChecks.CheckAssertionTopOrigin(input, TestContext.CancellationToken);

        Assert.AreEqual(ClaimOutcome.Success, claims[0].Outcome);
    }


    /// <summary>
    /// A <c>topOrigin</c> that is not a member of <see cref="AssertionCeremonyInput.ExpectedTopOrigins"/> fails —
    /// the analogous negative case to <see cref="MatchingTopOriginSucceeds"/>.
    /// </summary>
    [TestMethod]
    public async Task MismatchedTopOriginFails()
    {
        using AssertionCeremonyInput input = BuildAssertionInput(
            clientDataTopOrigin: "https://embedder.example",
            expectedTopOrigins: new HashSet<string> { "https://other-embedder.example" });

        List<Claim> claims = await Fido2AssertionChecks.CheckAssertionTopOrigin(input, TestContext.CancellationToken);

        Assert.AreEqual(ClaimOutcome.Failure, claims[0].Outcome);
    }


    /// <summary>
    /// Builds a minimal <see cref="AssertionCeremonyInput"/> exercising only the fields the origin claims
    /// read, leaving every other field at an arbitrary fixed value irrelevant to
    /// <see cref="Fido2AssertionChecks.CheckAssertionOrigin"/> and
    /// <see cref="Fido2AssertionChecks.CheckAssertionTopOrigin"/>.
    /// </summary>
    /// <param name="clientDataOrigin">The client-reported origin.</param>
    /// <param name="clientDataTopOrigin">The client-reported <c>topOrigin</c>, or <see langword="null"/> to omit it.</param>
    /// <param name="expectedOrigins">The relying party's accepted origins. Defaults to a set containing <paramref name="clientDataOrigin"/>.</param>
    /// <param name="expectedTopOrigins">The relying party's expected top-level origins. Defaults to <see langword="null"/>.</param>
    /// <returns>The constructed input; the caller disposes it.</returns>
    private static AssertionCeremonyInput BuildAssertionInput(
        string clientDataOrigin = "https://rp.example",
        string? clientDataTopOrigin = null,
        IReadOnlySet<string>? expectedOrigins = null,
        IReadOnlySet<string>? expectedTopOrigins = null)
    {
        var clientData = new ClientData(WellKnownClientDataTypes.Get, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX", clientDataOrigin, crossOrigin: null, clientDataTopOrigin);

        byte[] rpIdHash = CreateRpIdHash();
        byte[] authenticatorDataBytes = BuildAuthenticatorData(rpIdHash, flags: AuthenticatorDataFlags.None, signCount: 0);
        AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(authenticatorDataBytes, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        return new AssertionCeremonyInput
        {
            ClientData = clientData,
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
            ExpectedOrigins = expectedOrigins ?? new HashSet<string> { clientDataOrigin },
            ExpectedRpIdHash = WrapRpIdHash(rpIdHash, BaseMemoryPool.Shared),
            ExpectedTopOrigins = expectedTopOrigins,
            UserVerification = UserVerificationRequirement.Discouraged,
            StoredSignCount = 0,
            StoredUvInitialized = true
        };
    }
}
