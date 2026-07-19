using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Adversarial vectors for <see cref="RedirectUriMatching.IsRegisteredExact"/> — RFC 9700 §2.1 /
/// draft-ietf-oauth-client-id-metadata-document-02 §4.2 exact-match, simple-string-comparison
/// redirect_uri enforcement. Part A drives the pure matcher directly; Part B proves the PAR
/// endpoint (<see cref="WellKnownEndpointNames.AuthCodePar"/>) rejects a
/// <see cref="Uri"/>-equal-but-string-different <c>redirect_uri</c> end-to-end via the real
/// dispatcher (<c>TestHostShell.DispatchAtEndpointAsync</c>), never <see cref="Uri.Equals(object?)"/>.
/// </summary>
[TestClass]
internal sealed class RedirectUriMatchingTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string ClientId = "https://client.example.com";
    private static readonly Uri ClientBaseUri = new(ClientId);

    //The redirect URI TestHostShell.RegisterDpopClient registers by default.
    private static readonly Uri RegisteredRedirectUri = new("https://client.example.com/callback");


    //Part A — the pure matcher, no host.

    [TestMethod]
    public void ExactStringMatchIsAccepted()
    {
        Uri registered = new("https://app.example/cb");
        Uri requested = new("https://app.example/cb");

        bool isMatch = RedirectUriMatching.IsRegisteredExact([registered], requested);

        Assert.IsTrue(isMatch);
    }


    /// <summary>
    /// draft-ietf-oauth-client-id-metadata-document-02 §3's own example: a registered URL with no
    /// explicit port and a requested URL carrying the DEFAULT https port (:443) are NOT equivalent
    /// under simple string comparison, even though <see cref="Uri"/> equality treats them as the
    /// same authority.
    /// </summary>
    [TestMethod]
    public void DefaultPortVariantIsRejected()
    {
        Uri registered = new("https://app.example/cb");
        Uri requested = new("https://app.example:443/cb");

        //Sanity: Uri equality DOES consider these the same — this is exactly the laxity
        //RedirectUriMatching exists to avoid.
        Assert.AreEqual(registered, requested);

        bool isMatch = RedirectUriMatching.IsRegisteredExact([registered], requested);

        Assert.IsFalse(isMatch);
    }


    /// <summary>
    /// A percent-encoding case variant (<c>%2F</c> vs <c>%2f</c>) is a different octet sequence on
    /// the wire per RFC 3986 §6.2.1 simple string comparison, even though some URI parsers
    /// case-normalize percent-encoded triplets.
    /// </summary>
    [TestMethod]
    public void PercentEncodingCaseVariantIsRejected()
    {
        Uri registered = new("https://app.example/a%2Fb");
        Uri requested = new("https://app.example/a%2fb");

        bool isMatch = RedirectUriMatching.IsRegisteredExact([registered], requested);

        Assert.IsFalse(isMatch);
    }


    [TestMethod]
    public void NoRegisteredUrisNeverMatch()
    {
        Uri requested = new("https://app.example/cb");

        bool isMatch = RedirectUriMatching.IsRegisteredExact([], requested);

        Assert.IsFalse(isMatch);
    }


    [TestMethod]
    public void MatchesOneOfSeveralRegisteredUris()
    {
        Uri[] registered =
        [
            new Uri("https://app.example/a"),
            new Uri("https://app.example/cb"),
            new Uri("https://app.example/c")
        ];
        Uri requested = new("https://app.example/cb");

        bool isMatch = RedirectUriMatching.IsRegisteredExact(registered, requested);

        Assert.IsTrue(isMatch);
    }


    //Part B — the PAR endpoint end-to-end, via the real dispatcher (TestHostShell.DispatchAtEndpointAsync).

    /// <summary>
    /// The PAR endpoint rejects a <c>redirect_uri</c> that differs from the registered value only
    /// by an explicit default port — proving <see cref="RedirectUriMatching"/>, not
    /// <see cref="Uri.Equals(object?)"/>, governs the wire enforcement (RFC 9700 §2.1 /
    /// draft-ietf-oauth-client-id-metadata-document-02 §4.2).
    /// </summary>
    [TestMethod]
    public async Task ParRejectsDefaultPortVariantOfRegisteredRedirectUri()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        //Same authority under Uri equality, different octets under simple string comparison.
        string portVariant = "https://client.example.com:443/callback";
        Assert.AreEqual(RegisteredRedirectUri, new Uri(portVariant),
            "Sanity: the :443 variant must be Uri-equal to the registered redirect_uri for this to be a meaningful adversarial vector.");

        ServerHttpResponse response = await PushAsync(
            host, material, redirectUri: portVariant).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body, StringComparison.Ordinal);
    }


    /// <summary>Sanity: the exact registered redirect_uri string is accepted by the same PAR path.</summary>
    [TestMethod]
    public async Task ParAcceptsExactRegisteredRedirectUri()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse response = await PushAsync(
            host, material, redirectUri: RegisteredRedirectUri.OriginalString).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);
    }


    private async Task<ServerHttpResponse> PushAsync(
        TestHostShell host, VerifierKeyMaterial material, string redirectUri)
    {
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            fields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
