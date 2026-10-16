using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// In-process rows for <see cref="DpopResourceAccess.DecideAsync"/>: the arguments an application passes that are its
/// own configuration, which it is answered for with an exception before any decision, never with a decision on the
/// request; and the decision on a <c>Bearer</c> presentation of a validated token where DPoP-bound access tokens are
/// required, which no application answering that presentation before validating the token reaches over the wire.
/// </summary>
[TestClass]
internal sealed class DpopResourceAccessTests
{
    /// <summary>The test context, carrying the run's cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: "htu: The HTTP target
    /// URI (Section 7.1 of [RFC9110]) of the request to which the JWT is attached, without query and fragment parts.",
    /// with <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>: "The htu claim matches the
    /// HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment parts.",
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2">RFC 9110 Section 4.2</see>: "Although requests
    /// might target any URI scheme, the following schemes are inherent to HTTP servers", http and https, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">Section 4.2.4</see>: "A sender MUST NOT generate
    /// the userinfo subcomponent (and its "@" delimiter) when an "http" or "https" URI reference is generated within a
    /// message as a target URI or field value." The target URI an application names its resource by is the absolute
    /// http or https URI with no userinfo, query or fragment that a proof's <c>htu</c> is held to and the resource's
    /// nonces are issued for. A target URI of any other shape is the application's own argument and is refused with
    /// <see cref="ArgumentException"/> naming <c>request</c>, before any decision. The rows: a relative URI; an https URI
    /// with a query; an https URI with a fragment; an ftp URI; an https URI with userinfo.
    /// </summary>
    /// <param name="row">
    /// The target URI: <see cref="RelativeRow"/>, <see cref="QueryRow"/>, <see cref="FragmentRow"/>, <see cref="FtpRow"/>
    /// or <see cref="UserInfoRow"/>.
    /// </param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(RelativeRow)]
    [DataRow(QueryRow)]
    [DataRow(FragmentRow)]
    [DataRow(FtpRow)]
    [DataRow(UserInfoRow)]
    public async Task DecideRefusesATargetUriNoProofCanNameAsTheCallersArgumentAsync(string row)
    {
        Uri targetUri = row switch
        {
            RelativeRow => new Uri("/protected", UriKind.Relative),
            QueryRow => new Uri("https://rs.example/protected?view=full"),
            FragmentRow => new Uri("https://rs.example/protected#top"),
            FtpRow => new Uri("ftp://rs.example/protected"),
            UserInfoRow => new Uri("https://user@rs.example/protected"),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown target URI row.")
        };
        DpopResourceRequest request = new()
        {
            AccessToken = "access-token",
            IsDpopPresentation = true,
            HttpMethod = "GET",
            TargetUri = targetUri,
            DpopFieldLines = []
        };

        ArgumentException refusal = await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await DpopResourceAccess.DecideAsync(Integration, request, [], TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.AreEqual("request", refusal.ParamName);
    }


    /// <summary>
    /// The row whose target URI is relative. A constant, not a property, because a DataRow attribute argument must be a
    /// compile-time constant.
    /// </summary>
    private const string RelativeRow = "relative";

    /// <summary>
    /// The row whose target URI carries a query. A constant, not a property, because a DataRow attribute argument must
    /// be a compile-time constant.
    /// </summary>
    private const string QueryRow = "query";

    /// <summary>
    /// The row whose target URI carries a fragment. A constant, not a property, because a DataRow attribute argument
    /// must be a compile-time constant.
    /// </summary>
    private const string FragmentRow = "fragment";

    /// <summary>
    /// The row whose target URI has the ftp scheme. A constant, not a property, because a DataRow attribute argument
    /// must be a compile-time constant.
    /// </summary>
    private const string FtpRow = "ftp";

    /// <summary>
    /// The row whose target URI carries userinfo. A constant, not a property, because a DataRow attribute argument must
    /// be a compile-time constant.
    /// </summary>
    private const string UserInfoRow = "userinfo";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "To limit this,
    /// servers MUST only accept DPoP proofs for a limited time after their creation (preferably only for a relatively
    /// brief period on the order of seconds or minutes)." The freshness window an application's resource holds a proof's
    /// <c>iat</c> to either way of its clock is the application's own configuration. A window of minus one second names
    /// no time a proof is accepted for and is refused with <see cref="ArgumentException"/> naming <c>integration</c>,
    /// before any decision.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DecideRefusesANegativeFreshnessWindowAsTheCallersArgumentAsync()
    {
        ResourceServerIntegration integration = new()
        {
            TrustedIssuer = new Uri("https://issuer.test/tenant-a"),
            ExpectedAudience = "test-resource-server",
            ResolveVerificationKeyAsync = static (_, _, _, _, _) => ValueTask.FromResult<PublicKeyMemory?>(null),
            TimeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch),
            DpopFreshnessWindow = TimeSpan.FromSeconds(-1)
        };
        DpopResourceRequest request = new()
        {
            AccessToken = "access-token",
            IsDpopPresentation = true,
            HttpMethod = "GET",
            TargetUri = new Uri("https://rs.example/protected"),
            DpopFieldLines = []
        };

        ArgumentException refusal = await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await DpopResourceAccess.DecideAsync(integration, request, [], TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.AreEqual("integration", refusal.ParamName);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "dpop_bound_access_tokens_required OPTIONAL. Boolean value specifying whether the protected resource always
    /// requires the use of DPoP-bound access tokens [RFC9449].", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If the request lacks
    /// any authentication information (e.g., the client was unaware that authentication is necessary or attempted using
    /// an unsupported authentication method), the resource server SHOULD NOT include an error code or other error
    /// information." At a resource requiring DPoP-bound access tokens, a validated access token bound to no key and
    /// presented under the <c>Bearer</c> scheme is denied: 401, an empty body, and exactly two fields, the one
    /// <c>WWW-Authenticate</c> value
    /// <c>DPoP realm="protected", scope="openid", algs="ES256 ES384 ES512 ES256K RS256 RS384 RS512 PS256 PS384 PS512 EdDSA Ed25519", resource_metadata="https://rs.example/.well-known/oauth-protected-resource"</c>
    /// with no <c>error</c> and no <c>Bearer</c> challenge, and
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DecideRefusesABearerPresentationWhereDpopBoundAccessTokensAreRequiredAsync()
    {
        DpopResourceRequest request = new()
        {
            AccessToken = "access-token",
            IsDpopPresentation = false,
            IsSenderConstrained = false,
            HttpMethod = "GET",
            TargetUri = new Uri("https://rs.example/protected"),
            DpopFieldLines = [],
            IsDpopBoundAccessTokenRequired = true,
            Realm = "protected",
            Scope = "openid",
            ResourceMetadata = new Uri("https://rs.example/.well-known/oauth-protected-resource")
        };

        DpopResourceDecision decision = await DpopResourceAccess.DecideAsync(
            Integration, request, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(DpopResourceDecisionKind.Deny, decision.Kind);
        Assert.IsFalse(decision.IsPermitted, "A denial grants no access.");
        ServerHttpResponse response = Assert.IsInstanceOfType<ServerHttpResponse>(decision.Response);
        Assert.AreEqual(401, response.StatusCode);
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
        Assert.HasCount(2, response.Headers, "The challenge and the exposure field, no other field.");
        Assert.AreEqual(
            "DPoP realm=\"protected\", scope=\"openid\", algs=\"ES256 ES384 ES512 ES256K RS256 RS384 RS512 PS256 PS384 PS512 EdDSA Ed25519\", resource_metadata=\"https://rs.example/.well-known/oauth-protected-resource\"",
            response.Headers["WWW-Authenticate"]);
        Assert.AreEqual("WWW-Authenticate, DPoP-Nonce", response.Headers["Access-Control-Expose-Headers"]);
    }


    /// <summary>
    /// A resource server integration with no DPoP slot wired: the argument checks run before any slot is read, and a
    /// <c>Bearer</c> presentation where DPoP-bound access tokens are required is answered before any slot is read, so
    /// none is needed.
    /// </summary>
    private static ResourceServerIntegration Integration { get; } = new()
    {
        TrustedIssuer = new Uri("https://issuer.test/tenant-a"),
        ExpectedAudience = "test-resource-server",
        ResolveVerificationKeyAsync = static (_, _, _, _, _) => ValueTask.FromResult<PublicKeyMemory?>(null),
        TimeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch)
    };
}
