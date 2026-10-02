using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for the OIDC ID Token wire output composed through
/// <see cref="Oidc10IdTokenProducer"/> plus the contributor walk on
/// <see cref="AuthorizationServerIntegration.ClaimIssuer"/>.
/// </summary>
/// <remarks>
/// <para>
/// The producer composes only the JWT structural baseline
/// (<c>iss</c>, <c>aud</c>, <c>iat</c>, <c>exp</c>, <c>jti</c>, optional <c>nonce</c>);
/// the <c>sub</c>, <c>auth_time</c>, <c>acr</c>, <c>amr</c>, <c>cnf</c>,
/// and OIDC §5.4 scope-driven claims all arrive via the walking site's
/// contributor walk. The baseline regression below therefore drives a
/// full PAR / Authorize / Token exchange against
/// <see cref="TestHostShell"/> and pins the full wire-level ID Token
/// payload — that's the contract relying parties actually observe.
/// </para>
/// <para>
/// A fixed input set (subject, scope, nonce, issuer, client id, signing
/// key id) produces a canonical payload that this test pins, so any
/// future change that adds, removes, renames, or alters a claim for the
/// baseline input fails the assertion. Deliberate changes need a
/// deliberate baseline update, not a silent passing test.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Oidc10IdTokenProducerTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch.AddDays(-15));

    private const string ClientId = "https://idtoken-baseline.test";
    private const string SubjectId = "subject-baseline";
    private static Uri ClientBaseUri { get; } = new("https://idtoken-baseline.test");
    //RegisterDpopClient hard-codes its single registered redirect URI to
    //https://client.example.com/callback; the PAR/Authorize/Token flow must
    //present that exact URI to match the registration.
    private static Uri RedirectUri { get; } =
        new("https://client.example.com/callback");


    /// <summary>
    /// The whole ID Token payload a code redemption returns for the fixed inputs of this class, pinned as a
    /// canonical literal: the producer's structural baseline, its <c>jti</c> the value the identifier seam
    /// answers through <see cref="AnswerJwtIdentifiersAsync"/>, and the claims the contributor walk adds. The
    /// claims are those
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 Section 2</see>
    /// defines for the ID Token, with the <c>jti</c> of
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">RFC 7519 section 4.1.7</see>.
    /// </summary>
    [TestMethod]
    public async Task PayloadCarriesExpectedClaimsForBaselineInput()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await AnswerJwtIdentifiersAsync(host).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode,
            $"Token exchange must succeed. Body: {tokenResponse.Body}");

        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);
        string idToken = body.RootElement.GetProperty("id_token").GetString()!;
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(idToken);

        string actualCanonical = CanonicaliseClaims(payload.RootElement);

        //The baseline below pins the wire-level ID Token payload composed
        //by Oidc10IdTokenProducer + the standard contributor walk for the
        //fixed inputs above. Any change that legitimately alters the
        //payload — a new claim being emitted by default, a claim type
        //changing, a value formatting change — fails this assertion. If
        //the change is intentional, regenerate the literal by
        //uncommenting the TestContext.WriteLine line below, running the
        //test, and pasting the printed value here.
        //TestContext.WriteLine(actualCanonical);

        //iat = 2026-05-17T12:00:00Z = 1779019200
        //exp = iat + 1h default lifetime = 1779022800
        //auth_time: absent, the fixed inputs stamp no authentication instant and the
        //authorization server states none it was not given
        //iss = host's per-registration issuer (tenant-segmented)
        //jti = the seam's second answer under the JWT ID purpose; the access token, built first, draws the first
        //sub = identity-resolved SubjectId via the default subject identifier resolver
        string expectedIssuer = ExtractIssuer(payload.RootElement);
        string expectedCanonical =
            $$"""
            {"aud":"{{ClientId}}","exp":1779022800,"iat":1779019200,"iss":"{{expectedIssuer}}","jti":"jwt-id-2","sub":"{{SubjectId}}"}
            """;

        Assert.AreEqual(expectedCanonical, actualCanonical,
            "ID Token payload diverged from the baseline. If the change is "
            + "intentional, uncomment the TestContext.WriteLine line in this "
            + "test, copy the printed canonical string, and paste it into "
            + "expectedCanonical above. Otherwise the producer + contributor "
            + "walk regressed.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">RFC 7519 section 4.1.7</see>: "The "jti"
    /// (JWT ID) claim provides a unique identifier for the JWT." The ID Token's <c>jti</c> is the value the
    /// server's identifier seam answers for the producer's own draw under
    /// <see cref="WellKnownIdentifierPurposes.OAuthJti"/>: a code redemption draws one identifier under that
    /// purpose for the access token and one for the ID Token, in the order the producers run, and each token
    /// carries its own draw.
    /// </summary>
    [TestMethod]
    public async Task IdTokenJtiIsTheIdentifierSeamsOwnDrawUnderTheJwtIdPurpose()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        ConcurrentQueue<string> drawnJwtIds = await AnswerJwtIdentifiersAsync(host).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode,
            $"Token exchange must succeed. Body: {tokenResponse.Body}");

        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);
        using JsonDocument accessTokenPayload = JwtPayloadReader.ParsePayloadJson(
            body.RootElement.GetProperty("access_token").GetString()!);
        using JsonDocument idTokenPayload = JwtPayloadReader.ParsePayloadJson(
            body.RootElement.GetProperty("id_token").GetString()!);

        string[] expectedDraws = ["jwt-id-1", "jwt-id-2"];
        Assert.AreSequenceEqual(expectedDraws, drawnJwtIds.ToArray(),
            "A code redemption must draw one JWT ID for the access token and one for the ID Token.");
        Assert.AreEqual("jwt-id-1", accessTokenPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Jti).GetString(),
            "The access token's jti must be the seam's first answer.");
        Assert.AreEqual("jwt-id-2", idTokenPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Jti).GetString(),
            "The ID Token's jti must be the seam's answer to the ID Token producer's own draw.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">RFC 7519 section 4.1.7</see>: "The "jti"
    /// (JWT ID) claim provides a unique identifier for the JWT." A value that is empty or white space only identifies
    /// no token, and the authorization server refuses it for the ID Token as it refuses it for the access token: the
    /// identifier seam answers the access token's draw with <c>jwt-id-1</c> and the ID Token's draw with
    /// <paramref name="blankJwtId"/>, and the code redemption over the wire is answered 500 with an empty body, so no
    /// ID Token is issued. The producer refuses the answer with the <see cref="ArgumentException"/> that
    /// <see cref="JwtPayloadExtensions.ForAccessToken"/> throws for the access token's, which leaves the token
    /// endpoint unhandled, so the host records no fault of its own and the listener answers 500, as it answers the
    /// access token's walk for the same answer. The refusal is this library's rule.
    /// </summary>
    /// <param name="blankJwtId">The identifier the seam answers for the ID Token's draw.</param>
    [TestMethod]
    [DataRow("")]
    [DataRow(" ")]
    public async Task ABlankJwtIdentifierForTheIdTokenIsRefusedAsForTheAccessToken(string blankJwtId)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        ConcurrentQueue<string> drawnJwtIds = await AnswerJwtIdentifiersAsync(host, blankJwtId).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        //The pushed request, the authorize redirect and the code exchange each cross the loopback listener.
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, TestHostShell.MemoryPool);
        List<KeyValuePair<string, string>> parFields =
        [
            new(OAuthRequestParameterNames.ResponseType, WellKnownResponseTypes.Code),
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.CodeChallenge, pkce.EncodedChallenge),
            new(OAuthRequestParameterNames.CodeChallengeMethod, WellKnownCodeChallengeMethods.S256),
            new(OAuthRequestParameterNames.RedirectUri, RedirectUri.OriginalString),
            new(OAuthRequestParameterNames.Scope, WellKnownScopes.OpenId)
        ];
        (int parStatusCode, string parBody, Uri? authorizeLocation, int authorizeStatusCode) =
            await RawAuthCodeWirePushers.PushParAndAuthorizeAsync(
                host, segment, ClientId, SubjectId, parFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parStatusCode, parBody);
        Assert.AreEqual(302, authorizeStatusCode);
        Assert.IsNotNull(authorizeLocation, "The authorize answer is a redirect carrying a Location header.");
        string code = TestBrowser.ExtractQueryParam(authorizeLocation.OriginalString, OAuthRequestParameterNames.Code)!;

        (int status, string body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host,
            segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        string[] expectedDraws = ["jwt-id-1", blankJwtId];
        Assert.AreSequenceEqual(expectedDraws, drawnJwtIds.ToArray(),
            "The access token's draw must be answered normally and the ID Token's draw with the blank identifier.");
        Assert.AreEqual(500, status, body);
        Assert.AreEqual(string.Empty, body, "The refused redemption must carry no token.");
        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(),
            "The refusal must leave the token endpoint as the access token builder's refusal does, not as a fault the host answers.");
    }


    /// <summary>
    /// Wires the host's identifier seam so that every draw under
    /// <see cref="WellKnownIdentifierPurposes.OAuthJti"/> answers <c>jwt-id-</c> followed by the draw's ordinal
    /// (<c>jwt-id-1</c> first) and is recorded in the returned queue in draw order; every other purpose is
    /// answered by the seam the host was built with. A JWT ID is then a literal a row can state. When
    /// <paramref name="idTokenAnswer"/> is given, the second draw, the ID Token's in the order the producers run,
    /// answers it instead.
    /// </summary>
    /// <param name="host">The host whose authorization server draws the identifiers.</param>
    /// <param name="idTokenAnswer">The answer to the ID Token's draw, or <see langword="null"/> for <c>jwt-id-2</c>.</param>
    /// <returns>The JWT IDs the seam answered, in draw order.</returns>
    private static async Task<ConcurrentQueue<string>> AnswerJwtIdentifiersAsync(TestHostShell host, string? idTokenAnswer = null)
    {
        ConcurrentQueue<string> drawn = new();
        GenerateIdentifierDelegate original = host.Server.OAuth().GenerateIdentifierAsync!;
        int drawCount = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            candidateIntegration.GenerateIdentifierAsync = (purpose, context, cancellationToken) =>
            {
                if(!purpose.Equals(WellKnownIdentifierPurposes.OAuthJti))
                {
                    return original(purpose, context, cancellationToken);
                }

                int ordinal = Interlocked.Increment(ref drawCount);
                string value = (ordinal, idTokenAnswer) switch
                {
                    (2, { } answer) => answer,
                    _ => "jwt-id-" + ordinal.ToString(CultureInfo.InvariantCulture)
                };
                drawn.Enqueue(value);

                return ValueTask.FromResult(value);
            }).ConfigureAwait(false);

        return drawn;
    }


    private async Task<ServerHttpResponse> DriveCodeExchangeAsync(
        TestHostShell host, VerifierKeyMaterial material, string scope)
    {
        InProcessAuthCodeDriveResult result = await InProcessAuthCodeDriver.DriveAsync(
            host, material, SubjectId, RedirectUri,
            new InProcessAuthCodeDriveOptions { Scope = scope },
            TestContext.CancellationToken).ConfigureAwait(false);

        return result.TokenResponse;
    }


    /// <summary>
    /// Canonicalises a parsed ID Token JSON payload to a stable string with
    /// claim keys sorted lexicographically. Mirrors the prior pre-Phase-A
    /// canonicaliser; only the shapes the producer + standard contributor
    /// walk actually produces for the baseline input are handled.
    /// </summary>
    private static string CanonicaliseClaims(JsonElement payload)
    {
        List<KeyValuePair<string, JsonElement>> entries = [];
        foreach(JsonProperty prop in payload.EnumerateObject())
        {
            entries.Add(new KeyValuePair<string, JsonElement>(prop.Name, prop.Value));
        }
        entries.Sort((a, b) => StringComparer.Ordinal.Compare(a.Key, b.Key));

        StringBuilder sb = new();
        _ = sb.Append('{');
        bool first = true;
        foreach(KeyValuePair<string, JsonElement> entry in entries)
        {
            if(!first) { _ = sb.Append(','); }
            first = false;
            _ = sb.Append('"').Append(entry.Key).Append("\":");
            _ = entry.Value.ValueKind switch
            {
                JsonValueKind.String => sb.Append('"').Append(entry.Value.GetString()).Append('"'),
                JsonValueKind.Number => sb.Append(entry.Value.GetInt64().ToString(CultureInfo.InvariantCulture)),
                JsonValueKind.True => sb.Append("true"),
                JsonValueKind.False => sb.Append("false"),
                JsonValueKind.Null => sb.Append('"').Append(entry.Value.GetRawText()).Append('"'),
                JsonValueKind.Object => sb.Append('"').Append(entry.Value.GetRawText()).Append('"'),
                JsonValueKind.Array => sb.Append('"').Append(entry.Value.GetRawText()).Append('"'),
                JsonValueKind.Undefined => sb.Append('"').Append(entry.Value.GetRawText()).Append('"'),
                _ => sb.Append('"').Append(entry.Value.GetRawText()).Append('"')
            };
        }
        _ = sb.Append('}');
        return sb.ToString();
    }


    private static string ExtractIssuer(JsonElement payload) =>
        payload.GetProperty(WellKnownJwtClaimNames.Iss).GetString()!;


}
