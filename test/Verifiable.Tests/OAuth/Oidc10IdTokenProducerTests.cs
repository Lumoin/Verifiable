using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for the OIDC ID Token wire output composed through
/// <see cref="Oidc10IdTokenProducer"/> plus the contributor walk on
/// <see cref="ServerConfiguration.ClaimIssuer"/>.
/// </summary>
/// <remarks>
/// <para>
/// The producer composes only the JWT structural baseline
/// (<c>iss</c>, <c>aud</c>, <c>iat</c>, <c>exp</c>, optional <c>nonce</c>);
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

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 5, 17, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://idtoken-baseline.test";
    private const string SubjectId = "subject-baseline";
    private static readonly Uri ClientBaseUri = new("https://idtoken-baseline.test");
    //RegisterDpopClient hard-codes its single registered redirect URI to
    //https://client.example.com/callback; the PAR/Authorize/Token flow must
    //present that exact URI to match the registration.
    private static readonly Uri RedirectUri =
        new("https://client.example.com/callback");


    [TestMethod]
    public async Task PayloadCarriesExpectedClaimsForBaselineInput()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        //auth_time = the authorize-step instant, equal to iat for this fixture
        //iss = host's per-registration issuer (tenant-segmented)
        //sub = identity-resolved SubjectId via the default subject identifier resolver
        string expectedIssuer = ExtractIssuer(payload.RootElement);
        string expectedCanonical =
            $$"""
            {"aud":"{{ClientId}}","auth_time":1779019200,"exp":1779022800,"iat":1779019200,"iss":"{{expectedIssuer}}","sub":"{{SubjectId}}"}
            """;

        Assert.AreEqual(expectedCanonical, actualCanonical,
            "ID Token payload diverged from the baseline. If the change is "
            + "intentional, uncomment the TestContext.WriteLine line in this "
            + "test, copy the printed canonical string, and paste it into "
            + "expectedCanonical above. Otherwise the producer + contributor "
            + "walk regressed.");
    }


    private async Task<ServerHttpResponse> DriveCodeExchangeAsync(
        TestHostShell host, VerifierKeyMaterial material, string scope)
    {
        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, SensitiveMemoryPool<byte>.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = scope
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode);
        string code = ExtractCode(authorizeResponse.Location!);

        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeAuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Canonicalises a parsed ID Token JSON payload to a stable string with
    /// claim keys sorted lexicographically. Mirrors the prior pre-Phase-A
    /// canonicaliser; only the shapes the producer + standard contributor
    /// walk actually produces for the baseline input are handled.
    /// </summary>
    private static string CanonicaliseClaims(JsonElement payload)
    {
        List<KeyValuePair<string, JsonElement>> entries = new();
        foreach(JsonProperty prop in payload.EnumerateObject())
        {
            entries.Add(new KeyValuePair<string, JsonElement>(prop.Name, prop.Value));
        }
        entries.Sort((a, b) => StringComparer.Ordinal.Compare(a.Key, b.Key));

        StringBuilder sb = new();
        sb.Append('{');
        bool first = true;
        foreach(KeyValuePair<string, JsonElement> entry in entries)
        {
            if(!first) { sb.Append(','); }
            first = false;
            sb.Append('"').Append(entry.Key).Append("\":");
            switch(entry.Value.ValueKind)
            {
                case JsonValueKind.String:
                    sb.Append('"').Append(entry.Value.GetString()).Append('"');
                    break;
                case JsonValueKind.Number:
                    sb.Append(entry.Value.GetInt64().ToString(CultureInfo.InvariantCulture));
                    break;
                case JsonValueKind.True:
                    sb.Append("true");
                    break;
                case JsonValueKind.False:
                    sb.Append("false");
                    break;
                default:
                    sb.Append('"').Append(entry.Value.GetRawText()).Append('"');
                    break;
            }
        }
        sb.Append('}');
        return sb.ToString();
    }


    private static string ExtractIssuer(JsonElement payload) =>
        payload.GetProperty(WellKnownJwtClaimNames.Iss).GetString()!;


    private static string ExtractFromBody(string body, string property)
    {
        using JsonDocument doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty(property).GetString()!;
    }


    private static string ExtractCode(string location)
    {
        int q = location.IndexOf('?', StringComparison.Ordinal);
        foreach(string pair in location[(q + 1)..].Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq > 0 && string.Equals(
                pair[..eq], OAuthRequestParameterNames.Code, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
        }

        throw new InvalidOperationException(
            $"Authorize redirect did not carry a code parameter: {location}");
    }
}
