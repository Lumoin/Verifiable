using System.Collections.Immutable;
using System.Net.Http;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Unit and real-wire tests for the <c>client_secret_basic</c> / <c>client_secret_post</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1">RFC 6749 §2.3.1</see>)
/// client-authentication attach helpers: <see cref="OutgoingHeadersClientAuthExtensions.WithClientSecretBasic"/>
/// and <see cref="OutgoingFormFieldsClientAuthExtensions.WithClientSecretPost"/>.
/// </summary>
/// <remarks>
/// The centerpiece is <see cref="ClientSecretBasicUrlEncodesBeforeBase64HandDerivedKat"/>: a
/// hand-derived known-answer test proving the urlencode-BEFORE-base64 construction §2.3.1 requires,
/// using an identifier and secret containing <c>:</c>, <c>+</c>, and space — three characters the
/// <c>application/x-www-form-urlencoded</c> and Base64 alphabets treat differently, so a
/// naive <c>base64(id + ":" + secret)</c> implementation would silently diverge from this expected
/// value. The KAT was independently computed (Python, RFC 6749 Appendix B's own algorithm) and is
/// reproduced in this doc comment's neighbouring test for anyone re-deriving it:
/// <c>form_urlencode("client:a+b c")</c> = <c>client%3Aa%2Bb+c</c>,
/// <c>form_urlencode("sec:re t+val")</c> = <c>sec%3Are+t%2Bval</c>,
/// <c>base64("client%3Aa%2Bb+c:sec%3Are+t%2Bval")</c> = <c>Y2xpZW50JTNBYSUyQmIrYzpzZWMlM0FyZSt0JTJCdmFs</c>.
/// </remarks>
[TestClass]
internal sealed class ClientSecretAttachHelperTests
{
    private const string ClientId = "https://machine.example.com";
    private const string ClientSecret = "s3cret-of-the-machine";

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);


    /// <summary>
    /// The hand-derived KAT (see the class doc comment for the independent derivation): a client id
    /// and secret each containing <c>:</c>, <c>+</c>, and space produce the EXACT expected Basic
    /// header. A naive <c>base64(id + ":" + secret)</c> — skipping the urlencode step RFC 6749 §2.3.1
    /// requires — would instead produce <c>Y2xpZW50OmErYiBjOnNlYzpyZSB0K3ZhbA==</c>, a DIFFERENT value
    /// this test also asserts against, to make the correctness risk observable rather than merely
    /// asserted.
    /// </summary>
    [TestMethod]
    public void ClientSecretBasicUrlEncodesBeforeBase64HandDerivedKat()
    {
        const string clientId = "client:a+b c";
        const string clientSecret = "sec:re t+val";
        const string expectedCorrectHeader = "Basic Y2xpZW50JTNBYSUyQmIrYzpzZWMlM0FyZSt0JTJCdmFs";
        const string wrongNaiveHeader = "Basic Y2xpZW50OmErYiBjOnNlYzpyZSB0K3ZhbA==";

        OutgoingHeaders headers = OutgoingHeaders.Empty.WithClientSecretBasic(clientId, Encoding.UTF8.GetBytes(clientSecret));

        string actualHeader = headers.Values[WellKnownHttpHeaderNames.Authorization];
        Assert.AreEqual(expectedCorrectHeader, actualHeader);
        Assert.AreNotEqual(wrongNaiveHeader, actualHeader,
            "The urlencode-before-base64 construction must diverge from a naive raw id:secret concatenation for these characters.");
    }


    /// <summary>RFC 6749 Appendix B's own worked example (space, <c>%</c>, <c>&amp;</c>, <c>+</c>, and two non-ASCII code points) reproduced as a KAT independent of the client-secret framing.</summary>
    [TestMethod]
    public void FormUrlEncodingMatchesRfc6749AppendixBWorkedExample()
    {
        //RFC 6749 Appendix B: " %&+£€" (space, %, &, +, U+00A3, U+20AC) encodes to "+%25%26%2B%C2%A3%E2%82%AC".
        //Round through the Basic helper with an empty client id so only the secret half is observed.
        byte[] exampleUtf8 = Encoding.UTF8.GetBytes(" %&+£€");
        OutgoingHeaders headers = OutgoingHeaders.Empty.WithClientSecretBasic("x", exampleUtf8);

        byte[] decoded = Convert.FromBase64String(headers.Values[WellKnownHttpHeaderNames.Authorization]["Basic ".Length..]);
        string decodedPair = Encoding.UTF8.GetString(decoded);
        string encodedExample = decodedPair["x:".Length..];

        Assert.AreEqual("+%25%26%2B%C2%A3%E2%82%AC", encodedExample);
    }


    /// <summary>
    /// Proves byte-agreement between the client-side encoder and a spec-correct decoder: build a
    /// Basic header via <see cref="OutgoingHeadersClientAuthExtensions.WithClientSecretBasic"/> for an
    /// identifier/secret pair containing the same tricky characters as the KAT, wire it through the
    /// SHIPPED <see cref="ValidateClientCredentialsDelegate"/> seam (a
    /// test-side decoder that reverses RFC 6749 §2.3.1's construction — base64-decode, split on the
    /// first <c>:</c>, form-urldecode each half), and confirm the real, Kestrel-hosted authorization
    /// server accepts the client and issues a token.
    /// </summary>
    [TestMethod]
    public async Task ClientSecretBasicRoundTripsAgainstShippedAsValidationOverHttpWire()
    {
        const string clientId = "client:a+b c";
        const string clientSecret = "sec:re t+val";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            clientId,
            new Uri("https://machine.example.com"),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        app.Server.OAuth().ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
            ValueTask.FromResult(DecodeAndMatchBasicHeader(request, clientId, clientSecret));

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingHeaders headers = OutgoingHeaders.Empty.WithClientSecretBasic(clientId, Encoding.UTF8.GetBytes(clientSecret));
        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!,
            tokenUrl,
            new Dictionary<string, string> { [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials },
            headers,
            TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);
    }


    /// <summary>
    /// RFC 6749 §2.3 L864 ("The client MUST NOT use more than one authentication method in each
    /// request") binds the CLIENT; the RFC has no distinct AS-side "MUST reject a double-credentialed
    /// request" sentence in §2.3/§2.3.1. <see cref="ValidateClientCredentialsDelegate"/> receives BOTH
    /// the incoming request (the <c>Authorization</c> header) and the form fields unconditionally, and
    /// this library performs no structural rejection of a request presenting both — the
    /// application-supplied seam is the sole arbiter. This test PINS that current, intentional
    /// behavior: a request carrying a VALID <c>client_secret_basic</c> header AND a
    /// <c>client_secret_post</c> <c>client_secret</c> field the seam never inspects is accepted,
    /// proving the library does not reject the double-credentialed shape on the seam's behalf.
    /// </summary>
    [TestMethod]
    public async Task RequestCarryingBothBasicHeaderAndPostFieldsIsAcceptedWhenTheSeamOnlyChecksOneChannel()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        //A client_secret_basic-only policy: the seam checks ONLY the Authorization header and never
        //looks at the form fields, yet the endpoint hands both to it unconditionally
        //(AuthCodeEndpoints.cs's ValidateClientCredentialsAsync call sites).
        app.Server.OAuth().ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
            ValueTask.FromResult(DecodeAndMatchBasicHeader(request, ClientId, ClientSecret));

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //Attach BOTH a VALID Basic header and client_secret_post fields carrying a WRONG secret — RFC
        //6749 §2.3 tells the CLIENT not to do this, but nothing on the authorization-server side
        //structurally forbids it.
        OutgoingHeaders headers = OutgoingHeaders.Empty.WithClientSecretBasic(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        OutgoingFormFields form = new OutgoingFormFields { [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials }
            .WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes("wrong-secret-the-seam-never-checks"));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, headers, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body,
            "The current, intentional behavior: the seam alone decides; the library does not " +
            "structurally reject a request presenting both an Authorization header and body credentials.");
    }


    /// <summary>
    /// RFC 6749 §2.3 L860: "the authorization server MUST NOT rely on public client authentication for
    /// the purpose of identifying the client." The architecture satisfies this structurally —
    /// <c>LoadClientRegistrationDelegate</c> resolves the <see cref="ClientRecord"/> from
    /// <c>client_id</c>/tenant BEFORE <see cref="ValidateClientCredentialsDelegate"/> ever runs, and
    /// there is no code path for that later delegate's answer to feed back into which registration was
    /// resolved. This regression test pins the absence of that feedback path: the SAME registration
    /// (the same <see cref="ClientRecord.ClientId"/>) is identified whether the request is about to be
    /// REJECTED (wrong secret) or ACCEPTED (correct secret) — identification does not vary with what
    /// authentication decides.
    /// </summary>
    [TestMethod]
    public async Task RegistrationIdentificationIsUnaffectedByWhatClientAuthenticationWouldReturn()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        List<string> identifiedClientIds = [];
        app.Server.OAuth().ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
        {
            //Captured regardless of which value THIS call is about to return: this seam is only ever
            //handed the already-resolved registration, never the other way around.
            identifiedClientIds.Add(registration.ClientId);

            return ValueTask.FromResult(
                fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //(a) WRONG secret — authentication is about to be REJECTED.
        OutgoingFormFields rejectedForm = new OutgoingFormFields { [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials }
            .WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes("wrong-secret"));
        using HttpResponseMessage rejected = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, rejectedForm, TestContext.CancellationToken).ConfigureAwait(false);
        string rejectedBody = await rejected.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(401, (int)rejected.StatusCode, rejectedBody);

        //(b) CORRECT secret — authentication is about to be ACCEPTED.
        OutgoingFormFields acceptedForm = new OutgoingFormFields { [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials }
            .WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage accepted = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, acceptedForm, TestContext.CancellationToken).ConfigureAwait(false);
        string acceptedBody = await accepted.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)accepted.StatusCode, acceptedBody);

        //The SAME registration (same client_id) was identified on both calls — one about to reject, one
        //about to accept — proving identification does not vary with what authentication decides.
        Assert.HasCount(2, identifiedClientIds);
        Assert.AreEqual(ClientId, identifiedClientIds[0]);
        Assert.AreEqual(ClientId, identifiedClientIds[1]);
    }


    /// <summary>RFC 6749 §2.3.1: "The client MAY omit the parameter if the client secret is an empty string." An empty secret sets only <c>client_id</c>.</summary>
    [TestMethod]
    public void ClientSecretPostOmitsSecretFieldWhenSecretIsEmpty()
    {
        OutgoingFormFields form = new OutgoingFormFields().WithClientSecretPost(ClientId, ReadOnlySpan<byte>.Empty);

        Assert.AreEqual(ClientId, form[OAuthRequestParameterNames.ClientId]);
        Assert.IsFalse(form.ContainsKey(OAuthRequestParameterNames.ClientSecret));
    }


    /// <summary>The non-empty converse: both <c>client_id</c> and <c>client_secret</c> are set, the secret decoded verbatim from its UTF-8 carrier.</summary>
    [TestMethod]
    public void ClientSecretPostSetsBothFieldsWhenSecretIsNonEmpty()
    {
        OutgoingFormFields form = new OutgoingFormFields().WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        Assert.AreEqual(ClientId, form[OAuthRequestParameterNames.ClientId]);
        Assert.AreEqual(ClientSecret, form[OAuthRequestParameterNames.ClientSecret]);
    }


    /// <summary>End-to-end: a form built via <see cref="OutgoingFormFieldsClientAuthExtensions.WithClientSecretPost"/> authenticates against the shipped <c>client_credentials</c> endpoint over a real Kestrel-hosted wire.</summary>
    [TestMethod]
    public async Task ClientSecretPostRoundTripsOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        app.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(
                fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = new OutgoingFormFields { [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials }
            .WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);
    }


    /// <summary>
    /// The test-side reverse of <see cref="OutgoingHeadersClientAuthExtensions.WithClientSecretBasic"/>:
    /// base64-decode the <c>Authorization: Basic</c> header, split the pair on the FIRST <c>:</c> (the
    /// join character the encoder itself never percent-encodes into either half), and reverse
    /// <c>application/x-www-form-urlencoded</c> (<c>+</c> back to space, then <see cref="Uri.UnescapeDataString"/>
    /// for the remaining <c>%XX</c> triplets) on each half before comparing.
    /// </summary>
    private static bool DecodeAndMatchBasicHeader(IncomingRequest? request, string expectedClientId, string expectedClientSecret)
    {
        if(request is null
            || !request.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? authorizationHeader)
            || authorizationHeader is null
            || !authorizationHeader.StartsWith("Basic ", StringComparison.Ordinal))
        {
            return false;
        }

        byte[] decoded = Convert.FromBase64String(authorizationHeader["Basic ".Length..]);
        string pair = Encoding.UTF8.GetString(decoded);
        int separatorIndex = pair.IndexOf(':', StringComparison.Ordinal);
        if(separatorIndex < 0)
        {
            return false;
        }

        string decodedClientId = FormUrlDecode(pair[..separatorIndex]);
        string decodedClientSecret = FormUrlDecode(pair[(separatorIndex + 1)..]);

        return string.Equals(decodedClientId, expectedClientId, StringComparison.Ordinal)
            && string.Equals(decodedClientSecret, expectedClientSecret, StringComparison.Ordinal);
    }


    /// <summary>Reverses <c>application/x-www-form-urlencoded</c> (RFC 6749 Appendix B) on <paramref name="value"/>: <c>+</c> becomes space, then <see cref="Uri.UnescapeDataString"/> resolves the remaining <c>%XX</c> triplets.</summary>
    private static string FormUrlDecode(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));
}
