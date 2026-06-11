using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Jar;
using Verifiable.OAuth.Jarm;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Direct tests for the JARM primitives — <see cref="JarmResponseIssuance"/>,
/// <see cref="JarmResponseEncoding"/>, and <see cref="JarmResponseValidation"/> —
/// covering the JARM §2.4 processing rules and the §2.3 response encodings that
/// FAPI 2.0 Message Signing §5.4 requires.
/// </summary>
[TestClass]
internal sealed class JarmResponseTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private const string Issuer = "https://accounts.example.com";
    private const string ClientId = "s6BhdRkqt3";
    private const string KeyId = "authorization-response-key-1";

    private static readonly string[] AllowedAlgorithms = [WellKnownJwaValues.Es256];

    private static readonly Uri RedirectUri = new("https://client.example.com/cb");

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadDeserializer PayloadDeserializer =
        static bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
            ?? throw new FormatException("Payload JSON parsed to null.");


    [TestMethod]
    public async Task CodeResponseRoundTripsThroughClientValidation()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory serverPublic = keys.PublicKey;
        using PrivateKeyMemory serverPrivate = keys.PrivateKey;

        string responseJwt = await IssueAsync(serverPrivate, new Dictionary<string, object>
        {
            ["code"] = "PyyFaux2o7Q0YfXBU32jhw.5FXSQpvr8akv9CeRDSd0QA",
            ["state"] = "S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw"
        }).ConfigureAwait(false);

        JarmResponseValidationResult result = await ValidateAsync(
            responseJwt, serverPublic, Issuer, ClientId).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.AreEqual("PyyFaux2o7Q0YfXBU32jhw.5FXSQpvr8akv9CeRDSd0QA", result.Code);
        Assert.AreEqual("S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw", result.State);
        Assert.IsNotNull(result.Parameters);
        Assert.IsFalse(result.Parameters.ContainsKey(WellKnownJwtClaimNames.Iss));
        Assert.IsFalse(result.Parameters.ContainsKey(WellKnownJwtClaimNames.Aud));
        Assert.IsFalse(result.Parameters.ContainsKey(WellKnownJwtClaimNames.Exp));
    }


    [TestMethod]
    public async Task ErrorResponseRoundTripsThroughClientValidation()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory serverPublic = keys.PublicKey;
        using PrivateKeyMemory serverPrivate = keys.PrivateKey;

        string responseJwt = await IssueAsync(serverPrivate, new Dictionary<string, object>
        {
            ["error"] = OAuthErrors.AccessDenied,
            ["state"] = "af0ifjsldkj"
        }).ConfigureAwait(false);

        JarmResponseValidationResult result = await ValidateAsync(
            responseJwt, serverPublic, Issuer, ClientId).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.AreEqual(OAuthErrors.AccessDenied, result.Error);
        Assert.AreEqual("af0ifjsldkj", result.State);
    }


    [TestMethod]
    public async Task NumericResponseParameterSurvivesAsJsonNumber()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory serverPublic = keys.PublicKey;
        using PrivateKeyMemory serverPrivate = keys.PrivateKey;

        string responseJwt = await IssueAsync(serverPrivate, new Dictionary<string, object>
        {
            ["access_token"] = "2YotnFZFEjr1zCsicMWpAA",
            ["token_type"] = "bearer",
            ["expires_in"] = 3600L
        }).ConfigureAwait(false);

        JarmResponseValidationResult result = await ValidateAsync(
            responseJwt, serverPublic, Issuer, ClientId).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.IsNotNull(result.Parameters);
        Assert.IsTrue(JwtClaimReaders.TryToInt64(result.Parameters["expires_in"], out long expiresIn));
        Assert.AreEqual(3600L, expiresIn);
    }


    [TestMethod]
    public async Task DoesNotResolveKeysForUnexpectedIssuer()
    {
        //JARM §5.1: the client MUST first check that the issuer is well-known and
        //expected before using it to obtain signature-verification keys — a crafted
        //iss must never trigger key resolution.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory serverPublic = keys.PublicKey;
        using PrivateKeyMemory serverPrivate = keys.PrivateKey;

        string responseJwt = await IssueAsync(serverPrivate, new Dictionary<string, object>
        {
            ["code"] = "attacker-code"
        }, issuer: "https://attacker.example.com").ConfigureAwait(false);

        bool isResolverInvoked = false;
        ResolveJarmVerificationKeyDelegate resolver = (_, _, _) =>
        {
            isResolverInvoked = true;

            return ValueTask.FromResult<PublicKeyMemory?>(serverPublic);
        };

        JarmResponseValidationResult result = await JarmResponseValidation.ValidateAsync(
            responseJwt, Issuer, ClientId, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolver, PayloadDeserializer, TestSetup.Base64UrlDecoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsIssuerValid);
        Assert.IsFalse(result.IsValid);
        Assert.IsFalse(isResolverInvoked);
        Assert.IsNull(result.Parameters);
    }


    [TestMethod]
    public async Task RejectsAudienceMismatch()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory serverPublic = keys.PublicKey;
        using PrivateKeyMemory serverPrivate = keys.PrivateKey;

        string responseJwt = await IssueAsync(serverPrivate, new Dictionary<string, object>
        {
            ["code"] = "abc"
        }, clientId: "other-client").ConfigureAwait(false);

        JarmResponseValidationResult result = await ValidateAsync(
            responseJwt, serverPublic, Issuer, ClientId).ConfigureAwait(false);

        Assert.IsFalse(result.IsAudienceValid);
        Assert.IsFalse(result.IsValid);
        Assert.IsNull(result.Parameters);
    }


    [TestMethod]
    public async Task RejectsExpiredResponseAndWithholdsParameters()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory serverPublic = keys.PublicKey;
        using PrivateKeyMemory serverPrivate = keys.PrivateKey;

        string responseJwt = await IssueAsync(serverPrivate, new Dictionary<string, object>
        {
            ["code"] = "abc"
        }, expiresAt: TimeProvider.GetUtcNow().AddMinutes(-1)).ConfigureAwait(false);

        JarmResponseValidationResult result = await ValidateAsync(
            responseJwt, serverPublic, Issuer, ClientId).ConfigureAwait(false);

        //The signature itself is good — only freshness fails — yet §2.4 forbids
        //processing the response parameters before ALL checks succeed.
        Assert.IsTrue(result.IsSignatureValid);
        Assert.IsFalse(result.IsUnexpired);
        Assert.IsFalse(result.IsValid);
        Assert.IsNull(result.Parameters);
        Assert.IsNull(result.Code);
    }


    [TestMethod]
    public async Task RejectsTamperedResponse()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory serverPublic = keys.PublicKey;
        using PrivateKeyMemory serverPrivate = keys.PrivateKey;

        string responseJwt = await IssueAsync(serverPrivate, new Dictionary<string, object>
        {
            ["code"] = "legitimate-code"
        }).ConfigureAwait(false);

        string[] parts = responseJwt.Split('.');
        string payloadJson;
        using(IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(parts[1], Pool))
        {
            payloadJson = Encoding.UTF8.GetString(payloadBytes.Memory.Span).TrimEnd('\0');
        }

        string tamperedJson = payloadJson.Replace("legitimate-code", "attacker-code", StringComparison.Ordinal);
        string tamperedPayload = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(tamperedJson));
        string tamperedJwt = $"{parts[0]}.{tamperedPayload}.{parts[2]}";

        JarmResponseValidationResult result = await ValidateAsync(
            tamperedJwt, serverPublic, Issuer, ClientId).ConfigureAwait(false);

        Assert.IsFalse(result.IsSignatureValid);
        Assert.IsFalse(result.IsValid);
        Assert.IsNull(result.Parameters);
    }


    [TestMethod]
    public async Task RejectsAlgNoneEvenWhenListedAsAllowed()
    {
        JwtPayload payload = new(capacity: 4)
        {
            [WellKnownJwtClaimNames.Iss] = Issuer,
            [WellKnownJwtClaimNames.Aud] = ClientId,
            [WellKnownJwtClaimNames.Exp] = TimeProvider.GetUtcNow().AddMinutes(5).ToUnixTimeSeconds(),
            ["code"] = "abc"
        };
        JwtHeader header = new(capacity: 1)
        {
            [WellKnownJwkMemberNames.Alg] = "none"
        };
        string unsignedJwt =
            $"{TestSetup.Base64UrlEncoder(HeaderSerializer(header))}.{TestSetup.Base64UrlEncoder(PayloadSerializer(payload))}.";

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory serverPublic = keys.PublicKey;
        using PrivateKeyMemory serverPrivate = keys.PrivateKey;

        string[] misconfiguredAllowList = ["none", WellKnownJwaValues.Es256];
        ResolveJarmVerificationKeyDelegate resolver = (_, _, _) =>
            ValueTask.FromResult<PublicKeyMemory?>(serverPublic);

        JarmResponseValidationResult result = await JarmResponseValidation.ValidateAsync(
            unsignedJwt, Issuer, ClientId, misconfiguredAllowList, TimeProvider.GetUtcNow(),
            resolver, PayloadDeserializer, TestSetup.Base64UrlDecoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsAlgorithmAllowed);
        Assert.IsFalse(result.IsSignatureValid);
        Assert.IsFalse(result.IsValid);
        Assert.IsNull(result.Parameters);
    }


    [TestMethod]
    public async Task RejectsCollidingResponseParameterNames()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory serverPublic = keys.PublicKey;
        using PrivateKeyMemory serverPrivate = keys.PrivateKey;

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            _ = await IssueAsync(serverPrivate, new Dictionary<string, object>
            {
                [WellKnownJwtClaimNames.Iss] = "https://attacker.example.com"
            }).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    public void EncodesResponseJwtPerResponseMode()
    {
        const string ResponseJwt = "eyJh.eyJi.c2ln";

        string queryLocation = JarmResponseEncoding.ToQueryRedirectLocation(RedirectUri, ResponseJwt);
        string queryAppended = JarmResponseEncoding.ToQueryRedirectLocation(
            new Uri("https://client.example.com/cb?session=abc"), ResponseJwt);
        string fragmentLocation = JarmResponseEncoding.ToFragmentRedirectLocation(RedirectUri, ResponseJwt);
        string formPostBody = JarmResponseEncoding.ToFormPostBody(ResponseJwt);
        string formPostHtml = JarmResponseEncoding.ToFormPostHtml(RedirectUri, ResponseJwt);

        Assert.AreEqual($"https://client.example.com/cb?response={ResponseJwt}", queryLocation);
        Assert.AreEqual($"https://client.example.com/cb?session=abc&response={ResponseJwt}", queryAppended);
        Assert.AreEqual($"https://client.example.com/cb#response={ResponseJwt}", fragmentLocation);
        Assert.AreEqual($"response={ResponseJwt}", formPostBody);
        Assert.Contains("action=\"https://client.example.com/cb\"", formPostHtml);
        Assert.Contains($"name=\"response\" value=\"{ResponseJwt}\"", formPostHtml);
    }


    [TestMethod]
    public void ResolvesJwtShortcutToResponseTypeDefaultEncoding()
    {
        Assert.AreEqual(JarmResponseModes.QueryJwt,
            JarmResponseEncoding.ResolveEncodingMode(JarmResponseModes.Jwt, "code"));
        Assert.AreEqual(JarmResponseModes.QueryJwt,
            JarmResponseEncoding.ResolveEncodingMode(JarmResponseModes.Jwt, "none"));
        Assert.AreEqual(JarmResponseModes.FragmentJwt,
            JarmResponseEncoding.ResolveEncodingMode(JarmResponseModes.Jwt, "token"));
        Assert.AreEqual(JarmResponseModes.FragmentJwt,
            JarmResponseEncoding.ResolveEncodingMode(JarmResponseModes.Jwt, "code id_token"));
        Assert.AreEqual(JarmResponseModes.FormPostJwt,
            JarmResponseEncoding.ResolveEncodingMode(JarmResponseModes.FormPostJwt, "code"));

        _ = Assert.ThrowsExactly<ArgumentException>(() =>
            JarmResponseEncoding.ResolveEncodingMode("query", "code"));
    }


    private async ValueTask<string> IssueAsync(
        PrivateKeyMemory signingKey,
        IReadOnlyDictionary<string, object> responseParameters,
        string issuer = Issuer,
        string clientId = ClientId,
        DateTimeOffset? expiresAt = null) =>
        await JarmResponseIssuance.IssueAsync(
            signingKey, KeyId, issuer, clientId,
            expiresAt ?? TimeProvider.GetUtcNow().AddMinutes(5),
            responseParameters,
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);


    private async ValueTask<JarmResponseValidationResult> ValidateAsync(
        string responseJwt,
        PublicKeyMemory serverPublic,
        string expectedIssuer,
        string expectedClientId)
    {
        ResolveJarmVerificationKeyDelegate resolver = (_, _, _) =>
            ValueTask.FromResult<PublicKeyMemory?>(serverPublic);

        return await JarmResponseValidation.ValidateAsync(
            responseJwt, expectedIssuer, expectedClientId, AllowedAlgorithms,
            TimeProvider.GetUtcNow(), resolver, PayloadDeserializer,
            TestSetup.Base64UrlDecoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
