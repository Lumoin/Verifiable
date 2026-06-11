using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Direct tests for <see cref="SelfIssuedIdTokenIssuance"/> — the wallet
/// (Self-Issued OP) side of SIOPv2 §11 — including full round trips through the
/// Relying Party validator <see cref="SelfIssuedIdTokenValidation"/>, proving the
/// two sides agree on the subject forms of both Subject Syntax Types.
/// </summary>
[TestClass]
internal sealed class SiopSelfIssuedIdTokenIssuanceTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private const string ClientId = "https://verifier.example.org/cb";
    private const string RequestNonce = "n-0S6_WzA2Mj";

    private static readonly string[] AllowedAlgorithms = [WellKnownJwaValues.Es256];

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task JwkThumbprintTokenRoundTripsThroughRpValidation()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            subjectPrivate, subjectPublic, ClientId, RequestNonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.AreEqual(SiopSubjectSyntaxType.JwkThumbprint, result.SubjectSyntaxType);
        Assert.StartsWith(SiopSubjectSyntaxTypes.JwkThumbprintSha256Prefix, result.Subject);
    }


    [TestMethod]
    public async Task DecentralizedIdentifierTokenRoundTripsThroughRpValidation()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        const string Did = "did:example:NzbLsXh8uDCcd6MNwXF4W7noWXFZAfHkxZsRGC9Xs";
        const string KeyId = Did + "#key-1";
        string idToken = await SelfIssuedIdTokenIssuance.IssueWithDecentralizedIdentifierAsync(
            subjectPrivate, Did, KeyId, ClientId, RequestNonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        string? resolvedKid = null;
        ResolveDidVerificationKeyDelegate resolver = (_, kid, _) =>
        {
            resolvedKid = kid;

            return ValueTask.FromResult<PublicKeyMemory?>(subjectPublic);
        };

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolver,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.AreEqual(SiopSubjectSyntaxType.DecentralizedIdentifier, result.SubjectSyntaxType);
        Assert.AreEqual(Did, result.Subject);
        Assert.AreEqual(KeyId, resolvedKid);
    }


    [TestMethod]
    public async Task IssuesSelfIssuedClaimsAndJwtHeader()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        DateTimeOffset issuedAt = TimeProvider.GetUtcNow();
        TimeSpan lifetime = TimeSpan.FromMinutes(5);
        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            subjectPrivate, subjectPublic, ClientId, RequestNonce,
            issuedAt, lifetime,
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        string[] parts = idToken.Split('.');
        Assert.HasCount(3, parts);

        using JsonDocument header = ParseSegment(parts[0]);
        Assert.AreEqual(WellKnownJwaValues.Es256, header.RootElement.GetProperty(WellKnownJwkMemberNames.Alg).GetString());
        Assert.AreEqual(WellKnownJwkValues.TypeJwt, header.RootElement.GetProperty(WellKnownJoseHeaderNames.Typ).GetString());

        using JsonDocument payload = ParseSegment(parts[1]);
        string? iss = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Iss).GetString();
        string? sub = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString();
        Assert.AreEqual(iss, sub);
        Assert.AreEqual(ClientId, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud).GetString());
        Assert.AreEqual(RequestNonce, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Nonce).GetString());
        Assert.AreEqual(issuedAt.ToUnixTimeSeconds(), payload.RootElement.GetProperty(WellKnownJwtClaimNames.Iat).GetInt64());
        Assert.AreEqual(issuedAt.Add(lifetime).ToUnixTimeSeconds(), payload.RootElement.GetProperty(WellKnownJwtClaimNames.Exp).GetInt64());
        Assert.AreEqual(JsonValueKind.Object, payload.RootElement.GetProperty(WellKnownJwtClaimNames.SubJwk).ValueKind);
    }


    [TestMethod]
    public async Task RejectsNonDidSubjectForDecentralizedIdentifierType()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            _ = await SelfIssuedIdTokenIssuance.IssueWithDecentralizedIdentifierAsync(
                subjectPrivate, "https://not-a-did.example.com", "key-1", ClientId, RequestNonce,
                issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
                TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
                TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task SurfacesCancellation()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        using CancellationTokenSource cts = new();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
        {
            _ = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
                subjectPrivate, subjectPublic, ClientId, RequestNonce,
                issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
                TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
                cts.Token).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    private static JsonDocument ParseSegment(string segment)
    {
        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(segment, Pool);
        string json = System.Text.Encoding.UTF8.GetString(bytes.Memory.Span).TrimEnd('\0');

        return JsonDocument.Parse(json);
    }
}
