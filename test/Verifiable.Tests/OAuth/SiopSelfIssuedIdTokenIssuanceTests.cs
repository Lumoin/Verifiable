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

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://verifier.example.org/cb";
    private const string RequestNonce = "n-0S6_WzA2Mj";

    private static string[] AllowedAlgorithms { get; } = [WellKnownJwaValues.Es256];

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string? resolvedKid = null;
        ValueTask<PublicKeyMemory?> resolver(string _1, string? kid, CancellationToken _2)
        {
            resolvedKid = kid;

            return ValueTask.FromResult<PublicKeyMemory?>(subjectPublic);
        }

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
resolver,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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

        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            _ = await SelfIssuedIdTokenIssuance.IssueWithDecentralizedIdentifierAsync(
                subjectPrivate, "https://not-a-did.example.com", "key-1", ClientId, RequestNonce,
                issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
                TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
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

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
        {
            _ = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
                subjectPrivate, subjectPublic, ClientId, RequestNonce,
                issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
                TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
                cts.Token).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// The library's own rule for a lifetime it issues: the wallet writes the <c>iat</c> and <c>exp</c> of a Self-Issued
    /// ID Token (<see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-11">Self-Issued
    /// OpenID Provider v2 Section 11</see>) as whole-second NumericDates, so it issues the token for the whole seconds of
    /// the lifetime it is given: 90.7 seconds, issued half a second past a whole second, stamps an <c>exp</c> 90 seconds
    /// after the <c>iat</c>, under the JWK Thumbprint and the Decentralized Identifier Subject Syntax Types alike.
    /// </summary>
    /// <param name="subjectSyntaxType">The Subject Syntax Type the token is issued under.</param>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    [DataRow(JwkThumbprintSubject)]
    [DataRow(DecentralizedIdentifierSubject)]
    public async Task ASelfIssuedIdTokenUnderAFractionalLifetimeLivesItsWholeSecondsAsync(string subjectSyntaxType)
    {
        DateTimeOffset issuedAt = TimeProvider.GetUtcNow() + TimeSpan.FromTicks(TimeSpan.TicksPerSecond / 2);

        string idToken = await IssueUnderSubjectSyntaxTypeAsync(
            subjectSyntaxType, issuedAt, TimeSpan.FromTicks(907_000_000L)).ConfigureAwait(false);

        using JsonDocument payload = ParseSegment(idToken.Split('.')[1]);
        long iat = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Iat).GetInt64();
        long exp = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Exp).GetInt64();
        Assert.AreEqual(90L, exp - iat, idToken);
    }


    /// <summary>
    /// The library's own rule for a lifetime it issues: the wallet writes the <c>iat</c> and <c>exp</c> of a Self-Issued
    /// ID Token (<see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-11">Self-Issued
    /// OpenID Provider v2 Section 11</see>) as whole-second NumericDates, so a lifetime under one second would issue a
    /// token whose <c>exp</c> equals its <c>iat</c>. The lifetime is the caller's own argument: 500 milliseconds is
    /// refused with <see cref="ArgumentOutOfRangeException"/> under both Subject Syntax Types.
    /// </summary>
    /// <param name="subjectSyntaxType">The Subject Syntax Type the token is issued under.</param>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    [DataRow(JwkThumbprintSubject)]
    [DataRow(DecentralizedIdentifierSubject)]
    public async Task ASelfIssuedIdTokenLifetimeUnderOneSecondIsRefusedAsync(string subjectSyntaxType)
    {
        _ = await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(async () =>
        {
            _ = await IssueUnderSubjectSyntaxTypeAsync(
                subjectSyntaxType, TimeProvider.GetUtcNow(), TimeSpan.FromMilliseconds(500)).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// The row value naming the JWK Thumbprint Subject Syntax Type. A constant because <see cref="DataRowAttribute"/>
    /// takes compile-time constants only.
    /// </summary>
    private const string JwkThumbprintSubject = "jwk thumbprint";

    /// <summary>
    /// The row value naming the Decentralized Identifier Subject Syntax Type. A constant because
    /// <see cref="DataRowAttribute"/> takes compile-time constants only.
    /// </summary>
    private const string DecentralizedIdentifierSubject = "decentralized identifier";


    /// <summary>
    /// Issues a Self-Issued ID Token under <paramref name="subjectSyntaxType"/> with a fresh P-256 key, for the request's
    /// client and nonce.
    /// </summary>
    /// <param name="subjectSyntaxType">The Subject Syntax Type: <see cref="JwkThumbprintSubject"/> or <see cref="DecentralizedIdentifierSubject"/>.</param>
    /// <param name="issuedAt">The <c>iat</c> instant.</param>
    /// <param name="lifetime">The lifetime the token is issued with.</param>
    /// <returns>The compact-serialised Self-Issued ID Token.</returns>
    private async Task<string> IssueUnderSubjectSyntaxTypeAsync(string subjectSyntaxType, DateTimeOffset issuedAt, TimeSpan lifetime)
    {
        const string Did = "did:example:NzbLsXh8uDCcd6MNwXF4W7noWXFZAfHkxZsRGC9Xs";
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        return subjectSyntaxType switch
        {
            JwkThumbprintSubject => await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
                subjectPrivate, subjectPublic, ClientId, RequestNonce, issuedAt, lifetime,
                TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
                TestContext.CancellationToken).ConfigureAwait(false),
            DecentralizedIdentifierSubject => await SelfIssuedIdTokenIssuance.IssueWithDecentralizedIdentifierAsync(
                subjectPrivate, Did, Did + "#key-1", ClientId, RequestNonce, issuedAt, lifetime,
                TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
                TestContext.CancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(subjectSyntaxType), subjectSyntaxType, "Unknown Subject Syntax Type.")
        };
    }


    private static JsonDocument ParseSegment(string segment)
    {
        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(segment, Pool);
        string json = System.Text.Encoding.UTF8.GetString(bytes.Memory.Span).TrimEnd('\0');

        return JsonDocument.Parse(json);
    }
}
