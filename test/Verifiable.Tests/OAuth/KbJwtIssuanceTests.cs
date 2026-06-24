using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Json;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Direct tests for <see cref="KbJwtIssuance"/>. Exercises the holder-side
/// KB-JWT signing primitive in isolation; nothing else in the wallet flow is
/// involved.
/// </summary>
[TestClass]
internal sealed class KbJwtIssuanceTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task IssuesKbJwtWithCorrectSdHash()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        byte[] sdJwtInput = Encoding.UTF8.GetBytes(
            "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.signature~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFsaWNlIl0~");

        string compactKbJwt = await KbJwtIssuance.IssueAsync(
            sdJwtInput,
            holderPrivate,
            verifierNonce: "n-test",
            verifierAud: "https://verifier.example.com",
            iat: TimeProvider.GetUtcNow(),
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            headerSerializer: HeaderSerializer,
            payloadSerializer: PayloadSerializer,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Span<byte> expectedDigest = stackalloc byte[32];
        SHA256.HashData(sdJwtInput, expectedDigest);
        string expectedSdHash = TestSetup.Base64UrlEncoder(expectedDigest);

        string actualSdHash = ReadPayloadStringClaim(compactKbJwt, SdConstants.SdHashClaim);
        Assert.AreEqual(expectedSdHash, actualSdHash);
    }


    [TestMethod]
    public async Task IssuesKbJwtWithCorrectTypHeader()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        string compactKbJwt = await KbJwtIssuance.IssueAsync(
            Encoding.UTF8.GetBytes("eyJhbGciOiJFUzI1NiJ9.eyJ4IjoieSJ9.sig~"),
            holderPrivate,
            verifierNonce: "n-typ",
            verifierAud: "https://verifier.example.com",
            iat: TimeProvider.GetUtcNow(),
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            headerSerializer: HeaderSerializer,
            payloadSerializer: PayloadSerializer,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string typ = ReadHeaderStringClaim(compactKbJwt, WellKnownJoseHeaderNames.Typ);
        Assert.AreEqual(WellKnownMediaTypes.Jwt.KbJwt, typ);
    }


    [TestMethod]
    public async Task IssuesKbJwtWithSuppliedNonceAudIat()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        DateTimeOffset iat = new(2026, 5, 10, 12, 0, 0, TimeSpan.Zero);
        const string Nonce = "n-claims";
        const string Aud = "https://verifier.example.com/response";

        string compactKbJwt = await KbJwtIssuance.IssueAsync(
            Encoding.UTF8.GetBytes("eyJhbGciOiJFUzI1NiJ9.eyJ4IjoieSJ9.sig~"),
            holderPrivate,
            verifierNonce: Nonce,
            verifierAud: Aud,
            iat: iat,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            headerSerializer: HeaderSerializer,
            payloadSerializer: PayloadSerializer,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(Nonce, ReadPayloadStringClaim(compactKbJwt, WellKnownJwtClaimNames.Nonce));
        Assert.AreEqual(Aud, ReadPayloadStringClaim(compactKbJwt, WellKnownJwtClaimNames.Aud));
        Assert.AreEqual(iat.ToUnixTimeSeconds(), ReadPayloadInt64Claim(compactKbJwt, WellKnownJwtClaimNames.Iat));
    }


    [TestMethod]
    public async Task IssuesKbJwtSignedWithHolderKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        string compactKbJwt = await KbJwtIssuance.IssueAsync(
            Encoding.UTF8.GetBytes("eyJhbGciOiJFUzI1NiJ9.eyJ4IjoieSJ9.sig~"),
            holderPrivate,
            verifierNonce: "n-sig",
            verifierAud: "https://verifier.example.com",
            iat: TimeProvider.GetUtcNow(),
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            headerSerializer: HeaderSerializer,
            payloadSerializer: PayloadSerializer,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool valid = await Jws.VerifyAsync(
            compactKbJwt,
            TestSetup.Base64UrlDecoder,
            Pool,
            holderPublic,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(valid);
    }


    [TestMethod]
    public async Task SurfacesCancellation()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        using CancellationTokenSource cts = new();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
        {
            _ = await KbJwtIssuance.IssueAsync(
                Encoding.UTF8.GetBytes("eyJhbGciOiJFUzI1NiJ9.eyJ4IjoieSJ9.sig~"),
                holderPrivate,
                verifierNonce: "n-cancel",
                verifierAud: "https://verifier.example.com",
                iat: TimeProvider.GetUtcNow(),
                base64UrlEncoder: TestSetup.Base64UrlEncoder,
                headerSerializer: HeaderSerializer,
                payloadSerializer: PayloadSerializer,
                memoryPool: Pool,
                cancellationToken: cts.Token).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    private static string ReadPayloadStringClaim(string compactJwt, string claim)
    {
        using JsonDocument document = ParsePayload(compactJwt);
        return document.RootElement.GetProperty(claim).GetString()
            ?? throw new InvalidOperationException($"Claim '{claim}' is null.");
    }


    private static long ReadPayloadInt64Claim(string compactJwt, string claim)
    {
        using JsonDocument document = ParsePayload(compactJwt);
        return document.RootElement.GetProperty(claim).GetInt64();
    }


    private static string ReadHeaderStringClaim(string compactJwt, string claim)
    {
        using JsonDocument document = ParseHeader(compactJwt);
        return document.RootElement.GetProperty(claim).GetString()
            ?? throw new InvalidOperationException($"Header claim '{claim}' is null.");
    }


    private static JsonDocument ParsePayload(string compactJwt) =>
        ParseSegment(compactJwt, segmentIndex: 1);


    private static JsonDocument ParseHeader(string compactJwt) =>
        ParseSegment(compactJwt, segmentIndex: 0);


    //The pool may return an oversized buffer, so route through Encoding.UTF8.GetString
    //with the decoder's known content length read off the JSON-shape boundary —
    //equivalent to the canonical pattern used elsewhere when converting decoded
    //base64url bytes back into JsonDocument input.
    private static JsonDocument ParseSegment(string compactJwt, int segmentIndex)
    {
        string[] parts = compactJwt.Split('.');
        Assert.HasCount(3, parts);
        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[segmentIndex], Pool);
        string json = Encoding.UTF8.GetString(bytes.Memory.Span).TrimEnd('\0');
        return JsonDocument.Parse(json);
    }
}
