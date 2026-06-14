using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Server;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The SIOPv2 RP flow action handler: <see cref="SiopVerifierExecutor"/> registers a
/// <see cref="ValidateSelfIssuedIdToken"/> handler on the shared <see cref="OAuthActionExecutor"/>
/// that runs the §11.1 validation (the effectful step between pure PDA transitions) and maps the
/// verdict to <see cref="SelfIssuedAuthenticationVerified"/> or <see cref="SiopFlowFailed"/>.
/// </summary>
[TestClass]
internal sealed class SiopVerifierExecutorTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://verifier.example.com";
    private const string Nonce = "n-presentation-01";

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;
    private static readonly string[] AllowedAlgorithms = [WellKnownJwaValues.Es256];

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task ValidTokenYieldsVerifiedInput()
    {
        string idToken = await MintAsync(ClientId, Nonce).ConfigureAwait(false);
        OAuthActionExecutor executor = SiopVerifierExecutor.Create(
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder,
            HeaderSerializer, PayloadSerializer, Pool, TimeProvider);

        FlowInput input = await executor.ExecuteAsync(
            new ValidateSelfIssuedIdToken(idToken, ClientId, Nonce, AllowedAlgorithms),
            new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        SelfIssuedAuthenticationVerified verified = (SelfIssuedAuthenticationVerified)input;
        Assert.AreEqual(Nonce, verified.Nonce);
        Assert.AreEqual(SiopSubjectSyntaxType.JwkThumbprint, verified.SubjectSyntaxType);
        Assert.StartsWith("urn:ietf:params:oauth:jwk-thumbprint", verified.Subject);
    }


    [TestMethod]
    public async Task WrongNonceYieldsFailedInput()
    {
        //Token minted for the real nonce, but the transaction expected a different one.
        string idToken = await MintAsync(ClientId, Nonce).ConfigureAwait(false);
        OAuthActionExecutor executor = SiopVerifierExecutor.Create(
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder,
            HeaderSerializer, PayloadSerializer, Pool, TimeProvider);

        FlowInput input = await executor.ExecuteAsync(
            new ValidateSelfIssuedIdToken(idToken, ClientId, "a-different-nonce", AllowedAlgorithms),
            new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<SiopFlowFailed>(input);
        Assert.Contains("nonce=False", ((SiopFlowFailed)input).Reason);
    }


    private async Task<string> MintAsync(string audience, string nonce)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = keys.PublicKey;
        using PrivateKeyMemory siopPrivate = keys.PrivateKey;

        return await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, audience, nonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
